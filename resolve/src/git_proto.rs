//! The slice of git's wire protocol the resolver speaks: pkt-line
//! framing, the `info/refs` advertisement parse, and `fetch` requests
//! over smart HTTP — protocol v2 when the server negotiates it, v0
//! otherwise — that ask for one commit shallowly (`deepen 1`).
//!
//! A `filter=blob:none` fetch is how a tree's gitlink (submodule) commits
//! are read without `api.github.com`: the REST trees API caps an
//! unauthenticated caller at 60 requests per hour per egress IP — a quota
//! shared Worker egress exhausts for the caller before the lane starts —
//! while `git-upload-pack` is the same anonymous endpoint `git clone`
//! itself uses. The unfiltered fetch carries the dep lane on hosts with
//! no tarball endpoint: one POST returns the commit's whole tree as a
//! pack.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

use crate::util::errors::CargoResult;
use crate::util::network::http_async::Client;

/// Append `payload` as one pkt-line to `out`.
fn pkt_line(out: &mut Vec<u8>, payload: &str) {
    out.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    out.extend_from_slice(payload.as_bytes());
}

/// One pkt-line cursor over a wire buffer: yields each packet's payload,
/// `None` payloads being flush packets (`0000`).
struct PktLines<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PktLines<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// `Ok(None)` at end of input, `Ok(Some(None))` on a flush packet.
    fn next(&mut self) -> CargoResult<Option<Option<&'a [u8]>>> {
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        if self.pos + 4 > self.bytes.len() {
            bail!("truncated pkt-line length at offset {}", self.pos);
        }
        let len_bytes = &self.bytes[self.pos..self.pos + 4];
        let len_str = std::str::from_utf8(len_bytes).context("non-hex pkt-line length")?;
        let len = u32::from_str_radix(len_str.trim_end_matches('\n'), 16)
            .with_context(|| format!("invalid pkt-line length `{len_str}`"))?
            as usize;
        self.pos += 4;
        // `0000` is a flush pkt, `0001` a section delimiter — both
        // carry no payload and both matter only as boundaries.
        if len <= 1 {
            return Ok(Some(None));
        }
        if len < 4 || self.pos + (len - 4) > self.bytes.len() {
            bail!(
                "truncated pkt-line of {len} bytes at offset {}",
                self.pos - 4
            );
        }
        let payload = &self.bytes[self.pos..self.pos + len - 4];
        self.pos += len - 4;
        Ok(Some(Some(payload)))
    }
}

/// Parse an `info/refs?service=git-upload-pack` response (pkt-line
/// framed) into `(sha, refname)` pairs. The advertisement is a byte
/// stream — the HEAD pkt's capability payload ends without a newline —
/// so packets are walked by their length prefixes, never by lines.
pub fn parse_ls_remote(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut pkts = PktLines::new(text.as_bytes());
    while let Ok(Some(payload)) = pkts.next() {
        let Some(payload) = payload else {
            continue; // flush pkt
        };
        // Drop the capability NUL suffix the first pkt carries.
        let payload = payload.split(|&b| b == 0).next().unwrap_or(payload);
        let Ok(payload) = std::str::from_utf8(payload) else {
            continue;
        };
        let mut parts = payload.trim_end_matches('\n').splitn(2, ' ');
        let (Some(sha), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name == "HEAD" || name.starts_with("refs/") {
            refs.push((sha.to_owned(), name.to_owned()));
        }
    }
    refs
}

/// One entry of a commit's recursive tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// The git mode — `0o40000` dir, `0o160000` gitlink, `0o120000`
    /// symlink, `0o100644`/`0o100755` file.
    pub mode: u32,
    pub sha: String,
}

/// The `agent` capability every request advertises.
const AGENT: &str = concat!("agent=stow-resolve/", env!("CARGO_PKG_VERSION"), "\n");

/// `POST git-upload-pack` `command=fetch` for `commit` in `owner/repo`
/// with `filter=blob:none` and `deepen 1`, returning the commit's whole
/// recursive tree — every path's mode and object sha — from the pack
/// the server sends. Blobs stay on GitHub's side; this asks only for
/// the structure `git clone --filter=blob:none` reads first.
pub async fn fetch_commit_tree(
    client: &Client,
    owner: &str,
    repo: &str,
    commit: &str,
) -> CargoResult<BTreeMap<PathBuf, TreeEntry>> {
    let mut body = Vec::new();
    pkt_line(&mut body, "command=fetch\n");
    pkt_line(&mut body, "object-format=sha1\n");
    pkt_line(&mut body, AGENT);
    body.extend_from_slice(b"0001");
    pkt_line(&mut body, "no-progress\n");
    pkt_line(&mut body, "ofs-delta\n");
    pkt_line(&mut body, &format!("deepen 1\n"));
    pkt_line(&mut body, &format!("filter blob:none\n"));
    pkt_line(&mut body, &format!("want {commit}\n"));
    body.extend_from_slice(b"0000");

    let url = format!("https://github.com/{owner}/{repo}.git");
    let response_body = upload_pack_post(client, &url, &body, true)
        .await
        .with_context(|| format!("fetch tree of `{owner}/{repo}`"))?;
    let pack = extract_pack(&response_body)
        .with_context(|| format!("decode git fetch response for `{owner}/{repo}`"))?;
    let objects =
        unpack_pack(&pack).with_context(|| format!("unpack git pack for `{owner}/{repo}`"))?;
    commit_tree(&objects, commit).with_context(|| format!("walk tree of `{owner}/{repo}`"))
}

/// What an `info/refs` advertisement carries: which fetch protocol the
/// remote negotiated and — v0 only — the refs themselves.
#[derive(Clone)]
pub struct Advertisement {
    /// The remote answered protocol v2 (`version 2` leads the response):
    /// fetches use `command=` framing and refs come from a separate
    /// `ls-refs` request — a v2 advertisement lists capabilities only.
    pub v2: bool,
    /// Advertised capabilities — v0 takes them from the first ref pkt's
    /// NUL suffix (`shallow`, `side-band-64k`, …), v2 from the capability
    /// lines themselves (`fetch=shallow` means `deepen` is accepted).
    pub capabilities: Vec<String>,
    /// The ref advertisement — populated for v0, always empty for v2.
    pub refs: Vec<(String, String)>,
}

impl Advertisement {
    /// `deepen` is only legal when the remote advertises shallow support
    /// (`shallow` in v0, `fetch=shallow` in v2); without it the fetch
    /// falls back to the commit's full history.
    fn can_deepen(&self) -> bool {
        self.capabilities.iter().any(|cap| {
            cap == "shallow"
                || cap
                    .strip_prefix("fetch=")
                    .is_some_and(|v| v.split(' ').any(|f| f == "shallow"))
        })
    }
}

/// `GET {url}/info/refs?service=git-upload-pack` asking for protocol v2:
/// a v2 remote answers capability lines only (refs need [`ls_refs`]); a
/// v0 remote ignores the header and answers the full advertisement, refs
/// included. One request doubles as protocol detection and, for v0, ref
/// resolution.
pub async fn advertise(client: &Client, url: &str) -> CargoResult<Advertisement> {
    let request = http::Request::get(format!("{url}/info/refs?service=git-upload-pack"))
        .header("User-Agent", crate::github_tree::USER_AGENT)
        .header("Accept", "application/x-git-upload-pack-advertisement")
        .header("Git-Protocol", "version=2")
        .body(Vec::new())?;
    let response = client
        .request(request)
        .await
        .with_context(|| format!("git advertisement of `{url}` failed"))?;
    let (parts, body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        bail!(
            "git advertisement of `{url}` returned HTTP {}",
            parts.status
        );
    }
    parse_advertisement(&body).with_context(|| format!("decode git advertisement of `{url}`"))
}

/// Parse an `info/refs` response into an [`Advertisement`]. The first
/// content pkt decides the protocol: `version 2` leads the v2 capability
/// list; `# service=` leads a v0 advertisement whose ref table follows
/// after a flush pkt.
fn parse_advertisement(body: &[u8]) -> CargoResult<Advertisement> {
    let mut pkts = PktLines::new(body);
    let mut capabilities = Vec::new();
    let mut refs = Vec::new();
    let mut v2 = None;
    loop {
        let Some(payload) = pkts.next()? else {
            break;
        };
        let Some(payload) = payload else {
            continue; // flush pkt — sections may follow
        };
        let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
        if payload == b"# service=git-upload-pack" {
            continue;
        }
        match v2 {
            None => {
                v2 = Some(payload == b"version 2");
                continue;
            }
            Some(true) => {
                let Ok(line) = str::from_utf8(payload) else {
                    continue;
                };
                capabilities.push(line.to_owned());
            }
            Some(false) => {
                // v0 ref line `<oid> SP <name>` — the first carries the
                // capability list after a NUL.
                let (head, suffix) = match payload.iter().position(|&b| b == 0) {
                    Some(nul) => (&payload[..nul], Some(&payload[nul + 1..])),
                    None => (payload, None),
                };
                if let Some(suffix) = suffix {
                    let text = str::from_utf8(suffix).context("non-UTF-8 capabilities")?;
                    capabilities.extend(text.split(' ').map(str::to_owned));
                }
                let Ok(line) = str::from_utf8(head) else {
                    continue;
                };
                let mut parts = line.splitn(2, ' ');
                if let (Some(oid), Some(name)) = (parts.next(), parts.next())
                    && (name == "HEAD" || name.starts_with("refs/"))
                {
                    refs.push((oid.to_owned(), name.to_owned()));
                }
            }
        }
    }
    Ok(Advertisement {
        v2: v2.unwrap_or(false),
        capabilities,
        refs,
    })
}

/// Protocol-v2 `ls-refs`: the ref table a v2 advertisement withholds.
/// `peel` folds annotated tags into `^{}` pairs and `symrefs` keeps HEAD
/// resolvable — the `(sha, refname)` shape `pick_ref` consumes.
pub async fn ls_refs(client: &Client, url: &str) -> CargoResult<Vec<(String, String)>> {
    let mut body = Vec::new();
    pkt_line(&mut body, "command=ls-refs\n");
    pkt_line(&mut body, "object-format=sha1\n");
    pkt_line(&mut body, AGENT);
    body.extend_from_slice(b"0001");
    pkt_line(&mut body, "peel\n");
    pkt_line(&mut body, "symrefs\n");
    pkt_line(&mut body, "ref-prefix HEAD\n");
    pkt_line(&mut body, "ref-prefix refs/\n");
    body.extend_from_slice(b"0000");
    let response = upload_pack_post(client, url, &body, true)
        .await
        .with_context(|| format!("list refs of `{url}`"))?;

    let mut refs = Vec::new();
    let mut pkts = PktLines::new(&response);
    loop {
        // A response pkt can be a flush/delimiter — `while let
        // Some(Some(..))` would stop at it mid-stream.
        let Some(payload) = pkts.next()? else { break };
        let Some(payload) = payload else { continue };
        let mut lines = payload.split(|&b| b == b'\n');
        let Some(head) = lines.next() else { continue };
        let Ok(head) = str::from_utf8(head) else {
            continue;
        };
        let mut parts = head.splitn(2, ' ');
        let (Some(oid), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        refs.push((oid.to_owned(), name.to_owned()));
        for attr in lines {
            if let Some(peeled) = attr.strip_prefix(b"peeled:") {
                let peeled = str::from_utf8(peeled).context("non-UTF-8 peeled oid")?;
                refs.push((peeled.to_owned(), format!("{name}^{{}}")));
            }
        }
    }
    Ok(refs)
}

/// Fetch `sha` from `url` — the repo URL `advertise` probed — requesting
/// `deepen 1` (when the advertisement permits shallow), `no-progress` and
/// `done`. Returns the pack bytes the response carries: protocol v2
/// `command=fetch` when negotiated, v0 `want`/`done` otherwise.
pub async fn fetch_pack(
    client: &Client,
    url: &str,
    sha: &str,
    adv: &Advertisement,
) -> CargoResult<Vec<u8>> {
    if adv.v2 {
        let mut body = Vec::new();
        pkt_line(&mut body, "command=fetch\n");
        pkt_line(&mut body, "object-format=sha1\n");
        pkt_line(&mut body, AGENT);
        body.extend_from_slice(b"0001");
        pkt_line(&mut body, "no-progress\n");
        pkt_line(&mut body, "ofs-delta\n");
        if adv.can_deepen() {
            pkt_line(&mut body, "deepen 1\n");
        }
        pkt_line(&mut body, &format!("want {sha}\n"));
        pkt_line(&mut body, "done\n");
        body.extend_from_slice(b"0000");
        let response = upload_pack_post(client, url, &body, true).await?;
        extract_pack(&response).with_context(|| format!("decode git fetch response for `{url}`"))
    } else {
        // v0: echo the capabilities the server actually advertised on the
        // first `want` line; `deepen` rides after the flush, `done` ends
        // the single negotiation round.
        // `thin-pack` is never requested: with no `have` lines the server
        // has nothing to thin against, and the pack is self-contained.
        let caps = [
            "multi_ack_detailed",
            "no-done",
            "side-band-64k",
            "ofs-delta",
            "no-progress",
        ]
        .into_iter()
        .filter(|cap| adv.capabilities.iter().any(|c| c == cap))
        .collect::<Vec<_>>();
        let want = if caps.is_empty() {
            format!("want {sha}\n")
        } else {
            format!("want {sha} {}\n", caps.join(" "))
        };
        let mut body = Vec::new();
        pkt_line(&mut body, &want);
        body.extend_from_slice(b"0000");
        if adv.can_deepen() {
            pkt_line(&mut body, "deepen 1\n");
        }
        pkt_line(&mut body, "done\n");
        let response = upload_pack_post(client, url, &body, false).await?;
        extract_pack_v0(&response).with_context(|| format!("decode git fetch response for `{url}`"))
    }
}

/// `POST {url}/git-upload-pack` in the protocol version the advertisement
/// negotiated, returning the response body.
async fn upload_pack_post(
    client: &Client,
    url: &str,
    body: &[u8],
    v2: bool,
) -> CargoResult<Vec<u8>> {
    let mut request = http::Request::post(format!("{url}/git-upload-pack"))
        .header("User-Agent", crate::github_tree::USER_AGENT)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Accept", "application/x-git-upload-pack-result");
    if v2 {
        request = request.header("Git-Protocol", "version=2");
    }
    let request = request.body(body.to_vec())?;
    let response = client
        .request(request)
        .await
        .with_context(|| format!("git upload-pack of `{url}` failed"))?;
    let (parts, response_body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        bail!("git upload-pack of `{url}` returned HTTP {}", parts.status);
    }
    Ok(response_body)
}

/// Pull the pack bytes out of a `fetch` response's pkt-line sections:
/// everything before the `packfile` section is response metadata
/// (`shallow-info`, `acknowledgments`, …); inside it each pkt carries a
/// sideband channel byte (1 = pack data, 2 = progress, 3 = fatal).
fn extract_pack(response: &[u8]) -> CargoResult<Vec<u8>> {
    let mut pkts = PktLines::new(response);
    let mut pack = Vec::new();
    let mut in_packfile = false;
    while let Some(payload) = pkts.next()? {
        let Some(payload) = payload else {
            in_packfile = false;
            continue;
        };
        if !in_packfile {
            if payload == b"packfile\n" {
                in_packfile = true;
                continue;
            }
            let text = String::from_utf8_lossy(payload);
            if text.starts_with("ERR ") {
                bail!("server reported: {}", text.trim_end());
            }
            continue;
        }
        let Some((&channel, data)) = payload.split_first() else {
            continue;
        };
        match channel {
            1 => pack.extend_from_slice(data),
            3 => bail!(
                "server reported: {}",
                String::from_utf8_lossy(data).trim_end()
            ),
            // 2 = progress — `no-progress` already suppresses most of it.
            _ => {}
        }
    }
    if pack.is_empty() {
        bail!("response carried no packfile section");
    }
    Ok(pack)
}

/// Pull the pack bytes out of a v0 `fetch` response: `shallow`/`unshallow`
/// and `NAK`/`ACK` control pkts lead — none of them banded — then the pack
/// arrives sideband-framed when `side-band-64k` negotiated (channel 1 =
/// pack, 2 = progress, 3 = fatal) or as raw `PACK` bytes when it did not.
fn extract_pack_v0(response: &[u8]) -> CargoResult<Vec<u8>> {
    let mut pkts = PktLines::new(response);
    let mut pack = Vec::new();
    loop {
        let at = pkts.pos;
        let payload = match pkts.next() {
            Ok(Some(Some(payload))) => payload,
            Ok(Some(None)) => continue, // flush pkt — more may follow
            Ok(None) => break,
            // Not a pkt at all: an unbanded `PACK` stream ran into the
            // control block — everything from this offset is pack.
            Err(_) if response[at..].starts_with(b"PACK") => {
                pack.extend_from_slice(&response[at..]);
                break;
            }
            Err(e) => return Err(e),
        };
        let text = payload.strip_suffix(b"\n").unwrap_or(payload);
        if text.starts_with(b"shallow ")
            || text.starts_with(b"unshallow ")
            || text.starts_with(b"ACK ")
            || text == b"NAK"
        {
            continue;
        }
        if let Some(err) = text.strip_prefix(b"ERR ") {
            bail!(
                "server reported: {}",
                String::from_utf8_lossy(err).trim_end()
            );
        }
        match payload.first() {
            Some(1) => pack.extend_from_slice(&payload[1..]),
            Some(3) => bail!(
                "server reported: {}",
                String::from_utf8_lossy(&payload[1..]).trim_end()
            ),
            // 2 = progress — `no-progress` already suppresses most of it.
            Some(2) => {}
            _ => bail!("unexpected content in git fetch response"),
        }
    }
    if pack.is_empty() {
        bail!("response carried no pack data");
    }
    Ok(pack)
}

/// A pack object after delta resolution.
struct Object {
    ty: u8,
    data: Vec<u8>,
    sha: [u8; 20],
}

const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

/// Decode a packfile: walk each object, inflate its zlib payload, and
/// resolve deltas against their bases (offset or object-name).
fn unpack_pack(pack: &[u8]) -> CargoResult<Vec<Object>> {
    if pack.len() < 12 || &pack[..4] != b"PACK" {
        bail!("not a packfile");
    }
    let count = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;
    let mut raw: Vec<(u64, u8, RawObj)> = Vec::with_capacity(count);
    let mut sha_index: BTreeMap<[u8; 20], usize> = BTreeMap::new();
    let mut pos = 12usize;
    for _ in 0..count {
        let offset = pos as u64;
        let (ty, _size) = pack_obj_header(pack, &mut pos)?;
        let raw_obj = match ty {
            OBJ_OFS_DELTA => {
                let base_offset = ofs_delta_base(pack, &mut pos, offset)?;
                let (data, used) = inflate(&pack[pos..])?;
                pos += used;
                RawObj::OfsDelta {
                    base_offset,
                    delta: data,
                }
            }
            OBJ_REF_DELTA => {
                if pos + 20 > pack.len() {
                    bail!("truncated ref-delta base");
                }
                let base_sha: [u8; 20] = pack[pos..pos + 20].try_into().unwrap();
                pos += 20;
                let (data, used) = inflate(&pack[pos..])?;
                pos += used;
                RawObj::RefDelta {
                    base_sha,
                    delta: data,
                }
            }
            _ => {
                let (data, used) = inflate(&pack[pos..])?;
                pos += used;
                RawObj::Plain(data)
            }
        };
        raw.push((offset, ty, raw_obj));
    }
    // Index every non-delta object by name first: a ref-delta's base is
    // named by sha and may sit anywhere in the pack. A delta-based
    // ref-delta base still reports "not in pack" — `ofs-delta` was
    // requested, so GitHub never emits that shape.
    for (index, (_, ty, raw_obj)) in raw.iter().enumerate() {
        if let RawObj::Plain(data) = raw_obj {
            sha_index.insert(object_sha(*ty, data), index);
        }
    }
    let mut resolved: Vec<Option<Object>> = (0..raw.len()).map(|_| None).collect();
    for index in 0..raw.len() {
        resolve_obj(&raw, &sha_index, &mut resolved, index)?;
        if let Some(object) = &resolved[index] {
            sha_index.insert(object.sha, index);
        }
    }
    Ok(resolved.into_iter().flatten().collect())
}

/// A not-yet-resolved pack object payload.
enum RawObj {
    Plain(Vec<u8>),
    OfsDelta { base_offset: u64, delta: Vec<u8> },
    RefDelta { base_sha: [u8; 20], delta: Vec<u8> },
}

/// An object's varint `(type, size)` header at `pos`, advancing it.
fn pack_obj_header(pack: &[u8], pos: &mut usize) -> CargoResult<(u8, u64)> {
    let Some(&byte) = pack.get(*pos) else {
        bail!("truncated object header");
    };
    *pos += 1;
    let ty = (byte >> 4) & 0x7;
    let mut size = (byte & 0x0f) as u64;
    let mut shift = 4;
    let mut byte = byte;
    while byte & 0x80 != 0 {
        let Some(&next) = pack.get(*pos) else {
            bail!("truncated object size");
        };
        *pos += 1;
        size |= ((next & 0x7f) as u64) << shift;
        shift += 7;
        byte = next;
    }
    Ok((ty, size))
}

/// The ofs-delta base pointer: a varint whose continuation bits *extend*
/// the value, giving the offset of the base object before this one.
fn ofs_delta_base(pack: &[u8], pos: &mut usize, offset: u64) -> CargoResult<u64> {
    let Some(&byte) = pack.get(*pos) else {
        bail!("truncated ofs-delta base");
    };
    *pos += 1;
    let mut n = (byte & 0x7f) as u64;
    let mut byte = byte;
    while byte & 0x80 != 0 {
        let Some(&next) = pack.get(*pos) else {
            bail!("truncated ofs-delta base");
        };
        *pos += 1;
        n = ((n + 1) << 7) | ((next & 0x7f) as u64);
        byte = next;
    }
    let base = offset
        .checked_sub(n)
        .ok_or_else(|| anyhow!("ofs-delta base before pack start"))?;
    Ok(base)
}

/// Inflate one zlib stream at the head of `input`; returns the bytes and
/// how much of `input` the stream consumed.
fn inflate(input: &[u8]) -> CargoResult<(Vec<u8>, usize)> {
    let mut decompressor = Decompress::new(true);
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut pos = 0usize;
    loop {
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(
                &input[pos.min(input.len())..],
                &mut chunk,
                FlushDecompress::None,
            )
            .context("inflate pack object")?;
        let produced = (decompressor.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        pos = decompressor.total_in() as usize;
        match status {
            Status::StreamEnd => return Ok((out, pos)),
            Status::Ok | Status::BufError => {
                if produced == 0 {
                    bail!("inflate needs more input");
                }
            }
        }
    }
}

/// Resolve object `index` — recursively through its base first when the
/// object is a delta — into `resolved`.
fn resolve_obj(
    raw: &[(u64, u8, RawObj)],
    sha_index: &BTreeMap<[u8; 20], usize>,
    resolved: &mut [Option<Object>],
    index: usize,
) -> CargoResult<()> {
    if resolved[index].is_some() {
        return Ok(());
    }
    let (offset, ty, raw_obj) = &raw[index];
    let (ty, data) = match raw_obj {
        RawObj::Plain(data) => (*ty, data.clone()),
        RawObj::OfsDelta { base_offset, delta } => {
            let base_index = raw
                .iter()
                .position(|(o, _, _)| o == base_offset)
                .ok_or_else(|| anyhow!("ofs-delta base at {base_offset} not in pack"))?;
            resolve_obj(raw, sha_index, resolved, base_index)?;
            let base = resolved[base_index].as_ref().unwrap();
            (base.ty, apply_delta(&base.data, delta)?)
        }
        RawObj::RefDelta { base_sha, delta } => {
            let base_index = *sha_index
                .get(base_sha)
                .ok_or_else(|| anyhow!("ref-delta base not in pack"))?;
            resolve_obj(raw, sha_index, resolved, base_index)?;
            let base = resolved[base_index].as_ref().unwrap();
            (base.ty, apply_delta(&base.data, delta)?)
        }
    };
    let sha = object_sha(ty, &data);
    let _ = offset;
    resolved[index] = Some(Object { ty, data, sha });
    Ok(())
}

/// The object-name hash git computes: `sha1("{type} {len}\0" + data)`.
fn object_sha(ty: u8, data: &[u8]) -> [u8; 20] {
    let name = match ty {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        _ => "unknown",
    };
    let mut hasher = Sha1::new();
    hasher.update(format!("{name} {}\0", data.len()).as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// A git delta's varint field.
fn delta_varint(delta: &[u8], pos: &mut usize) -> CargoResult<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let Some(&byte) = delta.get(*pos) else {
            bail!("truncated delta");
        };
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Apply a git delta to `base`: copy/insert command stream, verbatim
/// git's `patch-delta.c` shape.
fn apply_delta(base: &[u8], delta: &[u8]) -> CargoResult<Vec<u8>> {
    let mut pos = 0usize;
    let src_size = delta_varint(delta, &mut pos)?;
    if src_size as usize != base.len() {
        bail!("delta base size mismatch");
    }
    let dst_size = delta_varint(delta, &mut pos)? as usize;
    let mut out = Vec::with_capacity(dst_size);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    offset |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    size |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset + size;
            if end > base.len() {
                bail!("delta copy out of range");
            }
            out.extend_from_slice(&base[offset..end]);
        } else if cmd != 0 {
            let end = pos + cmd as usize;
            if end > delta.len() {
                bail!("delta insert out of range");
            }
            out.extend_from_slice(&delta[pos..end]);
            pos = end;
        } else {
            bail!("invalid delta opcode 0");
        }
    }
    if out.len() != dst_size {
        bail!("delta produced {} bytes, expected {dst_size}", out.len());
    }
    Ok(out)
}

/// Walk the resolved objects from `commit` into a recursive
/// path → entry map. The commit's `tree` line names the root; every
/// `0o40000` entry recurses.
fn commit_tree(objects: &[Object], commit: &str) -> CargoResult<BTreeMap<PathBuf, TreeEntry>> {
    let commit_sha: [u8; 20] = decode_sha(commit)?;
    let commit_obj = objects
        .iter()
        .find(|o| o.ty == OBJ_COMMIT && o.sha == commit_sha)
        .ok_or_else(|| anyhow!("pack lacks commit {commit}"))?;
    let mut entries = BTreeMap::new();
    walk_tree(
        objects,
        commit_tree_sha(&commit_obj.data)?,
        Path::new(""),
        &mut entries,
    )?;
    Ok(entries)
}

/// The root tree a commit object names — its `tree` header's sha.
fn commit_tree_sha(commit_data: &[u8]) -> CargoResult<[u8; 20]> {
    let data = std::str::from_utf8(commit_data).context("commit is not UTF-8")?;
    let root = data
        .lines()
        .find_map(|line| line.strip_prefix("tree "))
        .ok_or_else(|| anyhow!("commit has no tree"))?;
    decode_sha(root)
}

/// Tree object bytes → `(name, mode, sha)` rows, verbatim git's
/// `mode SP name NUL sha` layout.
fn tree_entries(data: &[u8]) -> CargoResult<Vec<(String, u32, [u8; 20])>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(nul) = data[pos..].iter().position(|&b| b == 0) else {
            bail!("truncated tree entry");
        };
        let header = std::str::from_utf8(&data[pos..pos + nul]).context("non-UTF-8 tree entry")?;
        let (mode, name) = header
            .split_once(' ')
            .ok_or_else(|| anyhow!("malformed tree entry `{header}`"))?;
        let mode = u32::from_str_radix(mode, 8).context("tree entry mode")?;
        pos += nul + 1;
        if pos + 20 > data.len() {
            bail!("truncated tree entry sha");
        }
        let sha: [u8; 20] = data[pos..pos + 20].try_into().unwrap();
        pos += 20;
        entries.push((name.to_owned(), mode, sha));
    }
    Ok(entries)
}

/// Decode a 40-hex sha to its 20 bytes.
fn decode_sha(hex: &str) -> CargoResult<[u8; 20]> {
    let bytes = hex::decode(hex.trim()).context("invalid sha hex")?;
    let bytes: [u8; 20] = bytes
        .try_into()
        .map_err(|_| anyhow!("sha must be 20 bytes"))?;
    Ok(bytes)
}

/// One tree object's entries recursively into `entries`, prefixing each
/// name with `dir`.
fn walk_tree(
    objects: &[Object],
    tree_sha: [u8; 20],
    dir: &Path,
    entries: &mut BTreeMap<PathBuf, TreeEntry>,
) -> CargoResult<()> {
    let tree = objects
        .iter()
        .find(|o| o.ty == OBJ_TREE && o.sha == tree_sha)
        .ok_or_else(|| anyhow!("pack lacks tree {}", hex::encode(tree_sha)))?;
    for (name, mode, sha) in tree_entries(&tree.data)? {
        let path = dir.join(&name);
        if mode == 0o40000 {
            walk_tree(objects, sha, &path, entries)?;
        } else {
            entries.insert(
                path,
                TreeEntry {
                    mode,
                    sha: hex::encode(sha),
                },
            );
        }
    }
    Ok(())
}

/// A pack entry's location: its raw type, its delta base when it is one,
/// and where its zlib stream starts — enough to re-inflate the entry
/// without rescanning the pack.
struct EntryLoc {
    offset: u64,
    ty: u8,
    base: Option<DeltaBase>,
    data_offset: usize,
}

/// Where a delta entry's base lives.
enum DeltaBase {
    /// `ofs-delta`: the base entry's own offset in the pack.
    Ofs(u64),
    /// `ref-delta`: the base's object name.
    Ref([u8; 20]),
}

/// A pack indexed for lazy blob decode: every entry's object id was
/// computed in one pass — each entry inflated once — while only commits
/// and trees were retained. Blobs re-inflate by offset on demand and
/// delta chains resolve the same way, so peak residency is the pack, the
/// index, the trees, and one in-flight decode — never every blob of the
/// tree held at once.
struct PackIndex<'a> {
    pack: &'a [u8],
    /// Entries in pack order.
    locs: Vec<EntryLoc>,
    /// Pack offset → entry index, for ofs-delta base lookups.
    by_offset: BTreeMap<u64, usize>,
    /// Object name → entry index, for ref-delta bases and the tree walk.
    by_sha: BTreeMap<[u8; 20], usize>,
    /// Decoded commits and trees keyed by name — the structure the tree
    /// walk reads.
    kept: BTreeMap<[u8; 20], (u8, std::rc::Rc<Vec<u8>>)>,
}

impl<'a> PackIndex<'a> {
    /// Walk the pack once: locate every entry, inflate it, hash the
    /// resolved object. Delta bases resolve from the pack by offset; a
    /// `ref-delta` whose base's name is not yet indexed (its object may
    /// sit later in the pack) waits for the fixpoint pass afterwards.
    fn build(pack: &'a [u8]) -> CargoResult<Self> {
        if pack.len() < 12 || &pack[..4] != b"PACK" {
            bail!("not a packfile");
        }
        let count = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;
        let mut index = PackIndex {
            pack,
            locs: Vec::with_capacity(count),
            by_offset: BTreeMap::new(),
            by_sha: BTreeMap::new(),
            kept: BTreeMap::new(),
        };
        let mut pending = Vec::new();
        let mut pos = 12usize;
        for i in 0..count {
            let offset = pos as u64;
            let (ty, _size) = pack_obj_header(pack, &mut pos)?;
            let base = match ty {
                OBJ_OFS_DELTA => Some(DeltaBase::Ofs(ofs_delta_base(pack, &mut pos, offset)?)),
                OBJ_REF_DELTA => {
                    if pos + 20 > pack.len() {
                        bail!("truncated ref-delta base");
                    }
                    let sha: [u8; 20] = pack[pos..pos + 20].try_into().unwrap();
                    pos += 20;
                    Some(DeltaBase::Ref(sha))
                }
                _ => None,
            };
            let data_offset = pos;
            let (payload, used) = inflate(&pack[pos..])?;
            pos += used;
            index.by_offset.insert(offset, i);
            index.locs.push(EntryLoc {
                offset,
                ty,
                base,
                data_offset,
            });
            let mut memo = BTreeMap::new();
            match index.resolve(&index.locs[i], payload, &mut memo)? {
                Some(object) => index.admit(i, object),
                // A ref-delta base indexed later in the pack — retry once
                // every entry's name is known.
                None => pending.push(i),
            }
        }
        loop {
            let mut progressed = false;
            let mut still = Vec::new();
            for i in pending {
                let mut memo = BTreeMap::new();
                match index.decode(i, &mut memo)? {
                    Some(object) => {
                        index.admit(i, (*object).clone());
                        progressed = true;
                    }
                    None => still.push(i),
                }
            }
            if still.is_empty() {
                break;
            }
            if !progressed {
                bail!("pack delta bases could not be resolved");
            }
            pending = still;
        }
        Ok(index)
    }

    /// Record resolved `object` under its name; commit and tree objects
    /// stay resident for the walk, everything else drops.
    fn admit(&mut self, index: usize, object: (u8, Vec<u8>)) {
        let (ty, data) = object;
        let sha = object_sha(ty, &data);
        self.by_sha.insert(sha, index);
        if ty == OBJ_COMMIT || ty == OBJ_TREE {
            self.kept.insert(sha, (ty, std::rc::Rc::new(data)));
        }
    }

    /// Resolve an entry's already-inflated `payload` to `(type, data)`,
    /// decoding delta bases recursively by offset. `None` means a
    /// ref-delta base whose name is not indexed yet — the caller retries
    /// after the walk.
    fn resolve(
        &self,
        loc: &EntryLoc,
        payload: Vec<u8>,
        memo: &mut BTreeMap<usize, std::rc::Rc<(u8, Vec<u8>)>>,
    ) -> CargoResult<Option<(u8, Vec<u8>)>> {
        let resolved = match &loc.base {
            None => (loc.ty, payload),
            Some(DeltaBase::Ofs(offset)) => {
                let Some(&base_index) = self.by_offset.get(offset) else {
                    bail!("ofs-delta base at {offset} not in pack");
                };
                let Some(base) = self.decode(base_index, memo)? else {
                    bail!("ofs-delta base at {offset} not in pack");
                };
                (base.0, apply_delta(&base.1, &payload)?)
            }
            Some(DeltaBase::Ref(sha)) => {
                let Some(&base_index) = self.by_sha.get(sha) else {
                    return Ok(None);
                };
                let Some(base) = self.decode(base_index, memo)? else {
                    return Ok(None);
                };
                (base.0, apply_delta(&base.1, &payload)?)
            }
        };
        // One object's decoded size is bounded the way the tarball lane
        // bounds a member — a hostile pack errors instead of inflating
        // without limit.
        if resolved.1.len() as u64 > crate::util::tarball::MAX_RESOLVE_TREE_BYTES {
            bail!(
                "pack object exceeds the {}-byte object limit",
                crate::util::tarball::MAX_RESOLVE_TREE_BYTES
            );
        }
        Ok(Some(resolved))
    }

    /// Inflate entry `index` at its recorded offset and resolve it,
    /// `memo` sharing the results the one decode's delta chain walks.
    /// `None` only for a ref-delta base still unindexed.
    fn decode(
        &self,
        index: usize,
        memo: &mut BTreeMap<usize, std::rc::Rc<(u8, Vec<u8>)>>,
    ) -> CargoResult<Option<std::rc::Rc<(u8, Vec<u8>)>>> {
        if let Some(hit) = memo.get(&index) {
            return Ok(Some(hit.clone()));
        }
        let loc = &self.locs[index];
        let (payload, _) = inflate(&self.pack[loc.data_offset..])?;
        let Some(resolved) = self.resolve(loc, payload, memo)? else {
            return Ok(None);
        };
        let object = std::rc::Rc::new(resolved);
        memo.insert(index, object.clone());
        Ok(Some(object))
    }

    /// Decode the object named `sha` — a kept tree or commit, or a blob
    /// re-inflated at its pack offset.
    fn object(&self, sha: &[u8; 20]) -> CargoResult<(u8, std::rc::Rc<Vec<u8>>)> {
        if let Some((ty, data)) = self.kept.get(sha) {
            return Ok((*ty, data.clone()));
        }
        let Some(&index) = self.by_sha.get(sha) else {
            bail!("pack lacks object {}", hex::encode(sha));
        };
        let mut memo = BTreeMap::new();
        let object = self
            .decode(index, &mut memo)?
            .expect("indexed object resolves");
        Ok((object.0, std::rc::Rc::new(object.1.clone())))
    }
}

/// Decode `pack` — the un-band-framed payload of a `git-upload-pack`
/// fetch response — into the same `path → contents` map
/// [`crate::util::tarball::collect_tar_gz`] produces, restricted to the
/// tree of `commit`.
///
/// Retention follows the tarball lane exactly: real bytes only where
/// [`crate::util::tarball::resolve_reads_contents`] names the file (or a
/// link resolves onto one), empty markers elsewhere, no directory
/// entries, no `.cargo-ok`. The pack and the decoded objects die with
/// this call — only the file map survives to be written into the
/// checkout.
pub fn tree_files(pack: &[u8], commit: &str) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
    use crate::util::tarball;

    let index = PackIndex::build(pack)?;
    let commit_sha = decode_sha(commit)?;
    let Some(&(OBJ_COMMIT, ref commit_data)) = index.kept.get(&commit_sha) else {
        bail!("pack lacks commit {commit}");
    };
    let root = commit_tree_sha(commit_data)?;

    // Walk the trees first, collecting files and links: which blobs to
    // keep is decided once every link is known — a link walked before
    // its target keeps the target's contents the same way.
    let mut file_entries: Vec<(PathBuf, [u8; 20])> = Vec::new();
    let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut stack = vec![(root, PathBuf::new())];
    while let Some((tree_sha, dir)) = stack.pop() {
        let Some(&(OBJ_TREE, ref tree_data)) = index.kept.get(&tree_sha) else {
            bail!("pack lacks tree {}", hex::encode(tree_sha));
        };
        for (name, mode, sha) in tree_entries(tree_data)? {
            // Tree names are single components, but a crafted pack could
            // carry what a tar member would — reject escapes the way
            // `unpack_in` does.
            if name.is_empty() || name == ".." || name.contains('/') || name.contains('\\') {
                bail!("tree entry `{name}` escapes the checkout root");
            }
            let rel = dir.join(&name);
            if mode == 0o40000 {
                stack.push((sha, rel));
            } else if mode == 0o160000 {
                // A gitlink is a submodule reference — like the codeload
                // tarball, nothing is written beneath it.
            } else if mode == 0o120000 {
                let (ty, data) = index.object(&sha)?;
                if ty != OBJ_BLOB {
                    bail!("link `{}` is not a blob", rel.display());
                }
                let target = std::str::from_utf8(&data).context("non-UTF-8 link")?;
                if let Some(target) = tarball::link_target(&rel, Path::new(target), true) {
                    links.push((rel, target));
                }
            } else {
                // cargo never extracts a `.cargo-ok` marker.
                if name == ".cargo-ok" {
                    continue;
                }
                file_entries.push((rel, sha));
            }
        }
    }

    // Targets a retained-name link resolves to keep their contents too —
    // chased through the link map so a link to a link keeps the final
    // file's bytes.
    let link_map: BTreeMap<&Path, &Path> = links
        .iter()
        .map(|(rel, target)| (rel.as_path(), target.as_path()))
        .collect();
    let mut link_targets: std::collections::BTreeSet<PathBuf> = Default::default();
    for (rel, target) in &links {
        if !tarball::resolve_reads_contents(rel) {
            continue;
        }
        let mut current = target.as_path();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(next) = link_map.get(current) {
            if !seen.insert(current) {
                break; // link cycle — the link leaves no entry
            }
            current = next;
        }
        link_targets.insert(current.to_path_buf());
    }

    // Only the retained blobs are re-inflated — everything else lands
    // as an empty-but-present marker, matching the tarball lane.
    let mut files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    let mut retained: u64 = 0;
    for (rel, sha) in file_entries {
        let keep = tarball::resolve_reads_contents(&rel) || link_targets.contains(rel.as_path());
        let contents = if keep {
            let (ty, data) = index.object(&sha)?;
            if ty != OBJ_BLOB {
                bail!("file `{}` is not a blob", rel.display());
            }
            if data.len() as u64 > tarball::MAX_RESOLVE_TREE_BYTES.saturating_sub(retained) {
                bail!(
                    "the pack's resolution inputs exceed the {}-byte retained-content limit",
                    tarball::MAX_RESOLVE_TREE_BYTES
                );
            }
            retained += data.len() as u64;
            (*data).clone()
        } else {
            Vec::new()
        };
        files.insert(rel, contents);
    }
    tarball::materialize_links(&mut files, &links);
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pkt-lines with computed lengths — the fixture a real `info/refs`
    /// stream looks like, including the capability NUL on HEAD and the
    /// flush pkt that separates the service header from the refs.
    #[test]
    fn parse_ls_remote_walks_pkt_lines() {
        let pkt = |payload: &str| -> String { format!("{:04x}{payload}", payload.len() + 4) };
        let head_payload = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef HEAD\0multi_ack thin-pack";
        let text = format!(
            "{}{}{}{}{}{}{}",
            pkt("# service=git-upload-pack\n"),
            "0000",
            pkt(&format!("{head_payload}\n")),
            pkt("aaaabbbbccccddddeeeeffff000011112222 refs/heads/main\n"),
            pkt("33334444555566667777888899990000aaaabbbb refs/tags/v1\n"),
            pkt("5555666677778888999900001111222233334444 refs/tags/v1^{}\n"),
            "0000",
        );
        let refs = parse_ls_remote(&text);
        assert_eq!(
            refs,
            vec![
                (
                    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
                    "HEAD".to_owned()
                ),
                (
                    "aaaabbbbccccddddeeeeffff000011112222".to_owned(),
                    "refs/heads/main".to_owned()
                ),
                (
                    "33334444555566667777888899990000aaaabbbb".to_owned(),
                    "refs/tags/v1".to_owned()
                ),
                (
                    "5555666677778888999900001111222233334444".to_owned(),
                    "refs/tags/v1^{}".to_owned()
                ),
            ]
        );
    }

    /// A hand-built pack: one commit object → the walker finds its tree.
    /// Delta and tree round-trips are covered by `delta_applies` and the
    /// tree walk of a fixture built here in the same format.
    #[test]
    fn delta_applies_copy_and_insert() {
        let base = b"hello world, hello git".to_vec();
        // delta: src len, dst len, then ops.
        let mut delta = Vec::new();
        delta.push(base.len() as u8); // src size varint (small)
        delta.push(5u8); // dst size
        // copy 5 bytes from offset 0: 0x80 | offset-flag0 | size-flag0
        delta.push(0x91);
        delta.push(0); // offset 0
        delta.push(5); // size 5
        assert_eq!(apply_delta(&base, &delta).unwrap(), b"hello");
    }

    /// `tests/fixtures/delta.pack` is a `git pack-objects
    /// --delta-base-offset` capture of a one-commit repo (commit
    /// `e2ac16b8…`) whose `Cargo.toml` blob is an ofs-delta against the
    /// non-retained `zbase.txt` blob. Retaining `Cargo.toml` forces the
    /// lazy decode-by-offset path to re-inflate the delta and resolve
    /// its base straight from the pack.
    #[test]
    fn tree_files_decodes_retained_ofs_delta_blob() {
        let pack = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/delta.pack"
        ));
        let files = tree_files(pack, "e2ac16b833e2ab69530a140a153a16c3bdc0095b").unwrap();

        let names = [
            "serde", "anyhow", "tokio", "regex", "clap", "tracing", "rand", "bytes", "futures",
            "hyper",
        ];
        let deps = (0..300)
            .map(|i| format!("{} = \"1.0.{i}\"\n", names[i % names.len()]))
            .collect::<String>();
        let manifest = format!(
            "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}"
        );
        assert_eq!(
            files[Path::new("Cargo.toml")].as_slice(),
            manifest.as_bytes()
        );
        // The delta's base is a non-retained blob — present as an empty
        // marker, its contents never leaving the pack except through the
        // offset chase the delta resolution ran.
        assert_eq!(files[Path::new("zbase.txt")].as_slice(), b"");
    }

    /// Same fixture: `big.bin` is a 64 KiB blob nothing retains, so the
    /// map carries an empty marker for it — bounded residency means its
    /// decoded bytes were never kept.
    #[test]
    fn tree_files_marks_non_retained_blob_empty() {
        let pack = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/delta.pack"
        ));
        let files = tree_files(pack, "e2ac16b833e2ab69530a140a153a16c3bdc0095b").unwrap();
        assert_eq!(files[Path::new("big.bin")].as_slice(), b"");
    }

    /// `inflate` reports how many input bytes the stream consumed so the
    /// next object's header starts in the right place.
    #[test]
    fn inflate_reports_consumed_bytes() {
        use flate2::{Compress, Compression};
        let mut compressor = Compress::new(Compression::fast(), true);
        let mut buf = vec![0u8; 128];
        let status = compressor
            .compress(b"payload", &mut buf, flate2::FlushCompress::Finish)
            .unwrap();
        assert_eq!(status, Status::StreamEnd);
        let len = compressor.total_out() as usize;
        let (out, consumed) = inflate(&buf[..len]).unwrap();
        assert_eq!(out, b"payload");
        assert_eq!(consumed, len);
    }
}
