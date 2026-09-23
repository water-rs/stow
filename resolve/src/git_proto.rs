//! The slice of git's wire protocol the resolver speaks: pkt-line
//! framing, the `info/refs` advertisement parse, and a protocol-v2
//! `fetch` over smart HTTP that asks for one commit with
//! `filter=blob:none` and `deepen 1` — GitHub answers with a pack of the
//! commit plus every tree under it, no blobs, in one POST.
//!
//! That fetch is how a tree's gitlink (submodule) commits are read
//! without `api.github.com`: the REST trees API caps an unauthenticated
//! caller at 60 requests per hour per egress IP — a quota shared Worker
//! egress exhausts for the caller before the lane starts — while
//! `git-upload-pack` is the same anonymous endpoint `git clone` itself
//! uses.

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
    pkt_line(&mut body, "agent=stow-resolve/0.5.0\n");
    body.extend_from_slice(b"0001");
    pkt_line(&mut body, "thin-pack\n");
    pkt_line(&mut body, "no-progress\n");
    pkt_line(&mut body, "ofs-delta\n");
    pkt_line(&mut body, &format!("deepen 1\n"));
    pkt_line(&mut body, &format!("filter blob:none\n"));
    pkt_line(&mut body, &format!("want {commit}\n"));
    body.extend_from_slice(b"0000");

    let url = format!("https://github.com/{owner}/{repo}.git/git-upload-pack");
    let request = http::Request::post(&url)
        .header("User-Agent", crate::github_tree::USER_AGENT)
        .header("Content-Type", "application/x-git-upload-pack-request")
        .header("Accept", "application/x-git-upload-pack-result")
        .header("Git-Protocol", "version=2")
        .body(body)?;
    let response = client
        .request(request)
        .await
        .with_context(|| format!("fetch tree of `{owner}/{repo}` failed"))?;
    let (parts, response_body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        bail!(
            "git fetch of `{owner}/{repo}` returned HTTP {}",
            parts.status
        );
    }

    let pack = extract_pack(&response_body)
        .with_context(|| format!("decode git fetch response for `{owner}/{repo}`"))?;
    let objects =
        unpack_pack(&pack).with_context(|| format!("unpack git pack for `{owner}/{repo}`"))?;
    commit_tree(&objects, commit).with_context(|| format!("walk tree of `{owner}/{repo}`"))
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
    let data = std::str::from_utf8(&commit_obj.data).context("commit is not UTF-8")?;
    let root_sha = data
        .lines()
        .find_map(|line| line.strip_prefix("tree "))
        .ok_or_else(|| anyhow!("commit has no tree"))?;
    let mut entries = BTreeMap::new();
    walk_tree(objects, decode_sha(root_sha)?, Path::new(""), &mut entries)?;
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
    let mut pos = 0usize;
    let data = &tree.data;
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
        let path = dir.join(name);
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
