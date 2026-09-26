//! Stow-side util (not carried from cargo): a streaming `tar.gz` reader for
//! the resolve lanes.
//!
//! The worker isolate has 128 MB; the codeload tarballs of the preheat
//! projects (rust, zed, bun, wasmer, solana) are far larger than that
//! compressed, let alone unpacked, so the response body is decoded as it
//! arrives rather than collected — `BodyStream` → gzip → tar — and each
//! regular file's bytes are kept only when the vendored resolver will read
//! them ([`resolve_reads_contents`]); every other entry is recorded by path
//! with empty contents so cargo's target auto-discovery (`src/main.rs`,
//! `src/bin/*.rs`, `build.rs`, `examples/`, `tests/`, `benches/`) still sees
//! the file exists.
//!
//! Symlink and hardlink entries are recorded and materialized after the
//! walk — the flat [`crate::util::fs::MemoryVfs`] has no link primitive, so a
//! link takes a copy of its target's stored contents (real checkout
//! semantics: reads through the link see the target's bytes).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;
use futures::stream::{StreamExt as _, TryStreamExt as _};
use futures_util::io::AsyncReadExt as _;

use crate::util::errors::CargoResult;
use crate::util::network::http_async::BodyStream;

/// Bound on the bytes retained from one tarball: `Cargo.toml`, `Cargo.lock`,
/// toolchain files, in-tree cargo config and vendor checksums — the files
/// [`resolve_reads_contents`] keeps with real contents. Larger trees are a
/// resolve error, not silent loss.
pub const MAX_RESOLVE_TREE_BYTES: u64 = 32 * 1024 * 1024;

/// The tar block size.
const BLOCK: usize = 512;

/// `true` when the vendored resolver reads this archive member's contents —
/// anything else is existence-only during resolution (target autodiscovery,
/// readme/license-file detection, `examples/`/`tests/` presence).
///
/// Contents reads during a resolve are:
///
/// * `Cargo.toml` — [`crate::util::toml`] `paths::read` parses every
///   workspace member's manifest;
/// * `Cargo.lock` — read when the workspace ships one;
/// * `rust-toolchain` / `rust-toolchain.toml` — cargo's in-tree toolchain
///   pin;
/// * `.cargo/config` / `.cargo/config.toml` — `api::load_in_tree_config`
///   reads it for `[source]` replacement, `paths` overrides and target
///   rustflags;
/// * `.cargo-checksum.json` — the directory source (`[source] vendor` from
///   in-tree config) reads it in [`crate::sources::directory`];
/// * `.gitmodules` — the tree fetch itself reads it
///   ([`crate::github_tree::fill_submodules`]) to chase submodule contents
///   a codeload tarball leaves empty.
///
/// `readme`, `license-file`, `build`, `include`/`exclude` and every source
/// file are never read during resolution — manifest fields and target
/// autodiscovery need only the path.
pub fn resolve_reads_contents(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    match name {
        "Cargo.toml"
        | "Cargo.lock"
        | ".gitmodules"
        | "rust-toolchain"
        | "rust-toolchain.toml"
        | ".cargo-checksum.json" => true,
        "config" | "config.toml" => {
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                == Some(".cargo")
        }
        _ => false,
    }
}

/// `cargo::ops::registry::max_unpack_size` equivalent for a streamed body:
/// `max(512 MiB, compressed * 20)` when the compressed length is known.
/// Streamed fetches (codeload answers `Transfer-Encoding: chunked`, no
/// Content-Length) get a 4 GiB fixed bound instead — real repositories
/// decompress well past the 512 MiB floor, the bound only has to cut off a
/// runaway stream, and retention stays capped by [`MAX_RESOLVE_TREE_BYTES`].
pub fn unpack_size_bound(compressed_len: Option<u64>) -> u64 {
    const MAX_UNPACK_SIZE: u64 = 512 * 1024 * 1024;
    const MAX_COMPRESSION_RATIO: u64 = 20;
    const STREAMED_UNPACK_BOUND: u64 = 4 * 1024 * 1024 * 1024;
    match compressed_len {
        Some(len) => MAX_UNPACK_SIZE.max(len * MAX_COMPRESSION_RATIO),
        None => STREAMED_UNPACK_BOUND,
    }
}

/// How a member's leading path component comes off.
pub enum TarPrefix {
    /// Every member must sit under this directory — an entry that is not
    /// fails the unpack, mirroring `unpack_prefixed`'s prefix check.
    Required(PathBuf),
    /// Drop each member's first component, whatever name it has — the
    /// workspace lanes' rule, where the archive's top directory is not
    /// known ahead of time.
    FirstComponent,
}

/// One regular-file-bearing member type worth recording.
#[derive(Debug)]
pub enum TarMember {
    /// Regular file — `read_body`/`skip_body` consumes its payload.
    File,
    /// Directory — recorded nowhere (a `MemoryVfs` tree needs no dir rows).
    Directory,
    /// `ln -s` — `link_name` relative to the member's parent directory.
    Symlink,
    /// Hard link — `link_name` relative to the archive root.
    Hardlink,
}

/// A parsed tar member header.
#[derive(Debug)]
pub struct TarEntry {
    /// Raw archive path (components normalized, leading `./` removed).
    pub path: PathBuf,
    /// Declared payload size.
    pub size: u64,
    /// What kind of member this is.
    pub member: TarMember,
    /// Link target for [`TarMember::Symlink`]/[`TarMember::Hardlink`].
    pub link_name: Option<PathBuf>,
}

/// Sequential `tar` reader over an [`futures_util::io::AsyncRead`],
/// enforcing the decompressed-byte bound as bytes pass.
pub struct TarGz<R> {
    r: R,
    /// Decompressed bytes consumed so far.
    read: u64,
    /// Decompression bound — `unpack_size_bound`.
    limit: u64,
    /// Payload bytes of the current member not yet consumed.
    payload_left: u64,
    /// Bytes to the next header (payload + 512-roundup pad).
    block_left: u64,
    /// Pax/gnu-longname overrides applying to the next header.
    pend_name: Option<String>,
    pend_link: Option<String>,
    pend_size: Option<u64>,
    /// A `pax_global_header` block was seen — the archive's own end marker.
    ended_cleanly: bool,
}

impl<R: futures::io::AsyncRead + Unpin> TarGz<R> {
    /// Wraps a decompressed-byte stream. `limit` bounds what may be read.
    pub fn new(r: R, limit: u64) -> TarGz<R> {
        TarGz {
            r,
            read: 0,
            limit,
            payload_left: 0,
            block_left: 0,
            pend_name: None,
            pend_link: None,
            pend_size: None,
            ended_cleanly: false,
        }
    }

    /// Decompressed bytes consumed so far (header + payload + pad).
    pub fn decompressed(&self) -> u64 {
        self.read
    }

    /// Recover the wrapped reader — the walk can stop early and the caller
    /// still needs the raw stream (to drain a response body for hashing).
    pub fn into_inner(self) -> R {
        self.r
    }

    /// Read `buf.len()` bytes or fail inside the decompression bound.
    async fn read_into(&mut self, buf: &mut [u8]) -> CargoResult<()> {
        if self.read.saturating_add(buf.len() as u64) > self.limit {
            anyhow::bail!("decompressed tarball exceeds the {}-byte bound", self.limit);
        }
        self.r
            .read_exact(buf)
            .await
            .map_err(|e| anyhow::format_err!("read tarball stream: {e}"))?;
        self.read += buf.len() as u64;
        Ok(())
    }

    /// Read exactly `n` bytes, returning them.
    async fn read_n(&mut self, n: usize) -> CargoResult<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.read_into(&mut buf).await?;
        Ok(buf)
    }

    /// Consume whatever of the current member (payload + pad) is left.
    async fn drain_current(&mut self) -> CargoResult<()> {
        while self.block_left > 0 {
            let take = (self.block_left).min(64 * 1024) as usize;
            let _ = self.read_n(take).await?;
            self.block_left -= take as u64;
        }
        self.payload_left = 0;
        Ok(())
    }

    /// The next member header, or `None` at the archive's end blocks.
    /// Any unconsumed remainder of the previous member is skipped first.
    pub async fn next(&mut self) -> CargoResult<Option<TarEntry>> {
        self.drain_current().await?;
        loop {
            // A block past `ended_cleanly` may end in EOF mid-read — clean.
            let mut block = [0u8; BLOCK];
            match self.read_block(&mut block).await {
                Ok(true) => {}
                Ok(false) => {
                    if self.ended_cleanly {
                        return Ok(None);
                    }
                    anyhow::bail!("truncated tarball: stream ended before the end blocks");
                }
                Err(e) => return Err(e),
            }
            if block.iter().all(|b| *b == 0) {
                self.ended_cleanly = true;
                continue;
            }
            let size = parse_size(&block[124..136]).with_context(|| {
                format!(
                    "invalid tarball downloaded, bad size field at entry {:?}",
                    String::from_utf8_lossy(&block[..100])
                )
            })?;
            let typeflag = block[156];
            let mut name = String::from_utf8_lossy(nul_trim(&block[..100])).into_owned();
            let mut link_name = String::from_utf8_lossy(nul_trim(&block[157..257])).into_owned();
            // ustar splits long names into prefix/name fields.
            if &block[257..262] == b"ustar" {
                let prefix = String::from_utf8_lossy(nul_trim(&block[345..500]));
                if !prefix.is_empty() {
                    name = format!("{prefix}/{name}");
                }
            }
            if let Some(n) = self.pend_name.take() {
                name = n;
            }
            if let Some(l) = self.pend_link.take() {
                link_name = l;
            }
            match typeflag {
                // Extended pax header — applies to the *next* member.
                b'x' => {
                    let payload = self.read_n(padded(size) as usize).await?;
                    self.parse_pax(&payload[..size as usize]);
                    continue;
                }
                // Global pax header — informational, skip it.
                b'g' => {
                    let _ = self.read_n(padded(size) as usize).await?;
                    continue;
                }
                // GNU long name / long linkname — NUL-terminated payload.
                b'L' => {
                    let payload = self.read_n(padded(size) as usize).await?;
                    self.pend_name = Some(
                        String::from_utf8_lossy(nul_trim(&payload[..size as usize])).into_owned(),
                    );
                    continue;
                }
                b'K' => {
                    let payload = self.read_n(padded(size) as usize).await?;
                    self.pend_link = Some(
                        String::from_utf8_lossy(nul_trim(&payload[..size as usize])).into_owned(),
                    );
                    continue;
                }
                _ => {
                    // A pax `size=` overrides the header's field.
                    let size = self.pend_size.take().unwrap_or(size);
                    return self.entry(name, link_name, typeflag, size).map(Some);
                }
            }
        }
    }

    /// Assemble an entry, tracking the payload window.
    fn entry(
        &mut self,
        name: String,
        link_name: String,
        typeflag: u8,
        size: u64,
    ) -> CargoResult<TarEntry> {
        let member = match typeflag {
            b'0' | 0 | b'7' => TarMember::File,
            b'5' => TarMember::Directory,
            b'2' => TarMember::Symlink,
            b'1' => TarMember::Hardlink,
            t => anyhow::bail!(
                "invalid tarball downloaded, contains an entry at {name:?} with invalid type {:?}",
                t as char,
            ),
        };
        self.payload_left = match member {
            TarMember::File => size,
            _ => 0,
        };
        // A non-file member carrying a declared size still has those
        // bytes in the stream — drain them either way.
        self.block_left = padded(size);
        let path =
            tar_path(&name).with_context(|| format!("invalid tarball entry path {name:?}"))?;
        // A link target keeps its `..` components — relative links are
        // resolved against the link's directory, not the archive root.
        let link_name = if link_name.is_empty() {
            None
        } else {
            let mut target = PathBuf::new();
            for part in link_name.split('/') {
                target.push(part);
            }
            Some(target)
        };
        Ok(TarEntry {
            path,
            size,
            member,
            link_name,
        })
    }

    /// Read the rest of the current member's payload.
    pub async fn read_body(&mut self, buf: &mut Vec<u8>) -> CargoResult<()> {
        while self.payload_left > 0 {
            let take = self.payload_left.min(64 * 1024);
            let mut chunk = self.read_n(take as usize).await?;
            buf.append(&mut chunk);
            self.payload_left -= take;
            self.block_left -= take;
        }
        Ok(())
    }

    /// Skip the rest of the current member's payload.
    pub async fn skip_body(&mut self) -> CargoResult<()> {
        self.payload_left = 0;
        Ok(())
    }

    /// One 512-byte header block. `Ok(false)` is a clean EOF.
    async fn read_block(&mut self, block: &mut [u8; BLOCK]) -> CargoResult<bool> {
        if self.read.saturating_add(BLOCK as u64) > self.limit {
            anyhow::bail!("decompressed tarball exceeds the {}-byte bound", self.limit);
        }
        let mut filled = 0;
        while filled < BLOCK {
            match self.r.read(&mut block[filled..]).await {
                Ok(0) => {
                    if filled == 0 {
                        return Ok(false);
                    }
                    anyhow::bail!("truncated tarball: mid-header EOF");
                }
                Ok(n) => filled += n,
                Err(e) => return Err(anyhow::format_err!("read tarball stream: {e}")),
            }
        }
        self.read += BLOCK as u64;
        Ok(true)
    }

    /// `key=value` records out of a pax `x` payload for the next member.
    fn parse_pax(&mut self, payload: &[u8]) {
        let mut rest = payload;
        while !rest.is_empty() {
            // "<len> <key>=<value>\n"
            let Some(space) = rest.iter().position(|b| *b == b' ') else {
                break;
            };
            let Ok(len) = std::str::from_utf8(&rest[..space])
                .unwrap_or("0")
                .parse::<usize>()
            else {
                break;
            };
            if len == 0 || len > rest.len() {
                break;
            }
            let record = &rest[space + 1..len - 1]; // minus the trailing \n
            if let Some(v) = record.strip_prefix(b"path=") {
                self.pend_name = Some(String::from_utf8_lossy(v).into_owned());
            } else if let Some(v) = record.strip_prefix(b"linkpath=") {
                self.pend_link = Some(String::from_utf8_lossy(v).into_owned());
            } else if let Some(v) = record.strip_prefix(b"size=") {
                if let Ok(s) = std::str::from_utf8(v).unwrap_or("").trim().parse::<u64>() {
                    self.pend_size = Some(s);
                }
            }
            rest = &rest[len..];
        }
    }
}

/// `size` rounded up to a 512 boundary — the tar record span.
fn padded(size: u64) -> u64 {
    (size + BLOCK as u64 - 1) / BLOCK as u64 * BLOCK as u64
}

/// The octal-or-base256 tar size field.
fn parse_size(field: &[u8]) -> CargoResult<u64> {
    if field[0] & 0x80 != 0 {
        // GNU/POSIX base-256, big-endian over the remaining bytes.
        let mut v: u64 = (field[0] & 0x7f) as u64;
        for &b in &field[1..] {
            v = v
                .checked_mul(256)
                .and_then(|v| v.checked_add(b as u64))
                .context("tar size field overflows u64")?;
        }
        return Ok(v);
    }
    let text = std::str::from_utf8(nul_trim(field)).context("tar size field is not octal")?;
    u64::from_str_radix(text.trim(), 8).context("tar size field is not octal")
}

/// The bytes before the first NUL.
fn nul_trim(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..end]
}

/// A raw archive name to a `PathBuf`: split on `/`, drop empty and `.`
/// components, reject `..` and absolute members the way
/// `Entry::unpack_in` does.
fn tar_path(name: &str) -> CargoResult<PathBuf> {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            ".." => anyhow::bail!("tarball member `{name}` escapes the archive root"),
            _ => path.push(part),
        }
    }
    if name.starts_with('/') {
        anyhow::bail!("tarball member `{name}` is an absolute path")
    }
    Ok(path)
}

/// Where a link's target resolves inside the unpacked tree, `None` when it
/// lands outside (a dangling link — the file simply does not materialize).
fn link_target(rel: &Path, target: &Path, symlink: bool) -> Option<PathBuf> {
    // A symlink resolves against its own directory; a hardlink against the
    // archive root.
    let base: Vec<String> = if symlink {
        rel.parent()
            .map(|p| {
                p.components()
                    .filter_map(|c| match c {
                        Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut parts = base;
    for c in target.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            _ => return None,
        }
    }
    Some(parts.iter().collect())
}

/// Collect a streamed `tar.gz` into `path → contents`: contents are real
/// only for the files [`resolve_reads_contents`] names — everything else is
/// recorded empty — and link entries materialize their target's stored
/// contents after the walk. `decompressed_limit` bounds the gzip stream
/// (zip-bomb); `retained_limit` bounds the kept bytes — the error names the
/// limit.
pub async fn collect_tar_gz(
    body: BodyStream,
    prefix: TarPrefix,
    decompressed_limit: u64,
    retained_limit: u64,
) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
    let bytes = body.map(|r| r.map_err(|e| io::Error::other(format!("{e:#}"))));
    let reader = futures::io::BufReader::new(bytes.into_async_read());
    let gz = async_compression::futures::bufread::GzipDecoder::new(reader);
    let mut tar = TarGz::new(gz, decompressed_limit);

    let mut files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    // (link path, resolved target) pairs materialized after the walk.
    let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
    // Targets a retained-name link points at — their contents stay too.
    let mut link_targets: BTreeSet<PathBuf> = BTreeSet::new();
    let mut retained: u64 = 0;

    while let Some(entry) = tar.next().await? {
        // `unpack_prefixed` parity: codeload archives carry a
        // `pax_global_header` member outside the prefix directory.
        if entry.path == Path::new("pax_global_header") {
            tar.skip_body().await?;
            continue;
        }
        let rel: PathBuf = match &prefix {
            TarPrefix::Required(dir) => match entry.path.strip_prefix(dir) {
                Ok(p) => p.to_path_buf(),
                Err(_) => anyhow::bail!(
                    "invalid tarball downloaded, contains \
                     a file at {:?} which isn't under {dir:?}",
                    entry.path,
                ),
            },
            TarPrefix::FirstComponent => {
                let mut components = entry.path.components();
                match components.next() {
                    Some(Component::Normal(_top)) => components.as_path().to_path_buf(),
                    _ => continue,
                }
            }
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        match entry.member {
            TarMember::Directory => {
                tar.skip_body().await?;
            }
            TarMember::File => {
                // cargo never extracts a `.cargo-ok` marker from an archive.
                if rel.file_name().and_then(|n| n.to_str()) == Some(".cargo-ok") {
                    tar.skip_body().await?;
                    continue;
                }
                let keep = resolve_reads_contents(&rel) || link_targets.contains(&rel);
                if keep {
                    if entry.size > retained_limit.saturating_sub(retained) {
                        anyhow::bail!(
                            "the tarball's resolution inputs exceed the \
                             {retained_limit}-byte retained-content limit"
                        );
                    }
                    let mut data = Vec::new();
                    tar.read_body(&mut data).await?;
                    retained += data.len() as u64;
                    files.insert(rel, data);
                } else {
                    tar.skip_body().await?;
                    files.insert(rel, Vec::new());
                }
            }
            TarMember::Symlink | TarMember::Hardlink => {
                tar.skip_body().await?;
                if let Some(target) = entry
                    .link_name
                    .as_ref()
                    .and_then(|t| link_target(&rel, t, matches!(entry.member, TarMember::Symlink)))
                {
                    if resolve_reads_contents(&rel) {
                        link_targets.insert(target.clone());
                    }
                    links.push((rel, target));
                }
            }
        }
    }

    materialize_links(&mut files, &links);
    Ok(files)
}

/// Give every recorded link its target's stored contents: file links copy
/// the target file's bytes, dir links copy every file beneath the target.
/// Chained links resolve through the link map; cycles and dangling targets
/// leave no entry — reading one fails the way reading it on disk would.
fn materialize_links(files: &mut BTreeMap<PathBuf, Vec<u8>>, links: &[(PathBuf, PathBuf)]) {
    let link_map: BTreeMap<PathBuf, PathBuf> = links.iter().cloned().collect();
    // Follow a link chain to its final non-link target, `None` on a cycle.
    let follow = |target: &Path| -> Option<PathBuf> {
        let mut current = target;
        let mut seen = BTreeSet::new();
        while let Some(next) = link_map.get(current) {
            if !seen.insert(current.to_path_buf()) {
                return None;
            }
            current = next;
        }
        Some(current.to_path_buf())
    };
    for (link, target) in links {
        let Some(target) = follow(target) else {
            continue;
        };
        if let Some(bytes) = files.get(&target).cloned() {
            files.insert(link.clone(), bytes);
            continue;
        }
        // A link at a directory — every file beneath the target appears
        // beneath the link too.
        let children: Vec<(PathBuf, Vec<u8>)> = files
            .iter()
            .filter(|(p, _)| p.starts_with(&target))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect();
        for (child, bytes) in children {
            if let Ok(rest) = child.strip_prefix(&target) {
                files.insert(link.join(rest), bytes);
            }
        }
    }
}

/// Buffer a streamed response body whole — the non-2xx error path where
/// [`crate::util::errors::HttpNotSuccessful`] still wants the response text.
pub async fn collect_body(body: BodyStream) -> CargoResult<Vec<u8>> {
    body.try_collect::<Vec<Vec<u8>>>()
        .await
        .map(|chunks| chunks.concat())
}

/// Wrap any `Stream` of chunk results into the [`BodyStream`] shape.
pub fn body_stream<S>(stream: S) -> BodyStream
where
    S: futures::Stream<Item = CargoResult<Vec<u8>>> + 'static,
{
    Box::pin(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `bytes` into a chunk stream — `chunk` bounds each item's size.
    fn stream_of(bytes: Vec<u8>, chunk: usize) -> BodyStream {
        let chunks: Vec<CargoResult<Vec<u8>>> =
            bytes.chunks(chunk).map(|c| Ok(c.to_vec())).collect();
        Box::pin(futures::stream::iter(chunks))
    }

    /// A gzip'd tar built in memory.
    fn tar_gz(entries: &[(String, TarMember, Option<String>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut gz = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
            {
                let mut builder = tar::Builder::new(&mut gz);
                for (name, member, link, body) in entries {
                    let mut header = tar::Header::new_gnu();
                    match member {
                        TarMember::File => {
                            header.set_entry_type(tar::EntryType::Regular);
                            header.set_size(body.len() as u64);
                            header.set_cksum();
                            builder.append_data(&mut header, name, *body).unwrap();
                        }
                        TarMember::Directory => {
                            header.set_entry_type(tar::EntryType::Directory);
                            header.set_size(0);
                            header.set_cksum();
                            builder.append_data(&mut header, name, &[][..]).unwrap();
                        }
                        TarMember::Symlink => {
                            header.set_entry_type(tar::EntryType::Symlink);
                            header.set_size(0);
                            header.set_link_name(link.as_deref().unwrap()).unwrap();
                            header.set_cksum();
                            builder.append_data(&mut header, name, &[][..]).unwrap();
                        }
                        TarMember::Hardlink => {
                            header.set_entry_type(tar::EntryType::Link);
                            header.set_size(0);
                            header.set_link_name(link.as_deref().unwrap()).unwrap();
                            header.set_cksum();
                            builder.append_data(&mut header, name, &[][..]).unwrap();
                        }
                    }
                }
                builder.finish().unwrap();
            }
            gz.finish().unwrap();
        }
        out
    }

    fn blocks() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    /// Resident-set high-water in kB from `/proc/self/status`, when the
    /// platform exposes it (the memory-budget assertion is Linux-only).
    #[cfg(target_os = "linux")]
    fn rss_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find(|l| l.starts_with("VmHWM"))
            .and_then(|l| {
                l.trim_start_matches("VmHWM:")
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    }

    #[test]
    fn streams_entries_without_buffering_payloads() {
        // 160 MB of non-manifest content — over the isolate's 128 MB —
        // plus the manifest the resolve actually reads. The payload never
        // exists whole on either side: `ZeroBytes` manufactures it one
        // read at a time into the gzip encoder (compressed output lands
        // in a ~160 KB Vec), and the reader drops it instead of keeping
        // it — the VmHWM bound holds because nothing is buffered.
        let compressed = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            {
                let mut builder = tar::Builder::new(&mut gz);
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(160 * 1024 * 1024);
                header.set_cksum();
                builder
                    .append_data(
                        &mut header,
                        "big/big-160mb.bin",
                        ZeroBytes {
                            left: 160 * 1024 * 1024,
                        },
                    )
                    .unwrap();
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                let manifest = b"[package]\nname=\"x\"\nversion=\"0.1.0\"\n";
                header.set_size(manifest.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, "big/Cargo.toml", &manifest[..])
                    .unwrap();
                builder.finish().unwrap();
            }
            gz.finish().unwrap()
        };
        assert!(
            compressed.len() < 32 * 1024 * 1024,
            "zeros compress away: {}",
            compressed.len()
        );
        #[cfg(target_os = "linux")]
        let high_water_before = rss_kb();
        let files = blocks()
            .block_on(collect_tar_gz(
                stream_of(compressed, 64 * 1024),
                TarPrefix::FirstComponent,
                unpack_size_bound(None),
                MAX_RESOLVE_TREE_BYTES,
            ))
            .expect("streams through the 160 MB payload");
        assert_eq!(
            files[Path::new("big-160mb.bin")],
            Vec::<u8>::new(),
            "non-manifest payloads are stubbed"
        );
        assert!(
            String::from_utf8_lossy(&files[Path::new("Cargo.toml")]).contains("name=\"x\""),
            "manifest contents are retained"
        );
        let retained: usize = files.values().map(Vec::len).sum();
        assert!(retained < 1024, "retained {retained} bytes");
        #[cfg(target_os = "linux")]
        assert!(
            rss_kb() - high_water_before < 64 * 1024,
            "RSS high-water stayed under the 128 MB isolate bound"
        );
    }

    /// 160 MB of zeroes produced one `read` at a time.
    struct ZeroBytes {
        left: u64,
    }
    impl std::io::Read for ZeroBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.left.min(buf.len() as u64) as usize;
            buf[..n].fill(0);
            self.left -= n as u64;
            Ok(n)
        }
    }

    #[test]
    fn collects_retained_and_stub_entries() {
        let manifest = b"[package]\nname=\"x\"\nversion=\"0.1.0\"\n";
        let entries: Vec<(String, TarMember, Option<String>, &[u8])> = vec![
            (
                "top/proj/Cargo.toml".into(),
                TarMember::File,
                None,
                manifest,
            ),
            (
                "top/proj/Cargo.lock".into(),
                TarMember::File,
                None,
                b"[[lock]]",
            ),
            (
                "top/proj/src/main.rs".into(),
                TarMember::File,
                None,
                b"fn main() {}",
            ),
            (
                "top/proj/.cargo/config.toml".into(),
                TarMember::File,
                None,
                b"[source]\n",
            ),
            (
                "top/proj/vendor/v/.cargo-checksum.json".into(),
                TarMember::File,
                None,
                b"{\"files\":{}}",
            ),
            (
                "top/proj/README.md".into(),
                TarMember::File,
                None,
                b"readme",
            ),
        ];
        let bytes = tar_gz(&entries);
        let files = blocks()
            .block_on(collect_tar_gz(
                stream_of(bytes, 1024),
                TarPrefix::Required(PathBuf::from("top")),
                unpack_size_bound(None),
                MAX_RESOLVE_TREE_BYTES,
            ))
            .unwrap();
        assert_eq!(files[Path::new("proj/Cargo.toml")], manifest);
        assert_eq!(files[Path::new("proj/Cargo.lock")], b"[[lock]]");
        assert_eq!(files[Path::new("proj/.cargo/config.toml")], b"[source]\n");
        assert_eq!(
            files[Path::new("proj/vendor/v/.cargo-checksum.json")],
            b"{\"files\":{}}"
        );
        assert!(files.contains_key(Path::new("proj/src/main.rs")));
        assert!(files[Path::new("proj/src/main.rs")].is_empty(), "stubbed");
        assert!(
            files[Path::new("proj/README.md")].is_empty(),
            "readme is existence-only"
        );
    }

    #[test]
    fn symlink_materializes_target_contents() {
        let entries: Vec<(String, TarMember, Option<String>, &[u8])> = vec![
            (
                "top/proj/Cargo.toml".into(),
                TarMember::File,
                None,
                b"[package]",
            ),
            (
                "top/proj/crates/m/Cargo.toml".into(),
                TarMember::Symlink,
                Some("../../Cargo.toml".into()),
                b"",
            ),
            (
                "top/proj/docs".into(),
                TarMember::Symlink,
                Some("docs-real".into()),
                b"",
            ),
            (
                "top/proj/docs-real/a.txt".into(),
                TarMember::File,
                None,
                b"doc-bytes",
            ),
        ];
        let bytes = tar_gz(&entries);
        let files = blocks()
            .block_on(collect_tar_gz(
                stream_of(bytes, 4096),
                TarPrefix::Required(PathBuf::from("top")),
                unpack_size_bound(None),
                MAX_RESOLVE_TREE_BYTES,
            ))
            .unwrap();
        assert_eq!(
            files[Path::new("proj/crates/m/Cargo.toml")],
            b"[package]",
            "link at a retained name carries the target's contents"
        );
        assert!(
            files.contains_key(Path::new("proj/docs/a.txt")),
            "dir link children materialize under the link"
        );
    }

    #[test]
    fn retained_bytes_bound_errors_naming_the_limit() {
        let big = vec![b'x'; (MAX_RESOLVE_TREE_BYTES + 1) as usize];
        let entries: Vec<(String, TarMember, Option<String>, &[u8])> =
            vec![("top/proj/Cargo.toml".into(), TarMember::File, None, &big)];
        let bytes = tar_gz(&entries);
        let error = blocks()
            .block_on(collect_tar_gz(
                stream_of(bytes, 1 << 20),
                TarPrefix::Required(PathBuf::from("top")),
                unpack_size_bound(None),
                MAX_RESOLVE_TREE_BYTES,
            ))
            .unwrap_err();
        assert!(
            error.to_string().contains("retained-content limit")
                && error
                    .to_string()
                    .contains(&MAX_RESOLVE_TREE_BYTES.to_string()),
            "names the limit: {error}"
        );
    }

    #[test]
    fn prefix_escape_is_rejected() {
        let entries: Vec<(String, TarMember, Option<String>, &[u8])> =
            vec![("other/file.txt".into(), TarMember::File, None, b"x")];
        let bytes = tar_gz(&entries);
        let error = blocks()
            .block_on(collect_tar_gz(
                stream_of(bytes, 4096),
                TarPrefix::Required(PathBuf::from("top")),
                unpack_size_bound(None),
                MAX_RESOLVE_TREE_BYTES,
            ))
            .unwrap_err();
        assert!(error.to_string().contains("isn't under"), "{error}");
    }

    /// Peak retained bytes across zed's real codeload tarball — the
    /// number the 128 MB isolate budget is argued against. Run:
    /// `cargo test -p stow-resolve --features harness --lib -- --ignored
    ///   --nocapture tarball::tests::zed_codeload_retained_bytes`
    #[cfg(all(target_os = "linux", feature = "harness"))]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "downloads zed's real codeload tarball"]
    async fn zed_codeload_retained_bytes() {
        let url = std::env::var("ZED_TARBALL_URL").unwrap_or_else(|_| {
            "https://codeload.github.com/zed-industries/zed/tar.gz/refs/heads/main".to_owned()
        });
        let response = reqwest::get(&url).await.unwrap();
        assert!(response.status().is_success(), "{response:?}");
        let compressed_len = response.content_length();
        let body = body_stream(
            response
                .bytes_stream()
                .map(|chunk| chunk.map(|b| b.to_vec()).map_err(anyhow::Error::from)),
        );
        let files = collect_tar_gz(
            body,
            TarPrefix::FirstComponent,
            unpack_size_bound(compressed_len),
            MAX_RESOLVE_TREE_BYTES,
        )
        .await
        .unwrap();
        let retained: u64 = files.values().map(|v| v.len() as u64).sum();
        let retained_paths: Vec<_> = files
            .iter()
            .filter(|(_, data)| !data.is_empty())
            .map(|(p, d)| (p.clone(), d.len()))
            .collect();
        println!("entries: {}", files.len());
        println!("retained files: {}", retained_paths.len());
        println!(
            "retained bytes: {retained} ({:.2} MiB)",
            retained as f64 / 1048576.0
        );
        for (path, size) in retained_paths.iter().take(30) {
            println!("  {size:>9} {path:?}");
        }
        assert!(retained <= MAX_RESOLVE_TREE_BYTES);
    }
}
