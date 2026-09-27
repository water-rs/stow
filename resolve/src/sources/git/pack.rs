//! Pack decode and tree materialization for the smart-HTTP lane — the
//! counterpart of [`crate::util::tarball::collect_tar_gz`] for hosts that
//! serve no tarball endpoint.
//!
//! gix's pack reader does the object decoding: [`File::entry`] parses each
//! entry header off the pack, a measure-only zlib pass finds where each
//! compressed stream ends, and [`File::decode_entry`] resolves delta
//! chains (ofs-delta internally, ref-delta through a lookup closure).
//! Objects are indexed by id so the tree walk reads trees and blobs by
//! name.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use gix_features::zlib::{Decompress, FlushDecompress, Status};
use gix_object::bstr::ByteSlice;
use gix_object::{CommitRef, Kind, TreeRefIter};
use gix_pack::cache;
use gix_pack::data::decode::entry::ResolvedBase;
use gix_pack::data::{self, File};

use crate::util::CargoResult;
use crate::util::tarball;

/// The hash this resolver speaks on the wire — `object-format=sha1` is
/// the only format every host negotiates.
const HASH: gix_hash::Kind = gix_hash::Kind::Sha1;

/// A decoded pack object.
struct Object {
    kind: Kind,
    data: Vec<u8>,
}

/// Decode `pack` — the un-band-framed payload of a `git-upload-pack`
/// fetch response — into the same `path → contents` map
/// `collect_tar_gz` produces, restricted to the tree of `commit`.
///
/// Retention follows the tarball lane exactly: real bytes only where
/// [`tarball::resolve_reads_contents`] names the file (or a link resolves
/// onto one), empty markers elsewhere, no directory entries, no
/// `.cargo-ok`. The pack and the decoded objects die with this call —
/// only the file map survives to be written into the checkout.
pub fn tree_files(pack: Vec<u8>, commit: &str) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
    let file = File::from_data(pack, PathBuf::new(), HASH)
        .context("malformed pack header")?
        // A decoded object is transient; bound a single object (and its
        // delta chain) at the same budget the tarball lane gives retained
        // contents, so a hostile or pathological pack errors instead of
        // exhausting the isolate.
        .with_alloc_limit_bytes(Some(tarball::MAX_RESOLVE_TREE_BYTES as usize));
    let objects = decode_all(&file).context("decode pack")?;
    drop(file); // the pack is dead once its objects are decoded
    materialize_tree(&objects, commit)
}

/// Decode every object in the pack into an id-indexed map.
///
/// `decode_entry` resolves ofs-delta chains itself; a ref-delta whose
/// base id names another object *in* the pack resolves through the
/// closure, which consults the objects decoded so far. Such a base can be
/// another delta's result that is not decoded yet, so entries that fail
/// with [`data::decode::Error::DeltaBaseUnresolved`] retry on later
/// passes until the pack is complete or a pass makes no progress.
fn decode_all(file: &File<Vec<u8>>) -> CargoResult<HashMap<gix_hash::ObjectId, Object>> {
    let mut inflate = gix_features::zlib::Inflate::default();
    let mut entries = Vec::with_capacity(file.num_objects() as usize);
    let mut pos = 12usize; // pack header: magic + version + count
    for _ in 0..file.num_objects() {
        let entry = file
            .entry(pos as u64)
            .context("corrupt pack entry header")?;
        // The stream runs to the pack's trailer hash; the measure pass
        // finds where it actually ends.
        let input = file
            .entry_slice(entry.data_offset..file.pack_end() as u64)
            .ok_or_else(|| anyhow::anyhow!("pack entry offset out of range"))?;
        entries.push(entry.clone());
        pos = entry.data_offset as usize + stream_extent(input)?;
    }

    let mut objects: HashMap<gix_hash::ObjectId, Object> = HashMap::new();
    let mut pending = entries;
    loop {
        let mut still_pending = Vec::new();
        let mut progressed = false;
        for entry in pending {
            let resolve = |oid: &gix_hash::oid, out: &mut Vec<u8>| -> Option<ResolvedBase> {
                let object = objects.get(oid)?;
                out.extend_from_slice(&object.data);
                Some(ResolvedBase::OutOfPack {
                    kind: object.kind,
                    end: out.len(),
                })
            };
            let mut out = Vec::new();
            match file.decode_entry(
                entry.clone(),
                &mut out,
                &mut inflate,
                &resolve,
                &mut cache::Never,
            ) {
                Ok(outcome) => {
                    let id = gix_object::compute_hash(HASH, outcome.kind, &out)
                        .context("hash pack object")?;
                    objects.insert(
                        id,
                        Object {
                            kind: outcome.kind,
                            data: out,
                        },
                    );
                    progressed = true;
                }
                Err(data::decode::Error::DeltaBaseUnresolved(_)) => still_pending.push(entry),
                Err(e) => return Err(e).context("decode pack entry"),
            }
        }
        if still_pending.is_empty() {
            return Ok(objects);
        }
        if !progressed {
            bail!("pack delta bases could not be resolved");
        }
        pending = still_pending;
    }
}

/// Bytes the zlib stream at `input`'s head consumes. Where one pack entry
/// ends and the next begins is known only once its deflate stream
/// terminates — measure it with a scratch buffer, keeping nothing.
fn stream_extent(input: &[u8]) -> CargoResult<usize> {
    let mut decomp = Decompress::new();
    let mut scratch = [0u8; 64 * 1024];
    let mut consumed = 0usize;
    loop {
        let before = decomp.total_in() as usize;
        let status = decomp
            .decompress(&input[consumed..], &mut scratch, FlushDecompress::None)
            .context("inflate pack entry")?;
        consumed = decomp.total_in() as usize;
        match status {
            Status::StreamEnd => return Ok(consumed),
            Status::Ok | Status::BufError => {
                if consumed == before || consumed >= input.len() {
                    bail!("unterminated pack entry stream")
                }
            }
        }
    }
}

/// A file's entry in a walked tree.
struct FileEntry {
    rel: PathBuf,
    oid: gix_hash::ObjectId,
}

/// Walk the commit's tree over the decoded object map into the file map
/// the checkout writer consumes — same shape `collect_tar_gz` builds:
/// files only, `.cargo-ok` dropped, gitlinks absent, symlinks resolved to
/// their target's stored contents after the walk.
fn materialize_tree(
    objects: &HashMap<gix_hash::ObjectId, Object>,
    commit: &str,
) -> CargoResult<BTreeMap<PathBuf, Vec<u8>>> {
    let commit_id = gix_hash::ObjectId::from_hex(commit.as_bytes())
        .with_context(|| format!("invalid commit sha `{commit}`"))?;
    let commit_obj = objects
        .get(&commit_id)
        .filter(|o| o.kind == Kind::Commit)
        .ok_or_else(|| anyhow::anyhow!("pack lacks commit {commit}"))?;
    let tree_id = CommitRef::from_bytes(&commit_obj.data, HASH)
        .context("decode commit object")?
        .tree();

    // Walk the trees first, collecting files and links: unlike a tar
    // stream the order is not top-down, so which blobs to keep is decided
    // once every link is known — a link walked before its target keeps
    // the target's contents the same way.
    let mut file_entries: Vec<FileEntry> = Vec::new();
    let mut links: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut stack = vec![(tree_id, PathBuf::new())];
    while let Some((tree_id, dir)) = stack.pop() {
        let tree = objects
            .get(&tree_id)
            .filter(|o| o.kind == Kind::Tree)
            .ok_or_else(|| anyhow::anyhow!("pack lacks tree {tree_id}"))?;
        for entry in TreeRefIter::from_bytes(&tree.data, HASH) {
            let entry = entry.context("decode tree entry")?;
            let name = entry.filename.to_str().context("non-UTF-8 name in tree")?;
            // Tree names are single components, but a crafted pack could
            // carry what a tar member would — reject escapes the way
            // `unpack_in` does.
            if name.is_empty() || name == ".." || name.contains('/') || name.contains('\\') {
                bail!("tree entry `{name}` escapes the checkout root");
            }
            let rel = dir.join(name);
            if entry.mode.is_tree() {
                stack.push((entry.oid.to_owned(), rel));
            } else if entry.mode.is_commit() {
                // A gitlink is a submodule reference — like the codeload
                // tarball, nothing is written beneath it.
            } else if entry.mode.is_link() {
                let target = blob(objects, entry.oid)?;
                let target = Path::new(str::from_utf8(&target.data).context("non-UTF-8 link")?);
                if let Some(target) = tarball::link_target(&rel, target, true) {
                    links.push((rel, target));
                }
            } else {
                // cargo never extracts a `.cargo-ok` marker.
                if rel.file_name().and_then(|n| n.to_str()) == Some(".cargo-ok") {
                    continue;
                }
                file_entries.push(FileEntry {
                    rel,
                    oid: entry.oid.to_owned(),
                });
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
    let mut link_targets: BTreeSet<PathBuf> = BTreeSet::new();
    for (rel, target) in &links {
        if !tarball::resolve_reads_contents(rel) {
            continue;
        }
        let mut current = target.as_path();
        let mut seen = BTreeSet::new();
        while let Some(next) = link_map.get(current) {
            if !seen.insert(current) {
                break; // link cycle — the link leaves no entry
            }
            current = next;
        }
        link_targets.insert(current.to_path_buf());
    }

    let mut files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    let mut retained: u64 = 0;
    for FileEntry { rel, oid } in file_entries {
        let keep = tarball::resolve_reads_contents(&rel) || link_targets.contains(&rel);
        let contents = if keep {
            let data = &blob(objects, &oid)?.data;
            if data.len() as u64 > tarball::MAX_RESOLVE_TREE_BYTES.saturating_sub(retained) {
                bail!(
                    "the pack's resolution inputs exceed the \
                     {}-byte retained-content limit",
                    tarball::MAX_RESOLVE_TREE_BYTES
                );
            }
            retained += data.len() as u64;
            data.clone()
        } else {
            Vec::new()
        };
        files.insert(rel, contents);
    }
    tarball::materialize_links(&mut files, &links);
    Ok(files)
}

/// The blob object `oid` names, or a named error when the pack lacks it.
fn blob<'a>(
    objects: &'a HashMap<gix_hash::ObjectId, Object>,
    oid: &gix_hash::oid,
) -> CargoResult<&'a Object> {
    objects
        .get(oid)
        .filter(|o| o.kind == Kind::Blob)
        .ok_or_else(|| anyhow::anyhow!("pack lacks blob {oid}"))
}
