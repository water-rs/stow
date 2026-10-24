//! The crates.io daily database dump — the `preheat top-binaries`
//! lane's ranking and binary check (stow#891).
//!
//! `https://static.crates.io/db-dump.tar.gz` is a ~2 GB tar.gz holding
//! one `<timestamp>/` export directory: `data/<table>.csv` — one
//! Postgres CSV per table — plus `metadata.json`, the schema and the
//! export/import scripts. The lane fetches it once per run and reads
//! only the four tables the ranking joins, decompressed and parsed in
//! a single pass over the response stream — the tarball is never held
//! in memory or on disk:
//!
//! - `crates.csv` — `id` → `name`;
//! - `default_versions.csv` — `crate_id` → `version_id`, the release
//!   crates.io hands a bare `cargo add`;
//! - `versions.csv` — `id` → (`crate_id`, `num`, `bin_names`); the
//!   binary check reads `bin_names`, a Postgres array literal —
//!   `{a,b}`, `{}` or NULL (empty field) for none;
//! - `version_downloads.csv` — `version_id`, `downloads`, `date`: the
//!   ranking. The dump already trims the table to the last 90 days
//!   (rust-lang/crates.io#3611, documented in the dump's own
//!   README.md), so every row counts — there is no date filter.
//!
//! Columns are ordered alphabetically in each file, never in schema
//! order — every reader locates its columns by header name and fails
//! on a missing one. The tar's entry order is no contract either
//! (`versions.csv` precedes `version_downloads.csv` today), so each
//! table lands in the map the final join needs; the ids are dense
//! serials, indexed by `Vec` rather than hashed.

use std::io::{self, Cursor, Read};
use std::path::Component;

use futures_util::StreamExt;
use stow_types::stow_error;
use stow_types::transient::Backoff;

/// The dump object — one gzip tarball a day, CDN-served.
const DB_DUMP_URL: &str = "https://static.crates.io/db-dump.tar.gz";

/// One fetch+parse attempt's deadline: the ~2 GB download plus a pass
/// over ~50M CSV rows is a handful of minutes at any real rate; an
/// attempt that stalls longer is abandoned and the loop retries.
const DUMP_DEADLINE: std::time::Duration = std::time::Duration::from_mins(20);

/// How many body chunks the pump may run ahead of the parser — the
/// only part of the stream ever held in memory.
const CHUNK_BOUND: usize = 8;

/// Progress granularity for the download log.
const LOG_EVERY_BYTES: u64 = 256 * 1024 * 1024;

/// The `version_id`/`crate_id` "absent" marker inside the dense maps —
/// Postgres serials start at 1, so `0` never collides and doubles as
/// `Default`.
const ABSENT: u32 = 0;

/// A binary crate the dump ranks: the crate's name, its default
/// version, and its downloads over the dump's 90-day window — the
/// value the scheduler orders its queue by.
#[derive(Debug, Clone)]
pub struct BinaryCandidate {
    /// The crate name.
    pub id: String,
    /// The default version — `default_versions` → `versions.num`.
    pub version: String,
    /// Downloads over the last 90 days.
    pub downloads: u64,
}

/// How one fetch+parse attempt ended when it produced no ranking.
enum AttemptError {
    /// The transfer itself broke — the whole attempt retries under the
    /// shared [`Backoff`] budget.
    Transport(stow_types::error::Error),
    /// The bytes were bad — a malformed dump is deterministic, so this
    /// fails the lane at once.
    Data(stow_types::error::Error),
}

/// The `limit` binary crates ranked highest by 90-day downloads. The
/// dump is fetched once: the response stream is decompressed and
/// parsed on a blocking thread while it arrives. A broken transfer
/// restarts the whole attempt under [`Backoff`]; a malformed dump
/// fails without retrying.
pub async fn top_binary_crates(limit: usize) -> stow_types::error::Result<Vec<BinaryCandidate>> {
    let mut backoff = Backoff::new();
    loop {
        match tokio::time::timeout(DUMP_DEADLINE, dump_attempt(limit)).await {
            Ok(Ok(candidates)) => return Ok(candidates),
            Ok(Err(AttemptError::Data(error))) => return Err(error),
            Ok(Err(AttemptError::Transport(error))) => {
                let Some(wait) = backoff.next_wait(None) else {
                    return Err(error);
                };
                tracing::warn!(%error, "db-dump fetch failed; retrying");
                tokio::time::sleep(wait).await;
            }
            Err(_) => {
                let error = stow_error!("db-dump did not complete within {DUMP_DEADLINE:?}");
                let Some(wait) = backoff.next_wait(None) else {
                    return Err(error);
                };
                tracing::warn!(%error, "db-dump fetch failed; retrying");
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// One download+parse attempt.
async fn dump_attempt(limit: usize) -> Result<Vec<BinaryCandidate>, AttemptError> {
    let response = crate::crates_io::fetch_stream(DB_DUMP_URL)
        .await
        .map_err(AttemptError::Transport)?;
    let (tx, rx) = tokio::sync::mpsc::channel(CHUNK_BOUND);
    let parsed = tokio::task::spawn_blocking(move || parse(DumpReader::new(rx), limit));
    // The pump is joined, not spawned: when the deadline drops this
    // attempt, the pump and its sender drop with it, so the parser reads
    // end of stream and exits instead of a stale download running on
    // beside the retry.
    let (parsed, pumped) = tokio::join!(parsed, pump_body(response.into_body(), tx));
    match parsed.expect("dump parse panicked") {
        Ok(candidates) => Ok(candidates),
        Err(error) => match pumped {
            // The body broke mid-read; the parse error is its shadow,
            // so the whole attempt retries.
            Err(transport) => Err(AttemptError::Transport(transport)),
            // A clean body that failed to parse is a malformed dump.
            Ok(()) => Err(AttemptError::Data(error)),
        },
    }
}

/// Push the response body into the parser's channel. `Err` reports a
/// body that broke mid-read; a dropped receiver means the parser
/// already owns the outcome, which is a clean exit here.
async fn pump_body(
    mut body: zenwave::Body,
    tx: tokio::sync::mpsc::Sender<io::Result<zenwave::utils::Bytes>>,
) -> stow_types::error::Result<()> {
    let mut bytes = 0_u64;
    let mut next_log = LOG_EVERY_BYTES;
    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                let message = format!("db-dump body: {error}");
                let _ = tx.send(Err(io::Error::other(message.clone()))).await;
                return Err(stow_error!("{message}"));
            }
        };
        bytes += chunk.len() as u64;
        if bytes >= next_log {
            tracing::info!(bytes, "db-dump download");
            next_log += LOG_EVERY_BYTES;
        }
        if tx.send(Ok(chunk)).await.is_err() {
            return Ok(());
        }
    }
    tracing::info!(bytes, "db-dump download complete");
    Ok(())
}

/// The response body as a blocking `Read`: the pump's bounded channel
/// is the only buffer between the socket and the gzip decoder.
struct DumpReader {
    rx: tokio::sync::mpsc::Receiver<io::Result<zenwave::utils::Bytes>>,
    chunk: Cursor<zenwave::utils::Bytes>,
}

impl DumpReader {
    const fn new(rx: tokio::sync::mpsc::Receiver<io::Result<zenwave::utils::Bytes>>) -> Self {
        Self {
            rx,
            chunk: Cursor::new(zenwave::utils::Bytes::new()),
        }
    }
}

impl Read for DumpReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let read = self.chunk.read(buf)?;
            if read > 0 || buf.is_empty() {
                return Ok(read);
            }
            self.chunk = match self.rx.blocking_recv() {
                Some(Ok(chunk)) => Cursor::new(chunk),
                Some(Err(error)) => return Err(error),
                None => return Ok(0),
            };
        }
    }
}

/// One row of `versions.csv`, reduced to the facts the join needs.
/// `num` lives in [`Tables::num_arena`], sliced by `num_off..+num_len`.
/// `Default` is the hole an id without a row grows with — `crate_id`
/// `ABSENT`.
#[derive(Debug, Default, Clone, Copy)]
struct VersionRow {
    crate_id: u32,
    /// Where `num` sits in `num_arena`.
    num_off: u32,
    /// `num`'s length in bytes.
    num_len: u32,
    /// Whether `bin_names` listed a binary target.
    has_bin: bool,
}

/// The four tables, accumulated as they stream past in whatever order
/// the tar carries them.
#[derive(Default)]
struct Tables {
    /// `crate_id` → name. `None` is a hole in the id space.
    names: Vec<Option<Box<str>>>,
    /// `crate_id` → default `version_id`.
    default_version: Vec<u32>,
    /// `version_id` → its row's join facts.
    versions: Vec<VersionRow>,
    /// Every `num` string's bytes, referenced by `VersionRow`.
    num_arena: Vec<u8>,
    /// `version_id` → downloads in the dump's 90-day window.
    downloads: Vec<u64>,
    /// The dump's own timestamp, read from `metadata.json` for the log.
    timestamp: Option<String>,
    /// The tables not yet read — a missing table fails the run rather
    /// than ranking an empty join.
    pending: std::collections::BTreeSet<&'static str>,
}

/// Decompress `reader` — the tarball's byte stream — and join the four
/// tables into the ranked candidate list.
fn parse(reader: impl Read, limit: usize) -> stow_types::error::Result<Vec<BinaryCandidate>> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(reader));
    let mut tables = Tables {
        pending: [
            "crates.csv",
            "default_versions.csv",
            "versions.csv",
            "version_downloads.csv",
        ]
        .into_iter()
        .collect(),
        ..Tables::default()
    };
    let mut export_dir = String::new();
    let entries = archive
        .entries()
        .map_err(|error| stow_error!("read db-dump tar stream: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| stow_error!("read db-dump entry: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| stow_error!("db-dump entry path: {error}"))?
            .into_owned();
        // `components` strips a leading `./`; a non-UTF-8 path names
        // nothing the join reads.
        let Some(parts) = path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let [dir, middle @ .., name] = parts.as_slice() else {
            continue;
        };
        if export_dir.is_empty() {
            (*dir).clone_into(&mut export_dir);
        }
        match (middle, *name) {
            (
                ["data"],
                table @ ("crates.csv"
                | "default_versions.csv"
                | "versions.csv"
                | "version_downloads.csv"),
            ) => {
                tables.pending.remove(table);
                match table {
                    "crates.csv" => read_crates(entry, &mut tables)?,
                    "default_versions.csv" => read_default_versions(entry, &mut tables)?,
                    "versions.csv" => read_versions(entry, &mut tables)?,
                    _ => read_version_downloads(entry, &mut tables)?,
                }
            }
            ([], "metadata.json") => {
                tables.timestamp = metadata_timestamp(entry);
            }
            _ => {}
        }
    }
    tracing::info!(export = %export_dir, timestamp = ?tables.timestamp, "db-dump parsed");
    tables.finish(limit)
}

/// `metadata.json`'s `timestamp` — observability only; an unreadable
/// timestamp is not worth failing a fetch over.
fn metadata_timestamp(mut reader: impl Read) -> Option<String> {
    let mut body = Vec::new();
    reader.read_to_end(&mut body).ok()?;
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()?
        .get("timestamp")?
        .as_str()
        .map(str::to_owned)
}

/// The positions `needed` columns hold in `headers`; a missing column
/// is a schema change to fail on.
fn columns(
    headers: &csv::ByteRecord,
    table: &'static str,
    needed: &[&'static str],
) -> stow_types::error::Result<Vec<usize>> {
    needed
        .iter()
        .map(|name| {
            headers
                .iter()
                .position(|header| header == name.as_bytes())
                .ok_or_else(|| stow_error!("{table}: missing `{name}` column"))
        })
        .collect()
}

fn columns_err(table: &'static str) -> impl Fn(csv::Error) -> stow_types::error::Error {
    move |error| stow_error!("{table}: {error}")
}

/// One field of a record — a row narrower than the header is a
/// malformed dump row.
fn field<'a>(
    record: &'a csv::ByteRecord,
    index: usize,
    table: &str,
    column: &str,
) -> stow_types::error::Result<&'a [u8]> {
    record
        .get(index)
        .ok_or_else(|| stow_error!("{table}: a row is missing `{column}`"))
}

fn parse_int<T: std::str::FromStr>(
    raw: &[u8],
    table: &str,
    column: &str,
) -> stow_types::error::Result<T> {
    std::str::from_utf8(raw)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            stow_error!(
                "{table}.{column}: `{}` is not an integer",
                String::from_utf8_lossy(raw)
            )
        })
}

fn parse_u32(raw: &[u8], table: &str, column: &str) -> stow_types::error::Result<u32> {
    parse_int(raw, table, column)
}

fn parse_u64(raw: &[u8], table: &str, column: &str) -> stow_types::error::Result<u64> {
    parse_int(raw, table, column)
}

fn grow<T: Default>(vec: &mut Vec<T>, index: usize) -> &mut T {
    if index >= vec.len() {
        vec.resize_with(index + 1, T::default);
    }
    &mut vec[index]
}

fn read_crates(reader: impl Read, tables: &mut Tables) -> stow_types::error::Result<()> {
    let mut csv = csv::Reader::from_reader(reader);
    let [id, name] = <[usize; 2]>::try_from(columns(
        csv.byte_headers().map_err(columns_err("crates.csv"))?,
        "crates.csv",
        &["id", "name"],
    )?)
    .expect("columns returns one index per needed name");
    for record in csv.byte_records() {
        let record = record.map_err(columns_err("crates.csv"))?;
        let crate_id = parse_u32(field(&record, id, "crates.csv", "id")?, "crates.csv", "id")?;
        let name = std::str::from_utf8(field(&record, name, "crates.csv", "name")?)
            .map_err(|error| stow_error!("crates.csv: non-UTF-8 crate name: {error}"))?;
        *grow(&mut tables.names, crate_id as usize) = Some(name.into());
    }
    Ok(())
}

fn read_default_versions(reader: impl Read, tables: &mut Tables) -> stow_types::error::Result<()> {
    let mut csv = csv::Reader::from_reader(reader);
    let [crate_id, version_id] = <[usize; 2]>::try_from(columns(
        csv.byte_headers()
            .map_err(columns_err("default_versions.csv"))?,
        "default_versions.csv",
        &["crate_id", "version_id"],
    )?)
    .expect("columns returns one index per needed name");
    for record in csv.byte_records() {
        let record = record.map_err(columns_err("default_versions.csv"))?;
        let crate_id = parse_u32(
            field(&record, crate_id, "default_versions.csv", "crate_id")?,
            "default_versions.csv",
            "crate_id",
        )?;
        let version_id = parse_u32(
            field(&record, version_id, "default_versions.csv", "version_id")?,
            "default_versions.csv",
            "version_id",
        )?;
        *grow(&mut tables.default_version, crate_id as usize) = version_id;
    }
    Ok(())
}

fn read_versions(reader: impl Read, tables: &mut Tables) -> stow_types::error::Result<()> {
    let mut csv = csv::Reader::from_reader(reader);
    let [id, crate_id, num, bin_names] = <[usize; 4]>::try_from(columns(
        csv.byte_headers().map_err(columns_err("versions.csv"))?,
        "versions.csv",
        &["id", "crate_id", "num", "bin_names"],
    )?)
    .expect("columns returns one index per needed name");
    for record in csv.byte_records() {
        let record = record.map_err(columns_err("versions.csv"))?;
        let version_id = parse_u32(
            field(&record, id, "versions.csv", "id")?,
            "versions.csv",
            "id",
        )?;
        let crate_id = parse_u32(
            field(&record, crate_id, "versions.csv", "crate_id")?,
            "versions.csv",
            "crate_id",
        )?;
        let num = std::str::from_utf8(field(&record, num, "versions.csv", "num")?)
            .map_err(|error| stow_error!("versions.csv id {version_id}: non-UTF-8 num: {error}"))?;
        semver::Version::parse(num)
            .map_err(|error| stow_error!("versions.csv id {version_id}: num `{num}`: {error}"))?;
        let bin = field(&record, bin_names, "versions.csv", "bin_names")?;
        // A Postgres `text[]` literal: NULL exports as the empty field,
        // an empty set as `{}`, anything else as `{a,b}`.
        let has_bin = match bin {
            b"" | b"{}" => false,
            b if b.starts_with(b"{") && b.ends_with(b"}") => true,
            _ => {
                return Err(stow_error!(
                    "versions.csv id {version_id}: malformed bin_names `{}`",
                    String::from_utf8_lossy(bin)
                ));
            }
        };
        let num_off = u32::try_from(tables.num_arena.len())
            .map_err(|_| stow_error!("versions.csv: the num arena overflows u32"))?;
        tables.num_arena.extend_from_slice(num.as_bytes());
        let num_len = u32::try_from(num.len()).expect("a num field fits u32");
        *grow(&mut tables.versions, version_id as usize) = VersionRow {
            crate_id,
            num_off,
            num_len,
            has_bin,
        };
    }
    Ok(())
}

fn read_version_downloads(reader: impl Read, tables: &mut Tables) -> stow_types::error::Result<()> {
    let mut csv = csv::Reader::from_reader(reader);
    let [version_id, downloads] = <[usize; 2]>::try_from(columns(
        csv.byte_headers()
            .map_err(columns_err("version_downloads.csv"))?,
        "version_downloads.csv",
        &["version_id", "downloads"],
    )?)
    .expect("columns returns one index per needed name");
    for record in csv.byte_records() {
        let record = record.map_err(columns_err("version_downloads.csv"))?;
        let version_id = parse_u32(
            field(&record, version_id, "version_downloads.csv", "version_id")?,
            "version_downloads.csv",
            "version_id",
        )?;
        let downloads = parse_u64(
            field(&record, downloads, "version_downloads.csv", "downloads")?,
            "version_downloads.csv",
            "downloads",
        )?;
        *grow(&mut tables.downloads, version_id as usize) += downloads;
    }
    Ok(())
}

impl Tables {
    /// Fold the streamed tables into the ranked candidates: per-crate
    /// 90-day downloads through `versions.crate_id`, then the binary
    /// check through `default_versions` → `versions.bin_names`.
    fn finish(self, limit: usize) -> stow_types::error::Result<Vec<BinaryCandidate>> {
        if !self.pending.is_empty() {
            return Err(stow_error!(
                "db-dump is missing table(s): {}",
                self.pending.iter().copied().collect::<Vec<_>>().join(", ")
            ));
        }
        // A download row naming a version the dump does not list — or a
        // version naming a crate `crates.csv` does not — is an
        // inconsistent export, not a row to skip.
        let mut crate_downloads = vec![0_u64; self.names.len()];
        for (version_id, downloads) in self.downloads.iter().enumerate() {
            if *downloads == 0 {
                continue;
            }
            let row = self
                .versions
                .get(version_id)
                .filter(|row| row.crate_id != ABSENT)
                .ok_or_else(|| {
                    stow_error!(
                        "version_downloads.csv names version {version_id} absent from versions.csv"
                    )
                })?;
            *crate_downloads
                .get_mut(row.crate_id as usize)
                .ok_or_else(|| {
                    stow_error!(
                        "versions.csv names crate {} absent from crates.csv",
                        row.crate_id
                    )
                })? += downloads;
        }
        let mut candidates = Vec::new();
        for (crate_id, &default) in self.default_version.iter().enumerate() {
            if default == ABSENT {
                continue;
            }
            let row = self
                .versions
                .get(default as usize)
                .filter(|row| row.crate_id != ABSENT)
                .ok_or_else(|| {
                    stow_error!(
                        "default_versions.csv names version {default} absent from versions.csv"
                    )
                })?;
            if !row.has_bin {
                continue;
            }
            let name = self
                .names
                .get(crate_id)
                .and_then(Option::as_deref)
                .ok_or_else(|| {
                    stow_error!(
                        "default_versions.csv names crate {crate_id} absent from crates.csv"
                    )
                })?;
            let num = self
                .num_arena
                .get(row.num_off as usize..row.num_off as usize + row.num_len as usize)
                .ok_or_else(|| stow_error!("versions.csv id {default}: num range out of bounds"))?;
            candidates.push(BinaryCandidate {
                id: name.to_owned(),
                version: std::str::from_utf8(num)
                    .map_err(|error| stow_error!("versions.csv: non-UTF-8 num: {error}"))?
                    .to_owned(),
                downloads: crate_downloads[crate_id],
            });
        }
        // Downloads descending; the name breaks ties so the ranking does
        // not depend on export order.
        candidates.sort_by(|a, b| b.downloads.cmp(&a.downloads).then_with(|| a.id.cmp(&b.id)));
        candidates.truncate(limit);
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::{BinaryCandidate, parse};

    /// A gzipped tar holding exactly the files `entries` names — the
    /// same `flate2`/`tar` pair the reader uses in reverse.
    fn tarball(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, *path, body.as_bytes())
                .expect("append");
        }
        let tar = tar.into_inner().expect("tar finish");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).expect("gzip");
        gz.finish().expect("gzip finish")
    }

    /// The four-table fixture as `parse` meets it — `versions.csv`
    /// ahead of `version_downloads.csv`, matching the real entry order.
    ///
    /// ```text
    /// crate          default version   bin_names   90d downloads
    /// lib-only       1.0.0             {}          9000  (excluded: no bin)
    /// bin-a          2.0.0             {bin_a}     50+60 = 110
    /// bin-b          3.0.0             {bin_b}     400
    /// bin-c          4.0.0             {bin_c,other} 110
    /// lib-popular    5.0.0             {}          999999 (excluded: no bin)
    /// lib-with-bin   6.0.0             {bin_d}     80    (library AND binary — included)
    /// ```
    fn fixture() -> Vec<u8> {
        tarball(&[
            (
                "2026-10-24-020018/data/crates.csv",
                "id,name,created_at\n1,lib-only,\n2,bin-a,\n3,bin-b,\n4,bin-c,\n5,lib-popular,\n6,lib-with-bin,\n",
            ),
            (
                "2026-10-24-020018/data/versions.csv",
                "id,crate_id,num,bin_names,yanked\n\
                 10,1,1.0.0,{},f\n\
                 20,2,2.0.0,{bin_a},f\n\
                 30,3,3.0.0,{bin_b},f\n\
                 40,4,4.0.0,\"{bin_c,other}\",f\n\
                 50,5,5.0.0,{},f\n\
                 60,6,6.0.0,{bin_d},f\n",
            ),
            (
                "2026-10-24-020018/data/default_versions.csv",
                "crate_id,version_id,num_versions\n\
                 1,10,1\n2,20,1\n3,30,1\n4,40,1\n5,50,1\n6,60,1\n",
            ),
            (
                "2026-10-24-020018/data/version_downloads.csv",
                "version_id,downloads,date\n\
                 10,9000,2026-10-01\n\
                 20,50,2026-10-01\n20,60,2026-10-02\n\
                 30,400,2026-10-01\n\
                 40,110,2026-10-01\n\
                 50,999999,2026-10-01\n\
                 60,80,2026-10-01\n",
            ),
        ])
    }

    fn parse_fixture(limit: usize) -> Vec<BinaryCandidate> {
        parse(std::io::Cursor::new(fixture()), limit).expect("fixture parses")
    }

    /// The binary check runs `default_versions` → `versions.bin_names`:
    /// a library+binary crate is in, a library-only crate is out however
    /// popular, and the ranking is the 90-day window's sum across a
    /// version's days.
    #[test]
    fn ranking_is_90d_downloads_of_binary_defaults() {
        let candidates = parse_fixture(100);
        let names: Vec<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(names, ["bin-b", "bin-a", "bin-c", "lib-with-bin"]);
        let by_name = |name: &str| candidates.iter().find(|c| c.id == name).unwrap();
        assert_eq!(by_name("bin-a").downloads, 110);
        assert_eq!(by_name("bin-a").version, "2.0.0");
        assert_eq!(by_name("lib-with-bin").downloads, 80);
    }

    /// The cut keeps the `limit` highest-ranked and the tie order is
    /// deterministic — downloads descending, then the crate name.
    #[test]
    fn limit_cuts_and_ties_break_on_name() {
        let names = |limit: usize| {
            parse_fixture(limit)
                .into_iter()
                .map(|c| c.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(names(2), ["bin-b", "bin-a"]);
        assert_eq!(names(3), ["bin-b", "bin-a", "bin-c"]);
    }

    /// A missing table fails rather than ranking an empty join.
    #[test]
    fn a_missing_table_fails() {
        let gz = tarball(&[("2026-10-24-020018/data/crates.csv", "id,name\n1,only\n")]);
        let error = parse(std::io::Cursor::new(gz), 100).expect_err("missing tables fail");
        assert!(
            error.to_string().contains("version_downloads.csv"),
            "{error}"
        );
    }

    /// A header missing a needed column is a schema change to fail on.
    #[test]
    fn a_missing_column_fails() {
        let gz = tarball(&[
            ("2026-10-24-020018/data/crates.csv", "id,name\n1,only\n"),
            (
                "2026-10-24-020018/data/default_versions.csv",
                "crate_id,version_id\n1,1\n",
            ),
            (
                "2026-10-24-020018/data/versions.csv",
                "id,crate_id,num\n1,1,1.0.0\n",
            ),
            (
                "2026-10-24-020018/data/version_downloads.csv",
                "version_id,downloads\n1,5\n",
            ),
        ]);
        let error = parse(std::io::Cursor::new(gz), 100).expect_err("missing column fails");
        assert!(error.to_string().contains("bin_names"), "{error}");
    }

    /// A malformed row fails the parse, not the ranking.
    #[test]
    fn a_malformed_row_fails() {
        let gz = tarball(&[
            ("2026-10-24-020018/data/crates.csv", "id,name\n1,only\n"),
            (
                "2026-10-24-020018/data/default_versions.csv",
                "crate_id,version_id\n1,not-a-number\n",
            ),
            (
                "2026-10-24-020018/data/versions.csv",
                "id,crate_id,num,bin_names\n1,1,1.0.0,{}\n",
            ),
            (
                "2026-10-24-020018/data/version_downloads.csv",
                "version_id,downloads\n1,5\n",
            ),
        ]);
        assert!(parse(std::io::Cursor::new(gz), 100).is_err());
    }
}
