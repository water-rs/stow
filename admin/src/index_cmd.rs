//! `stow-admin index …` — the publish side of the signed artifact index
//! (water-rs/stow#188, #193). Its stdout lines are the machine contract
//! `index-publish.yml` consumes, so they print verbatim regardless of
//! `--json`.
//!
//! Since stow#455 the records source is GHCR, not the edge catalog, and
//! the export is incremental: every published `index.<target>.<rustc>`
//! slice carries a signed companion `folded.<target>.<rustc>` artifact —
//! the sorted list of records tags already folded into it — so one export
//! pass lists the tag space once, verifies the previous pairs against the
//! index workflow's identity, and pulls only the records tags missing
//! from every slice's folded set. `--full` ignores the folded sets for
//! the first publish of a new rustc and for disaster recovery. The delta
//! of the pass lands in `<out-dir>/new-records.json` — the delta the
//! pass folded. Every
//! `CI_TARGET_TRIPLES` member ends a pass with a slice: an entry that
//! got no rows and has no published pair is emitted empty at
//! generation 1, since `--target` consumers fetch the slice whether or
//! not their deps built on it. Each emitted slice stamps
//! `generation = prev + 1` (`1` on `--full` or a first publish), and
//! the pulled previous index rides beside the slice file as
//! `<file>.prev` — the base `index report`'s
//! `{base_generation, added, retired}` delta diffs against.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::api::{ArtifactRecord, CI_TARGET_TRIPLES, PublishedSliceRow};
use stow_types::identity::{DependencyIdentity, TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
    IndexDecodeError, content_sha256, encode, folded_tag, folded_tag_parts, index_tag,
};
use stow_types::public_cache::UnitShape;
use stow_types::records::{parse_records_tag, record_to_index_row};
use stow_types::registry::{CacheRepository, cache_repository, sha256_digest};
use stow_types::stow_error;

use crate::Edge;
use crate::cloudflare;
use crate::render;
use zenwave::ResponseExt as _;

/// Records artifacts pulled in flight per export — the shared
/// anonymous session already honors the registry's rate limit, so this
/// bounds in-flight work, not throughput.
const RECORDS_PULL_CONCURRENCY: usize = 16;
/// Previous `index`/`folded` pairs pulled in flight per export.
const PREV_PULL_CONCURRENCY: usize = 8;
/// Artifact records per sync request — each request lands as one
/// edge-side batch write, so a chunk is one round trip rather than a
/// body the worker timeout eats mid-flight.
/// Sync chunk posts in flight — the chunks are independent writes, so
/// the bound only limits how many edge requests the pass holds open.
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
/// Records artifacts are signed by `build-crate.yml` — the export pins
/// that identity the same way the CLI pins it for bundles.
const RECORDS_CERT_URL: &str = stow_types::trusted_builder::CERTIFICATE_IDENTITY;
/// The `index.*`/`folded.*` pair is signed by the index workflow — the
/// export verifies previous slices against it before folding on top.
pub const INDEX_CERT_URL: &str = stow_types::trusted_builder::INDEX_CERTIFICATE_IDENTITY;

#[derive(Args)]
pub struct IndexArgs {
    #[command(subcommand)]
    pub command: IndexCommand,
}

#[derive(Subcommand)]
pub enum IndexCommand {
    /// Fold the registry's records into every `(target, rustc_version)`
    /// slice in one pass: the previous published `index`/`folded` pair
    /// per slice, plus only the `records-*` artifacts no folded set
    /// covers. Writes each changed slice as `index.<target>.<rustc>` and
    /// its folded set as `folded.<target>.<rustc>` under `--out-dir`,
    /// plus `slices.json` (the publish/report loop's input) and
    /// `new-records.json` (the delta the pass folded). A
    /// `CI_TARGET_TRIPLES` member with no new rows and no published
    /// pair is still written — an empty first-publish slice, so
    /// `--target` consumers of a deps-less lane always find the tag.
    Export(IndexExportArgs),
    /// Push an exported index file and its folded companion to the
    /// registry and sign both.
    Publish(IndexPublishArgs),
    /// Report a just-published slice's semantic membership to the edge
    /// — what the scheduler's dependency gate checks before releasing
    /// a dependent. `index-publish.yml` runs it after a successful
    /// publish; running it again against the same file is idempotent.
    Report(IndexReportArgs),
    /// Print every `CI_TARGET_TRIPLES` entry, one per line — the slice
    /// list `index-publish.yml` iterates, read from the binary so the
    /// workflow never carries its own copy.
    Targets,
    /// Resolve the public hit leaderboard's bundle digests to crate
    /// identities through the signed index slices (stow#889) — the
    /// edge keeps no identity store, so the offline join lives here.
    Join(IndexJoinArgs),
}

#[derive(Args)]
pub struct IndexExportArgs {
    /// Directory the changed slices, their folded sets, `slices.json`
    /// and `new-records.json` are written to.
    #[arg(long)]
    out_dir: std::path::PathBuf,
    /// The rustc the pass exports — only `records-<rustc>-*` artifacts
    /// and `index.<target>.<rustc>`/`folded.<target>.<rustc>` pairs
    /// belong to it; other rustcs' tags are never pulled.
    #[arg(long)]
    rustc_version: String,
    /// Ignore every published `folded` set and re-pull all records of
    /// this rustc — the first publish of a new rustc and the
    /// disaster-recovery path. An index-format change needs a `--full`
    /// export: the previous slices are of the format this reader no
    /// longer reads.
    #[arg(long)]
    full: bool,
}

#[derive(Args)]
pub struct IndexJoinArgs {
    /// The rustc whose `index.<target>.<rustc>` slices resolve the
    /// digests — repeat for every rustc that published during the
    /// leaderboard's window.
    #[arg(long = "rustc-version")]
    rustc_versions: Vec<String>,
}

/// One entry of the `slices.json` array `index export` writes — also the
/// JSON line it prints per slice on stdout. The publish workflow reads
/// `content_sha256` (a digest of everything but the wall-clock
/// `generated_at`) to decide whether the published artifact is stale, and
/// `tag` for the GHCR reference.
#[derive(Debug, serde::Serialize)]
struct IndexExportSummary {
    target: String,
    rustc_version: String,
    tag: String,
    folded_tag: String,
    index_file: String,
    folded_file: String,
    rows: u64,
    bytes: usize,
    sha256: String,
    content_sha256: String,
}

/// Publish an index file `index export` wrote to the slice's OCI tag and
/// sign it, then do the same for its folded companion.
///
/// Two modes, selected by environment: with `STOW_MOCK_PRIVATE_KEY_PATH`
/// set the command delegates to `stow-mock-registry publish-index` —
/// writing the signed artifacts into `STOW_MOCK_REGISTRY_ROOT` exactly as
/// `stow-build` mock-populate does for bundles; without it the command
/// pushes to GHCR through `stow-oci` and signs with the `cosign` binary
/// (`GHCR_USERNAME`/`GHCR_TOKEN`), the production path
/// `index-publish.yml` runs.
#[derive(Args)]
pub struct IndexPublishArgs {
    /// The encoded index file (`index export --out-dir` wrote).
    #[arg(long)]
    file: std::path::PathBuf,
    /// The folded set file the same export wrote for the slice.
    #[arg(long)]
    folded: std::path::PathBuf,
}

/// The JSON line `index publish` prints on stdout.
#[derive(Debug, serde::Serialize)]
struct IndexPublishSummary {
    tag: String,
    folded_tag: String,
    manifest_digest: String,
    outcome: &'static str,
}

/// Report the slice an exported index file carries to the edge, so the
/// scheduler learns what the published index actually serves. The
/// file's header is authoritative — the slice key comes from it, so the
/// command takes only `--file`.
///
/// The default report is a delta: `index export` saves the previously
/// published index beside the slice file as `<file>.prev`, and the
/// report sends `base_generation` plus only the rows that moved. `--full`
/// sends the explicit full report the scheduler diffs itself; so does a
/// first publish (`generation == 1`), the only slice with no `.prev`.
/// A delta the edge refuses with 409 — its live generation moved past
/// `base_generation`, or the slice was never reported — is resent once
/// as the full report for the same file, which is the resync the
/// conflict asks for.
#[derive(Args)]
pub struct IndexReportArgs {
    /// The encoded index files (`index export --out-dir` wrote them) —
    /// repeatable, one per slice the run published; the whole set posts
    /// as ONE report per publish run (stow#940).
    #[arg(long, required = true)]
    file: Vec<std::path::PathBuf>,
    /// Send the explicit full report (`base_generation` unset) — the
    /// resync path for a slice whose optimistic-lock check failed, and
    /// the automatic shape of a first publish.
    #[arg(long)]
    full: bool,
}

/// The JSON line `index report` prints on stdout — one line for the
/// run's whole report.
#[derive(Debug, serde::Serialize)]
struct IndexReportSummary {
    /// Slices the report carried.
    slices: usize,
    /// Rows the report added across every slice — each slice's whole
    /// membership on a full report.
    added: usize,
    /// Rows the report retired — `0` on a full report.
    retired: usize,
    /// `true` when the report took the explicit full path (`--full`,
    /// first publishes with no `.prev` sidecar, or the resync a 409'd
    /// delta triggers).
    full: bool,
}

/// Dispatch one `index` subcommand.
pub async fn run(args: IndexArgs) -> stow_types::error::Result<()> {
    match args.command {
        IndexCommand::Export(args) => index_export(args).await,
        IndexCommand::Publish(args) => index_publish(args).await,
        IndexCommand::Report(args) => index_report(&Edge::connect()?, args).await,
        IndexCommand::Targets => {
            render::emit_line(&CI_TARGET_TRIPLES.join("\n"));
            Ok(())
        }
        IndexCommand::Join(args) => index_join(args).await,
    }
}

/// The trust a records read verifies against — the mock registry's local
/// key under `STOW_MOCK_PUBLIC_KEY_PATH`, else Fulcio/Rekor with the
/// `build-crate.yml` certificate identity pinned.
pub async fn records_trust() -> stow_types::error::Result<stow_oci::verify::Trust> {
    if let Ok(path) = std::env::var(STOW_MOCK_PUBLIC_KEY_PATH_ENV) {
        return Ok(stow_oci::verify::Trust::MockKey(path.into()));
    }
    let cache_dir = std::env::var_os("STOW_CACHE_DIR")
        .map_or_else(
            || dirs::home_dir().map(|home| home.join(".cache").join("stow")),
            |dir| Some(dir.into()),
        )
        .ok_or_else(|| stow_error!("resolve the sigstore trust cache directory"))?;
    Ok(stow_oci::verify::Trust::GithubCi(std::sync::Arc::new(
        stow_oci::verify::load_trust_material(&cache_dir).await?,
    )))
}

/// Verify the signature on one manifest digest and return `()` — the
/// shared half of every pull below: records artifacts pin the
/// `build-crate.yml` identity, the `index`/`folded` pair pins the index
/// workflow's.
///
/// `reference` is the transport pull reference the signature materials
/// fetch through; the signature itself binds the canonical
/// `ghcr.io/<repository>:<tag>` the publisher signed, so
/// `identity_reference` is what verification compares — the same split
/// the CLI's bundle and index verification makes.
pub async fn verify_artifact(
    session: &stow_oci::RegistrySession,
    trust: &stow_oci::verify::Trust,
    reference: &oci_client::Reference,
    identity_reference: &str,
    manifest_digest: &str,
    cert_url: &str,
) -> stow_types::error::Result<()> {
    let materials = stow_oci::pull_signature_materials(session, reference, manifest_digest).await?;
    stow_oci::verify::verify_materials(
        trust,
        identity_reference,
        manifest_digest,
        &materials,
        cert_url,
    )
}

/// The state a slice was published with on the last pass: the index as
/// pulled and verified — its rows the merge extends, its header's
/// generation the stamp increments, its body the `.prev` sidecar — and
/// the set of records tags already folded into it.
struct PrevSlice {
    index: ArtifactIndex,
    folded: BTreeSet<String>,
}

/// The three handles the export's pulls share — shared behind an `Arc`
/// so the injected pull closures may own their futures.
struct PullContext {
    session: stow_oci::RegistrySession,
    repository: CacheRepository,
    trust: stow_oci::verify::Trust,
}

impl PullContext {
    /// Pull and verify the published `index`/`folded` pair `folded`
    /// names. A folded tag without its index sibling — or an index with
    /// no folded set at all — is state an incremental export cannot
    /// extend; `--full` rebuilds it.
    async fn prev_slice(
        &self,
        folded: &str,
    ) -> stow_types::error::Result<Option<((TargetTriple, WireRustcVersion), PrevSlice)>> {
        let Some((target, rustc_version)) = folded_tag_parts(folded) else {
            return Ok(None);
        };
        let target =
            TargetTriple::parse(target).map_err(|error| stow_error!("folded target: {error}"))?;
        let rustc_version = WireRustcVersion::parse(rustc_version)
            .map_err(|error| stow_error!("folded rustc_version: {error}"))?;

        let folded_reference = self.session.reference(folded)?;
        let pulled_folded =
            stow_oci::pull_folded(&self.session, target.as_str(), rustc_version.as_str())
                .await?
                .ok_or_else(|| {
                    stow_error!("folded tag {folded} listed but its manifest does not exist")
                })?;
        verify_artifact(
            &self.session,
            &self.trust,
            &folded_reference,
            &self.repository.reference(folded),
            &pulled_folded.manifest_digest,
            INDEX_CERT_URL,
        )
        .await?;

        let Some(pulled_index) =
            stow_oci::pull_index(&self.session, target.as_str(), rustc_version.as_str()).await?
        else {
            return Err(stow_error!(
                "folded {folded} exists but index.{target}.{rustc_version} is missing — \
                 re-export with --full"
            ));
        };
        let itag = index_tag(target.as_str(), rustc_version.as_str());
        let index_reference = self.session.reference(&itag)?;
        verify_artifact(
            &self.session,
            &self.trust,
            &index_reference,
            &self.repository.reference(&itag),
            &pulled_index.manifest_digest,
            INDEX_CERT_URL,
        )
        .await?;
        let index = decode_published_slice(&index_reference, &rustc_version, &pulled_index.bytes)?;
        if index.header.target != target || index.header.rustc_version != rustc_version {
            return Err(stow_error!(
                "index.{target}.{rustc_version} carries header {}/{} — re-export with --full",
                index.header.target,
                index.header.rustc_version,
            ));
        }
        Ok(Some((
            (target, rustc_version),
            PrevSlice {
                index,
                folded: pulled_folded.tags.into_iter().collect(),
            },
        )))
    }

    /// Pull and verify one records artifact — a signature that fails the
    /// pinned identity is fatal: the alternative, silently dropping it,
    /// would export a slice that quietly misses crates.
    async fn records(&self, tag: &str) -> stow_types::error::Result<Vec<ArtifactRecord>> {
        let pulled = stow_oci::pull_records_by_tag(&self.session, tag).await?;
        let reference = self.session.reference(tag)?;
        verify_artifact(
            &self.session,
            &self.trust,
            &reference,
            &self.repository.reference(tag),
            &pulled.manifest_digest,
            RECORDS_CERT_URL,
        )
        .await?;
        Ok(pulled.records)
    }
}

/// `decode` a pulled published slice. The decoder stays strict — but a
/// slice published in a format this reader predates is recoverable
/// state, not corruption: a `--full` pass refolds every slice of that
/// rustc from its records artifacts. The callers name that recovery —
/// the workflow's `full` input plus the rustc the pass must run for.
pub fn decode_published_slice(
    reference: &oci_client::Reference,
    rustc_version: &WireRustcVersion,
    bytes: &[u8],
) -> stow_types::error::Result<ArtifactIndex> {
    ArtifactIndex::decode(bytes).map_err(|error| match error {
        IndexDecodeError::Format { .. } => stow_error!(
            "decode index {reference}: {error}; \
             re-export the slice with index-publish.yml `full: true` for rustc {rustc_version}"
        ),
        error => stow_error!("decode index {reference}: {error}"),
    })
}

/// One slice's export output.
struct SliceExport {
    target: TargetTriple,
    rustc_version: WireRustcVersion,
    index: ArtifactIndex,
    /// The sorted records-tag list folded into the slice.
    folded: Vec<String>,
    /// The published index this pass extends — the `.prev` sidecar
    /// `index report` diffs against. `None` on `--full` and on a first
    /// publish, where the report takes the explicit full path.
    prev: Option<ArtifactIndex>,
}

/// What one export pass produced.
struct ExportPass {
    /// Slices that changed — the only ones publish needs to touch.
    slices: Vec<SliceExport>,
    /// Every record this pass pulled — the folded delta.
    new_records: Vec<ArtifactRecord>,
    /// Records artifacts pulled — the O(change) meter the gate counts.
    pulled: usize,
}

/// A boxed pull future — the injected halves' shared return shape, so a
/// `&'a str` input may outlive the call only as long as the future does.
type PullFut<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = stow_types::error::Result<T>> + Send + 'a>>;

/// Index rows keyed by the `(c_metadata, unit_shape, dependency_identity)`
/// node a unit was published for. The `(c_metadata, unit_shape)` pair is
/// what a consumer's key space identifies, but it is not the row key:
/// two nodes that differ only in dependency context can compile to the
/// same unit, and each keeps a row so the slice answers for both
/// (stow#657).
type RowsByIdentity = BTreeMap<(String, UnitShape, DependencyIdentity), ArtifactIndexRow>;

/// Fold `row` into `rows` under its
/// `(c_metadata, unit_shape, dependency_identity)` key — a rebuilt unit
/// replaces its node's row, a second node publishing the same unit adds
/// a row beside it.
fn fold_row(rows: &mut RowsByIdentity, row: ArtifactIndexRow) -> stow_types::error::Result<()> {
    rows.insert(
        (
            row.c_metadata.as_str().to_owned(),
            row.unit_shape,
            row.dependency_identity()?,
        ),
        row,
    );
    Ok(())
}

/// The `(target, rustc)` an `index.*` tag names — the same suffix shape
/// [`folded_tag_parts`] splits, under the other half of the tag pair.
pub fn index_tag_parts(tag: &str) -> Option<(&str, &str)> {
    tag.strip_prefix("index.")?.split_once('.')
}

/// The export's registry reads as injectable halves, so the fold logic —
/// the part the O(change) gate measures — is a unit test, not an HTTP
/// dance. `pull_prev` resolves a `folded.*` tag to its published pair;
/// `pull_records` resolves a `records-*` tag to its rows.
///
/// `rustc` scopes the whole pass: a records tag names its rustc
/// (`records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`) and a
/// folded/index pair names it in its suffix, so tag selection alone
/// decides what this rustc's publish touches — another rustc's tags are
/// never pulled, and `--full` stays inside the same scope.
async fn export_pass<P, R>(
    tags: &[String],
    pull_prev: P,
    pull_records: R,
    full: bool,
    rustc: &WireRustcVersion,
) -> stow_types::error::Result<ExportPass>
where
    P: Fn(&str) -> PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>
        + Send
        + Sync,
    R: Fn(&str) -> PullFut<'static, Vec<ArtifactRecord>> + Send + Sync,
{
    let is_own_rustc =
        |tag_rustc: &str| WireRustcVersion::parse(tag_rustc).is_ok_and(|v| v == *rustc);
    let folded_tags: Vec<&str> = tags
        .iter()
        .filter(|tag| folded_tag_parts(tag).is_some_and(|(_, tag_rustc)| is_own_rustc(tag_rustc)))
        .map(String::as_str)
        .collect();
    let mut prev: BTreeMap<(TargetTriple, WireRustcVersion), PrevSlice> = BTreeMap::new();
    if !full {
        let pairs = futures_util::stream::iter(folded_tags.iter().copied().map(&pull_prev))
            .buffered(PREV_PULL_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
        for pair in pairs.into_iter().flatten() {
            prev.insert(pair.0, pair.1);
        }
        // An index tag with no folded sibling is untracked state an
        // incremental pass cannot extend — checked for this rustc's
        // slices only; another rustc's pairs are not this pass's state.
        for tag in tags.iter().filter(|tag| {
            index_tag_parts(tag).is_some_and(|(_, tag_rustc)| is_own_rustc(tag_rustc))
        }) {
            let suffix = &tag["index.".len()..];
            let covered = folded_tags
                .iter()
                .any(|folded| &folded["folded.".len()..] == suffix);
            if !covered {
                return Err(stow_error!(
                    "index tag {tag} has no folded companion — re-export with --full"
                ));
            }
        }
    }

    let folded_union: BTreeSet<&str> = prev
        .values()
        .flat_map(|slice| slice.folded.iter().map(String::as_str))
        .collect();
    // Per-build tags make a rebuilt task's artifact a tag no folded set
    // names. The pull order feeds the row-key dedup —
    // later rows win — so for one task hash the greater build folds
    // last and the newest build's row survives; a tag with no build
    // suffix, the shape every build of a task shared before stow#655,
    // folds before all of them. Across hashes the order is
    // deterministic by hash. Sorting by the tag string would misorder
    // run ids: `…-9-1` precedes `…-10-1` numerically, not lexically.
    let mut missing: Vec<(&str, Option<stow_types::records::BuildRun>, &str)> = tags
        .iter()
        .filter_map(|tag| {
            let parsed = parse_records_tag(tag)?;
            (parsed.rustc_version == rustc.as_str()
                && (full || !folded_union.contains(tag.as_str())))
            .then_some((parsed.task_hash, parsed.build, tag.as_str()))
        })
        .collect();
    missing.sort_unstable();
    let pulled_count = missing.len();
    let mut new_rows: BTreeMap<(TargetTriple, WireRustcVersion), RowsByIdentity> = BTreeMap::new();
    let mut new_folded: BTreeMap<(TargetTriple, WireRustcVersion), BTreeSet<String>> =
        BTreeMap::new();
    let mut new_records: Vec<ArtifactRecord> = Vec::new();
    let per_tag = futures_util::stream::iter(missing.iter().map(|entry| pull_records(entry.2)))
        .buffered(RECORDS_PULL_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;
    for ((_, _, tag), records) in missing.iter().zip(per_tag) {
        // The tag joins the folded set of every slice its records name;
        // a records artifact is immutable per build, so the tag is never
        // pulled again once marked.
        let mut named = BTreeSet::new();
        for record in &records {
            let key = (record.target.clone(), record.rustc_version.clone());
            named.insert(key.clone());
            let row = record_to_index_row(record);
            fold_row(new_rows.entry(key).or_default(), row)?;
        }
        for key in named {
            new_folded.entry(key).or_default().insert((*tag).to_owned());
        }
        new_records.extend(records);
    }

    // A slice is rewritten when new records routed to it — by index row
    // or by folded mark alone (all-unbundled artifacts produce no rows
    // but must still be marked so they are never re-pulled).
    Ok(ExportPass {
        slices: merge_exports(prev, &new_rows, &new_folded, rustc)?,
        new_records,
        pulled: pulled_count,
    })
}

/// Fold the new records into the previous slices: previous rows first,
/// then each new row through [`fold_row`] — a rebuilt unit replaces its
/// node's row, a second node publishing the same unit adds a row beside
/// it — and the folded set growing by every tag a record named.
/// `generated_at` is stamped once so every slice of the pass matches.
fn merge_exports(
    mut prev: BTreeMap<(TargetTriple, WireRustcVersion), PrevSlice>,
    new_rows: &BTreeMap<(TargetTriple, WireRustcVersion), RowsByIdentity>,
    new_folded: &BTreeMap<(TargetTriple, WireRustcVersion), BTreeSet<String>>,
    rustc: &WireRustcVersion,
) -> stow_types::error::Result<Vec<SliceExport>> {
    let mut slices = Vec::new();
    // The set of keys a published slice already covers — snapshot
    // before the closure starts borrowing `prev`.
    let published: BTreeSet<(TargetTriple, WireRustcVersion)> = prev.keys().cloned().collect();
    let mut push_slice = |key: &(TargetTriple, WireRustcVersion)| {
        let prev_slice = prev.remove(key);
        let mut merged = RowsByIdentity::new();
        if let Some(slice) = prev_slice.as_ref() {
            for row in &slice.index.rows {
                fold_row(&mut merged, row.clone())?;
            }
        }
        // New rows fold on top of the slice's own: a re-run task
        // rebuilding the same unit under the same node replaces its
        // row, and the sibling rule holds across the pass boundary.
        if let Some(rows) = new_rows.get(key) {
            for row in rows.values() {
                fold_row(&mut merged, row.clone())?;
            }
        }
        let mut folded: BTreeSet<String> = prev_slice
            .as_ref()
            .map(|slice| slice.folded.clone())
            .unwrap_or_default();
        if let Some(marks) = new_folded.get(key) {
            folded.extend(marks.iter().cloned());
        }
        slices.push((
            key.clone(),
            merged.into_values().collect::<Vec<_>>(),
            folded.into_iter().collect(),
            prev_slice,
        ));
        Ok::<(), stow_types::error::Error>(())
    };
    // A slice appears once whether rows, marks, or both routed to it;
    // the sort below makes iteration order moot.
    for key in new_rows.keys() {
        push_slice(key)?;
    }
    for key in new_folded.keys().filter(|key| !new_rows.contains_key(*key)) {
        push_slice(key)?;
    }
    // A CI target the pass has no slice for at all — nothing routed to
    // it and no published pair to extend — still emits: consumers fetch
    // every supported target's slice, and a target whose deps are all
    // host-side must pull a tag even when it has zero rows (stow#455 —
    // the per-target export loop index-publish.yml ran before the
    // single pass guaranteed this). A target with a published slice and
    // nothing new stays at its current generation, as before.
    for target in CI_TARGET_TRIPLES {
        let key = (
            TargetTriple::parse(*target)
                .map_err(|error| stow_error!("CI_TARGET_TRIPLES entry {target}: {error}"))?,
            rustc.clone(),
        );
        if !new_rows.contains_key(&key)
            && !new_folded.contains_key(&key)
            && !published.contains(&key)
        {
            push_slice(&key)?;
        }
    }
    slices.sort_by(|(a, _, _, _), (b, _, _, _)| a.cmp(b));
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| stow_error!("format generated_at: {error}"))?;
    slices
        .into_iter()
        .map(|((target, rustc_version), rows, folded, prev_slice)| {
            // The generation increments the index the pass extends; a
            // `--full` pass pulled no prev, and a first publish has
            // none, so both stamp `1`.
            let generation = prev_slice
                .as_ref()
                .map_or(1, |slice| slice.index.header.generation + 1);
            let row_count = u64::try_from(rows.len())
                .map_err(|_| stow_error!("row count {} exceeds u64", rows.len()));
            row_count.map(|row_count| SliceExport {
                index: ArtifactIndex {
                    header: ArtifactIndexHeader {
                        format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                        target: target.clone(),
                        rustc_version: rustc_version.clone(),
                        generated_at: now.clone(),
                        generation,
                        row_count,
                    },
                    rows,
                },
                folded,
                prev: prev_slice.map(|slice| slice.index),
                target,
                rustc_version,
            })
        })
        .collect()
}

/// One export pass over the whole registry: writes each changed slice as
/// `index.<target>.<rustc>` plus its `folded.<target>.<rustc>` companion
/// under `--out-dir`, `slices.json` for the publish/report loop, and
/// `new-records.json` — the records the pass folded.
async fn index_export(args: IndexExportArgs) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let base = registry_base()?;
    let http = stow_oci::RegistryHttp::new().await?;
    let repository = cache_repository(&rustc_version);
    let session = base.session(&repository, &http);
    let trust = records_trust().await?;
    let mut tags = session
        .list_tags()
        .await
        .map_err(|error| stow_error!("list registry tags: {error}"))?;
    tags.sort();
    let ctx = std::sync::Arc::new(PullContext {
        session,
        repository,
        trust,
    });
    let pull_prev = {
        let ctx = ctx.clone();
        move |tag: &str| {
            let ctx = ctx.clone();
            let tag = tag.to_owned();
            Box::pin(async move { ctx.prev_slice(&tag).await }) as PullFut<'static, _>
        }
    };
    let pull_records = {
        let ctx = ctx.clone();
        move |tag: &str| {
            let ctx = ctx.clone();
            let tag = tag.to_owned();
            Box::pin(async move { ctx.records(&tag).await }) as PullFut<'static, _>
        }
    };
    let pass = export_pass(&tags, pull_prev, pull_records, args.full, &rustc_version).await?;
    tracing::info!(
        pulled = pass.pulled,
        slices = pass.slices.len(),
        new_records = pass.new_records.len(),
        "exported artifact index"
    );

    tokio::fs::create_dir_all(&args.out_dir)
        .await
        .map_err(|error| stow_error!("create {}: {error}", args.out_dir.display()))?;
    let mut summaries = Vec::new();
    for slice in &pass.slices {
        let bytes = encode(&slice.index).map_err(|error| stow_error!("encode index: {error}"))?;
        let index_name = index_tag(slice.target.as_str(), slice.rustc_version.as_str());
        let folded_name = folded_tag(slice.target.as_str(), slice.rustc_version.as_str());
        let index_file = args.out_dir.join(&index_name);
        let folded_file = args.out_dir.join(&folded_name);
        tokio::fs::write(&index_file, &bytes)
            .await
            .map_err(|error| stow_error!("write index {}: {error}", index_file.display()))?;
        tokio::fs::write(&folded_file, serde_json::to_vec(&slice.folded)?)
            .await
            .map_err(|error| stow_error!("write folded {}: {error}", folded_file.display()))?;
        // The `.prev` sidecar is the report's delta base — the index
        // this pass extended, captured while the tag still named it.
        if let Some(prev) = &slice.prev {
            let prev_bytes =
                encode(prev).map_err(|error| stow_error!("encode previous index: {error}"))?;
            tokio::fs::write(prev_path(&index_file), &prev_bytes)
                .await
                .map_err(|error| stow_error!("write previous-index sidecar: {error}"))?;
        }
        let summary = IndexExportSummary {
            target: slice.target.as_str().to_owned(),
            rustc_version: slice.rustc_version.as_str().to_owned(),
            tag: index_name.clone(),
            folded_tag: folded_name.clone(),
            index_file: index_name,
            folded_file: folded_name,
            rows: slice.index.header.row_count,
            bytes: bytes.len(),
            sha256: sha256_digest(&bytes),
            content_sha256: content_sha256(&slice.index)
                .map_err(|error| stow_error!("digest index content: {error}"))?,
        };
        let line = serde_json::to_string(&summary)
            .map_err(|error| stow_error!("serialize index summary: {error}"))?;
        render::emit_line(&line);
        summaries.push(summary);
    }
    tokio::fs::write(
        args.out_dir.join("slices.json"),
        serde_json::to_vec(&summaries)?,
    )
    .await
    .map_err(|error| stow_error!("write slices.json: {error}"))?;
    tokio::fs::write(
        args.out_dir.join("new-records.json"),
        serde_json::to_vec(&pass.new_records)?,
    )
    .await
    .map_err(|error| stow_error!("write new-records.json: {error}"))?;
    Ok(())
}

/// The sidecar `index export` leaves beside each emitted slice file:
/// the encoded index the slice's tag resolved to before this export
/// ran — `index report`'s delta base.
fn prev_path(out: &std::path::Path) -> std::path::PathBuf {
    let mut prev = out.as_os_str().to_os_string();
    prev.push(".prev");
    std::path::PathBuf::from(prev)
}

/// Read the `.prev` sidecar beside `file` — the report's delta base.
/// `None` means the slice's first publish (`generation == 1`), the only
/// state with no sidecar to extend: it sends the explicit full report.
/// A missing sidecar at any later generation is broken export wiring —
/// an error naming the file and the generation, never a silent full
/// report that turns a bug into an O(slice) resync; every other IO
/// error propagates.
async fn read_prev_sidecar(
    file: &std::path::Path,
    generation: i64,
) -> stow_types::error::Result<Option<ArtifactIndex>> {
    let sidecar = prev_path(file);
    let bytes = match tokio::fs::read(&sidecar).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if generation == 1 {
                return Ok(None);
            }
            return Err(stow_error!(
                "missing previous-index sidecar {} for generation {}",
                sidecar.display(),
                generation,
            ));
        }
        Err(error) => {
            return Err(stow_error!(
                "read previous index {}: {error}",
                sidecar.display()
            ));
        }
    };
    ArtifactIndex::decode(&bytes)
        .map(Some)
        .map_err(|error| stow_error!("decode previous index {}: {error}", sidecar.display()))
}

/// The index file's semantic rows as [`PublishedSliceRow`]s — the
/// scheduler's slice membership. Artifact rows collapse onto semantic
/// identity + unit shape — several `c_metadata`/`compile_key` rows can name
/// one `(crate, version, features, shape)` — so the report
/// deduplicates. Two rows of the same identity at different unit shapes
/// stay separate: the gate compares each shape an edge requires against
/// its own row. A measured row above the sysroot's glibc floor
/// publishes in the index but a baseline host cannot load it, so it
/// releases no dependent — the same rule the catalog's coverage oracle
/// applies (stow#336).
fn semantic_rows(index: &ArtifactIndex) -> stow_types::error::Result<Vec<PublishedSliceRow>> {
    let mut seen = std::collections::BTreeSet::new();
    index
        .rows
        .iter()
        .filter(|row| {
            row.min_glibc
                .is_none_or(|floor| floor <= stow_types::glibc::GLIBC_BASELINE)
        })
        .map(|row| {
            Ok(PublishedSliceRow {
                crate_name: row.crate_name.clone(),
                version: row.version.clone(),
                features_json: row.features_json.clone(),
                unit_shape: row.unit_shape,
                dependency_identity: row.dependency_identity()?,
            })
        })
        .filter(|row| {
            let Ok(row) = row else { return true };
            seen.insert((
                row.crate_name.as_str().to_owned(),
                row.version.to_string(),
                row.features_json.raw(),
                row.dependency_identity.clone(),
                row.unit_shape,
            ))
        })
        .collect()
}

/// The identity a publish delta diffs on — the slice's semantic row
/// key, matching `published_slice_rows`' primary key.
fn row_key(
    row: &PublishedSliceRow,
) -> (
    String,
    String,
    String,
    stow_types::identity::DependencyIdentity,
    stow_types::public_cache::UnitShape,
) {
    (
        row.crate_name.as_str().to_owned(),
        row.version.to_string(),
        row.features_json.raw(),
        row.dependency_identity.clone(),
        row.unit_shape,
    )
}

/// `stow-admin index publish` — the second half of the index pipeline.
/// The file's own header is authoritative for the slice key, and the
/// `--folded` companion is pushed under `folded.<target>.<rustc>` in the
/// same step so the pair can never skew: the next export's folded set is
/// always the one this slice was built from.
async fn index_publish(args: IndexPublishArgs) -> stow_types::error::Result<()> {
    let bytes = tokio::fs::read(&args.file)
        .await
        .map_err(|error| stow_error!("read index file {}: {error}", args.file.display()))?;
    let index = ArtifactIndex::decode(&bytes)
        .map_err(|error| stow_error!("decode index file {}: {error}", args.file.display()))?;
    let folded_bytes = tokio::fs::read(&args.folded)
        .await
        .map_err(|error| stow_error!("read folded file {}: {error}", args.folded.display()))?;
    let folded: Vec<String> = serde_json::from_slice(&folded_bytes)
        .map_err(|error| stow_error!("decode folded file {}: {error}", args.folded.display()))?;
    let target = index.header.target.as_str().to_owned();
    let rustc_version = index.header.rustc_version.as_str().to_owned();
    let sha256 =
        content_sha256(&index).map_err(|error| stow_error!("digest index content: {error}"))?;
    let tag = index_tag(&target, &rustc_version);
    let ftag = folded_tag(&target, &rustc_version);

    let (manifest_digest, outcome) =
        if let Ok(private_key_path) = std::env::var(STOW_MOCK_PRIVATE_KEY_PATH_ENV) {
            publish_index_mock(&args.file, &args.folded, &private_key_path).await?
        } else {
            let credentials = stow_oci::RegistryCredentials::from_env()?;
            let http = stow_oci::RegistryHttp::new().await?;
            let outcome = stow_oci::publish_index(
                &credentials,
                &http,
                &bytes,
                &target,
                &index.header.rustc_version,
                &sha256,
            )
            .await?;
            // The folded set publishes under the same identity in the
            // same step — the export that follows only ever sees pairs
            // this command pushed.
            stow_oci::publish_folded(
                &credentials,
                &http,
                &serde_json::to_vec(&folded)?,
                &target,
                &index.header.rustc_version,
            )
            .await?;
            match outcome {
                stow_oci::IndexPublishOutcome::Published { manifest_digest } => {
                    (manifest_digest, "published")
                }
                stow_oci::IndexPublishOutcome::Unchanged { manifest_digest } => {
                    (manifest_digest, "unchanged")
                }
                stow_oci::IndexPublishOutcome::Resigned { manifest_digest } => {
                    (manifest_digest, "resigned")
                }
            }
        };
    tracing::info!(%tag, %ftag, %manifest_digest, outcome, "published artifact index slice");
    let line = serde_json::to_string(&IndexPublishSummary {
        tag,
        folded_tag: ftag,
        manifest_digest,
        outcome,
    })
    .map_err(|error| stow_error!("serialize index publish summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// `stow-admin index report` — post every slice the run published to
/// the edge admin route in ONE report per publish run (stow#940), so
/// the scheduler applies them in one append and one dispatch pass.
/// Each slice's set is the servable subset of its export: a row whose
/// measured glibc floor exceeds the builder baseline publishes in the
/// index but a baseline host cannot load it, so it releases no
/// dependent — the same rule the catalog's coverage oracle applies.
async fn index_report(edge: &Edge, args: IndexReportArgs) -> stow_types::error::Result<()> {
    let mut report = stow_types::api::PublishedRunReport {
        slices: Vec::with_capacity(args.file.len()),
    };
    for file in &args.file {
        report.slices.push(slice_report_for(file, args.full).await?);
    }
    let path = "/api/v1/admin/index/published";
    let url = format!("{}{path}", edge.base());
    match edge.post_unchecked(path, &report).await? {
        Ok(response) => {
            response
                .into_json::<serde_json::Value>()
                .await
                .map_err(|error| stow_error!("decode {url}: {error}"))?;
        }
        // A refused delta resyncs once with every slice sent as the
        // explicit full shape — the resync a per-slice 409 asked for;
        // a refused full report is an error.
        Err(zenwave::Error::Http {
            status, message, ..
        }) if status == zenwave::StatusCode::CONFLICT
            && report
                .slices
                .iter()
                .any(|slice| slice.base_generation.is_some()) =>
        {
            tracing::warn!(
                answer = %message,
                "slice report refused — resyncing with a full report"
            );
            report.slices.clear();
            for file in &args.file {
                report.slices.push(slice_report_for(file, true).await?);
            }
            edge.post_json::<_, serde_json::Value>(path, &report)
                .await
                .map_err(|error| error.wrap_err("full slice report"))?;
        }
        Err(error) => return Err(stow_error!("POST {url}: {error}")),
    }
    let summary = IndexReportSummary {
        slices: report.slices.len(),
        added: report.slices.iter().map(|slice| slice.added.len()).sum(),
        retired: report.slices.iter().map(|slice| slice.retired.len()).sum(),
        full: report
            .slices
            .iter()
            .all(|slice| slice.base_generation.is_none()),
    };
    tracing::info!(
        slices = summary.slices,
        added = summary.added,
        retired = summary.retired,
        full = summary.full,
        "reported the publish run's slices to the edge"
    );
    let line = serde_json::to_string(&summary)
        .map_err(|error| stow_error!("serialize index report summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// One file's [`stow_types::api::PublishedSlice`]: the header's
/// `(target, rustc_version)` pair and, per `full`, the whole servable
/// membership or the delta against the `.prev` sidecar `index export`
/// captured while the tag still named the previous index.
async fn slice_report_for(
    file: &std::path::Path,
    full: bool,
) -> stow_types::error::Result<stow_types::api::PublishedSlice> {
    let bytes = tokio::fs::read(file)
        .await
        .map_err(|error| stow_error!("read index file {}: {error}", file.display()))?;
    let index = ArtifactIndex::decode(&bytes)
        .map_err(|error| stow_error!("decode index file {}: {error}", file.display()))?;
    let rows = semantic_rows(&index)?;

    // The delta base is the `.prev` sidecar — resolved exactly, never
    // silently: `full` or a first publish takes the explicit full path.
    let (base_generation, added, retired) = if full {
        (None, rows.clone(), Vec::new())
    } else if let Some(prev) = read_prev_sidecar(file, index.header.generation).await? {
        let prev_rows = semantic_rows(&prev)?;
        let current: std::collections::BTreeSet<_> = rows.iter().map(row_key).collect();
        let previous: std::collections::BTreeSet<_> = prev_rows.iter().map(row_key).collect();
        let added: Vec<PublishedSliceRow> = rows
            .iter()
            .filter(|row| !previous.contains(&row_key(row)))
            .cloned()
            .collect();
        let retired: Vec<PublishedSliceRow> = prev_rows
            .into_iter()
            .filter(|row| !current.contains(&row_key(row)))
            .collect();
        (Some(prev.header.generation), added, retired)
    } else {
        (None, rows.clone(), Vec::new())
    };
    Ok(stow_types::api::PublishedSlice {
        target: index.header.target,
        rustc_version: index.header.rustc_version,
        base_generation,
        generation: Some(index.header.generation),
        added,
        retired,
    })
}

/// The registry base the anonymous bundle pulls go through —
/// `STOW_REGISTRY_BASE_URL` when set (the mock/local loop), else
/// production GHCR.
pub fn registry_base() -> stow_types::error::Result<stow_oci::RegistryBase> {
    std::env::var("STOW_REGISTRY_BASE_URL").map_or_else(
        |_| stow_oci::RegistryBase::production(),
        |url| stow_oci::RegistryBase::parse(&url),
    )
}

/// The stdout line `stow-mock-registry publish-index` reports.
#[derive(Debug, serde::Deserialize)]
struct MockIndexPublishReport {
    manifest_digest: String,
    outcome: String,
}

/// Mock-key mode: delegate the registry write and the mock signature to
/// the sibling `stow-mock-registry` binary, the same way `stow-build
/// serve` delegates bundle publication to `stow-mock-registry populate`.
/// The child reports the manifest digest and outcome on its last stdout
/// line.
async fn publish_index_mock(
    file: &std::path::Path,
    folded: &std::path::Path,
    private_key_path: &str,
) -> stow_types::error::Result<(String, &'static str)> {
    let registry_root = std::env::var(STOW_MOCK_REGISTRY_ROOT_ENV)
        .map_err(|_| stow_error!("missing {STOW_MOCK_REGISTRY_ROOT_ENV}"))?;
    let exe = std::env::current_exe()?;
    let mock_registry_exe = exe
        .parent()
        .ok_or_else(|| stow_error!("cannot determine parent directory of stow-admin binary"))?
        .join(format!(
            "stow-mock-registry{}",
            std::env::consts::EXE_SUFFIX
        ));
    if !mock_registry_exe.exists() {
        return Err(stow_error!(
            "mock registry binary not found at {}",
            mock_registry_exe.display()
        ));
    }
    let output = tokio::process::Command::new(&mock_registry_exe)
        .arg("publish-index")
        .arg("--file")
        .arg(file)
        .arg("--folded")
        .arg(folded)
        .arg("--registry-root")
        .arg(registry_root)
        .arg("--private-key")
        .arg(private_key_path)
        .output()
        .await?;
    if !output.status.success() {
        return Err(stow_error!(
            "mock registry publish-index failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| stow_error!("mock publish-index stdout is not UTF-8: {error}"))?;
    let report: MockIndexPublishReport = serde_json::from_str(
        stdout
            .lines()
            .last()
            .ok_or_else(|| stow_error!("mock publish-index printed no report"))?,
    )
    .map_err(|error| stow_error!("parse mock publish-index report: {error}"))?;
    let outcome = match report.outcome.as_str() {
        "published" => "published",
        "unchanged" => "unchanged",
        other => {
            return Err(stow_error!(
                "mock publish-index reported unknown outcome {other:?}"
            ));
        }
    };
    Ok((report.manifest_digest, outcome))
}

/// `CF_ACCOUNT_ID` — the account the digest leaderboard's Analytics
/// Engine SQL reads.
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";

/// The edge's 30-day digest leaderboard query, shared so the join
/// resolves exactly the rows `/stats` and `/api/v1/stats` publish.
const TOP_DIGESTS_SQL: &str = include_str!("../../edge/src/sql/stats_top_digests.sql");

/// One row of [`TOP_DIGESTS_SQL`] — `(digest, scaled hits)`; the sum
/// is `Float64` on the wire.
#[derive(Debug, serde::Deserialize)]
pub struct DigestLeaderboardRow {
    /// The served bundle digest, `sha256:…`.
    pub name: String,
    /// The edge-observed hit count — an undercount of real usage, the
    /// same caveat the leaderboard itself carries.
    #[serde(deserialize_with = "stow_types::analytics::de_f64")]
    pub hits: f64,
}

/// The crate identity a verified index slice gives one bundle digest —
/// crate, version, target and rustc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedIdentity {
    /// Crate name as published on crates.io.
    pub crate_name: String,
    /// Exact crate version.
    pub version: String,
    /// The slice's compilation target.
    pub target: String,
    /// The slice's rustc version.
    pub rustc_version: String,
}

/// One leaderboard row after the join — `None` when no verified slice
/// carries the digest (a bundle published before the current slices,
/// or one whose slice was re-exported under a different format).
#[derive(Debug, Clone, PartialEq)]
pub struct JoinedEntry {
    /// The edge-observed hit count.
    pub hits: f64,
    /// The digest's identity from a verified slice.
    pub identity: Option<JoinedIdentity>,
}

/// Resolve each leaderboard digest against the rows of verified
/// slices. One digest names one bundle across every slice, so the
/// first match wins — the same digest never maps to two identities.
pub fn join_leaderboard(
    digests: Vec<DigestLeaderboardRow>,
    slices: &[ArtifactIndex],
) -> Vec<JoinedEntry> {
    let lookup: HashMap<&str, (&ArtifactIndexHeader, &ArtifactIndexRow)> = slices
        .iter()
        .flat_map(|index| {
            index
                .rows
                .iter()
                .map(|row| (row.bundle_digest.as_str(), (&index.header, row)))
        })
        .collect();
    digests
        .into_iter()
        .map(|row| JoinedEntry {
            hits: row.hits,
            identity: lookup
                .get(row.name.as_str())
                .map(|(header, row)| JoinedIdentity {
                    crate_name: row.crate_name.to_string(),
                    version: row.version.to_string(),
                    target: header.target.to_string(),
                    rustc_version: header.rustc_version.to_string(),
                }),
        })
        .collect()
}

/// `index join` — pull the public digest leaderboard from Analytics
/// Engine, pull and verify the signed index slices for each named
/// rustc, and print the resolved leaderboard. The edge publishes the
/// digest under an undercount caveat; the identity here is the same
/// one the CLI resolved when it fetched the bundle.
async fn index_join(args: IndexJoinArgs) -> stow_types::error::Result<()> {
    let token = cloudflare::api_token()?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let sql_base = cloudflare::analytics_sql_base()?;
    let digests = cloudflare::analytics_engine_sql::<DigestLeaderboardRow>(
        &sql_base,
        &token,
        &account,
        TOP_DIGESTS_SQL,
    )
    .await
    .map_err(|error| stow_error!("analytics engine: {error}"))?;

    let base = registry_base()?;
    let http = stow_oci::RegistryHttp::new().await?;
    let trust = records_trust().await?;
    let mut slices = Vec::new();
    for version in &args.rustc_versions {
        let rustc_version = WireRustcVersion::parse(version.clone())
            .map_err(|error| stow_error!("--rustc-version: {error}"))?;
        let repository = cache_repository(&rustc_version);
        let session = base.session(&repository, &http);
        let mut tags = session
            .list_tags()
            .await
            .map_err(|error| stow_error!("list registry tags: {error}"))?;
        tags.sort();
        let pulls = tags.into_iter().filter_map(|tag| {
            let target = index_tag_parts(&tag)?.0.to_owned();
            Some((tag, target))
        });
        let pulls: Vec<_> = pulls
            .map(|(tag, target)| {
                let session = &session;
                let repository = &repository;
                let trust = &trust;
                let rustc_version = &rustc_version;
                async move {
                    let Some(pulled) =
                        stow_oci::pull_index(session, &target, rustc_version.as_str()).await?
                    else {
                        return Err(stow_error!(
                            "index tag {tag} listed but its manifest does not exist"
                        ));
                    };
                    let reference = session.reference(&tag)?;
                    verify_artifact(
                        session,
                        trust,
                        &reference,
                        &repository.reference(&tag),
                        &pulled.manifest_digest,
                        INDEX_CERT_URL,
                    )
                    .await?;
                    decode_published_slice(&reference, rustc_version, &pulled.bytes)
                }
            })
            .collect();
        slices.extend(futures_util::future::try_join_all(pulls).await?);
    }

    for entry in join_leaderboard(digests, &slices) {
        let identity = entry.identity.map_or_else(
            || "unresolved".to_owned(),
            |identity| {
                format!(
                    "{}@{} {} {}",
                    identity.crate_name, identity.version, identity.target, identity.rustc_version
                )
            },
        );
        render::emit_line(&format!("{identity}\t{:.0}", entry.hits));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    use semver::Version;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};
    use stow_types::records::{BuildRun, records_tag};

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.88.0";
    /// The canonical `ghcr.io/water-rs/stow-cache-<RUSTC>` signed
    /// references bind.
    const REFERENCE_BASE: &str = "ghcr.io/water-rs/stow-cache-1.88.0";
    /// A second rustc's tags the pass must never pull.
    const OTHER_RUSTC: &str = "1.99.0";

    /// The run identity an ordinary build's records tag carries.
    const BUILD: BuildRun = BuildRun {
        run_id: 1,
        run_attempt: 1,
    };

    fn build(run_id: u64) -> BuildRun {
        BuildRun {
            run_id,
            run_attempt: 1,
        }
    }

    fn record(task_id: &str) -> ArtifactRecord {
        let c_metadata = CMetadata::parse(task_id).expect("c_metadata");
        ArtifactRecord {
            dependency_task_ids: Vec::new(),
            compile_key: format!("key-{task_id}"),
            c_metadata,
            extra_filename: String::new(),
            target: TargetTriple::parse(TARGET).expect("target"),
            rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
            profile: Profile {
                opt_level: "3".to_owned(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse("serde").expect("crate name"),
            version: CrateVersion::new(Version::new(1, 0, 0)),
            features_json: FeaturesJson::canonicalize(vec![]).expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            oci_reference: format!("{REFERENCE_BASE}:{}", records_tag(RUSTC, task_id, BUILD)),
            oci_digest: "sha256:deadbeef".to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 10,
            bundle_digest: format!("sha256:{task_id:0>64}"),
            bundle_size: 100,
            compile_millis: 5,
            unit_shape: UnitShape {
                side: stow_types::public_cache::UnitSide::Target,
                invocation: stow_types::public_cache::UnitInvocation::Native,
                kind: stow_types::public_cache::UnitKind::Linked,
            },
            min_glibc: None,
        }
    }

    /// The published slice an incremental pass extends.
    fn prev_index(rows: Vec<ArtifactIndexRow>, generation: i64) -> ArtifactIndex {
        ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse(TARGET).expect("target"),
                rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
                generated_at: "2026-01-01T00:00:00Z".to_owned(),
                generation,
                row_count: u64::try_from(rows.len()).expect("row count"),
            },
            rows,
        }
    }

    /// The O(change) gate: a second export over N folded records plus k
    /// new ones pulls exactly k records artifacts — the folded set, not
    /// the store, is what a pass re-reads. And a second rustc's tags —
    /// its records, and its own folded/index pair — are never pulled by
    /// R's pass at all.
    #[test]
    fn second_export_pulls_only_new_records() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let folded_tag_name = folded_tag(TARGET, RUSTC);
        let prior = [record("aaaa1111"), record("bbbb2222")];
        let new = [record("cccc3333"), record("dddd4444")];
        let prev_rows: Vec<ArtifactIndexRow> = prior.iter().map(record_to_index_row).collect();
        let pulled = Mutex::new(Vec::<String>::new());
        // The tag's digest is one-way — the registry answers records by
        // task id (its manifest annotation), which the test models with
        // a tag→task-id lookup.
        let ids_by_tag: BTreeMap<String, String> = [RUSTC, OTHER_RUSTC]
            .iter()
            .flat_map(|rustc| {
                ["aaaa1111", "bbbb2222", "cccc3333", "dddd4444", "eeee5555"]
                    .iter()
                    .map(move |id| (records_tag(rustc, id, BUILD), (*id).to_owned()))
            })
            .collect();
        let pull_records = |tag: &str| {
            let tag = tag.to_owned();
            pulled.lock().unwrap().push(tag.clone());
            let task_id = ids_by_tag.get(&tag).expect("known tag").clone();
            Box::pin(async move { Ok(vec![record(&task_id)]) })
                as PullFut<'static, Vec<ArtifactRecord>>
        };
        let prev = PrevSlice {
            index: prev_index(prev_rows, 7),
            folded: prior
                .iter()
                .map(|r| records_tag(RUSTC, r.c_metadata.as_str(), BUILD))
                .collect(),
        };
        let folded_prev: Vec<String> = prev.folded.iter().cloned().collect();
        let prev_pulled = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let pull_prev = {
            let folded_tag_name = folded_tag_name.clone();
            let prev_pulled = prev_pulled.clone();
            move |tag: &str| {
                prev_pulled.lock().unwrap().push(tag.to_owned());
                let got = if tag == folded_tag_name {
                    Some((
                        (
                            TargetTriple::parse(TARGET).expect("t"),
                            WireRustcVersion::parse(RUSTC).expect("r"),
                        ),
                        PrevSlice {
                            index: prev.index.clone(),
                            folded: prev.folded.clone(),
                        },
                    ))
                } else {
                    None
                };
                Box::pin(async move { Ok(got) })
                    as PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>
            }
        };
        // Registry tag space: R's folded pair, its two already-folded
        // records, and two new ones — plus a second rustc's records and
        // folded/index pair, and an orphan index under a third rustc
        // (untracked state only the owning rustc's pass may flag).
        let tags: Vec<String> = [
            folded_tag_name.clone(),
            index_tag(TARGET, OTHER_RUSTC),
            folded_tag(TARGET, OTHER_RUSTC),
            records_tag(OTHER_RUSTC, "eeee5555", BUILD),
            index_tag(TARGET, "1.98.0"),
        ]
        .into_iter()
        .chain(folded_prev)
        .chain(
            new.iter()
                .map(|r| records_tag(RUSTC, r.c_metadata.as_str(), BUILD)),
        )
        .collect();
        let pass = block_on(export_pass(&tags, pull_prev, pull_records, false, &rustc))
            .expect("export pass");
        let mut pulled = pulled.into_inner().unwrap();
        pulled.sort();
        assert_eq!(
            pulled,
            vec![
                records_tag(RUSTC, "cccc3333", BUILD),
                records_tag(RUSTC, "dddd4444", BUILD)
            ],
        );
        assert_eq!(
            prev_pulled.lock().unwrap().clone(),
            vec![folded_tag_name],
            "only R's folded pair is pulled"
        );
        assert_eq!(pass.pulled, 2);
        let slice = pass
            .slices
            .iter()
            .find(|s| s.target.as_str() == TARGET)
            .expect("slice emitted");
        assert_eq!(slice.index.rows.len(), 4);
        assert_eq!(slice.folded.len(), 4);
        assert_eq!(pass.new_records.len(), 2);
        // The stamp extends the published slice's sequence, and the
        // report's delta base rides along.
        assert_eq!(slice.index.header.generation, 8);
        assert_eq!(slice.prev.as_ref().expect("prev index").rows.len(), 2);
    }

    /// Every supported target must have a signed slice for the pass's
    /// rustc — a `--target` consumer fetches it even when no record
    /// routed rows to it (stow#455). The first pass emits the empty
    /// generation-1 slices; a second pass, whose folded pairs all exist,
    /// finds nothing new and emits none.
    #[test]
    fn unsliced_ci_targets_emit_empty_first_publish() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        // The tag's digest is one-way — model the registry's
        // tag→task-id lookup the same way the gate test does.
        let ids_by_tag = std::sync::Arc::new(BTreeMap::from([(
            records_tag(RUSTC, "aaaa1111", BUILD),
            "aaaa1111".to_owned(),
        )]));
        let pull_records = {
            let ids_by_tag = ids_by_tag.clone();
            move |tag: &str| {
                let task_id = ids_by_tag.get(&tag.to_owned()).expect("known tag").clone();
                Box::pin(async move { Ok(vec![record(&task_id)]) })
                    as PullFut<'static, Vec<ArtifactRecord>>
            }
        };
        let no_prev = |_tag: &str| {
            Box::pin(async move {
                Ok(None)
                    as stow_types::error::Result<
                        Option<((TargetTriple, WireRustcVersion), PrevSlice)>,
                    >
            })
                as PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>
        };
        // One records artifact for TARGET only; no folded/index pairs
        // exist at all — the first publish of a fresh registry.
        let tags = vec![records_tag(RUSTC, "aaaa1111", BUILD)];
        let pass = block_on(export_pass(&tags, no_prev, pull_records, false, &rustc))
            .expect("export pass");
        let mut emitted: Vec<&str> = pass.slices.iter().map(|s| s.target.as_str()).collect();
        emitted.sort_unstable();
        let mut want = CI_TARGET_TRIPLES.to_vec();
        want.sort_unstable();
        assert_eq!(emitted, want, "every CI target emits a slice");
        for slice in &pass.slices {
            assert_eq!(slice.index.header.generation, 1);
            assert!(slice.prev.is_none());
            if slice.target.as_str() == TARGET {
                assert_eq!(slice.index.rows.len(), 1);
                assert_eq!(slice.folded.len(), 1);
            } else {
                assert_eq!(slice.index.rows.len(), 0);
                assert_eq!(slice.folded, [] as [std::string::String; 0]);
            }
        }

        // A second pass over the same records — now with every slice's
        // folded pair published — pulls nothing and emits nothing.
        let pull_prev = |tag: &str| {
            let target = tag
                .strip_prefix("folded.")
                .and_then(|rest| rest.split('.').next())
                .expect("folded tag")
                .to_owned();
            Box::pin(async move {
                Ok(Some((
                    (
                        TargetTriple::parse(target).expect("target"),
                        WireRustcVersion::parse(RUSTC).expect("rustc"),
                    ),
                    PrevSlice {
                        index: prev_index(vec![], 1),
                        folded: [records_tag(RUSTC, "aaaa1111", BUILD)].into(),
                    },
                )))
            })
                as PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>
        };
        let tags: Vec<String> = CI_TARGET_TRIPLES
            .iter()
            .map(|target| folded_tag(target, RUSTC))
            .chain(std::iter::once(records_tag(RUSTC, "aaaa1111", BUILD)))
            .collect();
        let pull_records = move |tag: &str| {
            let task_id = ids_by_tag.get(&tag.to_owned()).expect("known tag").clone();
            Box::pin(async move { Ok(vec![record(&task_id)]) })
                as PullFut<'static, Vec<ArtifactRecord>>
        };
        let pass = block_on(export_pass(&tags, pull_prev, pull_records, false, &rustc))
            .expect("export pass");
        assert!(pass.slices.is_empty(), "nothing new emits nothing");
        assert_eq!(pass.pulled, 0);
    }

    /// The future a `pull_prev` half returns.
    type PrevPull = PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>;

    /// A `pull_prev` half for a pass with no published slices at all.
    fn no_prev(_tag: &str) -> PrevPull {
        Box::pin(async { Ok(None) })
    }

    /// A rebuilt task publishes under its own tag — a build-2 artifact
    /// no folded set names — so the pass pulls exactly it, and its rows
    /// replace build 1's at the same row key.
    /// Before stow#655 the rebuild overwrote build 1's tag and no pass
    /// ever pulled it.
    #[test]
    fn a_rebuilt_tasks_new_build_tag_is_pulled_and_replaces_the_old_row() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let folded_tag_name = folded_tag(TARGET, RUSTC);
        // Build 1's record, already folded; build 2 rebuilt the same
        // unit — same c_metadata, a different bundle behind it.
        let mut first = record("aaaa1111");
        first.bundle_size = 1;
        let mut second = record("aaaa1111");
        second.bundle_size = 2;
        let prev = PrevSlice {
            index: prev_index(vec![record_to_index_row(&first)], 7),
            folded: [records_tag(RUSTC, "aaaa1111", build(1))].into(),
        };
        let pull_prev = {
            let folded_tag_name = folded_tag_name.clone();
            move |tag: &str| {
                let got = if tag == folded_tag_name {
                    Some((
                        (
                            TargetTriple::parse(TARGET).expect("t"),
                            WireRustcVersion::parse(RUSTC).expect("r"),
                        ),
                        PrevSlice {
                            index: prev.index.clone(),
                            folded: prev.folded.clone(),
                        },
                    ))
                } else {
                    None
                };
                Box::pin(async move { Ok(got) })
                    as PullFut<'static, Option<((TargetTriple, WireRustcVersion), PrevSlice)>>
            }
        };
        let pulled = Mutex::new(Vec::<String>::new());
        let pull_records = |tag: &str| {
            pulled.lock().unwrap().push(tag.to_owned());
            let second = second.clone();
            Box::pin(async move { Ok(vec![second]) }) as PullFut<'static, Vec<ArtifactRecord>>
        };
        let build2_tag = records_tag(RUSTC, "aaaa1111", build(2));
        let tags: Vec<String> = vec![
            folded_tag_name,
            records_tag(RUSTC, "aaaa1111", build(1)),
            build2_tag.clone(),
        ];
        let pass = block_on(export_pass(&tags, pull_prev, pull_records, false, &rustc))
            .expect("export pass");
        assert_eq!(pass.pulled, 1);
        assert_eq!(pulled.into_inner().unwrap(), vec![build2_tag]);
        let slice = pass
            .slices
            .iter()
            .find(|s| s.target.as_str() == TARGET)
            .expect("slice emitted");
        let row = slice
            .index
            .rows
            .iter()
            .find(|row| row.c_metadata.as_str() == "aaaa1111")
            .expect("row");
        assert_eq!(row.bundle_size, 2, "build 2's row replaced build 1's");
        assert_eq!(slice.folded.len(), 2, "both builds' tags are folded");
    }

    /// Two builds of one task pulled in the same pass fold in build
    /// order regardless of listing order — `…-9-1` precedes `…-10-1`
    /// numerically, never by tag string — so the newest build's row
    /// wins the row-key dedup.
    #[test]
    fn later_builds_fold_last_for_one_task() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let pull_records = |tag: &str| {
            let tag = tag.to_owned();
            Box::pin(async move {
                let build = parse_records_tag(&tag).expect("records tag").build;
                let mut record = record("aaaa1111");
                record.bundle_size = build.map_or(0, |build| build.run_id);
                Ok(vec![record])
            }) as PullFut<'static, Vec<ArtifactRecord>>
        };
        // The listing hands the pass run 10's tag before run 9's.
        let tags = vec![
            records_tag(RUSTC, "aaaa1111", build(10)),
            records_tag(RUSTC, "aaaa1111", build(9)),
        ];
        let pass = block_on(export_pass(&tags, no_prev, pull_records, false, &rustc))
            .expect("export pass");
        assert_eq!(pass.pulled, 2);
        let slice = pass
            .slices
            .iter()
            .find(|s| s.target.as_str() == TARGET)
            .expect("slice emitted");
        let rows: Vec<_> = slice
            .index
            .rows
            .iter()
            .filter(|row| row.c_metadata.as_str() == "aaaa1111")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bundle_size, 10, "run 10's row folded last");
    }

    /// A tag with no build suffix — what every build published before
    /// stow#655 — is still a records artifact: a pass that no folded set
    /// excuses from it pulls it, and it folds before every named build
    /// of its task, so the named build's row is the one that survives.
    #[test]
    fn a_tag_without_a_build_folds_before_its_tasks_named_builds() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let named = records_tag(RUSTC, "aaaa1111", build(3));
        let unnamed = named
            .strip_suffix("-3-1")
            .expect("the named tag ends in its build")
            .to_owned();
        let pull_records = |tag: &str| {
            let tag = tag.to_owned();
            Box::pin(async move {
                let build = parse_records_tag(&tag).expect("records tag").build;
                let mut record = record("aaaa1111");
                record.bundle_size = build.map_or(0, |build| build.run_id);
                Ok(vec![record])
            }) as PullFut<'static, Vec<ArtifactRecord>>
        };
        for full in [false, true] {
            let pass = block_on(export_pass(
                &[named.clone(), unnamed.clone()],
                no_prev,
                pull_records,
                full,
                &rustc,
            ))
            .expect("export pass");
            assert_eq!(pass.pulled, 2);
            let slice = pass
                .slices
                .iter()
                .find(|slice| slice.target.as_str() == TARGET)
                .expect("slice emitted");
            let rows: Vec<_> = slice
                .index
                .rows
                .iter()
                .filter(|row| row.c_metadata.as_str() == "aaaa1111")
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].bundle_size, 3, "the named build folded last");
        }
    }

    /// The `pull_prev` injection's answer — the slice key and its
    /// published pair, or `None` when the folded tag is not the pass's.
    type PrevPullOut = Option<((TargetTriple, WireRustcVersion), PrevSlice)>;

    /// A records pull answering `tag` with `by_tag`'s entry — each
    /// `records-*` tag the test's registry listing names maps to the
    /// records artifact it stands for.
    fn pull_records_by_tag(
        by_tag: BTreeMap<String, Vec<ArtifactRecord>>,
    ) -> impl Fn(&str) -> PullFut<'static, Vec<ArtifactRecord>> + Send + Sync {
        move |tag: &str| {
            let records = by_tag
                .get(tag)
                .unwrap_or_else(|| panic!("unknown records tag {tag}"))
                .clone();
            Box::pin(async move { Ok(records) }) as PullFut<'static, Vec<ArtifactRecord>>
        }
    }

    /// A prev pull answering `folded.<TARGET>.<RUSTC>` with `prev` and
    /// every other folded tag with `None`.
    fn pull_only_prev(
        index: ArtifactIndex,
        folded: BTreeSet<String>,
    ) -> impl Fn(&str) -> PullFut<'static, PrevPullOut> + Send + Sync {
        let folded_name = folded_tag(TARGET, RUSTC);
        move |tag: &str| {
            let got = (tag == folded_name).then(|| {
                (
                    (
                        TargetTriple::parse(TARGET).expect("target"),
                        WireRustcVersion::parse(RUSTC).expect("rustc"),
                    ),
                    PrevSlice {
                        index: index.clone(),
                        folded: folded.clone(),
                    },
                )
            });
            Box::pin(async move { Ok(got) }) as PullFut<'static, PrevPullOut>
        }
    }

    /// No published pairs — a first-publish registry.
    fn pull_no_prev() -> impl Fn(&str) -> PullFut<'static, PrevPullOut> + Send + Sync {
        |_tag| Box::pin(async move { Ok(None) }) as PullFut<'static, PrevPullOut>
    }

    /// A second publish of the `aaaa1111` unit — the same `c_metadata`
    /// and `unit_shape`, under `deps`' dependency context. stow#657: two
    /// nodes differing only in context compile to the same unit.
    fn shared_unit_record(deps: &[&str]) -> ArtifactRecord {
        let mut record = record("aaaa1111");
        record.dependency_task_ids = deps.iter().map(|dep| (*dep).to_owned()).collect();
        record
    }

    /// The slice `export_pass` emitted for `TARGET`.
    fn target_slice(pass: &ExportPass) -> &SliceExport {
        pass.slices
            .iter()
            .find(|slice| slice.target.as_str() == TARGET)
            .expect("TARGET slice")
    }

    /// stow#657: two nodes differing only in dependency context publish
    /// the same `(c_metadata, unit_shape)` unit — the fold keeps a row
    /// for each rather than letting the second node's record replace
    /// the first's, and the emitted order sorts them by their
    /// dependency identity.
    #[test]
    fn two_nodes_publishing_one_unit_keep_a_row_each() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let left = shared_unit_record(&["dep-left"]);
        let right = shared_unit_record(&["dep-right"]);
        let tags = [
            records_tag(RUSTC, "bbbb2222", BUILD),
            records_tag(RUSTC, "cccc3333", BUILD),
        ];
        let by_tag = BTreeMap::from([
            (tags[0].clone(), vec![left.clone()]),
            (tags[1].clone(), vec![right.clone()]),
        ]);
        let pass = block_on(export_pass(
            &tags,
            pull_no_prev(),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("export pass");
        let rows = &target_slice(&pass).index.rows;
        assert_eq!(rows.len(), 2);
        let identities: Vec<_> = rows
            .iter()
            .map(|row| row.dependency_identity().expect("row digest"))
            .collect();
        assert_eq!(
            identities.iter().collect::<BTreeSet<_>>(),
            [
                left.dependency_identity().expect("record digest"),
                right.dependency_identity().expect("record digest"),
            ]
            .iter()
            .collect::<BTreeSet<_>>(),
            "both nodes keep a row"
        );
        assert!(
            identities[0] < identities[1],
            "rows of one unit order by dependency identity"
        );
    }

    /// The same fold across the pass boundary: the first node's row is
    /// already in the published slice, the second node's record arrives
    /// in this pass — the slice gains a row beside the existing one and
    /// leaves it untouched.
    #[test]
    fn a_second_nodes_row_lands_beside_the_previous_slices() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let left = shared_unit_record(&["dep-left"]);
        let right = shared_unit_record(&["dep-right"]);
        let left_row = record_to_index_row(&left);
        let right_row = record_to_index_row(&right);
        let prev = prev_index(vec![left_row.clone()], 7);
        let tags = vec![
            folded_tag(TARGET, RUSTC),
            records_tag(RUSTC, "cccc3333", BUILD),
        ];
        let by_tag = BTreeMap::from([(tags[1].clone(), vec![right])]);
        let pass = block_on(export_pass(
            &tags,
            pull_only_prev(prev, [records_tag(RUSTC, "bbbb2222", BUILD)].into()),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("export pass");
        let slice = target_slice(&pass);
        assert_eq!(slice.index.header.generation, 8);
        let rows = &slice.index.rows;
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&left_row), "the earlier row is untouched");
        assert!(rows.contains(&right_row), "the second node's row landed");
    }

    /// The membership the export reports to the scheduler covers both
    /// nodes of a shared unit — the second node's row is semantic slice
    /// membership like the first's, not a duplicate.
    #[test]
    fn semantic_rows_reports_each_node_of_a_shared_unit() {
        let left = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let right = record_to_index_row(&shared_unit_record(&["dep-right"]));
        let index = prev_index(vec![left.clone(), right.clone()], 3);
        let rows = semantic_rows(&index).expect("semantic rows");
        assert_eq!(rows.len(), 2);
        let identities: BTreeSet<_> = rows
            .iter()
            .map(|row| row.dependency_identity.clone())
            .collect();
        assert!(identities.contains(&left.dependency_identity().expect("row digest")));
        assert!(identities.contains(&right.dependency_identity().expect("row digest")));
    }

    /// The publish delta already diffs on the dependency identity: a
    /// pass that adds a second node's row for a unit the slice already
    /// serves under another context reports exactly that row as added
    /// and retires nothing.
    #[test]
    fn a_second_nodes_row_reports_as_a_pure_addition() {
        let left = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let right = record_to_index_row(&shared_unit_record(&["dep-right"]));
        let right_identity = right.dependency_identity().expect("row digest");
        let previous = semantic_rows(&prev_index(vec![left.clone()], 7)).expect("semantic rows");
        let current = semantic_rows(&prev_index(vec![left, right], 8)).expect("semantic rows");
        assert_eq!(previous.len(), 1);
        assert_eq!(current.len(), 2);
        let current_keys: std::collections::BTreeSet<_> = current.iter().map(row_key).collect();
        let previous_keys: std::collections::BTreeSet<_> = previous.iter().map(row_key).collect();
        let added: Vec<_> = current
            .iter()
            .filter(|row| !previous_keys.contains(&row_key(row)))
            .collect();
        assert!(
            !previous
                .iter()
                .any(|row| !current_keys.contains(&row_key(row))),
            "nothing is retired"
        );
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].dependency_identity, right_identity);
    }

    /// A path whose `.prev` sidecar provably does not exist.
    fn no_sidecar_file() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "stow-index-report-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// The `.prev` rule is exact: generation 1 is the slice's first
    /// publish — the only state with no sidecar — so the report takes
    /// the explicit full path; a missing sidecar at any later
    /// generation is broken wiring and errors naming the file.
    #[test]
    fn a_first_publish_without_a_prev_sends_the_full_report() {
        let file = no_sidecar_file();
        let prev = block_on(read_prev_sidecar(&file, 1)).expect("first publish");
        assert!(prev.is_none());
    }

    #[test]
    fn a_missing_prev_after_the_first_publish_is_an_error() {
        let file = no_sidecar_file();
        let error = block_on(read_prev_sidecar(&file, 7)).expect_err("must fail");
        let message = error.to_string();
        assert!(
            message.contains(&prev_path(&file).display().to_string())
                && message.contains("generation 7"),
            "error names the file and generation: {message}"
        );
    }

    /// The signature binds the canonical `ghcr.io/<repository>:<tag>`,
    /// not whichever transport base the pull came through: a payload
    /// signed for GHCR verifies against the canonical reference and is
    /// rejected against the localhost mock's pull reference — the split
    /// `verify_artifact` makes.
    #[test]
    fn the_signature_binds_the_canonical_reference_not_the_transport() {
        let tag = records_tag(RUSTC, "aaaa1111", BUILD);
        let digest = "sha256:deadbeef";
        let payload = serde_json::to_vec(&serde_json::json!({
            "critical": {
                "type": "cosign container image signature",
                "image": { "docker-manifest-digest": digest },
                "identity": { "docker-reference": format!("{REFERENCE_BASE}:{tag}") },
            }
        }))
        .expect("payload");

        // What `verify_artifact` feeds `verify_material`.
        stow_oci::verify::verify_payload_identity(
            &payload,
            &format!("{REFERENCE_BASE}:{tag}"),
            digest,
        )
        .expect("canonical reference verifies");

        // The transport pull reference the signature materials fetch
        // through — the value verification compared before the fix.
        let transport = format!("127.0.0.1:28123/water-rs/stow-cache-1.88.0:{tag}");
        assert!(stow_oci::verify::verify_payload_identity(&payload, &transport, digest).is_err());
    }

    /// The file pair a delta report reads: the emitted slice at
    /// generation 3 and its `.prev` sidecar at generation 2. The
    /// `dep-right` row is the delta's only addition — the two rows
    /// share a unit and differ in dependency context (stow#657), so the
    /// semantic report keeps both.
    fn report_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("report fixture dir");
        let file = dir.path().join(index_tag(TARGET, RUSTC));
        let left = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let right = record_to_index_row(&shared_unit_record(&["dep-right"]));
        std::fs::write(
            &file,
            encode(&prev_index(vec![left.clone(), right], 3)).expect("encode index"),
        )
        .expect("write index file");
        std::fs::write(
            prev_path(&file),
            encode(&prev_index(vec![left], 2)).expect("encode prev"),
        )
        .expect("write prev sidecar");
        (dir, file)
    }

    /// The one slice inside the report body a captured request
    /// carried — the tests post single-file reports.
    fn posted_report(request: &crate::test_server::CapturedRequest) -> serde_json::Value {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("the report posts JSON");
        let slices = body["slices"].as_array().expect("a slices array");
        assert_eq!(slices.len(), 1, "a single-file report carries one slice");
        slices[0].clone()
    }

    /// stow#780: a delta report refused with the scheduler's 409 —
    /// the edge's live generation moved past `base_generation` —
    /// resyncs once as the full report for the same file: no
    /// `base_generation`, the slice's whole membership, and no
    /// `retired`.
    #[tokio::test]
    async fn a_conflicted_delta_resyncs_with_the_full_report() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 409,
                retry_after: None,
                body: r#"{"error":"slice report base generation 2 conflicts with the live generation 1"}"#,
            },
            crate::test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
            },
        ])
        .await;
        let (_dir, file) = report_fixture();
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![file],
                full: false,
            },
        )
        .await
        .expect("the resynced report succeeds");
        let requests = server.join().await;
        assert_eq!(requests.len(), 2, "the delta, then exactly one full report");
        let delta = posted_report(&requests[0]);
        assert_eq!(delta["base_generation"], 2);
        assert_eq!(
            delta["added"].as_array().expect("added rows").len(),
            1,
            "the delta carries only the moved row"
        );
        let full = posted_report(&requests[1]);
        assert!(full.get("base_generation").is_none());
        assert_eq!(full["generation"], 3);
        assert_eq!(full["added"].as_array().expect("added rows").len(), 2);
        assert!(
            full.get("retired").is_none(),
            "a full report carries no retired rows"
        );
    }

    /// A full report refused the same way stays an error — the resync
    /// itself failed, and no third request goes out.
    #[tokio::test]
    async fn a_conflicted_full_report_is_an_error() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 409,
                retry_after: None,
                body: r#"{"error":"slice report base generation 2 conflicts with the live generation 1"}"#,
            },
            crate::test_server::Step::Respond {
                status: 409,
                retry_after: None,
                body: r#"{"error":"slice report still conflicts"}"#,
            },
        ])
        .await;
        let (_dir, file) = report_fixture();
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![file],
                full: false,
            },
        )
        .await
        .expect_err("a refused resync is an error");
        let requests = server.join().await;
        assert_eq!(requests.len(), 2, "the delta plus exactly one resync");
    }

    /// A delta refused with anything but the generation conflict —
    /// here a plain 400 — is an error with no resync at all.
    #[tokio::test]
    async fn a_delta_refused_without_conflict_is_an_error() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 400,
            retry_after: None,
            body: r#"{"error":"malformed report"}"#,
        }])
        .await;
        let (_dir, file) = report_fixture();
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![file],
                full: false,
            },
        )
        .await
        .expect_err("a non-conflict refusal is an error");
        let requests = server.join().await;
        assert_eq!(requests.len(), 1, "no resync follows a non-409 refusal");
    }

    /// The join resolves a leaderboard digest to its crate identity
    /// through a fixture slice's row and leaves a digest no slice
    /// carries marked unresolved (stow#889).
    #[test]
    fn join_leaderboard_resolves_digests_through_slice_rows() {
        let index = prev_index(vec![record_to_index_row(&record("ab12"))], 1);
        let digest = index.rows[0].bundle_digest.clone();
        let joined = join_leaderboard(
            vec![
                DigestLeaderboardRow {
                    name: digest,
                    hits: 30.0,
                },
                DigestLeaderboardRow {
                    name: "sha256:unpublished".to_owned(),
                    hits: 20.0,
                },
            ],
            &[index],
        );
        assert_eq!(joined.len(), 2);
        let identity = joined[0].identity.as_ref().expect("resolved identity");
        assert_eq!(identity.crate_name, "serde");
        assert_eq!(identity.version, "1.0.0");
        assert_eq!(identity.target, TARGET);
        assert_eq!(identity.rustc_version, RUSTC);
        assert_eq!(joined[0].hits, 30.0);
        assert!(joined[1].identity.is_none());
        assert_eq!(joined[1].hits, 20.0);
    }
}
