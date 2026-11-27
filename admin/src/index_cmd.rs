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
use stow_types::records::{BuildRecords, LocalProcMacro};

use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use keyring_core::api::CredentialStoreApi;
#[cfg(test)]
use stow_types::api::ArtifactRecord;
use stow_types::api::{CI_TARGET_TRIPLES, PublishedSliceRow, runner_family};
use stow_types::identity::{DependencyIdentity, TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
    IndexDecodeError, LookupIndex, content_sha256, folded_tag, folded_tag_parts, index_tag,
};
use stow_types::public_cache::UnitShape;
use stow_types::records::{parse_records_tag, record_to_index_row};
use stow_types::registry::{CacheRepository, cache_repository, sha256_digest};
use stow_types::stow_error;
use stow_types::trusted_builder::TrustedWorkflow;

use crate::Edge;
use crate::cloudflare;
use crate::render;
use zenwave::ResponseExt as _;

/// Records artifacts pulled in flight per export — the shared
/// anonymous session already honors the registry's rate limit, so this
/// bounds in-flight work, not throughput. A pull is one registry round
/// trip, so the export's length is the new records over this bound: 16
/// in flight could not fold a full re-sign's 62,103 new records inside
/// the job's 30 minutes, and 64 does with room to spare.
const RECORDS_PULL_CONCURRENCY: usize = 64;
/// Published slices or previous `index`/`folded` pairs pulled in flight.
const PREV_PULL_CONCURRENCY: usize = 8;
/// Artifact records per sync request — each request lands as one
/// edge-side batch write, so a chunk is one round trip rather than a
/// body the worker timeout eats mid-flight.
/// Sync chunk posts in flight — the chunks are independent writes, so
/// the bound only limits how many edge requests the pass holds open.
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
// Records artifacts are signed by `build-crate.yml` and the `index.*` /
// `folded.*` pair by the index workflow, each at a release tag: the export
// pins those identities the same way the CLI pins them for bundles, and
// verifies previous slices against the index one before folding on top.

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
    /// plus `slices.json` (ordered host slices before cross slices),
    /// `shared-tags.json` (multi-slice records tags and the slice tags
    /// they named) and `new-records.json` (the delta the pass folded). A
    /// `CI_TARGET_TRIPLES` member with no new rows and no published
    /// pair is still written — an empty first-publish slice, so
    /// `--target` consumers of a deps-less lane always find the tag.
    Export(IndexExportArgs),
    /// Publish an exported pass directory to the registry in two phases:
    /// every slice's `index.<target>.<rustc>` first (host slices before
    /// cross slices, skipping cross slices whose runner host failed),
    /// then each succeeded slice's `folded.<target>.<rustc>` excluding
    /// newly-folded multi-slice tags that also named any failed slice.
    Publish(IndexPublishArgs),
    /// Report a just-published slice's semantic membership to the edge
    /// — what the scheduler's dependency gate checks before releasing
    /// a dependent. `index-publish.yml` runs it after a successful
    /// publish; running it again against the same file is idempotent.
    Report(IndexReportArgs),
    /// Report every published slice of the rustc whose generation the
    /// scheduler does not hold, replayed from the generation it holds
    /// along the slice's published history: one delta per generation it
    /// lacks. A publish run whose report failed, or that died between a
    /// slice's two tags, leaves a live generation the scheduler never
    /// received and no later export re-emits; `index-publish.yml` runs
    /// this before each export so the next run converges on the
    /// published state.
    Reconcile(IndexReconcileArgs),
    /// Print every stable rustc with a published
    /// `ghcr.io/water-rs/stow-cache-v2-<rustc>` package, one per line: the
    /// releases `static.rust-lang.org/manifests.txt` lists, each probed
    /// through the registry's anonymous tag listing. `operations.yml`
    /// reports each one's slices after a scheduler reset. Fails when a
    /// probe is refused or the transport fails, and when no release has
    /// a package.
    PublishedRustcs,
    /// Print every `CI_TARGET_TRIPLES` entry, one per line — the slice
    /// list `index-publish.yml` iterates, read from the binary so the
    /// workflow never carries its own copy.
    Targets,
    /// The one-time re-sign of a rustc's published `index`/`folded`
    /// slices from the branch identity to this run's release-tag
    /// identity; `index-publish.yml` runs it with `resign: true`. A rerun
    /// writes nothing.
    Resign(crate::index_resign::IndexResignArgs),
    /// The one-time migration of legacy `records-*` and `built-*` tags
    /// from standalone `.sig` images to inline `dev.stow.records.signatures`
    /// annotations (stow#1627); `index-publish.yml` runs it with
    /// `migrate_records: true`. Idempotent; deleted once run.
    MigrateRecords(crate::index_migrate_records::IndexMigrateRecordsArgs),
    /// Resolve the public hit leaderboard's bundle digests to crate
    /// identities through the signed index slices (stow#889) — the
    /// edge keeps no identity store, so the offline join lives here.
    Join(IndexJoinArgs),
    /// Upload exported per-target lookup JSON files to R2 for
    /// `stow.waterui.dev`'s cache lookup widget (stow#1688).
    PublishLookup(crate::lookup_r2::IndexPublishLookupArgs),
    /// Pull live verified index slices for one rustc from GHCR and
    /// upload their deduplicated lookup JSON files to R2 (stow#1688).
    SyncLookup(crate::lookup_r2::IndexSyncLookupArgs),
    /// Ensure the Cloudflare WAF allowlist and Cache Rule (ignore query
    /// strings) fronting the R2 lookup custom domain (stow#1688).
    EnsureLookupRules(crate::lookup_r2::IndexEnsureLookupRulesArgs),
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct IndexExportSummary {
    target: String,
    rustc_version: String,
    tag: String,
    folded_tag: String,
    index_file: String,
    folded_file: String,
    lookup_file: String,
    rows: u64,
    bytes: usize,
    sha256: String,
    content_sha256: String,
}

/// Publish every changed slice `index export --out-dir` wrote in two phases:
///
/// 1. Push and sign each slice's `index.<target>.<rustc>` tag, host slices
///    before cross-target slices. If a runner host slice fails, every cross
///    slice built on that host is skipped so downstream cross tasks are never
///    released before their dependencies' host-side build scripts are live.
/// 2. Push and sign each succeeded slice's `folded.<target>.<rustc>` tag,
///    excluding any newly-folded multi-slice `records-*` tag that also named a
///    slice whose phase-1 publish did not succeed. That guarantees the next
///    export's `folded_union` never skips a multi-slice record before every
///    slice it belongs to has published its rows.
///
/// Two modes, selected by environment: with `STOW_MOCK_PRIVATE_KEY_PATH`
/// set the command delegates to `stow-mock-registry publish-index` /
/// `publish-folded` — writing the signed artifacts into
/// `STOW_MOCK_REGISTRY_ROOT`; without it the command pushes to GHCR through
/// `stow-oci` (`GHCR_USERNAME`/`GHCR_TOKEN`) and signs keyless in process
/// under the job's OIDC identity, the production path `index-publish.yml`
/// runs.
#[derive(Args)]
pub struct IndexPublishArgs {
    /// The export directory `index export --out-dir` wrote (`slices.json`,
    /// `shared-tags.json`, and the slice files).
    #[arg(long)]
    dir: std::path::PathBuf,
}

/// The per-slice JSON summary `index publish --dir` prints on stdout and
/// writes to `<dir>/published.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct IndexPublishSummary {
    target: String,
    rustc_version: String,
    tag: String,
    folded_tag: String,
    index_file: String,
    lookup_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_digest: Option<String>,
    outcome: String,
    index_published: bool,
    folded_published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
/// A file whose `.prev` is the same generation (the export found no new
/// content) is not reported. A delta the edge refuses with 409 — the
/// scheduler does not hold `base_generation` — is replayed once from the
/// generation it does hold along the slice's published history, the
/// recovery `index reconcile` runs; a full report goes out only where
/// that history has no base for it.
#[derive(Args)]
pub struct IndexReportArgs {
    /// The encoded index files (`index export --out-dir` wrote them) —
    /// repeatable, one per slice the run published; the whole set posts
    /// as ONE report per publish run (stow#940).
    #[arg(long, required = true)]
    file: Vec<std::path::PathBuf>,
    /// Send the explicit full report (`base_generation` unset) — the
    /// report of a `full` export, and the automatic shape of a first
    /// publish.
    #[arg(long)]
    full: bool,
}

#[derive(Args)]
pub struct IndexReconcileArgs {
    /// The rustc whose published `index.<target>.<rustc>` slices are
    /// compared against the scheduler's.
    #[arg(long)]
    rustc_version: String,
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
    /// `true` when every report sent took the explicit full path
    /// (`--full`, or first publishes with no `.prev` sidecar).
    full: bool,
}

/// Dispatch one `index` subcommand.
pub async fn run(
    args: IndexArgs,
    store: &(impl CredentialStoreApi + Sync),
) -> stow_types::error::Result<()> {
    match args.command {
        IndexCommand::Export(args) => index_export(args).await,
        IndexCommand::Publish(args) => index_publish(args).await,
        IndexCommand::Report(args) => {
            let connect = |rustc_version: WireRustcVersion| {
                Box::pin(async move { PullContext::connect(&rustc_version).await })
                    as PullFut<'static, PullContext>
            };
            index_report(&Edge::connect(store)?, args, &connect).await
        }
        IndexCommand::Reconcile(args) => index_reconcile(&Edge::connect(store)?, args).await,
        IndexCommand::PublishedRustcs => published_rustcs().await,
        IndexCommand::Targets => {
            render::emit_line(&CI_TARGET_TRIPLES.join("\n"));
            Ok(())
        }
        IndexCommand::Resign(args) => crate::index_resign::run(args).await,
        IndexCommand::MigrateRecords(args) => crate::index_migrate_records::run(args).await,
        IndexCommand::Join(args) => index_join(args).await,
        IndexCommand::PublishLookup(args) => crate::lookup_r2::publish_lookup_files(args).await,
        IndexCommand::SyncLookup(args) => index_sync_lookup(args).await,
        IndexCommand::EnsureLookupRules(args) => {
            crate::lookup_r2::ensure_lookup_rules_cmd(args).await
        }
    }
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
    workflow: TrustedWorkflow,
) -> stow_types::error::Result<()> {
    stow_oci::verify_artifact_signature(
        session,
        trust,
        reference,
        identity_reference,
        manifest_digest,
        &stow_oci::verify::ReleaseIdentity::new(workflow),
    )
    .await
}

/// [`verify_artifact`] for an artifact the export took from the tag
/// listing: its signature manifest is known to exist, so a `404` on it is
/// retried as a stale read.
async fn verify_listed_artifact(
    session: &stow_oci::RegistrySession,
    trust: &stow_oci::verify::Trust,
    reference: &oci_client::Reference,
    identity_reference: &str,
    manifest_digest: &str,
    workflow: TrustedWorkflow,
) -> stow_types::error::Result<()> {
    stow_oci::verify_listed_artifact_signature(
        session,
        trust,
        reference,
        identity_reference,
        manifest_digest,
        &stow_oci::verify::ReleaseIdentity::new(workflow),
    )
    .await
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
    /// names. An index with no folded set is a publish that died between
    /// its two tags: the slice extends with an empty folded set, so the
    /// pass refolds every record onto the published rows and the next
    /// publish writes the pair. A folded tag without its index sibling
    /// is state an incremental export cannot extend; `--full` rebuilds
    /// it.
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

        let pulled_folded =
            stow_oci::pull_listed_folded(&self.session, target.as_str(), rustc_version.as_str())
                .await?;
        if let Some(pulled_folded) = &pulled_folded {
            verify_listed_artifact(
                &self.session,
                &self.trust,
                &self.session.reference(folded)?,
                &self.repository.reference(folded),
                &pulled_folded.manifest_digest,
                TrustedWorkflow::INDEX,
            )
            .await?;
        }

        // The folded tag was listed, so its sibling slice is published: its
        // absence is a stale read to retry, not an answer.
        let Some(pulled_index) =
            stow_oci::pull_listed_index(&self.session, target.as_str(), rustc_version.as_str())
                .await?
        else {
            return Err(stow_error!(
                "folded {folded} exists but index.{target}.{rustc_version} is missing — \
                 re-export with --full"
            ));
        };
        let itag = index_tag(target.as_str(), rustc_version.as_str());
        let index_reference = self.session.reference(&itag)?;
        verify_listed_artifact(
            &self.session,
            &self.trust,
            &index_reference,
            &self.repository.reference(&itag),
            &pulled_index.manifest_digest,
            TrustedWorkflow::INDEX,
        )
        .await?;
        let index = decode_slice_of(
            &index_reference,
            &target,
            &rustc_version,
            &pulled_index.bytes,
        )?;
        Ok(Some((
            (target, rustc_version),
            PrevSlice {
                index,
                folded: pulled_folded.map_or_default(|pulled| pulled.tags.into_iter().collect()),
            },
        )))
    }

    /// The anonymous registry session, repository and trust the reads
    /// of `rustc_version`'s cache package share.
    async fn connect(rustc_version: &WireRustcVersion) -> stow_types::error::Result<Self> {
        let base = registry_base()?;
        let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
        let repository = cache_repository(rustc_version);
        let session = base.session(&repository, &http);
        let trust = stow_oci::verify::records_trust().await?;
        Ok(Self {
            session,
            repository,
            trust,
        })
    }

    /// Verify a pulled index manifest under the index workflow and decode
    /// it as `index.<target>.<rustc>`.
    async fn verified_manifest(
        &self,
        target: &TargetTriple,
        rustc_version: &WireRustcVersion,
        pulled: stow_oci::PulledIndex,
        presence: Presence,
    ) -> stow_types::error::Result<SliceManifest> {
        let itag = index_tag(target.as_str(), rustc_version.as_str());
        let index_reference = self.session.reference(&itag)?;
        let identity_reference = self.repository.reference(&itag);
        match presence {
            Presence::Unknown => {
                verify_artifact(
                    &self.session,
                    &self.trust,
                    &index_reference,
                    &identity_reference,
                    &pulled.manifest_digest,
                    TrustedWorkflow::INDEX,
                )
                .await?;
            }
            Presence::Listed => {
                verify_listed_artifact(
                    &self.session,
                    &self.trust,
                    &index_reference,
                    &identity_reference,
                    &pulled.manifest_digest,
                    TrustedWorkflow::INDEX,
                )
                .await?;
            }
        }
        Ok(SliceManifest {
            index: decode_slice_of(&index_reference, target, rustc_version, &pulled.bytes)?,
            previous: pulled.previous,
        })
    }
}

/// How a read knows its manifest exists: [`Presence::Listed`] when a
/// signed manifest names it, so a `404` on its signature is a stale read
/// retried before it answers.
#[derive(Clone, Copy)]
enum Presence {
    Unknown,
    Listed,
}

/// One published manifest of a slice: its verified index, and the
/// manifest it replaced on the slice's tag (`None` on a first push).
struct SliceManifest {
    index: ArtifactIndex,
    previous: Option<String>,
}

/// A slice's published history: its live manifest, and each earlier
/// manifest by the digest a later one links. Every manifest it answers
/// is signature-verified under the index workflow and decoded as the
/// slice it was asked for.
trait SliceHistory: Send + Sync {
    /// The manifest `index.<target>.<rustc>` resolves to; `None` when
    /// the tag does not exist.
    fn live(
        &self,
        target: &TargetTriple,
        rustc_version: &WireRustcVersion,
    ) -> impl Future<Output = stow_types::error::Result<Option<SliceManifest>>> + Send;

    /// The manifest of the slice a later one links as its `previous`.
    fn linked(
        &self,
        target: &TargetTriple,
        rustc_version: &WireRustcVersion,
        manifest_digest: &str,
    ) -> impl Future<Output = stow_types::error::Result<SliceManifest>> + Send;
}

/// Opens the [`SliceHistory`] of one rustc's cache package — a refused
/// delta's replay connects to the registry only when it runs.
type ConnectHistory<'a, H> = &'a (dyn Fn(WireRustcVersion) -> PullFut<'static, H> + Sync);

impl SliceHistory for PullContext {
    async fn live(
        &self,
        target: &TargetTriple,
        rustc_version: &WireRustcVersion,
    ) -> stow_types::error::Result<Option<SliceManifest>> {
        let Some(pulled) =
            stow_oci::pull_index(&self.session, target.as_str(), rustc_version.as_str()).await?
        else {
            return Ok(None);
        };
        self.verified_manifest(target, rustc_version, pulled, Presence::Unknown)
            .await
            .map(Some)
    }

    async fn linked(
        &self,
        target: &TargetTriple,
        rustc_version: &WireRustcVersion,
        manifest_digest: &str,
    ) -> stow_types::error::Result<SliceManifest> {
        let pulled = stow_oci::pull_index_by_digest(&self.session, manifest_digest).await?;
        self.verified_manifest(target, rustc_version, pulled, Presence::Listed)
            .await
    }
}

impl PullContext {
    /// Pull and verify one records artifact — a signature that fails the
    /// pinned identity is fatal: the alternative, silently dropping it,
    /// would export a slice that quietly misses crates.
    async fn records(&self, tag: &str) -> stow_types::error::Result<BuildRecords> {
        let pulled = stow_oci::pull_listed_records_by_tag(&self.session, tag).await?;
        pulled.verify(
            &self.trust,
            &self.repository.reference(tag),
            &stow_oci::verify::ReleaseIdentity::new(TrustedWorkflow::BUILD),
        )?;
        Ok(pulled.records)
    }
}

/// Decode the verified bytes of `index.<target>.<rustc>` and require its
/// header to name that same target and rustc.
fn decode_slice_of(
    reference: &oci_client::Reference,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    bytes: &[u8],
) -> stow_types::error::Result<ArtifactIndex> {
    let index = decode_published_slice(reference, rustc_version, bytes)?;
    if index.header.target != *target || index.header.rustc_version != *rustc_version {
        return Err(stow_error!(
            "index.{target}.{rustc_version} carries header {}/{} — re-export with --full",
            index.header.target,
            index.header.rustc_version,
        ));
    }
    Ok(index)
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
    /// Slices that changed — ordered host slices before cross slices.
    slices: Vec<SliceExport>,
    /// Newly-folded `records-*` tags that contributed rows or local programs
    /// to more than one slice, mapped to the sorted `index.<target>.<rustc>`
    /// tags they named. Phase 2 of `index publish` excludes a shared tag from
    /// every slice's `folded.*` set unless every slice it named succeeded in
    /// phase 1.
    shared_tags: BTreeMap<String, Vec<String>>,
    /// Every record this pass pulled — the folded delta.
    new_records: BuildRecords,
    /// Records artifacts pulled — the O(change) meter the gate counts.
    pulled: usize,
}

/// The runner host triple `target` cross-compiles on, or `None` when `target`
/// builds on its own host (or is not a `CI_TARGET_TRIPLES` member).
fn cross_host_triple(target: &str) -> Option<&'static str> {
    let host = runner_family(target)?.host_triple();
    (host != target).then_some(host)
}

/// Ordering key placing every host slice before every cross-target slice, and
/// lexicographically by target then rustc within each group.
fn slice_order_key<'a>(target: &'a str, rustc: &'a str) -> (bool, &'a str, &'a str) {
    (cross_host_triple(target).is_some(), target, rustc)
}

/// A boxed pull future — the injected halves' shared return shape, so a
/// `&'a str` input may outlive the call only as long as the future does.
type PullFut<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = stow_types::error::Result<T>> + Send + 'a>>;

/// An index row's key: the `(c_metadata, profile, unit_shape,
/// dependency_identity)` node a unit was published for.
type RowKey = (
    String,
    stow_types::node_profile::NodeProfile,
    UnitShape,
    DependencyIdentity,
);

/// A bundle tag as one node publishes it. Within a `(target, rustc)`
/// slice the tag is `<crate>.<version>-<target>-<rustc>-<feature hash>-
/// <c_metadata><kind suffix>`, and `c_metadata` already hashes the
/// crate, version and features, so `(c_metadata, artifact_kind)` names
/// the tag. The side, profile and dependency identity complete the
/// node's task id.
type NodeBundle = (
    String,
    stow_types::artifact::ArtifactKind,
    stow_types::public_cache::UnitSide,
    stow_types::node_profile::NodeProfile,
    DependencyIdentity,
);

/// Index rows keyed by [`RowKey`]. The `(c_metadata, unit_shape)` pair
/// is what a consumer's key space identifies, but it is not the row key:
/// two nodes that differ only in dependency context can compile to the
/// same unit, and each keeps a row so the slice answers for both
/// (stow#657).
///
/// A bundle tag does not name the unit shape. One build may publish its
/// bundle at several shapes — a unit both invocation spellings produce
/// gets a record per spelling, all carrying the bundle's digest — and a
/// later build of the node that publishes the unit at another shape
/// moves the tag to a new digest. `by_bundle` holds, per node and tag,
/// the digest folded last and the row keys carrying it, so rows of an
/// earlier digest leave the slice and rows sharing the current one stay.
#[derive(Default)]
struct RowsByIdentity {
    rows: BTreeMap<RowKey, ArtifactIndexRow>,
    by_bundle: BTreeMap<NodeBundle, BundleRows>,
}

/// The digest a node's bundle tag names and the row keys published with it.
#[derive(Default)]
struct BundleRows {
    digest: String,
    keys: BTreeSet<RowKey>,
}

impl RowsByIdentity {
    fn values(&self) -> impl Iterator<Item = &ArtifactIndexRow> {
        self.rows.values()
    }

    fn into_values(self) -> impl Iterator<Item = ArtifactIndexRow> {
        self.rows.into_values()
    }
}

/// The bundle tag `row` was published under, as its node published it.
fn node_bundle(row: &ArtifactIndexRow) -> stow_types::error::Result<NodeBundle> {
    Ok((
        row.c_metadata.as_str().to_owned(),
        row.artifact_kind.clone(),
        row.unit_shape.side,
        row.node_profile,
        row.dependency_identity()?,
    ))
}

/// Fold `row` into `rows` under its [`RowKey`] — a rebuilt unit replaces
/// its node's row, a second node publishing the same unit adds a row
/// beside it — and evict the rows its node published earlier under the
/// same bundle tag with another digest.
fn fold_row(rows: &mut RowsByIdentity, row: ArtifactIndexRow) -> stow_types::error::Result<()> {
    let bundle = node_bundle(&row)?;
    let key = (
        row.c_metadata.as_str().to_owned(),
        row.node_profile,
        row.unit_shape,
        bundle.4.clone(),
    );
    let published = rows.by_bundle.entry(bundle.clone()).or_default();
    if published.digest != row.bundle_digest {
        for superseded in std::mem::take(&mut published.keys) {
            rows.rows.remove(&superseded);
        }
        published.digest.clone_from(&row.bundle_digest);
    }
    published.keys.insert(key.clone());
    if let Some(replaced) = rows.rows.insert(key.clone(), row) {
        let replaced_bundle = node_bundle(&replaced)?;
        if replaced_bundle != bundle
            && let Some(other) = rows.by_bundle.get_mut(&replaced_bundle)
        {
            other.keys.remove(&key);
        }
    }
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
    R: Fn(&str) -> PullFut<'static, BuildRecords> + Send + Sync,
{
    let is_own_rustc =
        |tag_rustc: &str| WireRustcVersion::parse(tag_rustc).is_ok_and(|v| v == *rustc);
    // A slice is published by its index tag, then its folded tag: a
    // publish that died between them leaves an index alone, which the
    // pass extends. Every own-rustc suffix either tag names is pulled.
    let own_suffixes: BTreeSet<&str> = tags
        .iter()
        .filter_map(|tag| {
            folded_tag_parts(tag)
                .filter(|(_, tag_rustc)| is_own_rustc(tag_rustc))
                .map(|_| &tag["folded.".len()..])
                .or_else(|| {
                    index_tag_parts(tag)
                        .filter(|(_, tag_rustc)| is_own_rustc(tag_rustc))
                        .map(|_| &tag["index.".len()..])
                })
        })
        .collect();
    let mut prev: BTreeMap<(TargetTriple, WireRustcVersion), PrevSlice> = BTreeMap::new();
    if !full {
        let folded_tags: Vec<String> = own_suffixes
            .iter()
            .map(|suffix| format!("folded.{suffix}"))
            .collect();
        let pairs = futures_util::stream::iter(folded_tags.iter().map(|tag| pull_prev(tag)))
            .buffered(PREV_PULL_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
        for pair in pairs.into_iter().flatten() {
            prev.insert(pair.0, pair.1);
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
    let mut shared_tags: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut new_records = BuildRecords::default();
    let mut new_programs: BTreeMap<(TargetTriple, WireRustcVersion), Vec<LocalProcMacro>> =
        BTreeMap::new();
    let per_tag = futures_util::stream::iter(missing.iter().map(|entry| pull_records(entry.2)))
        .buffered(RECORDS_PULL_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;
    for ((_, _, tag), records) in missing.iter().zip(per_tag) {
        // The tag joins the folded set of every slice its records name;
        // a records artifact is immutable per build, so the tag is never
        // pulled again once marked. Multi-slice tags are recorded in
        // `shared_tags` so phase 2 of `index publish` only marks them once
        // every named slice's index went live in phase 1.
        let mut named = BTreeSet::new();
        for record in &records.artifacts {
            let key = (record.target.clone(), record.rustc_version.clone());
            named.insert(key.clone());
            let row = record_to_index_row(record);
            fold_row(new_rows.entry(key).or_default(), row)?;
        }
        for program in &records.local_programs {
            let key = (
                program.node.target.clone(),
                program.node.rustc_version.clone(),
            );
            named.insert(key.clone());
            new_programs.entry(key).or_default().push(program.clone());
        }
        if named.len() > 1 {
            shared_tags.insert(
                (*tag).to_owned(),
                named
                    .iter()
                    .map(|(target, rustc)| index_tag(target.as_str(), rustc.as_str()))
                    .collect(),
            );
        }
        for key in named {
            new_folded.entry(key).or_default().insert((*tag).to_owned());
        }
        new_records.artifacts.extend(records.artifacts);
        new_records.local_programs.extend(records.local_programs);
    }

    // A slice is rewritten when new records routed to it — by index row
    // or by folded mark alone (all-unbundled artifacts produce no rows
    // but must still be marked so they are never re-pulled).
    Ok(ExportPass {
        slices: merge_exports(prev, &new_rows, &new_programs, &new_folded, rustc)?,
        shared_tags,
        new_records,
        pulled: pulled_count,
    })
}

/// Fold the new records into the previous slices: previous rows first,
/// then each new row through [`fold_row`] — a rebuilt unit replaces its
/// node's row, a second node publishing the same unit adds a row beside
/// it, a node's newer row on a bundle tag evicts its older one — and the
/// folded set growing by every tag a record named.
/// `generated_at` is stamped once so every slice of the pass matches.
fn merge_exports(
    mut prev: BTreeMap<(TargetTriple, WireRustcVersion), PrevSlice>,
    new_rows: &BTreeMap<(TargetTriple, WireRustcVersion), RowsByIdentity>,
    new_programs: &BTreeMap<(TargetTriple, WireRustcVersion), Vec<LocalProcMacro>>,
    new_folded: &BTreeMap<(TargetTriple, WireRustcVersion), BTreeSet<String>>,
    rustc: &WireRustcVersion,
) -> stow_types::error::Result<Vec<SliceExport>> {
    let mut slices = Vec::new();
    // The set of keys a published slice already covers — snapshot
    // before the closure starts borrowing `prev`.
    let published: BTreeSet<(TargetTriple, WireRustcVersion)> = prev.keys().cloned().collect();
    let mut push_slice = |key: &(TargetTriple, WireRustcVersion)| {
        let prev_slice = prev.remove(key);
        let mut merged = RowsByIdentity::default();
        if let Some(slice) = prev_slice.as_ref() {
            for row in slice.index.rows.iter().chain(&slice.index.build_scripts) {
                fold_row(&mut merged, row.clone())?;
            }
        }
        // New rows fold on top of the slice's own: a re-run task
        // rebuilding the same unit under the same node replaces its
        // row — at another unit shape too, since the bundle tag moved —
        // and the sibling rule holds across the pass boundary.
        if let Some(rows) = new_rows.get(key) {
            for row in rows.values() {
                fold_row(&mut merged, row.clone())?;
            }
        }
        let mut folded: BTreeSet<String> = prev_slice
            .as_ref()
            .map_or_default(|slice| slice.folded.clone());
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
    slices.sort_by(|((ta, ra), _, _, _), ((tb, rb), _, _, _)| {
        slice_order_key(ta.as_str(), ra.as_str()).cmp(&slice_order_key(tb.as_str(), rb.as_str()))
    });
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| stow_error!("format generated_at: {error}"))?;
    slices
        .into_iter()
        .map(|((target, rustc_version), rows, folded, prev_slice)| {
            let programs = merge_local_programs(
                prev_slice.as_ref(),
                new_programs.get(&(target.clone(), rustc_version.clone())),
            )?;
            let (rows, build_scripts) = stow_types::index::partition_build_scripts(rows);
            // The generation increments the index the pass extends; a
            // `--full` pass pulled no prev, and a first publish has
            // none, so both stamp `1`.
            let generation = prev_slice
                .as_ref()
                .map_or(1, |slice| slice.index.header.generation + 1);
            let row_count = u64::try_from(rows.len())
                .map_err(|_| stow_error!("row count {} exceeds u64", rows.len()))?;
            let mut index = ArtifactIndex {
                header: ArtifactIndexHeader {
                    format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                    target: target.clone(),
                    rustc_version: rustc_version.clone(),
                    generated_at: now.clone(),
                    generation,
                    row_count,
                },
                rows,
                build_scripts,
                local_programs: programs,
            };
            // A slice whose new records added only folded marks keeps the
            // published content, which the publish leaves on the tag: it
            // keeps the published header too, so no generation is reported
            // that no manifest carries.
            if let Some(slice) = &prev_slice
                && content_sha256(&index)? == content_sha256(&slice.index)?
            {
                index.header = slice.index.header.clone();
            }
            Ok(SliceExport {
                index,
                folded,
                prev: prev_slice.map(|slice| slice.index),
                target,
                rustc_version,
            })
        })
        .collect()
}

fn merge_local_programs(
    previous: Option<&PrevSlice>,
    incoming: Option<&Vec<LocalProcMacro>>,
) -> stow_types::error::Result<Vec<LocalProcMacro>> {
    let mut programs = BTreeMap::new();
    for program in previous
        .into_iter()
        .flat_map(|slice| &slice.index.local_programs)
        .chain(incoming.into_iter().flatten())
    {
        programs.insert(
            (
                program.task_id()?,
                program.unit_shape,
                program.compile_key.clone(),
            ),
            program.clone(),
        );
    }
    Ok(programs.into_values().collect())
}

/// Whether `tag` is in a namespace an export pass reads: the folded sets,
/// the index slices and the records.
fn is_export_tag(tag: &str) -> bool {
    ["folded.", "index.", "records-"]
        .iter()
        .any(|prefix| tag.starts_with(prefix))
}

/// One export pass over the whole registry: writes each changed slice as
/// `index.<target>.<rustc>` plus its `folded.<target>.<rustc>` companion
/// under `--out-dir`, `slices.json` for the publish/report loop, and
/// `new-records.json` — the records the pass folded.
async fn index_export(args: IndexExportArgs) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let base = registry_base()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let repository = cache_repository(&rustc_version);
    let session = base.session(&repository, &http);
    let trust = stow_oci::verify::records_trust().await?;
    let mut tags = session
        .list_tags()
        .await
        .map_err(|error| stow_error!("list registry tags: {error}"))?;
    tags.retain(|tag| is_export_tag(tag));
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
        new_records = pass.new_records.artifacts.len(),
        "exported artifact index"
    );

    tokio::fs::create_dir_all(&args.out_dir)
        .await
        .map_err(|error| stow_error!("create {}: {error}", args.out_dir.display()))?;
    let mut summaries = Vec::new();
    for slice in &pass.slices {
        let summary = write_exported_slice(&args.out_dir, slice).await?;
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
        args.out_dir.join("shared-tags.json"),
        serde_json::to_vec(&pass.shared_tags)?,
    )
    .await
    .map_err(|error| stow_error!("write shared-tags.json: {error}"))?;
    tokio::fs::write(
        args.out_dir.join("new-records.json"),
        serde_json::to_vec(&pass.new_records)?,
    )
    .await
    .map_err(|error| stow_error!("write new-records.json: {error}"))?;
    // Remove any stale `published.json` from an earlier wave sharing `--out-dir`.
    match tokio::fs::remove_file(args.out_dir.join("published.json")).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(stow_error!("remove stale published.json: {error}")),
    }
    Ok(())
}

async fn write_exported_slice(
    out_dir: &std::path::Path,
    slice: &SliceExport,
) -> stow_types::error::Result<IndexExportSummary> {
    let bytes = stow_shim::encode_index(&slice.index)
        .map_err(|error| stow_error!("encode index: {error}"))?;
    let index_name = index_tag(slice.target.as_str(), slice.rustc_version.as_str());
    let folded_name = folded_tag(slice.target.as_str(), slice.rustc_version.as_str());
    let lookup_name = format!("{index_name}.lookup.json");
    let index_file = out_dir.join(&index_name);
    let folded_file = out_dir.join(&folded_name);
    let lookup_file = out_dir.join(&lookup_name);
    tokio::fs::write(&index_file, &bytes)
        .await
        .map_err(|error| stow_error!("write index {}: {error}", index_file.display()))?;
    tokio::fs::write(&folded_file, serde_json::to_vec(&slice.folded)?)
        .await
        .map_err(|error| stow_error!("write folded {}: {error}", folded_file.display()))?;
    let lookup = LookupIndex::from_artifact_index(&slice.index);
    tokio::fs::write(&lookup_file, serde_json::to_vec(&lookup)?)
        .await
        .map_err(|error| stow_error!("write lookup {}: {error}", lookup_file.display()))?;
    // The `.prev` sidecar is the report's delta base — the index
    // this pass extended, captured while the tag still named it.
    if let Some(prev) = &slice.prev {
        let prev_bytes = stow_shim::encode_index(prev)
            .map_err(|error| stow_error!("encode previous index: {error}"))?;
        tokio::fs::write(prev_path(&index_file), &prev_bytes)
            .await
            .map_err(|error| stow_error!("write previous-index sidecar: {error}"))?;
    }
    Ok(IndexExportSummary {
        target: slice.target.as_str().to_owned(),
        rustc_version: slice.rustc_version.as_str().to_owned(),
        tag: index_name.clone(),
        folded_tag: folded_name.clone(),
        index_file: index_name,
        folded_file: folded_name,
        lookup_file: lookup_name,
        rows: slice.index.header.row_count,
        bytes: bytes.len(),
        sha256: sha256_digest(&bytes),
        content_sha256: content_sha256(&slice.index)
            .map_err(|error| stow_error!("digest index content: {error}"))?,
    })
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
/// one `(crate, version, features, profile, shape)` — so the report
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
                node_profile: row.node_profile,
                unit_shape: row.unit_shape,
                dependency_identity: row.dependency_identity()?,
            })
        })
        .chain(index.local_programs.iter().map(|program| {
            Ok(PublishedSliceRow {
                crate_name: program.node.crate_name.clone(),
                version: program.node.version.clone(),
                features_json: program.node.features_json.clone(),
                node_profile: program.node.profile,
                unit_shape: program.unit_shape,
                dependency_identity: program.dependency_identity()?,
            })
        }))
        .filter(|row| {
            let Ok(row) = row else { return true };
            seen.insert(row_key(row))
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
    stow_types::node_profile::NodeProfile,
    stow_types::identity::DependencyIdentity,
    stow_types::public_cache::UnitShape,
) {
    (
        row.crate_name.as_str().to_owned(),
        row.version.to_string(),
        row.features_json.raw(),
        row.node_profile,
        row.dependency_identity.clone(),
        row.unit_shape,
    )
}

/// One slice loaded and validated from `index export --out-dir` ahead of
/// phase 1.
struct PreparedSlice {
    summary: IndexExportSummary,
    rustc_version: WireRustcVersion,
    index_path: std::path::PathBuf,
    folded_path: std::path::PathBuf,
    index_bytes: Vec<u8>,
    folded: Vec<String>,
}

/// Phase-1 outcome for one slice inside [`publish_pass`].
enum Phase1Outcome {
    Published {
        manifest_digest: String,
        outcome: &'static str,
    },
    Failed(String),
    SkippedHostFailed(String),
}

/// Load and validate every slice listed in `slices.json` from `dir` before
/// pushing anything, so local corruption or export skew fails fast before any
/// tag moves.
async fn load_prepared_slices(
    dir: &std::path::Path,
    summaries: Vec<IndexExportSummary>,
) -> stow_types::error::Result<Vec<PreparedSlice>> {
    let mut prepared = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let index_path = dir.join(&summary.index_file);
        let folded_path = dir.join(&summary.folded_file);
        let index_bytes = tokio::fs::read(&index_path)
            .await
            .map_err(|error| stow_error!("read index file {}: {error}", index_path.display()))?;
        let index = ArtifactIndex::decode(&index_bytes)
            .map_err(|error| stow_error!("decode index file {}: {error}", index_path.display()))?;
        if index.header.target.as_str() != summary.target
            || index.header.rustc_version.as_str() != summary.rustc_version
        {
            return Err(stow_error!(
                "index file {} carries header {}/{}, expected {}/{}",
                index_path.display(),
                index.header.target,
                index.header.rustc_version,
                summary.target,
                summary.rustc_version,
            ));
        }
        let actual_content_sha256 = content_sha256(&index).map_err(|error| {
            stow_error!("digest index content {}: {error}", index_path.display())
        })?;
        if actual_content_sha256 != summary.content_sha256 {
            return Err(stow_error!(
                "index file {} content_sha256 {actual_content_sha256} disagrees with slices.json {}",
                index_path.display(),
                summary.content_sha256,
            ));
        }
        let folded_bytes = tokio::fs::read(&folded_path)
            .await
            .map_err(|error| stow_error!("read folded file {}: {error}", folded_path.display()))?;
        let folded: Vec<String> = serde_json::from_slice(&folded_bytes).map_err(|error| {
            stow_error!("decode folded file {}: {error}", folded_path.display())
        })?;
        prepared.push(PreparedSlice {
            rustc_version: index.header.rustc_version,
            summary,
            index_path,
            folded_path,
            index_bytes,
            folded,
        });
    }
    Ok(prepared)
}

fn build_publish_summary(
    slice: &PreparedSlice,
    manifest_digest: Option<String>,
    outcome: &str,
    index_published: bool,
    folded_published: bool,
    error: Option<String>,
) -> IndexPublishSummary {
    IndexPublishSummary {
        target: slice.summary.target.clone(),
        rustc_version: slice.summary.rustc_version.clone(),
        tag: slice.summary.tag.clone(),
        folded_tag: slice.summary.folded_tag.clone(),
        index_file: slice.summary.index_file.clone(),
        lookup_file: slice.summary.lookup_file.clone(),
        manifest_digest,
        outcome: outcome.to_owned(),
        index_published,
        folded_published,
        error,
    }
}

async fn publish_phase1_indexes<'a, I>(
    ordered: &[&'a PreparedSlice],
    publish_index: &I,
) -> (Vec<Phase1Outcome>, BTreeSet<&'a str>)
where
    I: Fn(&'a PreparedSlice) -> PullFut<'a, (String, &'static str)> + Send + Sync,
{
    let mut failed_hosts: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut succeeded_tags: BTreeSet<&'a str> = BTreeSet::new();
    let mut outcomes: Vec<Phase1Outcome> = Vec::with_capacity(ordered.len());

    for &slice in ordered {
        if let Some(host) = cross_host_triple(&slice.summary.target)
            && failed_hosts.contains(&(host, slice.summary.rustc_version.as_str()))
        {
            let message = format!(
                "skipped {} because runner host slice {host} failed in phase 1",
                slice.summary.tag
            );
            tracing::error!(tag = %slice.summary.tag, host, "{message}");
            outcomes.push(Phase1Outcome::SkippedHostFailed(message));
            continue;
        }
        match publish_index(slice).await {
            Ok((manifest_digest, outcome)) => {
                tracing::info!(
                    tag = %slice.summary.tag,
                    %manifest_digest,
                    outcome,
                    "published artifact index slice"
                );
                succeeded_tags.insert(slice.summary.tag.as_str());
                outcomes.push(Phase1Outcome::Published {
                    manifest_digest,
                    outcome,
                });
            }
            Err(error) => {
                let message = error.to_string();
                tracing::error!(tag = %slice.summary.tag, error = %message, "index publish failed");
                failed_hosts.insert((
                    slice.summary.target.as_str(),
                    slice.summary.rustc_version.as_str(),
                ));
                outcomes.push(Phase1Outcome::Failed(message));
            }
        }
    }
    (outcomes, succeeded_tags)
}

async fn publish_phase2_folded<'a, F>(
    ordered: Vec<&'a PreparedSlice>,
    phase1: Vec<Phase1Outcome>,
    excluded_tags: &BTreeSet<&str>,
    publish_folded: &F,
) -> Vec<IndexPublishSummary>
where
    F: Fn(&'a PreparedSlice, Vec<String>) -> PullFut<'a, ()> + Send + Sync,
{
    let mut results = Vec::with_capacity(ordered.len());
    for (slice, p1) in ordered.into_iter().zip(phase1) {
        let summary = match p1 {
            Phase1Outcome::Published {
                manifest_digest,
                outcome,
            } => {
                let filtered: Vec<String> = slice
                    .folded
                    .iter()
                    .filter(|tag| !excluded_tags.contains(tag.as_str()))
                    .cloned()
                    .collect();
                let (folded_published, error) = match publish_folded(slice, filtered).await {
                    Ok(()) => {
                        tracing::info!(
                            folded_tag = %slice.summary.folded_tag,
                            "published artifact index folded set"
                        );
                        (true, None)
                    }
                    Err(error) => {
                        let message = error.to_string();
                        tracing::error!(
                            folded_tag = %slice.summary.folded_tag,
                            error = %message,
                            "folded set publish failed"
                        );
                        (false, Some(message))
                    }
                };
                build_publish_summary(
                    slice,
                    Some(manifest_digest),
                    outcome,
                    true,
                    folded_published,
                    error,
                )
            }
            Phase1Outcome::Failed(message) => {
                build_publish_summary(slice, None, "failed", false, false, Some(message))
            }
            Phase1Outcome::SkippedHostFailed(message) => build_publish_summary(
                slice,
                None,
                "skipped-host-failed",
                false,
                false,
                Some(message),
            ),
        };
        results.push(summary);
    }
    results
}

/// Two-phase publish of an export pass:
///
/// - **Phase 1**: publish `index.<target>.<rustc>` only, host slices before
///   cross slices. If a runner host slice fails, every cross slice built on
///   that host is skipped (`skipped-host-failed`) so downstream cross tasks
///   cannot be released without their host-side build scripts.
/// - **Phase 2**: publish `folded.<target>.<rustc>` only for slices that
///   succeeded in phase 1, filtering out any newly-folded multi-slice tag in
///   `shared_tags` unless **every** slice it named succeeded in phase 1.
async fn publish_pass<'a, I, F>(
    slices: &'a [PreparedSlice],
    shared_tags: &BTreeMap<String, Vec<String>>,
    publish_index: I,
    publish_folded: F,
) -> Vec<IndexPublishSummary>
where
    I: Fn(&'a PreparedSlice) -> PullFut<'a, (String, &'static str)> + Send + Sync,
    F: Fn(&'a PreparedSlice, Vec<String>) -> PullFut<'a, ()> + Send + Sync,
{
    let mut ordered: Vec<&'a PreparedSlice> = slices.iter().collect();
    ordered.sort_by(|a, b| {
        slice_order_key(&a.summary.target, &a.summary.rustc_version).cmp(&slice_order_key(
            &b.summary.target,
            &b.summary.rustc_version,
        ))
    });
    let (phase1, succeeded_tags) = publish_phase1_indexes(&ordered, &publish_index).await;
    // Exclude any multi-slice tag from every slice's `folded.*` set unless
    // EVERY slice that tag named went live in phase 1; otherwise the next
    // export's `folded_union` would skip pulling that tag and permanently lose
    // its rows for the slice(s) that failed.
    let excluded_tags: BTreeSet<&str> = shared_tags
        .iter()
        .filter(|(_, slice_tags)| {
            !slice_tags
                .iter()
                .all(|tag| succeeded_tags.contains(tag.as_str()))
        })
        .map(|(records_tag, _)| records_tag.as_str())
        .collect();
    publish_phase2_folded(ordered, phase1, &excluded_tags, &publish_folded).await
}

/// `stow-admin index publish --dir <out-dir>` — the second half of the index
/// pipeline. Publishes every changed slice in two phases (`index.*` host-first,
/// then filtered `folded.*`), prints one JSON summary line per slice, writes
/// `<dir>/published.json`, and exits non-zero if any slice failed in either
/// phase.
async fn index_publish(args: IndexPublishArgs) -> stow_types::error::Result<()> {
    let published_path = args.dir.join("published.json");
    match tokio::fs::remove_file(&published_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(stow_error!(
                "remove stale {}: {error}",
                published_path.display()
            ));
        }
    }
    let slices_path = args.dir.join("slices.json");
    let slices_bytes = tokio::fs::read(&slices_path)
        .await
        .map_err(|error| stow_error!("read {}: {error}", slices_path.display()))?;
    let summaries: Vec<IndexExportSummary> = serde_json::from_slice(&slices_bytes)
        .map_err(|error| stow_error!("decode {}: {error}", slices_path.display()))?;
    let shared_path = args.dir.join("shared-tags.json");
    let shared_bytes = tokio::fs::read(&shared_path)
        .await
        .map_err(|error| stow_error!("read {}: {error}", shared_path.display()))?;
    let shared_tags: BTreeMap<String, Vec<String>> = serde_json::from_slice(&shared_bytes)
        .map_err(|error| stow_error!("decode {}: {error}", shared_path.display()))?;

    if summaries.is_empty() {
        tokio::fs::write(&published_path, b"[]")
            .await
            .map_err(|error| stow_error!("write {}: {error}", published_path.display()))?;
        return Ok(());
    }

    let prepared = load_prepared_slices(&args.dir, summaries).await?;
    let results = if let Ok(private_key_path) = std::env::var(STOW_MOCK_PRIVATE_KEY_PATH_ENV) {
        publish_pass_mock(&args.dir, &prepared, &shared_tags, &private_key_path).await?
    } else {
        publish_pass_production(&prepared, &shared_tags).await?
    };

    for summary in &results {
        let line = serde_json::to_string(summary)
            .map_err(|error| stow_error!("serialize index publish summary: {error}"))?;
        render::emit_line(&line);
    }
    tokio::fs::write(&published_path, serde_json::to_vec(&results)?)
        .await
        .map_err(|error| stow_error!("write {}: {error}", published_path.display()))?;

    let failed: Vec<&str> = results
        .iter()
        .filter_map(|summary| {
            if !summary.index_published {
                Some(summary.tag.as_str())
            } else if !summary.folded_published {
                Some(summary.folded_tag.as_str())
            } else {
                None
            }
        })
        .collect();
    if !failed.is_empty() {
        return Err(stow_error!(
            "index publish incomplete: {}",
            failed.join(", ")
        ));
    }
    Ok(())
}

async fn publish_pass_production(
    prepared: &[PreparedSlice],
    shared_tags: &BTreeMap<String, Vec<String>>,
) -> stow_types::error::Result<Vec<IndexPublishSummary>> {
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    // The keyless signer checks every signature it makes against the trust
    // readers verify with.
    let trust = stow_oci::verify::records_trust().await?;
    let publisher = stow_oci::Publisher::from_env(http, &trust, TrustedWorkflow::INDEX)?;
    let pub_ref = &publisher;
    Ok(publish_pass(
        prepared,
        shared_tags,
        |slice| {
            Box::pin(async move {
                let outcome = stow_oci::publish_index(
                    pub_ref,
                    &slice.index_bytes,
                    &slice.summary.target,
                    &slice.rustc_version,
                    &slice.summary.content_sha256,
                )
                .await?;
                Ok(match outcome {
                    stow_oci::IndexPublishOutcome::Published { manifest_digest } => {
                        (manifest_digest, "published")
                    }
                    stow_oci::IndexPublishOutcome::Unchanged { manifest_digest } => {
                        (manifest_digest, "unchanged")
                    }
                    stow_oci::IndexPublishOutcome::Resigned { manifest_digest } => {
                        (manifest_digest, "resigned")
                    }
                })
            })
        },
        |slice, filtered| {
            Box::pin(async move {
                let bytes = serde_json::to_vec(&filtered)?;
                stow_oci::publish_folded(
                    pub_ref,
                    &bytes,
                    &slice.summary.target,
                    &slice.rustc_version,
                )
                .await?;
                Ok(())
            })
        },
    )
    .await)
}

async fn publish_pass_mock(
    out_dir: &std::path::Path,
    prepared: &[PreparedSlice],
    shared_tags: &BTreeMap<String, Vec<String>>,
    private_key_path: &str,
) -> stow_types::error::Result<Vec<IndexPublishSummary>> {
    let registry_root = std::env::var(STOW_MOCK_REGISTRY_ROOT_ENV)
        .map_err(|_| stow_error!("missing {STOW_MOCK_REGISTRY_ROOT_ENV}"))?;
    let mock_registry_exe = mock_registry_binary()?;
    let registry_root_ref = registry_root.as_str();
    let mock_exe_ref = mock_registry_exe.as_path();
    Ok(publish_pass(
        prepared,
        shared_tags,
        |slice| {
            Box::pin(async move {
                publish_index_mock(
                    mock_exe_ref,
                    &slice.index_path,
                    registry_root_ref,
                    private_key_path,
                )
                .await
            })
        },
        |slice, filtered| {
            Box::pin(async move {
                publish_folded_mock(
                    mock_exe_ref,
                    out_dir,
                    slice,
                    &filtered,
                    registry_root_ref,
                    private_key_path,
                )
                .await
            })
        },
    )
    .await)
}

/// The edge route a publish run's slices are reported to.
const REPORT_PATH: &str = "/api/v1/admin/index/published";

/// POST a run's slices in the consecutive bodies
/// [`stow_types::api::PublishedRunReport::into_bodies`] splits them
/// into - each under the edge's request limit, a large full report in
/// parts the scheduler stages and applies with the last - and answer
/// the first refusal typed, so a caller can match its status. The outer
/// `Err` covers a slice that cannot split and build/auth failures.
async fn post_report_unchecked(
    edge: &Edge,
    slices: Vec<stow_types::api::PublishedSlice>,
) -> stow_types::error::Result<std::result::Result<(), zenwave::Error>> {
    let bodies = stow_types::api::PublishedRunReport::into_bodies(
        slices,
        stow_types::api::SLICE_REPORT_PART_BYTES,
        stow_types::api::REQUEST_BODY_LIMIT_BYTES,
    )?;
    let url = format!("{}{REPORT_PATH}", edge.base());
    for (at, body) in bodies.iter().enumerate() {
        match edge.post_unchecked(REPORT_PATH, body).await? {
            Ok(response) => {
                response
                    .into_json::<serde_json::Value>()
                    .await
                    .map_err(|error| stow_error!("decode {url}: {error}"))?;
            }
            Err(error) => return Ok(Err(error)),
        }
        tracing::debug!(
            body = at + 1,
            of = bodies.len(),
            "posted a slice report body"
        );
    }
    Ok(Ok(()))
}

/// [`post_report_unchecked`] where any refusal is an error naming the
/// route.
async fn post_report(
    edge: &Edge,
    slices: Vec<stow_types::api::PublishedSlice>,
) -> stow_types::error::Result<()> {
    post_report_unchecked(edge, slices)
        .await?
        .map_err(|error| stow_error!("POST {}{REPORT_PATH}: {error}", edge.base()))
}

fn report_summary_of(slices: &[stow_types::api::PublishedSlice]) -> IndexReportSummary {
    IndexReportSummary {
        slices: slices.len(),
        added: slices.iter().map(|slice| slice.added.len()).sum(),
        retired: slices.iter().map(|slice| slice.retired.len()).sum(),
        full: !slices.is_empty() && slices.iter().all(|slice| slice.base_generation.is_none()),
    }
}

/// `stow-admin index report` - post every slice the run published to
/// the edge admin route (stow#940), so the scheduler applies a run's
/// slices in one append and one dispatch pass when they fit one body,
/// and in bounded parts when they do not.
/// Each slice's set is the servable subset of its export: a row whose
/// measured glibc floor exceeds the builder baseline publishes in the
/// index but a baseline host cannot load it, so it releases no
/// dependent — the same rule the catalog's coverage oracle applies.
async fn index_report<H: SliceHistory>(
    edge: &Edge,
    args: IndexReportArgs,
    connect: ConnectHistory<'_, H>,
) -> stow_types::error::Result<()> {
    let mut slices = Vec::with_capacity(args.file.len());
    for file in &args.file {
        slices.extend(slice_report_for(file, args.full).await?);
    }
    // Report host slices before cross-target slices so a multi-body report
    // never releases cross-target dependents before their runner host slice.
    slices.sort_by(|a, b| {
        slice_order_key(a.target.as_str(), a.rustc_version.as_str()).cmp(&slice_order_key(
            b.target.as_str(),
            b.rustc_version.as_str(),
        ))
    });
    let has_delta = slices.iter().any(|slice| slice.base_generation.is_some());
    let reported: Vec<(TargetTriple, WireRustcVersion, i64)> = slices
        .iter()
        .map(|slice| {
            (
                slice.target.clone(),
                slice.rustc_version.clone(),
                slice.generation,
            )
        })
        .collect();
    let mut summary = report_summary_of(&slices);
    let outcome = if slices.is_empty() {
        Ok(())
    } else {
        post_report_unchecked(edge, slices).await?
    };
    match outcome {
        Ok(()) => {}
        // A refused delta means the scheduler does not hold the
        // generation the run's export extended: each slice is replayed
        // from the generation it does hold along the slice's published
        // history, as `index reconcile` replays it. A refused full
        // report is an error.
        Err(zenwave::Error::Http {
            status, message, ..
        }) if status == zenwave::StatusCode::CONFLICT && has_delta => {
            tracing::warn!(
                answer = %message,
                "slice report refused - replaying each slice from the generation the scheduler holds"
            );
            let replayed = recover_reported(edge, &reported, connect).await?;
            summary = report_summary_of(&replayed);
            if !replayed.is_empty() {
                post_report(edge, replayed)
                    .await
                    .map_err(|error| error.wrap_err("replayed slice report"))?;
            }
        }
        Err(error) => {
            return Err(stow_error!("POST {}{REPORT_PATH}: {error}", edge.base()));
        }
    }
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
/// captured while the tag still named the previous index. `None` when
/// the file is its `.prev` at the same generation — an export whose
/// slice gained only folded marks keeps the published content and
/// generation, so the publish leaves the tag in place and the scheduler
/// already holds it.
async fn slice_report_for(
    file: &std::path::Path,
    full: bool,
) -> stow_types::error::Result<Option<stow_types::api::PublishedSlice>> {
    let bytes = tokio::fs::read(file)
        .await
        .map_err(|error| stow_error!("read index file {}: {error}", file.display()))?;
    let index = ArtifactIndex::decode(&bytes)
        .map_err(|error| stow_error!("decode index file {}: {error}", file.display()))?;
    if full {
        return full_slice(&index).map(Some);
    }

    // The delta base is the `.prev` sidecar — resolved exactly, never
    // silently: a first publish takes the explicit full path.
    let Some(prev) = read_prev_sidecar(file, index.header.generation).await? else {
        return full_slice(&index).map(Some);
    };
    if prev.header.generation == index.header.generation {
        let (content, base) = (content_sha256(&index)?, content_sha256(&prev)?);
        if content != base {
            return Err(stow_error!(
                "index file {} and its previous-index sidecar share generation {} but not \
                 their content",
                file.display(),
                index.header.generation
            ));
        }
        return Ok(None);
    }
    delta_slice(&prev, &index).map(Some)
}

/// The report that carries a slice from `prev` to `index`, the next
/// generation published on its tag: the rows that moved between them.
fn delta_slice(
    prev: &ArtifactIndex,
    index: &ArtifactIndex,
) -> stow_types::error::Result<stow_types::api::PublishedSlice> {
    let rows = semantic_rows(index)?;
    let prev_rows = semantic_rows(prev)?;
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
    Ok(stow_types::api::PublishedSlice {
        target: index.header.target.clone(),
        rustc_version: index.header.rustc_version.clone(),
        base_generation: Some(prev.header.generation),
        generation: index.header.generation,
        part: 0,
        parts: 1,
        added,
        retired,
    })
}

/// The explicit full report of a slice: its whole servable membership,
/// which the scheduler takes as the slice's set.
fn full_slice(index: &ArtifactIndex) -> stow_types::error::Result<stow_types::api::PublishedSlice> {
    Ok(stow_types::api::PublishedSlice {
        target: index.header.target.clone(),
        rustc_version: index.header.rustc_version.clone(),
        base_generation: None,
        generation: index.header.generation,
        part: 0,
        parts: 1,
        added: semantic_rows(index)?,
        retired: Vec::new(),
    })
}

/// What the scheduler holds of one slice, from `GET /api/v1/admin/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeldSlice {
    /// The generation it last applied.
    generation: i64,
    /// The generation of a multi-part report it holds staged.
    staged: Option<i64>,
}

/// The scheduler's held state of every slice it was reported.
async fn held_slices(
    edge: &Edge,
) -> stow_types::error::Result<BTreeMap<(TargetTriple, WireRustcVersion), HeldSlice>> {
    let status: stow_types::api::AdminStatus = edge.get_json("/api/v1/admin/status").await?;
    Ok(status
        .index_slices
        .into_iter()
        .map(|slice| {
            (
                (slice.target, slice.rustc_version),
                HeldSlice {
                    generation: slice.generation,
                    staged: slice.staged_generation,
                },
            )
        })
        .collect())
}

/// The reports that carry the scheduler from what it holds of a slice to
/// `live`, the slice's published state, oldest first.
///
/// The scheduler applies a delta only on exactly the generation it
/// holds, so a report it never received is replayed: the walk follows
/// `live`'s `previous` links back to the manifest at the held
/// generation, and each later manifest is reported as the delta from
/// its predecessor — the report its own publish run sent or lost. Part 0
/// of the first replayed delta supersedes any incomplete staged report
/// on that slice, so the cost is always the rows that moved since the
/// held generation, never the slice's size. A full report is sent only
/// where no base exists: the scheduler holds nothing of the slice (a
/// reset, or a slice it was never reported), an incomplete full resync
/// is staged at the live generation itself, or the walk reaches a
/// generation-1 manifest — a first or `full` publish, whose own report
/// was full — before the held generation, and the replay starts from
/// its full report.
///
/// # Errors
/// When a manifest above the held generation links no predecessor, or
/// a link's generation is not the one below it: the history does not
/// hold the scheduler's base, and the slice is republished by an
/// `index-publish.yml` run with `full`.
async fn recovery_reports(
    history: &impl SliceHistory,
    live: SliceManifest,
    held: Option<HeldSlice>,
) -> stow_types::error::Result<Vec<stow_types::api::PublishedSlice>> {
    let live_generation = live.index.header.generation;
    let held = match held {
        Some(held) if held.staged.is_none() && held.generation == live_generation => {
            return Ok(Vec::new());
        }
        None => return full_slice(&live.index).map(|full| vec![full]),
        Some(held) if held.generation == live_generation => {
            return full_slice(&live.index).map(|full| vec![full]);
        }
        Some(held) => held.generation,
    };
    let target = live.index.header.target.clone();
    let rustc_version = live.index.header.rustc_version.clone();
    // Newest first: `live`, then each manifest it links, down to the base.
    let mut walked = vec![live];
    let base = loop {
        let oldest = walked.last().expect("the walk starts at the live manifest");
        let generation = oldest.index.header.generation;
        if generation == held {
            break walked.pop().map(|base| base.index);
        }
        if generation == 1 {
            break None;
        }
        let Some(previous) = oldest.previous.clone() else {
            return Err(stow_error!(
                "{target}/{rustc_version}: the scheduler holds generation {held}, and the \
                 published history from the live generation {live_generation} ends at \
                 generation {generation}, which links no earlier manifest — republish the \
                 slice with an index-publish.yml run with `full`"
            ));
        };
        let linked = history.linked(&target, &rustc_version, &previous).await?;
        if linked.index.header.generation != generation - 1 {
            return Err(stow_error!(
                "{target}/{rustc_version}: generation {generation} links {previous} at \
                 generation {}, not {}",
                linked.index.header.generation,
                generation - 1
            ));
        }
        walked.push(linked);
    };
    let mut steps = walked.into_iter().rev().map(|manifest| manifest.index);
    let mut reports = Vec::new();
    let mut prev = if let Some(base) = base {
        base
    } else {
        let first = steps.next().expect("the walk holds the live manifest");
        reports.push(full_slice(&first)?);
        first
    };
    for index in steps {
        reports.push(delta_slice(&prev, &index)?);
        prev = index;
    }
    Ok(reports)
}

/// After a refused delta: every reported slice replayed from the
/// generation the scheduler holds to its live manifest, which must be
/// the generation the run reported — the run published it.
async fn recover_reported<H: SliceHistory>(
    edge: &Edge,
    slices: &[(TargetTriple, WireRustcVersion, i64)],
    connect: ConnectHistory<'_, H>,
) -> stow_types::error::Result<Vec<stow_types::api::PublishedSlice>> {
    let held = held_slices(edge).await?;
    let mut histories: BTreeMap<WireRustcVersion, H> = BTreeMap::new();
    let mut reports = Vec::new();
    for (target, rustc_version, generation) in slices {
        if !histories.contains_key(rustc_version) {
            histories.insert(rustc_version.clone(), connect(rustc_version.clone()).await?);
        }
        let history = &histories[rustc_version];
        let live = history.live(target, rustc_version).await?.ok_or_else(|| {
            stow_error!("{target}/{rustc_version}: the reported slice has no published index")
        })?;
        if live.index.header.generation != *generation {
            return Err(stow_error!(
                "{target}/{rustc_version}: the live index is generation {}, not the reported {generation}",
                live.index.header.generation,
            ));
        }
        let key = (target.clone(), rustc_version.clone());
        reports.extend(recovery_reports(history, live, held.get(&key).copied()).await?);
    }
    Ok(reports)
}

/// The verified `index.<target>.<rustc>` slices that exist for `rustc_version`,
/// in `CI_TARGET_TRIPLES` order. The slice tags follow from the supported
/// targets and the rustc, so no tag listing is needed; a target whose slice
/// was never published is skipped.
async fn published_slices(
    history: &impl SliceHistory,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<SliceManifest>> {
    let targets = CI_TARGET_TRIPLES
        .iter()
        .map(|target| {
            TargetTriple::parse(*target)
                .map_err(|error| stow_error!("CI_TARGET_TRIPLES entry {target}: {error}"))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let live = futures_util::stream::iter(
        targets
            .iter()
            .map(|target| history.live(target, rustc_version)),
    )
    .buffered(PREV_PULL_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    Ok(live.into_iter().flatten().collect())
}

/// `stow-admin index sync-lookup`: pull every live verified
/// `index.<target>.<rustc>` slice from GHCR and upload its deduplicated
/// lookup JSON to R2.
async fn index_sync_lookup(
    args: crate::lookup_r2::IndexSyncLookupArgs,
) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let history = PullContext::connect(&rustc_version).await?;
    let published = published_slices(&history, &rustc_version).await?;
    for slice in &published {
        let lookup = LookupIndex::from_artifact_index(&slice.index);
        let summary = crate::lookup_r2::upload_lookup_index(&lookup, &args.bucket).await?;
        let line = serde_json::to_string(&summary)
            .map_err(|error| stow_error!("serialize lookup upload summary: {error}"))?;
        render::emit_line(&line);
    }
    Ok(())
}

/// `stow-admin index reconcile`: the published slices of one rustc the
/// scheduler does not hold at their live generation, each replayed from
/// the generation it holds ([`recovery_reports`]). Every manifest read
/// is signature-verified against the index workflow's identity, exactly
/// as the export reads them.
async fn index_reconcile(edge: &Edge, args: IndexReconcileArgs) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let history = PullContext::connect(&rustc_version).await?;
    let held = held_slices(edge).await?;
    let published = published_slices(&history, &rustc_version).await?;
    let summary = reconcile(edge, &history, published, &held).await?;
    let line = serde_json::to_string(&summary)
        .map_err(|error| stow_error!("serialize index reconcile summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// Replay every `live` slice the scheduler does not hold as published
/// and post the reports, host slices before cross-target slices.
async fn reconcile(
    edge: &Edge,
    history: &impl SliceHistory,
    mut live: Vec<SliceManifest>,
    held: &BTreeMap<(TargetTriple, WireRustcVersion), HeldSlice>,
) -> stow_types::error::Result<IndexReconcileSummary> {
    live.sort_by(|a, b| {
        slice_order_key(
            a.index.header.target.as_str(),
            a.index.header.rustc_version.as_str(),
        )
        .cmp(&slice_order_key(
            b.index.header.target.as_str(),
            b.index.header.rustc_version.as_str(),
        ))
    });
    let replays = futures_util::stream::iter(live.into_iter().map(|manifest| {
        let key = (
            manifest.index.header.target.clone(),
            manifest.index.header.rustc_version.clone(),
        );
        recovery_reports(history, manifest, held.get(&key).copied())
    }))
    .buffered(PREV_PULL_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    let summary = IndexReconcileSummary {
        reported: replays.iter().filter(|reports| !reports.is_empty()).count(),
        reports: replays.iter().map(Vec::len).sum(),
        full: replays
            .iter()
            .flatten()
            .filter(|report| report.base_generation.is_none())
            .count(),
    };
    let reports: Vec<_> = replays.into_iter().flatten().collect();
    tracing::info!(
        slices = summary.reported,
        reports = summary.reports,
        full = summary.full,
        "replayed the published slices the scheduler does not hold at their live generation"
    );
    if !reports.is_empty() {
        post_report(edge, reports)
            .await
            .map_err(|error| error.wrap_err("reconcile slice report"))?;
    }
    Ok(summary)
}

/// Cache packages probed in flight — anonymous tag listings against the
/// registry's rate limit, one pull token each.
const PUBLISHED_PROBE_CONCURRENCY: usize = 8;

/// `stow-admin index published-rustcs`.
async fn published_rustcs() -> stow_types::error::Result<()> {
    let releases = crate::rust_channel::stable_releases().await?;
    let base = registry_base()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let published = probe_published(&base, &http, releases, PUBLISHED_PROBE_CONCURRENCY).await?;
    if published.is_empty() {
        return Err(stow_error!(
            "no stable rustc release has a published stow-cache package"
        ));
    }
    for rustc in &published {
        render::emit_line(rustc.as_ref());
    }
    Ok(())
}

/// The rustcs of `candidates` whose cache package holds tags, probed
/// `concurrency` at a time, in candidate order. A package the registry
/// reports absent (GHCR answers an unpublished or private repository
/// `403`/`DENIED`, a spec registry `404`/`NAME_UNKNOWN`) is not
/// published, and neither is an empty one; any other refusal or
/// transport failure fails the probe.
async fn probe_published(
    base: &stow_oci::RegistryBase,
    http: &stow_oci::RegistryHttp,
    candidates: Vec<WireRustcVersion>,
    concurrency: usize,
) -> stow_types::error::Result<Vec<WireRustcVersion>> {
    use futures_util::{StreamExt as _, TryStreamExt as _};
    let published: Vec<WireRustcVersion> = futures_util::stream::iter(candidates)
        .map(|rustc| async move {
            let repository = cache_repository(&rustc);
            let holds_tags = base
                .session(&repository, http)
                .has_tags()
                .await
                .map_err(|error| stow_error!("probe {repository}: {error}"))?;
            Ok::<_, stow_types::error::Error>(holds_tags.then_some(rustc))
        })
        .buffered(concurrency)
        .try_filter_map(|rustc| async move { Ok(rustc) })
        .try_collect()
        .await?;
    Ok(published)
}

/// The JSON line `index reconcile` prints on stdout.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct IndexReconcileSummary {
    /// Slices the reconcile replayed.
    reported: usize,
    /// Reports the replay posted — one per generation the scheduler
    /// lacked, from the first with no base.
    reports: usize,
    /// Of those, the full reports: a slice the scheduler holds nothing
    /// or a staged full report of, or a first or `full` publish the
    /// replay passed.
    full: usize,
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

fn mock_registry_binary() -> stow_types::error::Result<std::path::PathBuf> {
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
    Ok(mock_registry_exe)
}

/// Mock-key phase 1: delegate the signed index write to the sibling
/// `stow-mock-registry publish-index` binary. The child reports the manifest
/// digest and outcome on its last stdout line.
async fn publish_index_mock(
    mock_registry_exe: &std::path::Path,
    file: &std::path::Path,
    registry_root: &str,
    private_key_path: &str,
) -> stow_types::error::Result<(String, &'static str)> {
    let output = tokio::process::Command::new(mock_registry_exe)
        .arg("publish-index")
        .arg("--file")
        .arg(file)
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

/// Mock-key phase 2: delegate the signed folded-set write to the sibling
/// `stow-mock-registry publish-folded` binary. When multi-slice tags were
/// filtered out, write the filtered list to a temporary file beside the export
/// so the exported file stays intact.
async fn publish_folded_mock(
    mock_registry_exe: &std::path::Path,
    out_dir: &std::path::Path,
    slice: &PreparedSlice,
    filtered: &[String],
    registry_root: &str,
    private_key_path: &str,
) -> stow_types::error::Result<()> {
    if filtered == slice.folded.as_slice() {
        return run_mock_publish_folded(
            mock_registry_exe,
            slice,
            &slice.folded_path,
            registry_root,
            private_key_path,
        )
        .await;
    }
    let mut temp = tempfile::NamedTempFile::new_in(out_dir)
        .map_err(|error| stow_error!("create filtered folded temp file: {error}"))?;
    let bytes = serde_json::to_vec(filtered)?;
    std::io::Write::write_all(&mut temp, &bytes)
        .map_err(|error| stow_error!("write filtered folded temp file: {error}"))?;
    run_mock_publish_folded(
        mock_registry_exe,
        slice,
        temp.path(),
        registry_root,
        private_key_path,
    )
    .await
}

async fn run_mock_publish_folded(
    mock_registry_exe: &std::path::Path,
    slice: &PreparedSlice,
    folded_path: &std::path::Path,
    registry_root: &str,
    private_key_path: &str,
) -> stow_types::error::Result<()> {
    let output = tokio::process::Command::new(mock_registry_exe)
        .arg("publish-folded")
        .arg("--target")
        .arg(&slice.summary.target)
        .arg("--rustc-version")
        .arg(&slice.summary.rustc_version)
        .arg("--file")
        .arg(folded_path)
        .arg("--registry-root")
        .arg(registry_root)
        .arg("--private-key")
        .arg(private_key_path)
        .output()
        .await?;
    if !output.status.success() {
        return Err(stow_error!(
            "mock registry publish-folded failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
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
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let trust = stow_oci::verify::records_trust().await?;
    let mut slices = Vec::new();
    for version in &args.rustc_versions {
        let rustc_version = WireRustcVersion::parse(version.clone())
            .map_err(|error| stow_error!("--rustc-version: {error}"))?;
        let repository = cache_repository(&rustc_version);
        let session = base.session(&repository, &http);
        let ctx = PullContext {
            session,
            repository,
            trust: trust.clone(),
        };
        slices.extend(
            published_slices(&ctx, &rustc_version)
                .await?
                .into_iter()
                .map(|manifest| manifest.index),
        );
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
    /// The canonical `ghcr.io/water-rs/stow-cache-v2-<RUSTC>` signed
    /// references bind.
    const REFERENCE_BASE: &str = "ghcr.io/water-rs/stow-cache-v2-1.88.0";
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
            node_profile: stow_types::node_profile::NodeProfile::Dev,
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
            build_scripts: Vec::new(),
            local_programs: Vec::new(),
        }
    }

    /// A build script is an output of its crate's node: its record joins
    /// the slice's `build_scripts`, never its node `rows`, whether it
    /// arrives in a new pass or rides in the published slice it extends,
    /// and a script published by several nodes is one row.
    #[test]
    fn build_script_records_fold_beside_the_node_rows() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let key = (TargetTriple::parse(TARGET).expect("target"), rustc.clone());
        let script = |task_id: &str, c_metadata: &str| {
            let mut script = record(task_id);
            script.c_metadata = CMetadata::parse(c_metadata).expect("c_metadata");
            script.artifact_kind = ArtifactKind::BuildScript;
            script.crate_types = vec![RustCrateType::Bin];
            script
        };
        let carried = record_to_index_row(&script("aaaa1111", "b5c00001"));
        let mut prev_index = prev_index(vec![record_to_index_row(&record("bbbb2222"))], 3);
        prev_index.build_scripts = vec![carried];
        let prev = BTreeMap::from([(
            key.clone(),
            PrevSlice {
                index: prev_index,
                folded: BTreeSet::new(),
            },
        )]);
        let mut new_rows = BTreeMap::<_, RowsByIdentity>::new();
        let rows = new_rows.entry(key.clone()).or_default();
        // The same script published by two nodes, and a fresh one.
        fold_row(rows, record_to_index_row(&script("cccc3333", "b5c00001"))).expect("fold");
        fold_row(rows, record_to_index_row(&script("dddd4444", "b5c00002"))).expect("fold");
        fold_row(rows, record_to_index_row(&record("eeee5555"))).expect("fold");

        let slices = merge_exports(prev, &new_rows, &BTreeMap::new(), &BTreeMap::new(), &rustc)
            .expect("merge");
        let slice = slices
            .iter()
            .find(|slice| (slice.target.clone(), slice.rustc_version.clone()) == key)
            .expect("the slice");
        assert!(
            slice
                .index
                .rows
                .iter()
                .all(|row| row.artifact_kind != ArtifactKind::BuildScript),
            "a build script is not a node row"
        );
        assert_eq!(slice.index.rows.len(), 2);
        assert_eq!(slice.index.header.row_count, 2);
        let scripts: Vec<&str> = slice
            .index
            .build_scripts
            .iter()
            .map(|row| row.c_metadata.as_str())
            .collect();
        assert_eq!(scripts, ["b5c00001", "b5c00002"]);
    }

    /// The O(change) gate: a second export over N folded records plus k
    /// new ones pulls exactly k records artifacts — the folded set, not
    /// the store, is what a pass re-reads. And a second rustc's tags —
    /// its records, and its own folded/index pair — are never pulled by
    /// R's pass at all.
    #[test]
    fn a_local_program_is_folded_and_reported_without_a_bundle() {
        let row = record("aaaa1111");
        let key = (row.target.clone(), row.rustc_version.clone());
        let program = LocalProcMacro {
            node: stow_types::task_graph::TaskNodeIdentity {
                crate_name: row.crate_name,
                version: row.version,
                features_json: row.features_json,
                target: row.target,
                rustc_version: row.rustc_version.clone(),
                host_side: row.unit_shape.side == stow_types::public_cache::UnitSide::Host,
                profile: row.node_profile,
            },
            dependency_task_ids: row.dependency_task_ids,
            dependency_c_metadata_json: row.dependency_c_metadata_json,
            compile_key: row.compile_key,
            c_metadata: row.c_metadata,
            unit_shape: row.unit_shape,
        };
        let programs = BTreeMap::from([(key.clone(), vec![program.clone()])]);
        let marks = BTreeMap::from([(key.clone(), BTreeSet::from(["records-test".to_owned()]))]);
        let slices = merge_exports(
            BTreeMap::new(),
            &BTreeMap::new(),
            &programs,
            &marks,
            &row.rustc_version,
        )
        .unwrap();
        let slice = slices
            .iter()
            .find(|slice| (slice.target.clone(), slice.rustc_version.clone()) == key)
            .unwrap();
        assert_eq!(slice.index.rows, []);
        assert_eq!(slice.index.local_programs, [program]);
        assert_eq!(semantic_rows(&slice.index).unwrap().len(), 1);
        assert_eq!(slice.folded, ["records-test"]);
    }

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
            Box::pin(async move {
                Ok(BuildRecords {
                    artifacts: vec![record(&task_id)],
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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
        assert_eq!(pass.new_records.artifacts.len(), 2);
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
                Box::pin(async move {
                    Ok(BuildRecords {
                        artifacts: vec![record(&task_id)],
                        local_programs: Vec::new(),
                    })
                }) as PullFut<'static, BuildRecords>
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
            Box::pin(async move {
                Ok(BuildRecords {
                    artifacts: vec![record(&task_id)],
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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
            Box::pin(async move {
                Ok(BuildRecords {
                    artifacts: vec![second],
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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
                Ok(BuildRecords {
                    artifacts: vec![record],
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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
                Ok(BuildRecords {
                    artifacts: vec![record],
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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
    ) -> impl Fn(&str) -> PullFut<'static, BuildRecords> + Send + Sync {
        move |tag: &str| {
            let records = by_tag
                .get(tag)
                .unwrap_or_else(|| panic!("unknown records tag {tag}"))
                .clone();
            Box::pin(async move {
                Ok(BuildRecords {
                    artifacts: records,
                    local_programs: Vec::new(),
                })
            }) as PullFut<'static, BuildRecords>
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

    #[test]
    fn fold_row_preserves_profiles_of_a_shared_unit() {
        use stow_types::node_profile::NodeProfile;
        let dev = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let mut release = dev.clone();
        release.node_profile = NodeProfile::Release;
        let mut rows = RowsByIdentity::default();
        for row in [dev.clone(), release.clone(), dev.clone()] {
            fold_row(&mut rows, row).expect("fold row");
        }
        assert_eq!(rows.values().count(), 2);
        assert!(rows.values().any(|row| row == &dev));
        assert!(rows.values().any(|row| row == &release));
    }

    /// One node's record of `aaaa1111` at `invocation`, whose bundle
    /// carries `digest`. The bundle tag names no unit shape, so every
    /// such record lands on one tag.
    fn shaped_record(
        invocation: stow_types::public_cache::UnitInvocation,
        digest: &str,
    ) -> ArtifactRecord {
        let mut record = record("aaaa1111");
        record.unit_shape.invocation = invocation;
        record.bundle_digest = format!("sha256:{digest:0>64}");
        record
    }

    /// A rebuild of one node that publishes its unit at another shape
    /// moves the bundle tag: within one pass, the newer build's row is
    /// the only one the slice keeps, whichever shape sorts first.
    #[test]
    fn a_newer_build_on_the_same_tag_evicts_the_older_shape_within_a_pass() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        for (older, newer) in [(Target, Native), (Native, Target)] {
            let older = shaped_record(older, "01d");
            let newer = shaped_record(newer, "e3");
            let tags = vec![
                records_tag(RUSTC, "bbbb2222", build(9)),
                records_tag(RUSTC, "bbbb2222", build(10)),
            ];
            let by_tag = BTreeMap::from([
                (tags[0].clone(), vec![older]),
                (tags[1].clone(), vec![newer.clone()]),
            ]);
            let pass = block_on(export_pass(
                &tags,
                pull_no_prev(),
                pull_records_by_tag(by_tag),
                false,
                &rustc,
            ))
            .expect("export pass");
            assert_eq!(
                target_slice(&pass).index.rows,
                [record_to_index_row(&newer)]
            );
        }
    }

    /// The same eviction across the pass boundary, on the build-script
    /// list: the published slice's row on the tag leaves once a newer
    /// build of its node publishes the unit at another shape.
    #[test]
    fn a_newer_build_on_the_same_tag_evicts_the_published_shape() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let script = |invocation, digest| {
            let mut script = shaped_record(invocation, digest);
            script.artifact_kind = ArtifactKind::BuildScript;
            script.crate_types = vec![RustCrateType::Bin];
            script
        };
        let mut published = prev_index(Vec::new(), 4);
        published.build_scripts = vec![record_to_index_row(&script(Target, "01d"))];
        let newer = script(Native, "e3");
        let tags = vec![
            folded_tag(TARGET, RUSTC),
            records_tag(RUSTC, "bbbb2222", build(10)),
        ];
        let by_tag = BTreeMap::from([(tags[1].clone(), vec![newer.clone()])]);
        let pass = block_on(export_pass(
            &tags,
            pull_only_prev(published, [records_tag(RUSTC, "bbbb2222", build(9))].into()),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("export pass");
        let slice = target_slice(&pass);
        assert_eq!(slice.index.rows, []);
        assert_eq!(slice.index.build_scripts, [record_to_index_row(&newer)]);
    }

    /// A `--full` pass re-pulls every build of the rustc in build order,
    /// so a superseded shape on a moved tag never survives it.
    #[test]
    fn a_full_pass_keeps_only_the_newest_row_on_a_tag() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let older = shaped_record(Target, "01d");
        let newer = shaped_record(Native, "e3");
        let tags = vec![
            folded_tag(TARGET, RUSTC),
            records_tag(RUSTC, "bbbb2222", build(10)),
            records_tag(RUSTC, "bbbb2222", build(9)),
        ];
        let by_tag = BTreeMap::from([
            (tags[1].clone(), vec![newer.clone()]),
            (tags[2].clone(), vec![older]),
        ]);
        let pass = block_on(export_pass(
            &tags,
            pull_no_prev(),
            pull_records_by_tag(by_tag),
            true,
            &rustc,
        ))
        .expect("export pass");
        assert_eq!(
            target_slice(&pass).index.rows,
            [record_to_index_row(&newer)]
        );
    }

    /// One bundle published at both invocation spellings: every row
    /// carrying the digest the tag names stays, within a pass and on
    /// top of the published slice, and a newer digest evicts them all.
    #[test]
    fn rows_sharing_the_bundles_digest_stay_side_by_side() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let native = record_to_index_row(&shaped_record(Native, "b0"));
        let target = record_to_index_row(&shaped_record(Target, "b0"));
        let mut rows = RowsByIdentity::default();
        for row in [
            native.clone(),
            target.clone(),
            native.clone(),
            target.clone(),
        ] {
            fold_row(&mut rows, row).expect("fold row");
        }
        assert_eq!(rows.values().count(), 2);
        assert!(rows.values().any(|row| row == &native));
        assert!(rows.values().any(|row| row == &target));

        let newer = record_to_index_row(&shaped_record(Native, "e3"));
        fold_row(&mut rows, newer.clone()).expect("fold row");
        assert_eq!(rows.into_values().collect::<Vec<_>>(), [newer]);
    }

    /// The published slice's two shapes of one bundle survive a pass
    /// that folds them again from a re-pulled build of the same bundle.
    #[test]
    fn a_published_bundles_shapes_stay_across_the_pass_boundary() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let native = shaped_record(Native, "b0");
        let target = shaped_record(Target, "b0");
        let published = prev_index(
            vec![record_to_index_row(&native), record_to_index_row(&target)],
            4,
        );
        let tags = vec![
            folded_tag(TARGET, RUSTC),
            records_tag(RUSTC, "bbbb2222", build(10)),
        ];
        let by_tag = BTreeMap::from([(tags[1].clone(), vec![native.clone()])]);
        let pass = block_on(export_pass(
            &tags,
            pull_only_prev(published, [records_tag(RUSTC, "bbbb2222", build(9))].into()),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("export pass");
        let rows = &target_slice(&pass).index.rows;
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&record_to_index_row(&native)));
        assert!(rows.contains(&record_to_index_row(&target)));
    }

    /// Eviction follows the tag: one node's units at two shapes under
    /// distinct bundle tags both stay.
    #[test]
    fn rows_on_distinct_tags_stay_side_by_side() {
        use stow_types::public_cache::UnitInvocation::{Native, Target};
        let first = record_to_index_row(&shaped_record(Target, "01d"));
        // The kind suffix makes it another tag: `…-aaaa1111-dy`.
        let mut second = record_to_index_row(&shaped_record(Native, "e3"));
        second.artifact_kind = ArtifactKind::Dylib;
        let mut rows = RowsByIdentity::default();
        for row in [first.clone(), second.clone()] {
            fold_row(&mut rows, row).expect("fold row");
        }
        assert_eq!(rows.values().count(), 2);
        assert!(rows.values().any(|row| row == &first));
        assert!(rows.values().any(|row| row == &second));
    }

    #[test]
    fn semantic_rows_preserves_each_profile() {
        use stow_types::node_profile::NodeProfile;
        let dev = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let mut release = dev.clone();
        release.node_profile = NodeProfile::Release;
        let rows =
            semantic_rows(&prev_index(vec![dev.clone(), release, dev], 3)).expect("semantic rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .map(|row| row.node_profile)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([NodeProfile::Dev, NodeProfile::Release]),
        );
    }

    #[tokio::test]
    async fn slice_report_tracks_profile_additions_and_retirements() {
        use stow_types::node_profile::NodeProfile;
        let dir = tempfile::tempdir().expect("report fixture dir");
        let file = dir.path().join(index_tag(TARGET, RUSTC));
        let dev = record_to_index_row(&shared_unit_record(&["dep-left"]));
        let mut release = dev.clone();
        release.node_profile = NodeProfile::Release;
        for retain_dev in [true, false] {
            let current = if retain_dev {
                vec![dev.clone(), release.clone()]
            } else {
                vec![release.clone()]
            };
            std::fs::write(
                &file,
                stow_shim::encode_index(&prev_index(current, 3)).expect("encode index"),
            )
            .expect("write index");
            std::fs::write(
                prev_path(&file),
                stow_shim::encode_index(&prev_index(vec![dev.clone()], 2)).expect("encode prev"),
            )
            .expect("write previous index");
            let report = slice_report_for(&file, false)
                .await
                .expect("delta report")
                .expect("the slice moved");
            assert_eq!(report.base_generation, Some(2));
            assert_eq!(report.added.len(), 1);
            assert_eq!(report.added[0].node_profile, NodeProfile::Release);
            assert_eq!(report.retired.len(), usize::from(!retain_dev));
            if !retain_dev {
                assert_eq!(report.retired[0].node_profile, NodeProfile::Dev);
            }
        }
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
        let transport = format!("127.0.0.1:28123/water-rs/stow-cache-v2-1.88.0:{tag}");
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
            stow_shim::encode_index(&prev_index(vec![left.clone(), right], 3))
                .expect("encode index"),
        )
        .expect("write index file");
        std::fs::write(
            prev_path(&file),
            stow_shim::encode_index(&prev_index(vec![left], 2)).expect("encode prev"),
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

    /// A slice's published history held in memory: each manifest under
    /// a digest naming its generation, linked to the one below it.
    struct FakeHistory {
        live: Option<String>,
        manifests: BTreeMap<String, (ArtifactIndex, Option<String>)>,
    }

    impl FakeHistory {
        /// `indexes`, oldest first, each linked to the one before it;
        /// the last is live.
        fn chain(indexes: Vec<ArtifactIndex>) -> Self {
            let mut manifests = BTreeMap::new();
            let mut previous: Option<String> = None;
            for index in indexes {
                let digest = format!("sha256:{:064}", manifests.len());
                manifests.insert(digest.clone(), (index, previous.replace(digest)));
            }
            Self {
                live: previous,
                manifests,
            }
        }

        fn manifest(&self, digest: &str) -> SliceManifest {
            let (index, previous) = self.manifests[digest].clone();
            SliceManifest { index, previous }
        }

        fn live_manifest(&self) -> SliceManifest {
            self.manifest(self.live.as_deref().expect("a live manifest"))
        }
    }

    impl SliceHistory for FakeHistory {
        fn live(
            &self,
            _target: &TargetTriple,
            _rustc_version: &WireRustcVersion,
        ) -> impl Future<Output = stow_types::error::Result<Option<SliceManifest>>> + Send {
            std::future::ready(Ok(self.live.as_deref().map(|digest| self.manifest(digest))))
        }

        fn linked(
            &self,
            _target: &TargetTriple,
            _rustc_version: &WireRustcVersion,
            manifest_digest: &str,
        ) -> impl Future<Output = stow_types::error::Result<SliceManifest>> + Send {
            std::future::ready(Ok(self.manifest(manifest_digest)))
        }
    }

    /// The registry connection a report that never needs a replay is
    /// handed: reaching it fails the test.
    fn no_history(_rustc: WireRustcVersion) -> PullFut<'static, FakeHistory> {
        panic!("the report needed no replay")
    }

    /// The registry connection a replaying report is handed: the
    /// fixture slice's history from generation 1 to the file's 3.
    fn history_to_generation_3(_rustc: WireRustcVersion) -> PullFut<'static, FakeHistory> {
        Box::pin(async {
            Ok(FakeHistory::chain(vec![
                prev_index(Vec::new(), 1),
                prev_index(vec![row("dep-left")], 2),
                prev_index(vec![row("dep-left"), row("dep-right")], 3),
            ]))
        })
    }

    fn row(dep: &str) -> ArtifactIndexRow {
        record_to_index_row(&shared_unit_record(&[dep]))
    }

    const fn held(generation: i64) -> HeldSlice {
        HeldSlice {
            generation,
            staged: None,
        }
    }

    /// `GET /api/v1/admin/status` holding the fixture slice at
    /// generation 1.
    const STATUS_AT_GENERATION_1: &str = r#"{"pending_miss":0,"pending_human":0,"ready":0,
        "in_flight":[],"targets":[],"dispatch_frozen":false,
        "index_slices":[{"target":"x86_64-unknown-linux-gnu","rustc_version":"1.88.0",
            "generation":1,"staged_generation":null}],
        "memory":{"resident_bytes":0,"normal_line_bytes":0,"small_line_bytes":0,
            "wasm_linear_bytes":null,"backlog_entries":0,"backlog_bytes":0}}"#;

    /// stow#1581: a delta report refused with the scheduler's 409 — it
    /// holds generation 1, not the base 2 the export extended — replays
    /// the slice from generation 1 along its published history: one
    /// delta per generation it lacks, never the slice's full membership.
    #[tokio::test]
    async fn a_conflicted_delta_replays_from_the_held_generation() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 409,
                retry_after: None,
                body: r#"{"error":"slice report base generation 2 conflicts with the live generation 1"}"#,
            },
            crate::test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_AT_GENERATION_1,
            },
            crate::test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"ok":true}"#,
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
            &history_to_generation_3,
        )
        .await
        .expect("the replayed report succeeds");
        let requests = server.join().await;
        assert_eq!(requests.len(), 4, "the delta, the status, then two replays");
        assert_eq!(requests[1].head.uri.path(), "/api/v1/admin/status");
        for (request, base) in requests[2..].iter().zip([1, 2]) {
            let replay = posted_report(request);
            assert_eq!(replay["base_generation"], base);
            assert_eq!(replay["generation"], base + 1);
            assert_eq!(replay["added"].as_array().expect("added rows").len(), 1);
        }
    }

    /// A full report over the edge's request limit posts as consecutive
    /// bodies, each under it: the slice's parts arrive in order with one
    /// generation and part count, and together carry every row once.
    #[tokio::test]
    async fn a_full_report_over_the_body_limit_posts_in_parts() {
        let dir = tempfile::tempdir().expect("report dir");
        let file = dir.path().join(index_tag(TARGET, RUSTC));
        let rows: Vec<_> = (0..12_000)
            .map(|i| record_to_index_row(&shared_unit_record(&[&format!("dep-{i}")])))
            .collect();
        std::fs::write(
            &file,
            stow_shim::encode_index(&prev_index(rows, 7)).expect("encode index"),
        )
        .expect("write index file");
        let server = crate::test_server::Loopback::start(Vec::new()).await;
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![file],
                full: true,
            },
            &no_history,
        )
        .await
        .expect("the parts post");
        let requests = server.join().await;
        assert!(requests.len() > 1, "the report needs several bodies");
        let mut identities = BTreeSet::new();
        for (at, request) in requests.iter().enumerate() {
            assert!(request.body.len() <= stow_types::api::REQUEST_BODY_LIMIT_BYTES);
            let slice = posted_report(request);
            assert_eq!(slice["part"], at);
            assert_eq!(slice["parts"], requests.len());
            assert_eq!(slice["generation"], 7);
            assert!(slice.get("base_generation").is_none());
            for row in slice["added"].as_array().expect("added rows") {
                assert!(identities.insert(row["dependency_identity"].to_string()));
            }
        }
        assert_eq!(identities.len(), 12_000);
    }

    /// A body over the edge's limit fails on the client naming the
    /// route and the size, and nothing is sent.
    #[tokio::test]
    async fn a_body_over_the_edge_limit_is_refused_before_sending() {
        let server = crate::test_server::Loopback::start(Vec::new()).await;
        let edge = Edge::for_test(server.url.clone());
        let body = "x".repeat(stow_types::api::REQUEST_BODY_LIMIT_BYTES);
        let error = edge
            .post_json::<_, serde_json::Value>("/api/v1/admin/index/published", &body)
            .await
            .expect_err("an oversized body");
        let message = error.to_string();
        assert!(
            message.contains("/api/v1/admin/index/published"),
            "{message}"
        );
        assert!(
            message.contains(&format!("{}-byte body", body.len() + 2)),
            "{message}"
        );
        assert!(server.join().await.is_empty(), "nothing was sent");
    }

    /// A replay refused the same way stays an error — the recovery
    /// itself failed, and no further request goes out.
    #[tokio::test]
    async fn a_conflicted_replay_is_an_error() {
        let server = crate::test_server::Loopback::start(vec![
            crate::test_server::Step::Respond {
                status: 409,
                retry_after: None,
                body: r#"{"error":"slice report base generation 2 conflicts with the live generation 1"}"#,
            },
            crate::test_server::Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_AT_GENERATION_1,
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
            &history_to_generation_3,
        )
        .await
        .expect_err("a refused replay is an error");
        let requests = server.join().await;
        assert_eq!(requests.len(), 3, "the delta, the status, one replay");
    }

    /// An export whose slice gained only folded marks keeps the
    /// published header, and its report sends nothing for the slice:
    /// the publish leaves the tag in place, and the scheduler holds it.
    #[tokio::test]
    async fn an_unchanged_slice_reports_nothing() {
        let dir = tempfile::tempdir().expect("report dir");
        let file = dir.path().join(index_tag(TARGET, RUSTC));
        let index =
            stow_shim::encode_index(&prev_index(vec![row("dep-left")], 2)).expect("encode index");
        std::fs::write(&file, &index).expect("write index file");
        std::fs::write(prev_path(&file), &index).expect("write prev sidecar");
        assert!(
            slice_report_for(&file, false)
                .await
                .expect("the report reads")
                .is_none()
        );
        let server = crate::test_server::Loopback::start(Vec::new()).await;
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![file],
                full: false,
            },
            &no_history,
        )
        .await
        .expect("nothing to report");
        assert!(server.join().await.is_empty(), "nothing was posted");
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
            &no_history,
        )
        .await
        .expect_err("a non-conflict refusal is an error");
        let requests = server.join().await;
        assert_eq!(requests.len(), 1, "no resync follows a non-409 refusal");
    }

    /// stow#1049: a publish that died between the index and folded
    /// tags leaves an index with no folded companion. The next export
    /// extends it with an empty folded set — every record refolds onto
    /// the published rows — instead of refusing the state.
    #[test]
    fn an_index_without_its_folded_companion_is_extended() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let published = record("aaaa1111");
        let new = record("bbbb2222");
        let prev = prev_index(vec![record_to_index_row(&published)], 4);
        let tags = vec![
            index_tag(TARGET, RUSTC),
            records_tag(RUSTC, "aaaa1111", BUILD),
            records_tag(RUSTC, "bbbb2222", BUILD),
        ];
        let by_tag = BTreeMap::from([
            (tags[1].clone(), vec![published]),
            (tags[2].clone(), vec![new]),
        ]);
        let pass = block_on(export_pass(
            &tags,
            pull_only_prev(prev, BTreeSet::new()),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("the orphaned index is extended");
        assert_eq!(pass.pulled, 2, "an empty folded set refolds every record");
        let slice = target_slice(&pass);
        assert_eq!(slice.index.header.generation, 5);
        assert_eq!(slice.index.rows.len(), 2);
        assert_eq!(slice.folded.len(), 2, "the next publish writes the pair");
    }

    /// A pass that folds only records the slice already serves adds
    /// folded marks and no content: the slice keeps its published
    /// header, so the generation it reports is the one its tag carries.
    #[test]
    fn a_pass_that_adds_no_content_keeps_the_published_generation() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let published = record("aaaa1111");
        let prev = prev_index(vec![record_to_index_row(&published)], 4);
        let tags = vec![
            index_tag(TARGET, RUSTC),
            records_tag(RUSTC, "aaaa1111", BUILD),
        ];
        let by_tag = BTreeMap::from([(tags[1].clone(), vec![published])]);
        let pass = block_on(export_pass(
            &tags,
            pull_only_prev(prev.clone(), BTreeSet::new()),
            pull_records_by_tag(by_tag),
            false,
            &rustc,
        ))
        .expect("the pass");
        let slice = target_slice(&pass);
        assert_eq!(slice.index.header, prev.header);
        assert_eq!(slice.folded.len(), 1, "the mark is still published");
    }

    /// stow#1049: a report that failed after its slices went live is
    /// retried by the next run, and stow#1581: what the scheduler lacks
    /// is replayed from the generation it holds, one delta per
    /// generation, never as the slice's full membership; a slice it
    /// holds is left alone.
    #[test]
    fn the_reconcile_replays_only_what_the_scheduler_lacks() {
        let history = FakeHistory::chain(vec![
            prev_index(vec![row("a")], 1),
            prev_index(vec![row("a"), row("b")], 2),
            prev_index(vec![row("b"), row("c")], 3),
            prev_index(vec![row("b"), row("c"), row("d")], 4),
        ]);
        let replay = |held| {
            block_on(recovery_reports(&history, history.live_manifest(), held))
                .expect("the history holds the base")
        };
        // The lost report of generation 4, and of 3 and 4.
        let lost = replay(Some(held(3)));
        assert_eq!(lost.len(), 1);
        assert_eq!((lost[0].base_generation, lost[0].generation), (Some(3), 4));
        assert_eq!((lost[0].added.len(), lost[0].retired.len()), (1, 0));
        let two = replay(Some(held(2)));
        assert_eq!(
            two.iter()
                .map(|report| (report.base_generation, report.generation))
                .collect::<Vec<_>>(),
            [(Some(2), 3), (Some(3), 4)]
        );
        assert_eq!((two[0].added.len(), two[0].retired.len()), (1, 1));
        // Held at the live generation: nothing to send.
        assert_eq!(
            replay(Some(held(4))),
            [] as [stow_types::api::PublishedSlice; 0]
        );
        // An interrupted staged report behind the live generation
        // recovers by replaying the delta from the held generation —
        // part 0 supersedes the staged state instead of re-sending the
        // whole slice (stow#1614).
        let interrupted = replay(Some(HeldSlice {
            generation: 3,
            staged: Some(4),
        }));
        assert_eq!(interrupted.len(), 1);
        assert_eq!(
            (interrupted[0].base_generation, interrupted[0].generation),
            (Some(3), 4)
        );
        assert_eq!(
            (interrupted[0].added.len(), interrupted[0].retired.len()),
            (1, 0)
        );
        // No base — a scheduler holding nothing, or an incomplete full
        // resync staged at the live generation itself — takes the live
        // slice in full.
        for no_base in [
            None,
            Some(HeldSlice {
                generation: 4,
                staged: Some(4),
            }),
        ] {
            let full = replay(no_base);
            assert_eq!(full.len(), 1);
            assert_eq!((full[0].base_generation, full[0].generation), (None, 4));
            assert_eq!(full[0].added.len(), 3);
        }
    }

    /// stow#1614: a delta over `SLICE_REPORT_PART_BYTES` stays a delta
    /// rather than degrading into a full slice report.
    #[test]
    fn a_delta_over_one_part_stays_a_delta() {
        let base_rows: Vec<_> = (0..10).map(|i| row(&format!("base-{i:04}"))).collect();
        let mut next_rows = base_rows.clone();
        next_rows.extend((0..3_500).map(|i| row(&format!("added-crate-{i:05}"))));
        let prev = prev_index(base_rows, 292);
        let live = prev_index(next_rows, 293);
        let delta = delta_slice(&prev, &live).expect("delta");
        assert!(
            stow_types::api::json_len(&delta).expect("len")
                > stow_types::api::SLICE_REPORT_PART_BYTES,
            "fixture delta exceeds one part"
        );
        assert_eq!(delta.base_generation, Some(292));
        assert_eq!(delta.generation, 293);
        assert_eq!(delta.added.len(), 3_500);
        let bodies = stow_types::api::PublishedRunReport::into_bodies(
            vec![delta],
            stow_types::api::SLICE_REPORT_PART_BYTES,
            stow_types::api::REQUEST_BODY_LIMIT_BYTES,
        )
        .expect("split bodies");
        assert!(bodies.len() > 1);
        assert!(
            bodies
                .iter()
                .flat_map(|body| &body.slices)
                .all(|part| part.base_generation == Some(292))
        );
    }

    /// A `full` publish restamps generation 1 and links the manifest it
    /// replaced: a scheduler holding a generation from before it replays
    /// from that publish's own full report, then the deltas above it.
    #[test]
    fn the_replay_starts_at_a_full_publish_after_the_held_generation() {
        let history = FakeHistory::chain(vec![
            prev_index(vec![row("a")], 4),
            prev_index(vec![row("a"), row("b")], 5),
            prev_index(vec![row("b")], 1),
            prev_index(vec![row("b"), row("c")], 2),
        ]);
        let replay = block_on(recovery_reports(
            &history,
            history.live_manifest(),
            Some(held(5)),
        ))
        .expect("the replay");
        assert_eq!(
            replay
                .iter()
                .map(|report| (report.base_generation, report.generation))
                .collect::<Vec<_>>(),
            [(None, 1), (Some(1), 2)]
        );
    }

    /// A history that does not reach the held generation — a manifest
    /// above it links no predecessor, or a link skips a generation — is
    /// an error naming the slice, never a silent full report.
    #[test]
    fn a_history_without_the_held_base_is_an_error() {
        let mut history = FakeHistory::chain(vec![
            prev_index(vec![row("a")], 2),
            prev_index(vec![row("a"), row("b")], 3),
        ]);
        let unlinked = FakeHistory {
            live: history.live.clone(),
            manifests: history
                .manifests
                .iter()
                .map(|(digest, (index, _))| (digest.clone(), (index.clone(), None)))
                .collect(),
        };
        let error = block_on(recovery_reports(
            &unlinked,
            unlinked.live_manifest(),
            Some(held(2)),
        ))
        .expect_err("no link down to generation 2");
        let message = error.to_string();
        assert!(
            message.contains(TARGET) && message.contains("`full`"),
            "{message}"
        );
        // Generation 3 linking generation 1 skips the held generation 2.
        let oldest = history.manifests.keys().next().expect("a manifest").clone();
        history
            .manifests
            .get_mut(&oldest)
            .expect("oldest")
            .0
            .header
            .generation = 1;
        let error = block_on(recovery_reports(
            &history,
            history.live_manifest(),
            Some(held(2)),
        ))
        .expect_err("a skipped generation");
        assert!(error.to_string().contains("not 2"), "{error}");
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

    /// The scripted answers of one anonymous probe: the challenge, the
    /// token and the tag listing.
    fn probe_steps(
        base: &str,
        token: crate::test_server::Step,
        tags: crate::test_server::Step,
    ) -> Vec<crate::test_server::Step> {
        use crate::test_server::Step;
        vec![
            Step::RespondWith {
                status: 401,
                retry_after: None,
                headers: vec![(
                    "www-authenticate".to_owned(),
                    format!("Bearer realm=\"{base}/token\",service=\"mock-registry\""),
                )],
                body: "",
            },
            token,
            tags,
        ]
    }

    fn respond(status: u16, body: &'static str) -> crate::test_server::Step {
        crate::test_server::Step::Respond {
            status,
            retry_after: None,
            body,
        }
    }

    const TOKEN: &str = r#"{"token":"t"}"#;
    const NAME_UNKNOWN: &str =
        r#"{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known"}]}"#;
    const DENIED: &str =
        r#"{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}"#;

    async fn probe(
        script: impl FnOnce(&str) -> Vec<crate::test_server::Step>,
        rustcs: &[&str],
    ) -> stow_types::error::Result<Vec<String>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let server = crate::test_server::Loopback::start_on(listener, url.clone(), script(&url));
        let base = stow_oci::RegistryBase::parse(&url).expect("registry base");
        let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT)
            .await
            .expect("registry http");
        let candidates = rustcs
            .iter()
            .map(|rustc| WireRustcVersion::parse(*rustc).expect("rustc"))
            .collect();
        // One in flight: the scripted server answers in arrival order.
        let result = probe_published(&base, &http, candidates, 1).await;
        let requests = server.join().await;
        if let Ok(published) = &result {
            // A package costs its token mint and one tag listing.
            assert!(requests.len() >= 2 * rustcs.len() || published.is_empty());
        }
        result.map(|published| published.iter().map(ToString::to_string).collect())
    }

    /// Present packages publish; a `403`/`DENIED` (GHCR's answer for an
    /// unpublished repository), a `404`/`NAME_UNKNOWN` and an empty tag
    /// list do not.
    #[test]
    fn probe_published_keeps_only_packages_holding_tags() {
        let published = block_on(probe(
            |base| {
                let mut steps = probe_steps(
                    base,
                    respond(200, TOKEN),
                    respond(200, r#"{"tags":["index.x86_64-unknown-linux-gnu.1.98.0"]}"#),
                );
                steps.extend(probe_steps(
                    base,
                    respond(200, TOKEN),
                    respond(404, NAME_UNKNOWN),
                ));
                // The token exchange is refused: the listing is never asked.
                steps.extend(
                    probe_steps(base, respond(403, DENIED), respond(200, TOKEN))
                        .into_iter()
                        .take(2),
                );
                steps.extend(probe_steps(
                    base,
                    respond(200, TOKEN),
                    respond(
                        200,
                        r#"{"name":"water-rs/stow-cache-v2-1.101.0","tags":null}"#,
                    ),
                ));
                steps.extend(probe_steps(
                    base,
                    respond(200, TOKEN),
                    respond(200, r#"{"tags":["records-1.99.1-a"]}"#),
                ));
                steps
            },
            &["1.98.0", "1.99.0", "1.100.0", "1.101.0", "1.99.1"],
        ))
        .expect("probe");
        assert_eq!(published, ["1.98.0", "1.99.1"]);
    }

    /// Any other refusal fails the probe, naming the package.
    #[test]
    fn probe_published_fails_on_any_other_refusal() {
        let error = block_on(probe(
            |base| {
                probe_steps(
                    base,
                    respond(200, TOKEN),
                    respond(400, r#"{"errors":[{"code":"UNSUPPORTED","message":"no"}]}"#),
                )
            },
            &["1.98.0"],
        ))
        .expect_err("a refusal is not 'unpublished'");
        assert!(
            error.to_string().contains("stow-cache-v2-1.98.0"),
            "{error}"
        );
    }

    /// stow#1393: the published slices are found by probing the
    /// `index.<target>.<rustc>` manifest of every `CI_TARGET_TRIPLES`
    /// entry, never by listing the package's tags, and a target with no
    /// published slice is skipped rather than an error.
    #[test]
    fn published_slices_probe_each_target_without_listing_tags() {
        block_on(async {
            // The session's `/v2/` challenge, answered without asking for a
            // token, then one absent manifest per target.
            let steps = std::iter::once(respond(200, "{}"))
                .chain(CI_TARGET_TRIPLES.iter().map(|_| respond(404, "")))
                .collect::<Vec<_>>();
            let server = crate::test_server::Loopback::start(steps).await;
            let base = stow_oci::RegistryBase::parse(&server.url).expect("registry base");
            let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT)
                .await
                .expect("registry http");
            let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
            let repository = cache_repository(&rustc);
            let ctx = PullContext {
                session: base.session(&repository, &http),
                repository,
                trust: stow_oci::verify::Trust::MockKey(std::path::PathBuf::new()),
            };
            let slices = published_slices(&ctx, &rustc).await;
            let paths = server
                .join()
                .await
                .iter()
                .map(|request| request.head.uri.path().to_owned())
                .collect::<Vec<_>>();
            let slices = slices.unwrap_or_else(|error| panic!("{error}: {paths:?}"));
            assert!(slices.is_empty(), "no target has a published slice");
            let (challenge, manifests) = paths.split_first().expect("the challenge");
            assert_eq!(challenge, "/v2/");
            // The pulls run concurrently, so their arrival order is not
            // the target order.
            let asked = manifests
                .iter()
                .map(|path| path.rsplit('/').next().expect("a path segment"))
                .collect::<std::collections::BTreeSet<_>>();
            let expected = CI_TARGET_TRIPLES
                .iter()
                .map(|target| format!("index.{target}.{RUSTC}"))
                .collect::<Vec<_>>();
            assert_eq!(manifests.len(), expected.len(), "{paths:?}");
            assert_eq!(
                asked,
                expected.iter().map(String::as_str).collect(),
                "{paths:?}"
            );
        });
    }

    fn record_for_target(
        target: &str,
        task_id: &str,
        kind: ArtifactKind,
        crate_name: &str,
    ) -> ArtifactRecord {
        let mut r = record(task_id);
        let is_script = kind == ArtifactKind::BuildScript;
        r.target = TargetTriple::parse(target).expect("target");
        r.crate_name = CrateName::parse(crate_name).expect("crate name");
        r.artifact_kind = kind;
        if is_script {
            r.crate_types = vec![RustCrateType::Bin];
            r.unit_shape.side = stow_types::public_cache::UnitSide::Host;
        }
        r
    }

    fn run_recovery_export(
        stored_indexes: &BTreeMap<String, ArtifactIndex>,
        stored_folded: &BTreeMap<String, Vec<String>>,
        by_tag: &BTreeMap<String, Vec<ArtifactRecord>>,
        tags: &[String],
        rustc: &WireRustcVersion,
    ) -> (ExportPass, Vec<String>) {
        let pulled = Mutex::new(Vec::<String>::new());
        let pass = block_on(export_pass(
            tags,
            |ftag| {
                let got = stored_folded.get(ftag).map(|folded| {
                    let (target, rustc_str) = folded_tag_parts(ftag).expect("folded tag");
                    let itag = index_tag(target, rustc_str);
                    (
                        (
                            TargetTriple::parse(target).expect("target"),
                            WireRustcVersion::parse(rustc_str).expect("rustc"),
                        ),
                        PrevSlice {
                            index: stored_indexes[&itag].clone(),
                            folded: folded.iter().cloned().collect(),
                        },
                    )
                });
                Box::pin(async move { Ok(got) })
            },
            |tag| {
                pulled.lock().unwrap().push(tag.to_owned());
                let records = by_tag[tag].clone();
                Box::pin(async move {
                    Ok(BuildRecords {
                        artifacts: records,
                        local_programs: Vec::new(),
                    })
                })
            },
            false,
            rustc,
        ))
        .expect("recovery export pass");
        (pass, pulled.into_inner().unwrap())
    }

    fn prepared_from_slice(slice: &SliceExport) -> PreparedSlice {
        let index_bytes = stow_shim::encode_index(&slice.index).expect("encode index");
        let index_name = index_tag(slice.target.as_str(), slice.rustc_version.as_str());
        let folded_name = folded_tag(slice.target.as_str(), slice.rustc_version.as_str());
        let lookup_name = format!("{index_name}.lookup.json");
        let summary = IndexExportSummary {
            target: slice.target.as_str().to_owned(),
            rustc_version: slice.rustc_version.as_str().to_owned(),
            tag: index_name.clone(),
            folded_tag: folded_name.clone(),
            index_file: index_name.clone(),
            folded_file: folded_name.clone(),
            lookup_file: lookup_name,
            rows: slice.index.header.row_count,
            bytes: index_bytes.len(),
            sha256: sha256_digest(&index_bytes),
            content_sha256: content_sha256(&slice.index).expect("content sha"),
        };
        PreparedSlice {
            summary,
            rustc_version: slice.rustc_version.clone(),
            index_path: std::path::PathBuf::from(index_name),
            folded_path: std::path::PathBuf::from(folded_name),
            index_bytes,
            folded: slice.folded.clone(),
        }
    }

    #[test]
    fn merge_exports_orders_host_slices_before_cross_slices() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let slices = merge_exports(
            BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &rustc,
        )
        .expect("merge exports");
        let targets: Vec<&str> = slices.iter().map(|s| s.target.as_str()).collect();
        assert_eq!(
            targets,
            vec![
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
                "x86_64-unknown-linux-gnu",
                "aarch64-apple-ios",
                "aarch64-apple-ios-sim",
                "aarch64-linux-android",
                "aarch64-pc-windows-msvc",
                "aarch64-unknown-linux-gnu",
                "wasm32-unknown-unknown",
            ]
        );
    }

    struct SimulatedPublish {
        summaries: Vec<IndexPublishSummary>,
        events: Vec<String>,
        indexes: BTreeMap<String, ArtifactIndex>,
        folded: BTreeMap<String, Vec<String>>,
    }

    fn simulate_publish(
        pass: &ExportPass,
        include_targets: &[&str],
        fail_target: &str,
    ) -> SimulatedPublish {
        let prepared: Vec<PreparedSlice> = pass
            .slices
            .iter()
            .filter(|s| include_targets.contains(&s.target.as_str()))
            .map(prepared_from_slice)
            .collect();
        let events = Mutex::new(Vec::<String>::new());
        let indexes = Mutex::new(BTreeMap::<String, ArtifactIndex>::new());
        let folded = Mutex::new(BTreeMap::<String, Vec<String>>::new());
        let summaries = block_on(publish_pass(
            &prepared,
            &pass.shared_tags,
            |slice| {
                let (target, tag) = (slice.summary.target.clone(), slice.summary.tag.clone());
                let index = ArtifactIndex::decode(&slice.index_bytes).expect("decode");
                events.lock().unwrap().push(format!("index:{target}"));
                let result = if target == fail_target {
                    Err(stow_error!("simulated failure for {fail_target}"))
                } else {
                    indexes.lock().unwrap().insert(tag, index);
                    Ok(("sha256:00".to_owned(), "published"))
                };
                Box::pin(async move { result })
            },
            |slice, filtered| {
                events
                    .lock()
                    .unwrap()
                    .push(format!("folded:{}", slice.summary.target));
                folded
                    .lock()
                    .unwrap()
                    .insert(slice.summary.folded_tag.clone(), filtered);
                Box::pin(async { Ok(()) })
            },
        ));
        SimulatedPublish {
            summaries,
            events: events.into_inner().unwrap(),
            indexes: indexes.into_inner().unwrap(),
            folded: folded.into_inner().unwrap(),
        }
    }

    /// Regression for the cross-target build-script loss incident: a
    /// cross-target crate with a `build.rs` publishes one `records-*` artifact
    /// carrying target-side `Rlib`s (`aarch64-unknown-linux-gnu`) and a
    /// host-side `BuildScript` (`x86_64-unknown-linux-gnu`). When the runner
    /// host slice fails in phase 1:
    /// 1. Every cross slice on that host is skipped (`skipped-host-failed`),
    ///    never published or reported without its host slice.
    /// 2. Unrelated runner families (`aarch64-apple-darwin` + `aarch64-apple-ios`)
    ///    still publish both `index.*` and `folded.*`.
    /// 3. Neither `folded.x86_64-unknown-linux-gnu` nor
    ///    `folded.aarch64-unknown-linux-gnu` is written, so the next export
    ///    re-pulls the shared `records-*` tag and publishes both the `Rlib`
    ///    and the `BuildScript`.
    #[test]
    fn publish_pass_gates_cross_slices_when_host_fails_and_preserves_recovery() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let (linux_host, linux_cross) = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
        let (mac_host, ios_cross) = ("aarch64-apple-darwin", "aarch64-apple-ios");
        let crc_tag = records_tag(RUSTC, "aaaa1111", BUILD);
        let ios_tag = records_tag(RUSTC, "bbbb2222", BUILD);
        let crc_rlib = record_for_target(linux_cross, "aaaa1111", ArtifactKind::Rlib, "crc32fast");
        let crc_script = record_for_target(
            linux_host,
            "aaaa1112",
            ArtifactKind::BuildScript,
            "crc32fast",
        );
        let by_tag = BTreeMap::from([
            (crc_tag.clone(), vec![crc_rlib.clone(), crc_script.clone()]),
            (
                ios_tag.clone(),
                vec![
                    record_for_target(ios_cross, "bbbb2222", ArtifactKind::Rlib, "crc32fast"),
                    record_for_target(mac_host, "bbbb2223", ArtifactKind::BuildScript, "crc32fast"),
                ],
            ),
        ]);
        let tags = vec![crc_tag.clone(), ios_tag.clone()];
        let pass1 = block_on(export_pass(
            &tags,
            pull_no_prev(),
            pull_records_by_tag(by_tag.clone()),
            false,
            &rustc,
        ))
        .expect("export pass 1");
        assert_eq!(
            pass1.shared_tags.get(&crc_tag),
            Some(&vec![
                index_tag(linux_cross, RUSTC),
                index_tag(linux_host, RUSTC),
            ])
        );
        let sim = simulate_publish(
            &pass1,
            &[linux_host, linux_cross, mac_host, ios_cross],
            linux_host,
        );
        assert_eq!(
            sim.events,
            vec![
                format!("index:{mac_host}"),
                format!("index:{linux_host}"),
                format!("index:{ios_cross}"),
                format!("folded:{mac_host}"),
                format!("folded:{ios_cross}"),
            ]
        );
        let by_target: BTreeMap<&str, &IndexPublishSummary> = sim
            .summaries
            .iter()
            .map(|s| (s.target.as_str(), s))
            .collect();
        assert!(by_target[mac_host].index_published && by_target[mac_host].folded_published);
        assert!(by_target[ios_cross].index_published && by_target[ios_cross].folded_published);
        assert_eq!(by_target[linux_host].outcome, "failed");
        assert_eq!(by_target[linux_cross].outcome, "skipped-host-failed");

        let mut next_tags: Vec<String> = sim.folded.keys().cloned().collect();
        next_tags.extend([crc_tag.clone(), ios_tag]);
        let (pass2, pulled) =
            run_recovery_export(&sim.indexes, &sim.folded, &by_tag, &next_tags, &rustc);
        assert_eq!(pulled, vec![crc_tag]);
        let host_slice = pass2
            .slices
            .iter()
            .find(|s| s.target.as_str() == linux_host)
            .expect("host slice recovered");
        let cross_slice = pass2
            .slices
            .iter()
            .find(|s| s.target.as_str() == linux_cross)
            .expect("cross slice recovered");
        assert_eq!(
            host_slice.index.build_scripts,
            vec![record_to_index_row(&crc_script)]
        );
        assert_eq!(cross_slice.index.rows, vec![record_to_index_row(&crc_rlib)]);
    }

    /// Converse failure mode: the runner host slice succeeds in phase 1, then
    /// the cross-target slice fails in phase 1. Phase 2 MUST exclude the shared
    /// cross-build `records-*` tag from `folded.<host>` while still recording
    /// host-only tags, so the next export re-pulls ONLY the shared tag, keeps
    /// the host slice's generation unchanged (`content_sha256` equal), and
    /// publishes the missing cross slice `Rlib`s.
    #[test]
    fn publish_pass_excludes_shared_tags_from_host_folded_when_cross_fails_and_recovers() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let (linux_host, linux_cross) = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
        let host_only_tag = records_tag(RUSTC, "cccc3333", BUILD);
        let shared_tag = records_tag(RUSTC, "dddd4444", BUILD);
        let cross_rlib = record_for_target(linux_cross, "dddd4444", ArtifactKind::Rlib, "rustix");
        let by_tag = BTreeMap::from([
            (
                host_only_tag.clone(),
                vec![record_for_target(
                    linux_host,
                    "cccc3333",
                    ArtifactKind::Rlib,
                    "serde",
                )],
            ),
            (
                shared_tag.clone(),
                vec![
                    cross_rlib.clone(),
                    record_for_target(linux_host, "dddd4445", ArtifactKind::BuildScript, "rustix"),
                ],
            ),
        ]);
        let tags = vec![host_only_tag.clone(), shared_tag.clone()];
        let pass1 = block_on(export_pass(
            &tags,
            pull_no_prev(),
            pull_records_by_tag(by_tag.clone()),
            false,
            &rustc,
        ))
        .expect("export pass 1");
        let sim = simulate_publish(&pass1, &[linux_host, linux_cross], linux_cross);
        let by_target: BTreeMap<&str, &IndexPublishSummary> = sim
            .summaries
            .iter()
            .map(|s| (s.target.as_str(), s))
            .collect();
        assert!(by_target[linux_host].index_published && by_target[linux_host].folded_published);
        assert!(
            !by_target[linux_cross].index_published && !by_target[linux_cross].folded_published
        );

        let host_ftag = folded_tag(linux_host, RUSTC);
        assert_eq!(
            sim.folded.get(&host_ftag),
            Some(&vec![host_only_tag.clone()]),
            "host folded keeps host-only tag and excludes shared tag whose cross slice failed"
        );
        assert!(
            !sim.folded.contains_key(&folded_tag(linux_cross, RUSTC)),
            "failed cross slice writes no folded tag"
        );

        let next_tags = vec![host_ftag, host_only_tag, shared_tag.clone()];
        let (pass2, pulled) =
            run_recovery_export(&sim.indexes, &sim.folded, &by_tag, &next_tags, &rustc);
        assert_eq!(pulled, vec![shared_tag.clone()]);
        let host_slice = pass2
            .slices
            .iter()
            .find(|s| s.target.as_str() == linux_host)
            .expect("host slice");
        let cross_slice = pass2
            .slices
            .iter()
            .find(|s| s.target.as_str() == linux_cross)
            .expect("cross slice");
        assert_eq!(host_slice.index.header.generation, 1);
        assert!(host_slice.folded.contains(&shared_tag));
        assert_eq!(
            cross_slice.index.rows,
            vec![record_to_index_row(&cross_rlib)]
        );
        assert_eq!(cross_slice.folded, vec![shared_tag]);
    }

    #[test]
    fn publish_pass_allows_cross_only_slice_when_host_was_not_in_pass() {
        let rustc = WireRustcVersion::parse(RUSTC).expect("rustc");
        let linux_cross = "aarch64-unknown-linux-gnu";
        let tag = records_tag(RUSTC, "eeee5555", BUILD);
        let rlib = record_for_target(linux_cross, "eeee5555", ArtifactKind::Rlib, "byteorder");
        let pass = block_on(export_pass(
            std::slice::from_ref(&tag),
            pull_no_prev(),
            pull_records_by_tag(BTreeMap::from([(tag.clone(), vec![rlib])])),
            false,
            &rustc,
        ))
        .expect("export pass");
        let prepared: Vec<PreparedSlice> = pass
            .slices
            .iter()
            .filter(|s| s.target.as_str() == linux_cross)
            .map(prepared_from_slice)
            .collect();
        let summaries = block_on(publish_pass(
            &prepared,
            &pass.shared_tags,
            |_slice| Box::pin(async { Ok(("sha256:22".to_owned(), "published")) }),
            |_slice, _filtered| Box::pin(async { Ok(()) }),
        ));
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].index_published && summaries[0].folded_published);
    }

    #[tokio::test]
    async fn index_report_and_reconcile_post_host_slices_before_cross_slices() {
        let dir = tempfile::tempdir().expect("report dir");
        let make_index = |target: &str| ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse(target).expect("target"),
                rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
                generated_at: "2026-01-01T00:00:00Z".to_owned(),
                generation: 1,
                row_count: 1,
            },
            rows: vec![record_to_index_row(&record_for_target(
                target,
                "aaaa1111",
                ArtifactKind::Rlib,
                "serde",
            ))],
            build_scripts: Vec::new(),
            local_programs: Vec::new(),
        };
        let android = "aarch64-linux-android";
        let linux_cross = "aarch64-unknown-linux-gnu";
        let linux_host = "x86_64-unknown-linux-gnu";

        let android_file = dir.path().join(index_tag(android, RUSTC));
        let host_file = dir.path().join(index_tag(linux_host, RUSTC));
        std::fs::write(
            &android_file,
            stow_shim::encode_index(&make_index(android)).expect("encode android"),
        )
        .expect("write android");
        std::fs::write(
            &host_file,
            stow_shim::encode_index(&make_index(linux_host)).expect("encode host"),
        )
        .expect("write host");

        let server = crate::test_server::Loopback::start(Vec::new()).await;
        // Pass cross file BEFORE host file; `index_report` must sort host first.
        index_report(
            &Edge::for_test(server.url.clone()),
            IndexReportArgs {
                file: vec![android_file, host_file],
                full: true,
            },
            &no_history,
        )
        .await
        .expect("index report");
        let requests = server.join().await;
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("report JSON");
        let reported_targets: Vec<&str> = body["slices"]
            .as_array()
            .expect("slices array")
            .iter()
            .map(|s| s["target"].as_str().expect("target"))
            .collect();
        assert_eq!(reported_targets, vec![linux_host, android]);

        // Reconcile given cross slices ahead of host slice must also post host first.
        let server = crate::test_server::Loopback::start(Vec::new()).await;
        let live = vec![
            SliceManifest {
                index: make_index(android),
                previous: None,
            },
            SliceManifest {
                index: make_index(linux_cross),
                previous: None,
            },
            SliceManifest {
                index: make_index(linux_host),
                previous: None,
            },
        ];
        let dummy_history = FakeHistory::chain(Vec::new());
        reconcile(
            &Edge::for_test(server.url.clone()),
            &dummy_history,
            live,
            &BTreeMap::new(),
        )
        .await
        .expect("reconcile");
        let requests = server.join().await;
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("reconcile JSON");
        let reconciled_targets: Vec<&str> = body["slices"]
            .as_array()
            .expect("slices array")
            .iter()
            .map(|s| s["target"].as_str().expect("target"))
            .collect();
        assert_eq!(reconciled_targets, vec![linux_host, android, linux_cross]);
    }
}
