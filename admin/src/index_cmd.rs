//! `stow-admin index …` — the publish side of the signed artifact index
//! (water-rs/stow#188, #193). Its stdout lines are the machine contract
//! `index-publish.yml` consumes, so they print verbatim regardless of
//! `--json`.

use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::api::{
    ArtifactIndexPage, ArtifactRecord, CI_TARGET_TRIPLES, EnqueueRequest, EnqueueSource,
    PublishedSliceReport, PublishedSliceRow, RegisterArtifactsRequest,
};
use stow_types::identity::{TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, content_sha256, decode,
    encode, index_tag,
};
use stow_types::registry::sha256_digest;
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

use crate::Edge;
use crate::render;

/// Rows requested per index page — the endpoint's maximum, so a slice
/// exports in the fewest requests.
const INDEX_PAGE_LIMIT: usize = 1000;
/// Bundle pulls in flight per backfill page — the shared anonymous
/// session already honors the registry's rate limit, so this bounds
/// in-flight work, not throughput.
const BACKFILL_PULL_CONCURRENCY: usize = 16;
/// Artifact records per backfill register request — each request lands
/// as one edge-side batch write, so a chunk is one round trip rather
/// than a page-wide body the worker timeout eats mid-flight.
const BACKFILL_REGISTER_CHUNK: usize = 100;
/// Register chunk requests in flight — the chunks are independent
/// writes, so the bound only limits how many edge requests a page
/// holds open at once.
const BACKFILL_REGISTER_CONCURRENCY: usize = 4;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";

#[derive(Args)]
pub struct IndexArgs {
    #[command(subcommand)]
    pub command: IndexCommand,
}

#[derive(Subcommand)]
pub enum IndexCommand {
    /// Page the admin index endpoint for one `(target, rustc_version)`
    /// slice, assemble the index, encode it, and write `--out`. The
    /// stdout line is the JSON [`IndexExportSummary`] the publish
    /// workflow reads.
    Export(IndexExportArgs),
    /// Push an exported index file to the registry and sign it.
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
    /// Measure the glibc floor on catalog rows that predate the
    /// `min_glibc` field (stow#336): each unmeasured row's stored bundle
    /// is pulled anonymously and parsed, the records re-register with
    /// the measured floor, rows above the builder baseline enqueue
    /// rebuilds, and the touched `(target, rustc)` slices print so the
    /// operator can re-publish them via `index-publish.yml` — the only
    /// signer clients accept.
    /// Mutating — applies under `--yes`.
    BackfillMinGlibc(BackfillMinGlibcArgs),
}

/// `stow-admin index backfill-min-glibc` — the stow#336 repair pass.
#[derive(Args)]
pub struct BackfillMinGlibcArgs {
    /// Rows to fetch per listing page; the endpoint's maximum is 1000.
    /// Pages are pulled until the listing drains — re-registered rows
    /// leave it — so this bounds request size, not total work.
    #[arg(long, default_value_t = 1000)]
    limit: usize,
    /// Re-register the measured records and enqueue the over-floor
    /// rebuilds. Without it the command prints the plan and exits.
    #[arg(long)]
    yes: bool,
}

/// The plan the operator previews under `--yes` gating.
#[derive(Debug, serde::Serialize)]
struct BackfillMinGlibcPlan {
    /// Catalog rows missing a `min_glibc` measurement.
    unmeasured_rows: usize,
    /// `(target, rustc)` slices those rows publish under — the set the
    /// apply touches and prints for the follow-up publish run.
    slices: Vec<String>,
}

/// What the applied backfill did.
#[derive(Debug, serde::Serialize)]
struct BackfillMinGlibcResult {
    /// Rows re-registered with a measured floor (`None` included — a
    /// measured row with no glibc dependency still leaves the listing).
    registered: usize,
    /// Rebuild tasks submitted to the scheduler — one per measured row
    /// whose floor exceeds the builder baseline, so the new sysroot
    /// builder mints a servable artifact at the same identity.
    rebuilds_enqueued: usize,
    /// The `(target, rustc)` slices the pass touched — printed so the
    /// operator sees exactly what index-publish.yml re-signs next. The
    /// backfill never publishes: index slices are cosign-signed keyless
    /// and clients only accept `index-publish.yml` on refs/heads/main,
    /// so a slice signed under any other identity would be rejected.
    slices: Vec<String>,
}

#[derive(Args)]
pub struct IndexExportArgs {
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    /// File the encoded index is written to.
    #[arg(long)]
    out: std::path::PathBuf,
}

/// The JSON line `index export` prints on stdout — the workflow reads
/// `content_sha256` (a digest of everything but the wall-clock
/// `generated_at`) to decide whether the published artifact is stale, and
/// `tag` for the GHCR reference.
#[derive(Debug, serde::Serialize)]
struct IndexExportSummary {
    rows: u64,
    bytes: usize,
    sha256: String,
    content_sha256: String,
    tag: String,
}

/// Publish an index file `index export` wrote to the slice's OCI tag and
/// sign it.
///
/// Two modes, selected by environment: with `STOW_MOCK_PRIVATE_KEY_PATH`
/// set the command delegates to `stow-mock-registry publish-index` —
/// writing the signed artifact into `STOW_MOCK_REGISTRY_ROOT` exactly as
/// `stow-build` mock-populate does for bundles; without it the command
/// pushes to GHCR through `stow-oci` and signs with the `cosign` binary
/// (`GHCR_USERNAME`/`GHCR_TOKEN`), the production path
/// `index-publish.yml` runs.
#[derive(Args)]
pub struct IndexPublishArgs {
    /// The encoded index file (`index export --out`).
    #[arg(long)]
    file: std::path::PathBuf,
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
}

/// The JSON line `index publish` prints on stdout.
#[derive(Debug, serde::Serialize)]
struct IndexPublishSummary {
    tag: String,
    manifest_digest: String,
    outcome: &'static str,
}

/// Report the slice an exported index file carries to the edge, so the
/// scheduler learns what the published index actually serves. The
/// file's header is authoritative — the slice key comes from it, so the
/// command takes only `--file`.
///
/// The default report is a delta: `index export` saves the previously
/// published index beside `--out` as `<file>.prev`, and the report
/// sends `base_generation` plus only the rows that moved. `--full`
/// (or a file with no `.prev` — a slice's first publish) sends the
/// explicit full report the scheduler diffs itself.
#[derive(Args)]
pub struct IndexReportArgs {
    /// The encoded index file (`index export --out`).
    #[arg(long)]
    file: std::path::PathBuf,
    /// Send the explicit full report (`base_generation` unset) — the
    /// resync path for a slice whose optimistic-lock check failed, and
    /// the automatic shape of a first publish.
    #[arg(long)]
    full: bool,
}

/// The JSON line `index report` prints on stdout.
#[derive(Debug, serde::Serialize)]
struct IndexReportSummary {
    /// Rows the report added to the slice — the whole membership on a
    /// full report.
    added: usize,
    /// Rows the report retired — `0` on a full report.
    retired: usize,
    /// `true` when the report took the explicit full path (`--full` or
    /// no `.prev` sidecar).
    full: bool,
    tag: String,
}

/// Dispatch one index subcommand on the executor it needs. `publish`
/// drives `RegistrySession`'s reqwest client, which is built on hyper and
/// so needs a Tokio reactor — it runs on a dedicated current-thread
/// runtime exactly as `stow-build publish` does, with rustls's
/// process-level provider installed before any TLS client is built. The
/// other subcommands run on smol like the rest of the binary.
pub fn run(args: IndexArgs) -> stow_types::error::Result<()> {
    match args.command {
        IndexCommand::Export(args) => {
            smol::block_on(async move { index_export(&Edge::connect().await?, args).await })
        }
        IndexCommand::Publish(args) => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| stow_error!("install ring CryptoProvider"))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| stow_error!("build tokio runtime: {error}"))?
                .block_on(index_publish(args))
        }
        IndexCommand::Report(args) => {
            smol::block_on(async move { index_report(&Edge::connect().await?, args).await })
        }
        IndexCommand::Targets => {
            render::emit_line(&CI_TARGET_TRIPLES.join("\n"));
            Ok(())
        }
        IndexCommand::BackfillMinGlibc(args) => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .map_err(|_| stow_error!("install ring CryptoProvider"))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| stow_error!("build tokio runtime: {error}"))?
                .block_on(async move {
                    let edge = Edge::connect().await?;
                    backfill_min_glibc(&edge, args).await
                })
        }
    }
}

/// Page the admin index endpoint for the slice, assemble the
/// [`ArtifactIndex`], encode it and write `--out`; the stdout line is the
/// [`IndexExportSummary`] the publish workflow consumes.
async fn index_export(edge: &Edge, args: IndexExportArgs) -> stow_types::error::Result<()> {
    let target =
        TargetTriple::parse(&args.target).map_err(|error| stow_error!("index target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(&args.rustc_version)
        .map_err(|error| stow_error!("index rustc_version: {error}"))?;

    let base = format!(
        "{}/api/v1/admin/index/{}/{}",
        edge.base(),
        target,
        rustc_version
    );
    let mut rows = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let url = after.as_ref().map_or_else(
            || format!("{base}?limit={INDEX_PAGE_LIMIT}"),
            |cursor| format!("{base}?after={cursor}&limit={INDEX_PAGE_LIMIT}"),
        );
        let bearer = edge.bearer().await?;
        let mut client = zenwave::client().timeout(REQUEST_TIMEOUT).retry(2);
        let response = client
            .get(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {bearer}")))
            .map_err(|error| stow_error!("fetch index page {url}: {error}"))?
            .await
            .map_err(|error| stow_error!("fetch index page {url}: {error}"))?;
        let response = response
            .error_for_status()
            .await
            .map_err(|error| stow_error!("index page {url}: {error}"))?;
        let page: ArtifactIndexPage = response
            .into_json()
            .await
            .map_err(|error| stow_error!("decode index page {url}: {error}"))?;
        let empty = page.rows.is_empty();
        rows.extend(page.rows);
        match page.next_after {
            Some(cursor) if !empty => after = Some(cursor),
            _ => break,
        }
    }
    tracing::info!(%target, %rustc_version, rows = rows.len(), "exported artifact index slice");

    // The previous published index fixes the generation stamp and gives
    // `index report` its delta base — pull it now, while the tag still
    // resolves to it (the report runs after `index publish` moved the
    // tag to this index). Saved beside `--out` as `<file>.prev`.
    let prev = prev_published_index(target.as_str(), rustc_version.as_str()).await?;
    let generation = prev.as_ref().map_or(1, |index| index.header.generation + 1);

    let index = ArtifactIndex {
        header: ArtifactIndexHeader {
            format_version: ARTIFACT_INDEX_FORMAT_VERSION,
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| stow_error!("format generated_at: {error}"))?,
            generation,
            row_count: u64::try_from(rows.len())
                .map_err(|_| stow_error!("row count {} exceeds u64", rows.len()))?,
        },
        rows,
    };
    let bytes = encode(&index).map_err(|error| stow_error!("encode index: {error}"))?;
    let summary = IndexExportSummary {
        rows: index.header.row_count,
        bytes: bytes.len(),
        sha256: sha256_digest(&bytes),
        content_sha256: content_sha256(&index)
            .map_err(|error| stow_error!("digest index content: {error}"))?,
        tag: index_tag(target.as_str(), rustc_version.as_str()),
    };
    smol::fs::write(&args.out, &bytes)
        .await
        .map_err(|error| stow_error!("write index {}: {error}", args.out.display()))?;
    if let Some(prev) = prev {
        let prev_bytes =
            encode(&prev).map_err(|error| stow_error!("encode previous index: {error}"))?;
        smol::fs::write(prev_path(&args.out), &prev_bytes)
            .await
            .map_err(|error| stow_error!("write previous-index sidecar: {error}"))?;
    }
    let line = serde_json::to_string(&summary)
        .map_err(|error| stow_error!("serialize index summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// The sidecar `index export` leaves beside `--out`: the encoded index
/// the slice's tag resolved to before this export ran — `index report`'s
/// delta base. A report on a file with no sidecar (a slice's first
/// publish, or an export predating this feature) falls back to the
/// explicit full report.
fn prev_path(out: &std::path::Path) -> std::path::PathBuf {
    let mut prev = out.as_os_str().to_os_string();
    prev.push(".prev");
    std::path::PathBuf::from(prev)
}

/// The previously published index for `(target, rustc_version)` — the
/// artifact the slice's tag resolves to *right now*, pulled while it is
/// still the tag's target. `None` when no index exists yet.
///
/// Mock mode reads `STOW_MOCK_REGISTRY_ROOT` directly, exactly where
/// `stow-mock-registry publish-index` wrote the tagged manifest and its
/// blob; the production path pulls through `stow-oci` under the same
/// `GHCR_USERNAME`/`GHCR_TOKEN` credentials `index publish` uses. No
/// credential means no registry is reachable at all — an offline export
/// is treated as a first publish rather than a failure.
async fn prev_published_index(
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<ArtifactIndex>> {
    let tag = index_tag(target, rustc_version);
    if let Ok(registry_root) = std::env::var(STOW_MOCK_REGISTRY_ROOT_ENV) {
        let root = std::path::Path::new(&registry_root);
        let manifest_path = root
            .join("manifests")
            .join(stow_types::registry::GHCR_REPOSITORY)
            .join(&tag);
        let Ok(manifest_bytes) = smol::fs::read(&manifest_path).await else {
            return Ok(None);
        };
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| stow_error!("parse mock index manifest: {error}"))?;
        let digest = manifest
            .pointer("/layers/0/digest")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| stow_error!("mock index manifest carries no layer digest"))?;
        let blob = smol::fs::read(root.join("blobs").join(digest.replace(':', "_")))
            .await
            .map_err(|error| stow_error!("read mock index blob: {error}"))?;
        return decode(&blob)
            .map(Some)
            .map_err(|error| stow_error!("decode mock index: {error}"));
    }
    let Ok(credentials) = stow_oci::RegistryCredentials::from_env() else {
        return Ok(None);
    };
    let session = credentials
        .session()
        .map_err(|error| stow_error!("build registry session: {error}"))?;
    stow_oci::pull_published_index(&session, target, rustc_version)
        .await?
        .map(|bytes| decode(&bytes).map_err(|error| stow_error!("decode index: {error}")))
        .transpose()
}

/// The index file's semantic rows as [`PublishedSliceRow`]s — the
/// scheduler's slice membership. Artifact rows collapse onto semantic
/// identity + unit shape — several `c_metadata`/`compile_key` rows can name
/// one `(crate, version, features, shape)` — so the report
/// deduplicates. Two rows of the same identity at different unit shapes
/// stay separate: the gate compares each shape an edge requires against
/// its own row. A catalog row carrying no shape (registered before the
/// column existed) reports as shapeless and covers nothing. A measured
/// row above the sysroot's glibc floor publishes in the index but a
/// baseline host cannot load it, so it releases no dependent — the same
/// rule the catalog's coverage oracle applies (stow#336).
fn semantic_rows(index: &ArtifactIndex) -> Vec<PublishedSliceRow> {
    let mut seen = std::collections::BTreeSet::new();
    index
        .rows
        .iter()
        .filter(|row| {
            row.min_glibc
                .is_none_or(|floor| floor <= stow_types::glibc::GLIBC_BASELINE)
        })
        .map(|row| PublishedSliceRow {
            crate_name: row.crate_name.clone(),
            version: row.version.clone(),
            features_json: row.features_json.clone(),
            unit_shape: row.unit_shape,
        })
        .filter(|row| {
            seen.insert((
                row.crate_name.as_str().to_owned(),
                row.version.to_string(),
                row.features_json.raw(),
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
    Option<stow_types::public_cache::UnitShape>,
) {
    (
        row.crate_name.as_str().to_owned(),
        row.version.to_string(),
        row.features_json.raw(),
        row.unit_shape,
    )
}

/// `stow-admin index publish` — the second half of the index pipeline.
/// The file's own header is authoritative: `--target`/`--rustc-version`
/// must match it, so a workflow loop bug cannot publish a slice under a
/// foreign tag.
async fn index_publish(args: IndexPublishArgs) -> stow_types::error::Result<()> {
    let target =
        TargetTriple::parse(&args.target).map_err(|error| stow_error!("index target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(&args.rustc_version)
        .map_err(|error| stow_error!("index rustc_version: {error}"))?;
    let bytes = smol::fs::read(&args.file)
        .await
        .map_err(|error| stow_error!("read index file {}: {error}", args.file.display()))?;
    let index = decode(&bytes)
        .map_err(|error| stow_error!("decode index file {}: {error}", args.file.display()))?;
    if index.header.target != target || index.header.rustc_version != rustc_version {
        return Err(stow_error!(
            "index file {} is a {}/{} slice, not {}/{}",
            args.file.display(),
            index.header.target,
            index.header.rustc_version,
            target,
            rustc_version
        ));
    }
    let sha256 =
        content_sha256(&index).map_err(|error| stow_error!("digest index content: {error}"))?;
    let tag = index_tag(target.as_str(), rustc_version.as_str());

    let (manifest_digest, outcome) =
        if let Ok(private_key_path) = std::env::var(STOW_MOCK_PRIVATE_KEY_PATH_ENV) {
            publish_index_mock(&args.file, &private_key_path).await?
        } else {
            let credentials = stow_oci::RegistryCredentials::from_env()?;
            let outcome = stow_oci::publish_index(
                &credentials,
                &bytes,
                target.as_str(),
                rustc_version.as_str(),
                &sha256,
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
    tracing::info!(%tag, %manifest_digest, outcome, "published artifact index slice");
    let line = serde_json::to_string(&IndexPublishSummary {
        tag,
        manifest_digest,
        outcome,
    })
    .map_err(|error| stow_error!("serialize index publish summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// `stow-admin index report` — post the slice's semantic membership to
/// the edge admin route so the scheduler's dependency gate can release
/// dependents whose edges the published index now serves. The set sent
/// is the servable subset of the export: a row whose measured glibc
/// floor exceeds the builder baseline publishes in the index but a
/// baseline host cannot load it, so it releases no dependent — the same
/// rule the catalog's coverage oracle applies.
async fn index_report(edge: &Edge, args: IndexReportArgs) -> stow_types::error::Result<()> {
    let bytes = smol::fs::read(&args.file)
        .await
        .map_err(|error| stow_error!("read index file {}: {error}", args.file.display()))?;
    let index = decode(&bytes)
        .map_err(|error| stow_error!("decode index file {}: {error}", args.file.display()))?;
    let target = index.header.target.clone();
    let rustc_version = index.header.rustc_version.clone();
    let rows = semantic_rows(&index);

    // The delta base is the `.prev` sidecar `index export` captured
    // while the tag still named the previous index. `--full`, or a file
    // with no sidecar (first publish, older export), takes the explicit
    // full path — the caller never retries it silently and neither does
    // the DO: a `base_generation` mismatch answers 409 instead.
    let prev = match smol::fs::read(prev_path(&args.file)).await {
        Ok(bytes) => Some(decode(&bytes).map_err(|error| {
            stow_error!(
                "decode previous index {}: {error}",
                prev_path(&args.file).display()
            )
        })?),
        Err(_) => None,
    };
    let (base_generation, added, retired) = if args.full {
        (None, rows, Vec::new())
    } else if let Some(prev) = prev {
        let prev_rows = semantic_rows(&prev);
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
        (None, rows, Vec::new())
    };
    let report = PublishedSliceReport {
        base_generation,
        generation: Some(index.header.generation),
        added,
        retired,
    };
    edge.post_json::<_, serde_json::Value>(
        &format!("/api/v1/admin/index/{target}/{rustc_version}"),
        &report,
    )
    .await?;
    let tag = index_tag(target.as_str(), rustc_version.as_str());
    let summary = IndexReportSummary {
        added: report.added.len(),
        retired: report.retired.len(),
        full: report.base_generation.is_none(),
        tag: tag.clone(),
    };
    tracing::info!(
        %tag,
        added = summary.added,
        retired = summary.retired,
        full = summary.full,
        "reported published index slice to the edge"
    );
    let line = serde_json::to_string(&summary)
        .map_err(|error| stow_error!("serialize index report summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

/// The registry base the anonymous bundle pulls go through —
/// `STOW_REGISTRY_BASE_URL` when set (the mock/local loop), else
/// production GHCR.
fn backfill_registry_base() -> stow_types::error::Result<stow_oci::RegistryBase> {
    std::env::var("STOW_REGISTRY_BASE_URL").map_or_else(
        |_| stow_oci::RegistryBase::production(),
        |url| stow_oci::RegistryBase::parse(&url),
    )
}

/// Fetch one page of the NULL-`min_glibc` listing.
async fn list_unmeasured(
    edge: &Edge,
    limit: usize,
) -> stow_types::error::Result<Vec<ArtifactRecord>> {
    edge.get_json(&format!(
        "/api/v1/admin/artifacts/unmeasured-glibc?limit={limit}"
    ))
    .await
}

/// Pull, measure and re-register one listing page; returns the rows
/// registered, `0` when the listing is drained. Every re-registered row
/// leaves the NULL listing, so the caller loops until this returns `0`.
/// Rows whose measured floor exceeds [`GLIBC_BASELINE`] collect into
/// `rebuilds` — the sysroot is not part of the compile key, so a rebuild
/// at the same identity mints the same key and the register upsert
/// replaces the row with its servable floor. They submit as
/// `HumanRequest`: an operator asked for these exact crates again, and
/// only the human lane resurrects a `completed` queue row — a miss-lane
/// submit would no-op against the row the original build left.
async fn measure_register_page(
    edge: &Edge,
    base: &stow_oci::RegistryBase,
    limit: usize,
    slices: &mut std::collections::BTreeSet<String>,
    rebuilds: &mut Vec<EnqueueRequest>,
) -> stow_types::error::Result<usize> {
    let session = base.session();
    let page = list_unmeasured(edge, limit).await?;
    if page.is_empty() {
        return Ok(0);
    }
    // Pull and measure bounded-concurrent through the shared session;
    // `buffered` keeps page order so the register chunks stay stable.
    let measured = futures_util::stream::iter(
        page.into_iter()
            .map(|record| measure_backfill_row(&session, record)),
    )
    .buffered(BACKFILL_PULL_CONCURRENCY)
    .try_collect::<Vec<MeasuredBackfillRow>>()
    .await?;

    let mut records = Vec::with_capacity(measured.len());
    for row in measured {
        slices.insert(row.slice);
        if row.over_floor {
            rebuilds.push(EnqueueRequest {
                crate_name: row.record.crate_name.clone(),
                version: row.record.version.clone(),
                features_json: row.record.features_json.clone(),
                target: row.record.target.clone(),
                rustc_version: row.record.rustc_version.clone(),
                downloads: 0,
                source: EnqueueSource::HumanRequest,
                depends_on: Vec::new(),
                preserve_lockfile: false,
                host_side: false,
            });
        }
        records.push(row.record);
    }

    // Chunk posts are independent edge writes — bound them too, so a
    // page does not serialize one request per chunk.
    let registered = records.len();
    futures_util::stream::iter(records.chunks(BACKFILL_REGISTER_CHUNK))
        .map(Ok::<_, stow_types::error::Error>)
        .try_for_each_concurrent(BACKFILL_REGISTER_CONCURRENCY, |chunk| async move {
            let request = RegisterArtifactsRequest {
                task_id: None,
                records: chunk.to_vec(),
            };
            edge.post_json::<_, serde_json::Value>("/api/v1/admin/artifacts/register", &request)
                .await
                .map(|_| ())
        })
        .await?;
    Ok(registered)
}

/// One backfill page row after measurement: the record with its floor
/// written, the `(target, rustc)` slice it publishes under, and whether
/// that floor still exceeds the builder baseline — such a row stays
/// unservable on old hosts until the enqueued rebuild lands.
struct MeasuredBackfillRow {
    record: ArtifactRecord,
    slice: String,
    over_floor: bool,
}

/// Pull one row's stored bundle through the shared anonymous session
/// and return the record with its measured glibc floor.
async fn measure_backfill_row(
    session: &stow_oci::RegistrySession,
    record: ArtifactRecord,
) -> stow_types::error::Result<MeasuredBackfillRow> {
    let bundle_reference = stow_types::registry::bundle_oci_reference(&record.oci_reference)
        .ok_or_else(|| stow_error!("no bundle reference fits for {}", record.oci_reference))?
        .parse()
        .map_err(|error| {
            stow_error!(
                "parse bundle reference of {}: {error}",
                record.oci_reference
            )
        })?;
    let (_, manifest) = stow_oci::pull_tagged_manifest(session, &bundle_reference).await?;
    let layer = manifest.layers.first().ok_or_else(|| {
        stow_error!(
            "bundle manifest of {} carries no layers",
            record.oci_reference
        )
    })?;
    let bundle = stow_oci::pull_blob_verified(session, layer).await?;
    let mut record = record;
    record.min_glibc = stow_types::glibc::min_glibc_of_bundle(&bundle)?;
    Ok(MeasuredBackfillRow {
        over_floor: record
            .min_glibc
            .is_some_and(|floor| floor > stow_types::glibc::GLIBC_BASELINE),
        slice: format!("{}/{}", record.target, record.rustc_version),
        record,
    })
}

/// `stow-admin index backfill-min-glibc` — the operator half of stow#336.
/// The listing is NULL-driven: the plan previews its first page, and the
/// apply drains it in pages — each re-registered row leaves the listing,
/// so re-listing returns the next batch until empty, the same pass shape
/// `stow-build backfill-bundles` runs. Every pulled bundle is measured
/// across its `files/` members and re-registered as a push caller
/// (`task_id: None`). Publishing stays with `index-publish.yml` on
/// main — index slices are cosign-signed keyless and clients pin the
/// certificate identity, so a slice signed under this command's caller
/// would overwrite a production slice with one every client rejects —
/// and the pass prints the touched slices so the follow-up publish run
/// covers them.
async fn backfill_min_glibc(
    edge: &Edge,
    args: BackfillMinGlibcArgs,
) -> stow_types::error::Result<()> {
    let first_page = list_unmeasured(edge, args.limit).await?;
    let plan = BackfillMinGlibcPlan {
        unmeasured_rows: first_page.len(),
        slices: first_page
            .iter()
            .map(|record| format!("{}/{}", record.target, record.rustc_version))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    tracing::info!(
        rows = first_page.len(),
        "listed unmeasured-glibc catalog rows (first page)"
    );

    render::mutation(
        crate::render::Output::Json,
        args.yes,
        plan,
        |envelope: &render::Planned<BackfillMinGlibcPlan, BackfillMinGlibcResult>| {
            let mut out = format!(
                "{} unmeasured row(s) across {} slice(s)\n",
                envelope.plan.unmeasured_rows,
                envelope.plan.slices.len()
            );
            for slice in &envelope.plan.slices {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("  {slice}\n"));
            }
            if let Some(result) = &envelope.result {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!(
                        "registered {}; rebuilds enqueued {}; touched slices {}\n",
                        result.registered,
                        result.rebuilds_enqueued,
                        result.slices.join(", ")
                    ),
                );
            }
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!("{}", render::plan_footer(envelope.dry_run)),
            );
            out
        },
        async move |_plan: &BackfillMinGlibcPlan| {
            let base = backfill_registry_base()?;
            let mut registered = 0usize;
            let mut slices = std::collections::BTreeSet::new();
            let mut rebuilds = Vec::<EnqueueRequest>::new();
            // One measured page drains out of the listing, so each pass
            // takes the next batch until none remain.
            loop {
                let count =
                    measure_register_page(edge, &base, args.limit, &mut slices, &mut rebuilds)
                        .await?;
                if count == 0 {
                    break;
                }
                registered += count;
            }
            // Two rows can name the same task identity — different
            // c_metadata, same canonical crate/version/features — so
            // dedupe before submit; the scheduler would drop the
            // duplicates anyway.
            let mut seen = std::collections::BTreeSet::new();
            rebuilds.retain(|request| {
                seen.insert((
                    request.crate_name.as_str().to_owned(),
                    request.version.to_string(),
                    request.features_json.raw(),
                    request.target.as_str().to_owned(),
                    request.rustc_version.as_str().to_owned(),
                ))
            });
            if !rebuilds.is_empty() {
                crate::submit(edge, &rebuilds).await?;
            }
            let rebuilds_enqueued = rebuilds.len();
            Ok(BackfillMinGlibcResult {
                registered,
                rebuilds_enqueued,
                slices: slices.into_iter().collect(),
            })
        },
    )
    .await
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
    let output = smol::process::Command::new(&mock_registry_exe)
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
