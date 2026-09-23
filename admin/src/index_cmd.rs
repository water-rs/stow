//! `stow-admin index …` — the publish side of the signed artifact index
//! (water-rs/stow#188, #193). Its stdout lines are the machine contract
//! `index-publish.yml` consumes, so they print verbatim regardless of
//! `--json`.

use clap::{Args, Subcommand};
use stow_types::api::{ArtifactIndexPage, CI_TARGET_TRIPLES};
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
    /// Print every `CI_TARGET_TRIPLES` entry, one per line — the slice
    /// list `index-publish.yml` iterates, read from the binary so the
    /// workflow never carries its own copy.
    Targets,
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

/// Dispatch one index subcommand on the executor it needs. `publish`
/// drives `oci-client`, which is built on hyper and so needs a Tokio
/// reactor — it runs on a dedicated current-thread runtime exactly as
/// `stow-build publish` does, with rustls's process-level provider
/// installed before any TLS client is built. The other subcommands run on
/// smol like the rest of the binary.
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
        IndexCommand::Targets => {
            render::emit_line(&CI_TARGET_TRIPLES.join("\n"));
            Ok(())
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

    let index = ArtifactIndex {
        header: ArtifactIndexHeader {
            format_version: ARTIFACT_INDEX_FORMAT_VERSION,
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|error| stow_error!("format generated_at: {error}"))?,
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
    let line = serde_json::to_string(&summary)
        .map_err(|error| stow_error!("serialize index summary: {error}"))?;
    render::emit_line(&line);
    Ok(())
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
