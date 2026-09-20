//! `stow-admin index …` — the publish side of the signed artifact index
//! (water-rs/stow#188, #193). Its stdout lines are the machine contract
//! `index-publish.yml` consumes, so they print verbatim regardless of
//! `--json`.

use clap::{Args, Subcommand};
use stow_types::api::{ArtifactIndexPage, CI_TARGET_TRIPLES};
use stow_types::identity::{TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, content_sha256, encode,
    index_tag,
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

pub async fn run(edge: &Edge, args: IndexArgs) -> stow_types::error::Result<()> {
    match args.command {
        IndexCommand::Export(args) => index_export(edge, args).await,
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
        let mut client = zenwave::client().timeout(REQUEST_TIMEOUT).retry(2);
        let response = client
            .get(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {}", edge.token())))
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
