//! `stow-admin artifacts …` — inspect catalog rows and their GHCR bundle
//! manifests, and prune rows for retired toolchains.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::{
    ArtifactInspection, ArtifactPruneRequest, ArtifactPruneResponse, ArtifactRecord,
};
use stow_types::identity::{CMetadata, TargetTriple, WireRustcVersion};
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct ArtifactsArgs {
    #[command(subcommand)]
    pub command: ArtifactsCommand,
}

#[derive(Subcommand)]
pub enum ArtifactsCommand {
    /// The catalog row plus the bundle image's OCI manifest for one
    /// `(target, rustc, c_metadata)` identity.
    Inspect(InspectArgs),
    /// Delete every catalog row built by a retired rustc and invalidate
    /// its lookup-cache entries. GHCR image tags are not deleted — they
    /// age out under the package's own retention.
    Prune(PruneArgs),
}

#[derive(Args)]
pub struct InspectArgs {
    /// Cargo `-C metadata` identity of the artifact.
    pub c_metadata: String,
    /// Compilation target triple.
    #[arg(long)]
    pub target: String,
    /// Rustc version the artifact was built by.
    #[arg(long)]
    pub rustc: String,
}

#[derive(Args)]
pub struct PruneArgs {
    /// Retired toolchain whose rows are pruned.
    #[arg(long)]
    pub rustc: String,
    /// Delete the rows. Without it the command prints the plan and exits
    /// 0 without touching the catalog.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(
    edge: &Edge,
    args: ArtifactsArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    match args.command {
        ArtifactsCommand::Inspect(args) => inspect(edge, args, output).await,
        ArtifactsCommand::Prune(args) => prune(edge, args, output).await,
    }
}

async fn inspect(edge: &Edge, args: InspectArgs, output: Output) -> stow_types::error::Result<()> {
    let target =
        TargetTriple::parse(&args.target).map_err(|error| stow_error!("--target: {error}"))?;
    let rustc_version =
        WireRustcVersion::parse(&args.rustc).map_err(|error| stow_error!("--rustc: {error}"))?;
    let c_metadata =
        CMetadata::parse(&args.c_metadata).map_err(|error| stow_error!("c_metadata: {error}"))?;
    let inspection: ArtifactInspection = edge
        .get_json(&format!(
            "/api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}"
        ))
        .await?;
    render::emit(output, &inspection, |inspection| {
        let record = &inspection.record;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "record  {} {} ({})",
            record.crate_name, record.version, record.c_metadata
        );
        let _ = writeln!(out, "  target      {}", record.target);
        let _ = writeln!(out, "  rustc       {}", record.rustc_version);
        let _ = writeln!(out, "  oci         {}", record.oci_reference);
        let _ = writeln!(out, "  digest      {}", record.oci_digest);
        let _ = writeln!(
            out,
            "  bundle      {} ({} bytes)",
            record.bundle_digest, record.bundle_size
        );
        let _ = writeln!(
            out,
            "  kind        {:?}  native={}",
            record.artifact_kind, record.has_native
        );
        let manifest = &inspection.manifest;
        let _ = writeln!(out, "manifest schemaVersion={}", manifest.schema_version);
        let _ = writeln!(
            out,
            "  config  {} {} ({} bytes)",
            manifest.config.media_type, manifest.config.digest, manifest.config.size
        );
        let mut table = Table::new(&["layer", "media_type", "size"]);
        for layer in &manifest.layers {
            table.push([
                layer.digest.clone(),
                layer.media_type.clone(),
                render::size(layer.size),
            ]);
        }
        if !table.is_empty() {
            let _ = write!(out, "{}", table.render());
        }
        out
    })
}

/// The plan an `artifacts prune` prints: every catalog row the retired
/// toolchain owns.
#[derive(Debug, serde::Serialize)]
struct PrunePlan {
    /// Retired toolchain being pruned.
    rustc_version: WireRustcVersion,
    /// Catalog rows the delete will remove.
    rows: Vec<ArtifactRecord>,
}

async fn prune(edge: &Edge, args: PruneArgs, output: Output) -> stow_types::error::Result<()> {
    let rustc_version =
        WireRustcVersion::parse(&args.rustc).map_err(|error| stow_error!("--rustc: {error}"))?;
    let rows: Vec<ArtifactRecord> = edge
        .get_json(&format!(
            "/api/v1/admin/artifacts?rustc_version={rustc_version}&limit=1000"
        ))
        .await?;
    let plan = PrunePlan {
        rustc_version: rustc_version.clone(),
        rows,
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<PrunePlan, ArtifactPruneResponse>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "prune {} row(s) built by rustc {}\n",
                plan.rows.len(),
                plan.rustc_version
            );
            let mut table = Table::new(&["crate", "version", "target", "c_metadata", "bundle"]);
            for row in &plan.rows {
                table.push([
                    row.crate_name.as_str().to_owned(),
                    row.version.to_string(),
                    row.target.as_str().to_owned(),
                    row.c_metadata.as_str().to_owned(),
                    render::size(row.bundle_size),
                ]);
            }
            if !table.is_empty() {
                let _ = write!(out, "{}", table.render());
            }
            if let Some(result) = &envelope.result {
                let _ = write!(out, "\ndeleted {} row(s)", result.deleted);
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |plan: &PrunePlan| {
            let request = ArtifactPruneRequest {
                rustc_version: plan.rustc_version.clone(),
            };
            edge.post_json("/api/v1/admin/artifacts/prune", &request)
                .await
        },
    )
    .await
}
