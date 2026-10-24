//! `stow-admin artifacts inspect` — the catalog row for one
//! `(target, rustc, c_metadata)` identity, read from the signed
//! `index.<target>.<rustc>` slice in GHCR and verified the way the CLI
//! reads it.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::identity::{CMetadata, TargetTriple, WireRustcVersion};
use stow_types::stow_error;

use crate::coverage::IndexSource;
use crate::render::{self, Output};

#[derive(Args)]
pub struct ArtifactsArgs {
    #[command(subcommand)]
    pub command: ArtifactsCommand,
}

#[derive(Subcommand)]
pub enum ArtifactsCommand {
    /// The index row for one `(target, rustc, c_metadata)` identity.
    Inspect(InspectArgs),
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

pub async fn run(args: ArtifactsArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        ArtifactsCommand::Inspect(args) => inspect(args, output).await,
    }
}

async fn inspect(args: InspectArgs, output: Output) -> stow_types::error::Result<()> {
    let target =
        TargetTriple::parse(&args.target).map_err(|error| stow_error!("--target: {error}"))?;
    let rustc_version =
        WireRustcVersion::parse(&args.rustc).map_err(|error| stow_error!("--rustc: {error}"))?;
    let c_metadata =
        CMetadata::parse(&args.c_metadata).map_err(|error| stow_error!("c_metadata: {error}"))?;
    let index = IndexSource::new(&rustc_version)
        .await?
        .verified_index_slice(target.as_str())
        .await?
        .ok_or_else(|| {
            stow_error!("index slice index.{target}.{rustc_version} is not published")
        })?;
    let row = index
        .rows
        .iter()
        .find(|row| row.c_metadata == c_metadata)
        .ok_or_else(|| stow_error!("index.{target}.{rustc_version} has no row for {c_metadata}"))?;
    render::emit(output, row, |row| {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "record  {} {} ({})",
            row.crate_name, row.version, row.c_metadata
        );
        let _ = writeln!(out, "  target      {}", index.header.target);
        let _ = writeln!(out, "  rustc       {}", index.header.rustc_version);
        let _ = writeln!(out, "  features    {}", row.features_json.raw());
        let _ = writeln!(
            out,
            "  bundle      {} ({} bytes)",
            row.bundle_digest, row.bundle_size
        );
        let _ = writeln!(
            out,
            "  kind        {:?}  dep_identity {}",
            row.artifact_kind, row.dependency_identity
        );
        out
    })
}
