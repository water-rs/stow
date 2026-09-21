//! `stow-admin coverage <crate>[@version] [--target T]` — which servable
//! artifact identities exist per CI target, and which targets have none.

use std::fmt::Write as _;

use clap::Args;
use stow_types::api::CrateCoverage;
use stow_types::identity::{CrateName, CrateVersion, TargetTriple};
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct CoverageArgs {
    /// Crate name, optionally `name@version` to scope to one version.
    pub crate_spec: String,
    /// Limit the listing to one CI target.
    #[arg(long)]
    pub target: Option<String>,
}

/// Split `name[@version]`; the version half must parse as semver. Shared
/// by `coverage` and `preheat plan`, which take the same spec shape.
pub fn parse_crate_spec(
    spec: &str,
) -> stow_types::error::Result<(CrateName, Option<CrateVersion>)> {
    let (name, version) = match spec.split_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (spec, None),
    };
    let crate_name =
        CrateName::parse(name).map_err(|error| stow_error!("crate name `{name}`: {error}"))?;
    let version = version
        .map(|raw| {
            semver::Version::parse(raw)
                .map(CrateVersion::new)
                .map_err(|error| stow_error!("version `{raw}`: {error}"))
        })
        .transpose()?;
    Ok((crate_name, version))
}

pub async fn run(edge: &Edge, args: CoverageArgs, output: Output) -> stow_types::error::Result<()> {
    let (crate_name, version) = parse_crate_spec(&args.crate_spec)?;
    let target = args
        .target
        .as_deref()
        .map(|raw| TargetTriple::parse(raw).map_err(|error| stow_error!("--target: {error}")))
        .transpose()?;
    let mut path = format!("/api/v1/admin/coverage/{crate_name}");
    let mut params: Vec<String> = Vec::new();
    if let Some(version) = &version {
        params.push(format!("version={version}"));
    }
    if let Some(target) = &target {
        params.push(format!("target={target}"));
    }
    if !params.is_empty() {
        let _ = write!(path, "?{}", params.join("&"));
    }
    let coverage: CrateCoverage = edge.get_json(&path).await?;
    render::emit(output, &coverage, |coverage| {
        let mut out = format!(
            "{} {}\n",
            coverage.crate_name,
            coverage
                .version
                .as_ref()
                .map_or_else(|| "(all versions)".to_owned(), ToString::to_string)
        );
        let mut table = Table::new(&[
            "target",
            "version",
            "features",
            "rustc",
            "c_metadata",
            "bundle",
        ]);
        for target in &coverage.targets {
            if target.artifacts.is_empty() {
                table.push([
                    target.target.as_str().to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "—".to_owned(),
                    "none".to_owned(),
                ]);
            }
            for artifact in &target.artifacts {
                table.push([
                    target.target.as_str().to_owned(),
                    artifact.version.to_string(),
                    artifact.features_json.raw(),
                    artifact.rustc_version.as_str().to_owned(),
                    artifact.c_metadata.as_str().to_owned(),
                    render::size(artifact.bundle_size),
                ]);
            }
        }
        let _ = write!(out, "{}", table.render());
        out
    })
}
