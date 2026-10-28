//! `stow-admin coverage <crate>[@version] [--target T] [--rustc R]` —
//! which servable artifact identities exist per CI target, and which
//! targets have none. The answer comes from the signed `index` slices
//! in GHCR — pulled and verified the way the CLI reads them — never
//! from a mirrored store.

use std::fmt::Write as _;

use clap::Args;
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::api::{CI_TARGET_TRIPLES, CoverageArtifact, CoverageTarget, CrateCoverage};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use stow_types::registry::cache_repository;
use stow_types::stow_error;

use crate::index_cmd::{INDEX_CERT_URL, decode_published_slice, registry_base, verify_artifact};
use crate::render::{self, Output, Table};

/// The concurrent slice-pull bound — one pull per CI target at most.
const PULL_CONCURRENCY: usize = CI_TARGET_TRIPLES.len();

#[derive(Args)]
pub struct CoverageArgs {
    /// Crate name, optionally `name@version` to scope to one version.
    pub crate_spec: String,
    /// Limit the listing to one CI target.
    #[arg(long)]
    pub target: Option<String>,
    /// The rustc whose slice answers; defaults to the stable channel.
    #[arg(long)]
    pub rustc: Option<String>,
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

/// The registry pieces every per-target pull shares: one session on the
/// rustc's package, the records trust and the repository — built once,
/// borrowed by each pull.
pub struct IndexSource {
    session: stow_oci::RegistrySession,
    trust: stow_oci::verify::Trust,
    repository: stow_types::registry::CacheRepository,
    rustc_version: WireRustcVersion,
}

impl IndexSource {
    /// Build the shared pull pieces once for `rustc_version`.
    pub async fn new(rustc_version: &WireRustcVersion) -> stow_types::error::Result<Self> {
        let base = registry_base()?;
        let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
        let repository = cache_repository(rustc_version);
        let session = base.session(&repository, &http);
        let trust = crate::index_cmd::records_trust().await?;
        Ok(Self {
            session,
            trust,
            repository,
            rustc_version: rustc_version.clone(),
        })
    }

    /// Pull and verify `index.<target>.<rustc>` — `None` when the slice
    /// has never been published.
    pub async fn verified_index_slice(
        &self,
        target: &str,
    ) -> stow_types::error::Result<Option<stow_types::index::ArtifactIndex>> {
        let Some(pulled) =
            stow_oci::pull_index(&self.session, target, self.rustc_version.as_str()).await?
        else {
            return Ok(None);
        };
        let itag = stow_types::index::index_tag(target, self.rustc_version.as_str());
        let reference = self.session.reference(&itag)?;
        verify_artifact(
            &self.session,
            &self.trust,
            &reference,
            &self.repository.reference(&itag),
            &pulled.manifest_digest,
            INDEX_CERT_URL,
        )
        .await?;
        decode_published_slice(&reference, &self.rustc_version, &pulled.bytes).map(Some)
    }
}

pub async fn run(args: CoverageArgs, output: Output) -> stow_types::error::Result<()> {
    let (crate_name, version) = parse_crate_spec(&args.crate_spec)?;
    let rustc_version = match &args.rustc {
        Some(raw) => {
            WireRustcVersion::parse(raw).map_err(|error| stow_error!("--rustc: {error}"))?
        }
        None => crate::rust_channel::stable_rustc_version().await?,
    };
    let targets = match &args.target {
        Some(raw) => {
            let target =
                TargetTriple::parse(raw).map_err(|error| stow_error!("--target: {error}"))?;
            vec![target]
        }
        None => CI_TARGET_TRIPLES
            .iter()
            .map(|triple| {
                TargetTriple::parse(*triple)
                    .map_err(|error| stow_error!("CI target `{triple}`: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut coverage = CrateCoverage {
        crate_name: crate_name.clone(),
        version: version.clone(),
        targets: Vec::new(),
    };
    let indexes = pull_indexes(&targets, &rustc_version).await?;
    for (target, index) in targets.into_iter().zip(indexes) {
        let Some(index) = index else {
            coverage.targets.push(CoverageTarget {
                artifacts: Vec::new(),
                target,
            });
            continue;
        };
        let artifacts = index
            .rows
            .iter()
            .filter(|row| {
                row.crate_name == crate_name && version.as_ref().is_none_or(|v| &row.version == v)
            })
            .map(|row| CoverageArtifact {
                version: row.version.clone(),
                features_json: row.features_json.clone(),
                rustc_version: index.header.rustc_version.clone(),
                c_metadata: row.c_metadata.clone(),
                bundle_size: row.bundle_size,
            })
            .collect();
        coverage.targets.push(CoverageTarget { artifacts, target });
    }
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

/// Pull and verify every target's `index.<t>.<rustc>` slice at once —
/// `buffered` keeps `targets` order in the answers.
async fn pull_indexes(
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<Option<stow_types::index::ArtifactIndex>>> {
    let source = IndexSource::new(rustc_version).await?;
    futures_util::stream::iter(
        targets
            .iter()
            .map(|target| source.verified_index_slice(target.as_str())),
    )
    .buffered(PULL_CONCURRENCY)
    .try_collect()
    .await
}
