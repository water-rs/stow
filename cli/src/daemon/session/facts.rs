//! What a session is opened with, in two parts.
//!
//! [`BuildFacts`] are what any build's decisions read: its environment,
//! toolchain, config, output roots and the rules for refusals. They hold
//! for a session whatever opened it. [`DriverFacts`] are what a driver's
//! own analysis settled before cargo started: the project's layout, the
//! analysis seed and the rustc spelling the miss journal records.
//!
//! Plain data only: the process that runs a session has its own
//! environment and working directory and none of the driver's handles, so
//! everything the build's decisions read travels here, once, when the
//! session opens. A session never changes them afterwards; what it
//! derives (the serve map, the allow set, the analysis facts) lives in its
//! own state.

use std::ffi::OsString;
use std::path::PathBuf;

use stow_types::api::DependencyGraphEntry;

use crate::cache_policy::CachePolicyEntry;
use crate::cargo_cmd::ProjectFacts;
use crate::config::StowConfig;
use crate::daemon::session::invocation::{OutputRoots, RefusalPolicy};
use crate::facade::ServeMap;
use crate::prefetch::PrefetchArtifact;
use crate::toolchain::ToolchainFacts;
use crate::unit_node::UnitNodeTable;

/// Everything one build's session is opened with.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionFacts {
    /// What decides the build's units, whoever opened the session.
    pub build: BuildFacts,
    /// What the driver's own analysis settled.
    pub driver: DriverFacts,
}

/// The facts the decisions of any build read.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildFacts {
    /// The build's full environment: what every process the session
    /// starts runs with, and what bare spellings resolve through.
    pub environ: Vec<(OsString, OsString)>,
    /// The build's working directory.
    pub cwd: PathBuf,
    /// The build's rustc and the answers probed from it.
    pub toolchain: ToolchainFacts,
    /// The resolved config, run flags included. `None` for a build with no
    /// config: every unit compiles uncached.
    pub config: Option<StowConfig>,
    /// The public cache is off for this build (an unsupported toolchain, a
    /// profile the cache cannot key); local lookups still run.
    pub public_cache_disabled: bool,
    /// The consumer target the build's wrappers fall back to for an
    /// invocation that does not spell `--target`.
    pub public_cache_target: Option<String>,
    /// The directories the build's compiler outputs live under.
    pub roots: OutputRoots,
    /// What a refused request does to the build.
    pub refusal_policy: RefusalPolicy,
    /// How the build tells a crates.io package from another registry's.
    pub(crate) registry_sources: crate::RegistrySources,
    /// The extra rustc arguments appended to every unit — the workspace
    /// path remap and any flags the driver selected — after the user's own
    /// rustflags sources keep their cargo semantics.
    pub rustc_extra_args: Vec<String>,
}

/// The facts only a driver has: what its pre-cargo analysis resolved.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriverFacts {
    /// The build's project: its layout, targets and rustc.
    pub project: ProjectFacts,
    /// The rustc spelling the build's own cargo configuration names: what
    /// the miss journal records for the drain to run.
    pub build_rustc: OsString,
    /// What the build's analysis knew before cargo started.
    pub seed: Seed,
}

/// The facts the driver's own analysis had settled when the session
/// opened.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Seed {
    /// The build's initial serve map; `None` plans every unit through the
    /// lookup chain.
    pub serve_map: Option<ServeMap>,
    /// The crates the analysis marked as worth a public lookup; `None` is
    /// "no policy" and allows every unit.
    pub cache_policy_entries: Option<Vec<CachePolicyEntry>>,
    /// The build's per-side unit node table.
    pub unit_nodes: Option<UnitNodeTable>,
    /// The artifacts the driver already fetched.
    pub prefetch_artifacts: Option<Vec<PrefetchArtifact>>,
    /// Whether the plan path may serve a semver upgrade.
    pub semantic_fallback_enabled: bool,
    /// The facts above came from the filesystem-only pass: the full
    /// analysis is owed to the build while cargo runs.
    pub deferred: bool,
    /// The analysis's inexact superset-hit report, journaled with the
    /// build's misses.
    pub inexact_entries: Vec<DependencyGraphEntry>,
}

#[cfg(test)]
impl SessionFacts {
    /// Facts for a session a test assembles from parts: a project that
    /// names no real workspace, the given toolchain's facts and no config.
    pub(crate) fn for_tests(
        toolchain: ToolchainFacts,
        roots: OutputRoots,
        refusal_policy: RefusalPolicy,
    ) -> Self {
        let project = ProjectFacts {
            action: "check".to_owned(),
            cargo_args: Vec::new(),
            workspace_root: PathBuf::from("/workspace"),
            current_dir: PathBuf::from("/workspace"),
            current_dir_relative: PathBuf::new(),
            manifest_path: PathBuf::from("/workspace/Cargo.toml"),
            metadata_args: crate::cargo_cmd::MetadataArgs::default(),
            target: toolchain.host_target.clone(),
            target_given: false,
            host_target: toolchain.host_target.clone(),
            rustc_version: toolchain.release.clone(),
        };
        Self {
            build: BuildFacts {
                environ: Vec::new(),
                cwd: PathBuf::from("/workspace"),
                public_cache_target: Some(project.target.clone()),
                toolchain,
                config: None,
                public_cache_disabled: false,
                roots,
                refusal_policy,
                registry_sources: crate::RegistrySources::CargoConfig(
                    std::iter::once("index.crates.io".to_owned()).collect(),
                ),
                rustc_extra_args: Vec::new(),
            },
            driver: DriverFacts {
                project,
                build_rustc: OsString::from("rustc"),
                seed: Seed::default(),
            },
        }
    }
}
