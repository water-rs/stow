//! Stow's per-side unit graph types — the same shapes the vendored
//! resolver emits (`resolve/src/api.rs`), defined here on the published
//! `cargo` crate's types.
//!
//! One node per `(package, side)` as cargo's feature resolver decides
//! them — `FeaturesFor::NormalOrDev` on the requested target,
//! `FeaturesFor::HostDep` and proc-macro units on the runner-family host
//! triple, `FeaturesFor::ArtifactDep(t)` on `t`. Edges between nodes are
//! exactly the dependency edges cargo would compile; dev-dependency edges
//! are absent (stow builds the same unit set `cargo build` does, not
//! `cargo test`).

use std::collections::HashMap;

use cargo::core::PackageIdSpec;
use cargo::core::dependency::DepKind;
use cargo::core::resolver::features::{PackageFeaturesKey, ResolvedFeatures};
use serde::{Deserialize, Serialize};

/// Stow's per-side unit graph under `units`/`roots`.
#[derive(Debug, Serialize)]
pub struct StowResolveOutput {
    /// One node per `(package, side)` cargo would compile — the units stow
    /// keys builds and dedup on.
    pub units: Vec<StowUnit>,
    /// Unit keys the workspace members produce — the roots of `units`.
    pub roots: Vec<StowUnitKey>,
    /// Whether any workspace member declares or autodiscovers a `[[bin]]`
    /// — cargo's own target discovery (declared `[bin]`/`[[bin]]` plus
    /// `src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs` under `autobins`)
    /// ran during package load, so this sees member binaries in nested
    /// `crates/*` dirs exactly as `cargo build` does.
    pub has_binary: bool,
}

/// A node's identity: which package, on which platform, with which side's
/// feature set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StowUnitKey {
    /// Package-id spec as cargo prints it (`name version (source)`).
    pub pkg: PackageIdSpec,
    /// Triple the unit compiles on: a requested target, the runner-family
    /// host triple, or an artifact-dep target.
    pub platform: String,
    /// Which cargo side produced the features: `target`, `host`, or an
    /// artifact-dep target. Two nodes can share `(pkg, platform)` with
    /// different sides and carry different feature sets.
    pub side: StowSide,
    /// Which unit of the package this is — a package supplies both a lib
    /// and a build script.
    pub kind: StowUnitKind,
}

/// The cargo side a unit's features were resolved under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StowSide {
    /// `FeaturesFor::NormalOrDev` — the normal/dev side.
    Target,
    /// `FeaturesFor::HostDep` — build-dep/proc-macro side, features unified
    /// under the host platform.
    Host,
    /// `FeaturesFor::ArtifactDep(t)` — an `-Z bindeps` artifact dependency.
    Artifact,
}

/// Which unit of a package a node represents.
///
/// Mirrors `cargo build --unit-graph`'s `mode`/`target.kind`: every
/// package with a `build.rs` produces a host compile unit *and* a `run`
/// unit on the owning lib's platform; the lib unit edges to its run
/// unit, the run unit to the compile unit, and the compile unit to the
/// build-dep libs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StowUnitKind {
    /// A `lib`/`proc-macro` library target — the unit stow builds and caches.
    Lib,
    /// A `build.rs` compile unit — always a host compile.
    BuildScript,
    /// The `build.rs` execution unit — sits at the owning lib's platform
    /// between the lib and the script compile, as `run-custom-build` does in
    /// cargo's unit graph.
    RunBuildScript,
}

/// One build unit in the resolved graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StowUnit {
    /// The node's identity.
    #[serde(flatten)]
    pub key: StowUnitKey,
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// Which target of the package this unit compiles.
    pub unit_kind: StowUnitKind,
    /// Resolved feature set for this side — cargo's `activated_features`.
    pub features: Vec<String>,
    /// Whether the unit's package is a crates.io package — a registry
    /// `SourceId`, or a workspace member the caller marked
    /// [`crate::session::SessionInput::members_are_crates_io`]. Path
    /// members, path deps, and git packages are traversed by the graph
    /// but are not build tasks; only `is_crates_io` units may become
    /// tasks.
    pub is_crates_io: bool,
    /// Direct dependency edges of this unit.
    pub deps: Vec<StowDep>,
}

/// An edge from one unit to the unit that dep resolves to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StowDep {
    /// The target unit's identity.
    #[serde(flatten)]
    pub key: StowUnitKey,
    /// Dependency crate name.
    pub name: String,
    /// Dependency crate version.
    pub version: String,
    /// The dep's manifest kind on this edge.
    #[serde(with = "dep_kind_serde")]
    pub dep_kind: DepKind,
}

/// The vendored wire shape for [`DepKind`]: `null` for normal, `"dev"`,
/// `"build"`. Upstream `DepKind` implements `Serialize` with this shape
/// but no `Deserialize`, so the field module round-trips it.
mod dep_kind_serde {
    use cargo::core::dependency::DepKind;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    /// `None` for normal, `Some("dev")`/`Some("build")` — cargo's own
    /// `Serialize for DepKind` shape.
    // serde's serialize_with contract fixes the `&DepKind` signature.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(kind: &DepKind, s: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(kind, s)
    }

    /// The inverse of upstream's serialize.
    ///
    /// # Errors
    /// Unknown kind strings.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DepKind, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(DepKind::Normal),
            Some(s) if s == "dev" => Ok(DepKind::Development),
            Some(s) if s == "build" => Ok(DepKind::Build),
            Some(s) => Err(de::Error::custom(format!("unknown dependency kind `{s}`"))),
        }
    }
}

/// Pair of package specs requested for compilation along with enabled
/// features — the vendored `ops::SpecsAndResolvedFeatures` plus the
/// per-side dependency edges derived from [`crate::edges`].
///
/// `Debug` is manual: cargo's `ResolvedFeatures` has none.
pub struct SpecsAndResolvedFeatures {
    /// Packages that are supposed to be built.
    pub specs: Vec<PackageIdSpec>,
    /// The features activated per package.
    pub resolved_features: ResolvedFeatures,
    /// Resolved dependency edges per `(package, side)` as decided by the
    /// feature resolver — the graph cargo actually compiles, host edges
    /// keyed `FeaturesFor::HostDep` with cfg evaluated against the host
    /// triple.
    pub edges: HashMap<PackageFeaturesKey, Vec<crate::edges::SideEdge>>,
}

impl std::fmt::Debug for SpecsAndResolvedFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpecsAndResolvedFeatures")
            .field("specs", &self.specs)
            .field("edges", &self.edges)
            .finish_non_exhaustive()
    }
}
