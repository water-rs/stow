use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;
use crate::versioning::SemverBreakingLine;

/// The task the scheduler dispatches to `stow-build`, carried verbatim as the
/// `workflow_dispatch` input of the trusted build workflow.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildTaskPayload {
    /// Opaque scheduler task identifier (blake3 of identity tuple).
    pub task_id: String,
    /// Crate name as known to crates.io.
    pub crate_name: CrateName,
    /// Exact crate version to build.
    pub version: CrateVersion,
    /// Canonicalized features list (sorted, deduplicated).
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version (e.g. `"1.83.0"`).
    pub rustc_version: WireRustcVersion,
    /// When true, the trusted build runner keeps the bundled `Cargo.lock` from
    /// the crates.io tarball instead of removing it. Used by the binary-derived
    /// overlay (`stow-admin preheat-binary-overlay`) so transitive `c_metadata`
    /// matches what `cargo install --locked <bin>` would produce on the user's
    /// machine. Defaults to false to preserve the historical "build against
    /// latest semver-compatible deps" behavior for library preheats.
    #[serde(default)]
    pub preserve_lockfile: bool,
}

/// Artifact record CI POSTs to the edge worker's
/// `/api/v1/admin/artifacts/register` endpoint after a successful build,
/// sign, and OCI push. The edge worker validates the `x-stow-register-token`
/// in constant time and persists the row in D1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Stable hash of the trusted build's exact rustc invocation identity.
    pub compile_key: String,
    /// Cargo's `-C metadata` value — part of the composite cache lookup key.
    pub c_metadata: CMetadata,
    /// Cargo's `-C extra-filename` suffix from the trusted build.
    pub extra_filename: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Rustc version string (e.g., "1.83.0").
    pub rustc_version: WireRustcVersion,
    /// Exact profile observed from the captured rustc invocation.
    pub profile: Profile,
    /// Exact `--emit` modes observed from the captured rustc invocation.
    /// Must be strictly sorted and deduplicated.
    pub emit: Vec<String>,
    /// Crate name (for analytics/display).
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// JSON-encoded feature set; canonicalized (sorted + deduplicated).
    pub features_json: FeaturesJson,
    /// JSON-encoded dependency `c_metadata` identities captured from rustc
    /// --extern inputs; sorted by `(crate_name, c_metadata)`.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// OCI reference (e.g., "ghcr.io/water-rs/stow-cache/serde:...").
    pub oci_reference: String,
    /// OCI manifest digest (e.g., "sha256:...").
    pub oci_digest: String,
    /// Whether this artifact has native (C/C++) components.
    pub has_native: bool,
    /// Primary artifact kind for OCI naming and analytics.
    pub artifact_kind: ArtifactKind,
    /// Declared Rust crate types from cargo metadata / rustc args.
    pub crate_types: Vec<RustCrateType>,
    /// Artifact size in bytes, for CF Cache 512MB limit decisions.
    pub artifact_size: u64,
}

/// Request body for scheduler task submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueRequest {
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Total download count from crates.io (used for priority calculation).
    pub downloads: u64,
    /// Source of the enqueue request.
    pub source: EnqueueSource,
    /// Task-level dependencies that must be completed before this task can dispatch.
    #[serde(default)]
    pub depends_on: Vec<EnqueueDependency>,
    /// Mirrors `BuildTaskPayload::preserve_lockfile`. Set to true for binary-
    /// derived overlay enqueues so the trusted build resolves transitive deps
    /// against the binary's published `Cargo.lock`.
    #[serde(default)]
    pub preserve_lockfile: bool,
}

/// One task-level dependency that must complete before its parent dispatches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueDependency {
    /// Dependency crate name.
    pub crate_name: CrateName,
    /// Dependency crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
}

/// Where an enqueue request originated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnqueueSource {
    /// Watcher detected a crate version update.
    CrateUpdate,
    /// Watcher detected a new rustc stable release.
    RustcUpdate,
    /// Edge reported a cache miss.
    CacheMiss,
}

/// CI reports job completion to the scheduler DO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCompleteReport {
    pub task_id: String,
    pub success: bool,
    pub error: Option<String>,
    /// Number of artifacts uploaded (including transitive deps).
    pub artifacts_uploaded: u32,
}

/// A normalized dependency entry from a resolved Cargo dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyGraphEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub version: semver::Version,
    /// Sorted, deduplicated features (raw list — wire form is JSON array).
    pub features: Vec<String>,
}

/// One exact dependency edge in a client-resolved Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResolvedDependencyGraphDependency {
    /// Dependency crate name.
    pub crate_name: CrateName,
    /// Dependency crate version.
    pub version: semver::Version,
}

/// One exact crates.io package node resolved from the client's current lockfile graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependencyGraphEntry {
    /// Package crate name.
    pub crate_name: CrateName,
    /// Package crate version.
    pub version: semver::Version,
    /// Sorted, deduplicated features (raw list — wire form is JSON array).
    pub features: Vec<String>,
    /// Direct dependencies of this package.
    pub dependencies: Vec<ResolvedDependencyGraphDependency>,
}

/// Request sent by the CLI to edge for graph-aware cache analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphRequest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Direct dependency entries from the user's lockfile graph.
    pub entries: Vec<DependencyGraphEntry>,
    /// Optional client-pre-resolved transitive graph.
    #[serde(default)]
    pub expanded_entries: Vec<ResolvedDependencyGraphEntry>,
}

/// Edge response for one dependency entry in the requested graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphAnalysisEntry {
    pub dependency: DependencyGraphEntry,
    pub current_artifact_count: u32,
    pub current_artifacts: Vec<DependencyGraphArtifact>,
    pub recommended: Option<RecommendedDependencyVersion>,
}

/// One exact cached artifact currently available for a dependency entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphArtifact {
    /// Cargo `-C metadata` value of the cached artifact.
    pub c_metadata: CMetadata,
}

/// The recommended upgrade target for one dependency entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedDependencyVersion {
    pub version: semver::Version,
    pub artifact_count: u32,
}

/// Batch response describing the current graph's cache coverage and upgrades.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphResponse {
    pub entries: Vec<DependencyGraphAnalysisEntry>,
    pub expanded_cached: usize,
    pub expanded_total: usize,
    pub expanded_entries: Vec<DependencyGraphEntry>,
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
}

/// Exact artifact batch request for one resolved dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchArtifactRequest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Exact artifacts to fetch in one batch.
    pub entries: Vec<BatchArtifactRequestEntry>,
}

/// One exact artifact to batch fetch from edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchArtifactRequestEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
}

/// Semantic artifact request from the CLI runtime wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticArtifactRequest {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Sorted `(crate_name, c_metadata)` of dependencies driving the cache key.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Cargo profile observed from the rustc invocation.
    pub profile: Profile,
    /// Sorted, deduplicated `--emit` modes.
    pub emit: Vec<String>,
    /// Artifact kind (rlib / dylib / proc-macro).
    pub kind: ArtifactKind,
    /// Declared rust crate types.
    pub crate_types: Vec<RustCrateType>,
}

/// A dependency miss that falls inside Stow's prebuild window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphMiss {
    /// The dependency that missed cache.
    pub dependency: DependencyGraphEntry,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Semver breaking line containing the missing version.
    pub breaking_line: SemverBreakingLine,
}

/// Scheduler DO queue status for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStatus {
    pub pending: u32,
    pub dispatched: u32,
    pub running: u32,
    pub completed: u32,
    pub failed: u32,
}

/// One direct dependency the user's project declares: crate name + semver
/// requirement string from `[dependencies]` in `Cargo.toml`. Sent to the
/// edge's stow-resolver endpoint so it can synthesize a cache-optimized
/// `Cargo.lock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDirectDependency {
    /// Direct dependency crate name.
    pub crate_name: CrateName,
    /// Semver requirement string (e.g. `"^1.0"`, `">=1.0,<2"`, `"=1.5.3"`).
    pub req: String,
    /// Features the user's manifest enables for this dep, in raw form.
    /// `default` is included if the user did not set `default-features = false`.
    #[serde(default)]
    pub features: Vec<String>,
}

/// Request body for `/api/v1/catalog/resolve-lockfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveLockfileRequest {
    /// User's compilation target triple.
    pub target: TargetTriple,
    /// User's stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// User's direct deps with semver requirements.
    pub direct: Vec<UserDirectDependency>,
}

/// Edge response carrying a stow-synthesized `Cargo.lock` whose every
/// `[[package]]` entry corresponds to a cached artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveLockfileResponse {
    /// `Some` when stow's resolver found a consistent cache-optimized
    /// assignment for every direct dep + transitive closure. `None` when
    /// no consistent assignment exists in cache (CLI falls back to
    /// cargo's resolver).
    pub lockfile_toml: Option<String>,
    /// Crate names from `direct` that the resolver could not satisfy from
    /// cache. Empty when `lockfile_toml` is `Some`.
    pub uncovered_direct: Vec<CrateName>,
    /// Number of (crate, version) candidate slots the resolver explored.
    pub candidates_considered: u32,
    /// Diagnostic: top partial-match candidates from the seed search,
    /// each entry `"<crate> <version> covered=<n>/<total>: <reason>"`.
    /// Empty when a seed was found.
    #[serde(default)]
    pub seed_diagnostics: Vec<String>,
}
