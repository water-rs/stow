use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::platform::Profile;
use crate::versioning::SemverBreakingLine;

/// The payload that stow-build receives from the GH Actions `repository_dispatch` event.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildTaskPayload {
    pub task_id: String,
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
}

/// Artifact record written to D1 by CI via Cloudflare D1 REST API.
///
/// This is the trusted path: CI → D1 directly, bypassing the untrusted edge worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Stable hash of the trusted build's exact rustc invocation identity.
    pub compile_key: String,
    /// Cargo's `-C metadata` value — part of the composite cache lookup key.
    pub c_metadata: String,
    /// Cargo's `-C extra-filename` suffix from the trusted build.
    pub extra_filename: String,
    /// Compilation target triple.
    pub target: String,
    /// Rustc version string (e.g., "1.83.0").
    pub rustc_version: String,
    /// Exact profile observed from the captured rustc invocation.
    pub profile: Profile,
    /// Exact `--emit` modes observed from the captured rustc invocation.
    pub emit: Vec<String>,
    /// Crate name (for analytics/display).
    pub crate_name: String,
    /// Crate version.
    pub version: String,
    /// JSON-encoded feature set.
    pub features_json: String,
    /// JSON-encoded dependency c_metadata identities captured from rustc --extern inputs.
    pub dependency_c_metadata_json: String,
    /// OCI reference (e.g., "ghcr.io/stow-rs/cache/serde:...").
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
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
    /// Total download count from crates.io (used for priority calculation).
    pub downloads: u64,
    /// Source of the enqueue request.
    pub source: EnqueueSource,
    /// Task-level dependencies that must be completed before this task can dispatch.
    #[serde(default)]
    pub depends_on: Vec<EnqueueDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueDependency {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub target: String,
    pub rustc_version: String,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphEntry {
    pub crate_name: String,
    pub version: semver::Version,
    pub features: Vec<String>,
}

/// One exact dependency edge in a client-resolved Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResolvedDependencyGraphDependency {
    pub crate_name: String,
    pub version: semver::Version,
}

/// One exact crates.io package node resolved from the client's current lockfile graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDependencyGraphEntry {
    pub crate_name: String,
    pub version: semver::Version,
    pub features: Vec<String>,
    pub dependencies: Vec<ResolvedDependencyGraphDependency>,
}

/// Request sent by the CLI to edge for graph-aware cache analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphRequest {
    pub target: String,
    pub rustc_version: String,
    pub entries: Vec<DependencyGraphEntry>,
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
    pub c_metadata: String,
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
    pub target: String,
    pub rustc_version: String,
    pub entries: Vec<BatchArtifactRequestEntry>,
}

/// One exact artifact to batch fetch from edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchArtifactRequestEntry {
    pub crate_name: String,
    pub c_metadata: String,
}

/// Semantic artifact request from the CLI runtime wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticArtifactRequest {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub dependency_c_metadata_json: String,
    pub target: String,
    pub rustc_version: String,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
}

/// A dependency miss that falls inside Stow's prebuild window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphMiss {
    pub dependency: DependencyGraphEntry,
    pub target: String,
    pub rustc_version: String,
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
