use serde::{Deserialize, Serialize};

/// The payload that stow-build receives from the GH Actions `repository_dispatch` event.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildTaskPayload {
    pub task_id: String,
    pub crate_name: String,
    pub version: String,
    pub target: String,
}

/// Artifact record written to D1 by CI via Cloudflare D1 REST API.
///
/// This is the trusted path: CI → D1 directly, bypassing the untrusted edge worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Cargo's `-C metadata` value — part of the composite cache lookup key.
    pub c_metadata: String,
    /// Compilation target triple.
    pub target: String,
    /// Rustc version string (e.g., "1.83.0").
    pub rustc_version: String,
    /// Crate name (for analytics/display).
    pub crate_name: String,
    /// Crate version.
    pub version: String,
    /// JSON-encoded feature set.
    pub features_json: String,
    /// OCI reference (e.g., "ghcr.io/stow-rs/cache/serde:...").
    pub oci_reference: String,
    /// OCI manifest digest (e.g., "sha256:...").
    pub oci_digest: String,
    /// Whether this artifact has native (C/C++) components.
    pub has_native: bool,
    /// Whether this is a proc-macro crate.
    pub is_proc_macro: bool,
    /// Artifact size in bytes, for CF Cache 512MB limit decisions.
    pub artifact_size: u64,
}

/// Request body for scheduler DO's `/enqueue` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueRequest {
    pub crate_name: String,
    pub version: String,
    pub target: String,
    /// Total download count from crates.io (used for priority calculation).
    pub downloads: u64,
    /// Source of the enqueue request.
    pub source: EnqueueSource,
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

/// Edge forwards cache miss boost to the scheduler DO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissBoost {
    pub crate_name: String,
    pub target: String,
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
