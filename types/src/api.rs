//! HTTP wire types exchanged between the CLI, the edge worker, the
//! scheduler Durable Object, and trusted CI.
//!
//! Field docs describe the wire meaning of each payload; the validated
//! identity newtypes from [`crate::identity`] carry the invariants.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;
use crate::versioning::SemverBreakingLine;

/// The compilation target triples the trusted CI build fleet covers.
///
/// The runner map in `build-crate.yml` builds for exactly this set, so
/// `POST /api/v1/requests` expands every requested crate onto each of
/// them.
pub const CI_TARGET_TRIPLES: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// The task the scheduler dispatches to `stow-build`, carried verbatim as the
/// `workflow_dispatch` input of the trusted build workflow.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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

/// Artifact record CI POSTs to the edge's register endpoint after a build.
///
/// Sent to `/api/v1/admin/artifacts/register` once the build, sign, and OCI
/// push have all succeeded. The edge worker validates the
/// `x-stow-register-token` in constant time and persists the row in D1.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
    /// OCI reference (e.g., "ghcr.io/water-rs/stow-cache:serde.1.0.0-...").
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum EnqueueSource {
    /// Watcher detected a crate version update.
    CrateUpdate,
    /// Watcher detected a new rustc stable release.
    RustcUpdate,
    /// Edge reported a cache miss.
    CacheMiss,
    /// A Turnstile-verified human submitted `POST /api/v1/requests`. Tasks
    /// enqueued with this source land in the scheduler's human lane.
    HumanRequest,
}

/// Admission ticket the edge mints for one canonical enqueue task when a
/// public request misses the cache.
///
/// Returned inside miss responses — as the 404 body of
/// `POST /api/v1/artifacts/semantic` and in
/// `DependencyGraphResponse::miss_admissions` — so the fetch path stays
/// cheap. The client redeems the ticket by solving its proof-of-work and
/// posting an [`EnqueueTicket`] to `POST /api/v1/enqueue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnqueueAdmission {
    /// Canonical scheduler task id (blake3-derived identity string).
    pub task_id: String,
    /// Server-issued challenge — the hex HMAC-SHA256 over
    /// `task_id ‖ canonical request JSON ‖ issue_minute` under the edge's
    /// `STOW_POW_CHALLENGE_SECRET`. Opaque to clients; accepted during its
    /// issue minute and the minute after it.
    pub challenge: String,
    /// Leading zero bits the client's
    /// `blake3(task_id ‖ challenge ‖ nonce)` digest must show for
    /// `/enqueue` to accept the ticket. `0` means the queue is shallow
    /// enough that admission is free.
    pub difficulty: u32,
    /// The canonical enqueue request this admission authorizes. The edge is
    /// stateless: the client echoes `request` back in its ticket and
    /// `/api/v1/enqueue` forwards it to the scheduler after verifying the
    /// challenge binds it.
    pub request: EnqueueRequest,
}

/// Request body for `POST /api/v1/enqueue`: the redemption of an
/// [`EnqueueAdmission`].
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnqueueTicket {
    /// Canonical task id carried by the admission.
    pub task_id: String,
    /// The admission's server-issued challenge.
    pub challenge: String,
    /// Client-computed nonce such that
    /// `blake3(task_id ‖ challenge ‖ nonce)` has at least the required
    /// number of leading zero bits.
    pub nonce: u64,
    /// The canonical enqueue request from the admission. The edge
    /// recomputes the challenge HMAC over this payload and forwards it to
    /// the scheduler — no server-side request lookup.
    pub request: EnqueueRequest,
}

/// CI reports job completion to the scheduler DO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BuildCompleteReport {
    /// Scheduler task identifier, echoing `BuildTaskPayload::task_id`.
    pub task_id: String,
    /// Whether the build, sign, push, and registration all succeeded.
    pub success: bool,
    /// Failure description when `success` is false.
    pub error: Option<String>,
    /// Number of artifacts uploaded (including transitive deps).
    pub artifacts_uploaded: u32,
}

/// A normalized dependency entry from a resolved Cargo dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct DependencyGraphEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Sorted, deduplicated features (raw list — wire form is JSON array).
    pub features: Vec<String>,
}

/// One exact dependency edge in a client-resolved Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct ResolvedDependencyGraphDependency {
    /// Dependency crate name.
    pub crate_name: CrateName,
    /// Dependency crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
}

/// One exact crates.io package node resolved from the client's current lockfile graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedDependencyGraphEntry {
    /// Package crate name.
    pub crate_name: CrateName,
    /// Package crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Sorted, deduplicated features (raw list — wire form is JSON array).
    pub features: Vec<String>,
    /// Direct dependencies of this package.
    pub dependencies: Vec<ResolvedDependencyGraphDependency>,
}

/// Request sent by the CLI to edge for graph-aware cache analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DependencyGraphAnalysisEntry {
    /// The dependency entry this analysis row describes.
    pub dependency: DependencyGraphEntry,
    /// Number of cached artifacts covering `dependency` exactly.
    pub current_artifact_count: u32,
    /// The exact cached artifacts available for `dependency`.
    pub current_artifacts: Vec<DependencyGraphArtifact>,
    /// A newer semver-compatible version with cache coverage, when the edge
    /// found one worth recommending.
    pub recommended: Option<RecommendedDependencyVersion>,
}

/// One exact cached artifact currently available for a dependency entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DependencyGraphArtifact {
    /// Cargo `-C metadata` value of the cached artifact.
    pub c_metadata: CMetadata,
}

/// The recommended upgrade target for one dependency entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecommendedDependencyVersion {
    /// Version stow recommends upgrading to.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Number of cached artifacts covering that version.
    pub artifact_count: u32,
}

/// Batch response describing the current graph's cache coverage and upgrades.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DependencyGraphResponse {
    /// Per-entry analysis rows, one per requested `DependencyGraphEntry`.
    pub entries: Vec<DependencyGraphAnalysisEntry>,
    /// Packages in the transitive expansion that have full cache coverage.
    pub expanded_cached: usize,
    /// Total packages the transitive expansion resolved.
    pub expanded_total: usize,
    /// The client's pre-resolved transitive graph, normalized to
    /// `DependencyGraphEntry` form and echoed back; the edge never expands
    /// the graph itself.
    pub expanded_entries: Vec<DependencyGraphEntry>,
    /// Exact artifacts the client should batch-fetch to satisfy the graph.
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
    /// Enqueue admissions minted for this request's cache misses. The edge
    /// no longer enqueues on the fetch path; the client redeems each
    /// admission via `POST /api/v1/enqueue` after solving its proof-of-work.
    #[serde(default)]
    pub miss_admissions: Vec<EnqueueAdmission>,
}

/// Exact artifact batch request for one resolved dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchArtifactRequest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Exact artifacts to fetch in one batch.
    pub entries: Vec<BatchArtifactRequestEntry>,
}

/// One exact artifact to batch fetch from edge.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchArtifactRequestEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
}

/// Semantic artifact request from the CLI runtime wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SchedulerStatus {
    /// Tasks waiting to become dispatchable.
    pub pending: u32,
    /// Pending tasks in the human lane — a subset of `pending` counted
    /// separately so operators can see human-requested work.
    pub human_pending: u32,
    /// Tasks whose `workflow_dispatch` was sent but not yet picked up.
    pub dispatched: u32,
    /// Tasks a CI run has claimed but not yet reported complete.
    pub running: u32,
    /// Tasks that completed successfully.
    pub completed: u32,
    /// Tasks whose CI run reported failure.
    pub failed: u32,
}

/// One direct dependency the user's project declares.
///
/// Carries the crate name and semver requirement string from
/// `[dependencies]` in `Cargo.toml`. Sent to the edge's stow-resolver
/// endpoint so it can synthesize a cache-optimized `Cargo.lock`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

/// Request body for `POST /api/v1/requests`: a human asking for one crate
/// to be built into the public cache.
///
/// The endpoint is the submission path behind the request form on
/// `stow.waterui.dev`; the Turnstile token is the admission check and every
/// accepted request lands in the scheduler's human lane ahead of the
/// cache-miss queue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CrateRequest {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact version to request. When `None` the edge resolves the newest
    /// non-prerelease, non-yanked crates.io version.
    #[serde(default)]
    pub version: Option<CrateVersion>,
    /// Features to enable for the requested crate, in the canonical
    /// [`FeaturesJson`] representation. An empty list means the crate's
    /// `default` feature set.
    pub features_json: FeaturesJson,
    /// Cloudflare Turnstile token produced by the invisible widget. Verified
    /// against siteverify before the edge does any resolution work.
    pub turnstile_token: String,
}

/// One crate in a `GET /api/v1/crates/search` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateSearchHit {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// The crate's one-line description, when it has one.
    #[serde(default)]
    pub description: Option<String>,
    /// Newest version crates.io lists for the crate.
    pub max_version: CrateVersion,
    /// All-time download count, the ordering crates.io search returns.
    pub downloads: u64,
}

/// Response body for `GET /api/v1/crates/search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateSearchResponse {
    /// Matching crates, most downloaded first, capped by the `limit` query
    /// parameter.
    pub crates: Vec<CrateSearchHit>,
}

/// Response body for `GET /api/v1/crates/{crate_name}/versions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateVersionsResponse {
    /// Published, non-yanked versions, newest first.
    pub versions: Vec<CrateVersion>,
}

/// One feature a crate version declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateFeature {
    /// The feature name, as written in the crate's `[features]` table or
    /// implied by an optional dependency.
    pub name: String,
    /// The features and optional dependencies this one turns on. Empty for
    /// an implicit optional-dependency feature.
    pub implies: Vec<String>,
    /// Whether the crate's `default` feature set enables this feature,
    /// directly or transitively.
    pub default: bool,
}

/// Response body for `GET /api/v1/crates/{crate_name}/versions/{version}/features`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateFeaturesResponse {
    /// Every selectable feature of the version, `default` first and the
    /// rest alphabetical.
    pub features: Vec<CrateFeature>,
}

/// Which scheduler lane a queue row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskLane {
    /// Filled by the cache-miss path and watchers; subject to
    /// `STOW_DISPATCH_MIN_AGE_MINUTES` before dispatch.
    Miss,
    /// Filled by the Turnstile-verified human request API. Dispatches ahead
    /// of the miss lane and bypasses the minimum-age hold.
    Human,
}

impl TaskLane {
    /// The stable string persisted in the scheduler's `lane` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Miss => "miss",
            Self::Human => "human",
        }
    }

    /// Inverse of [`Self::as_str`] for values read back from queue rows.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "miss" => Some(Self::Miss),
            "human" => Some(Self::Human),
            _ => None,
        }
    }
}

/// Lifecycle of one scheduler queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueTaskStatus {
    /// Waiting for dependencies or dispatch eligibility.
    Pending,
    /// `workflow_dispatch` sent, awaiting the CI job to claim it.
    Dispatched,
    /// A CI run claimed the task but has not reported completion.
    Running,
    /// Build, signing, push, and registration all succeeded.
    Completed,
    /// The CI run reported failure.
    Failed,
}

impl QueueTaskStatus {
    /// The stable string persisted in the scheduler's `status` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Inverse of [`Self::as_str`] for values read back from queue rows.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "dispatched" => Some(Self::Dispatched),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Per-target state reported inside [`CrateRequestTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrateRequestState {
    /// The artifact already exists in the public cache for this target.
    Cached,
    /// This request enqueued the task into the human lane.
    Queued,
    /// The task was already in the queue (re-requesting promoted or
    /// refreshed it) when this request arrived.
    AlreadyQueued,
    /// The task has been dispatched or is actively building.
    Building,
}

/// Per-target outcome inside a [`CrateRequestOutcome`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateRequestTarget {
    /// Compilation target triple — one of [`CI_TARGET_TRIPLES`].
    pub target: TargetTriple,
    /// Where this target's task stands after the request.
    pub state: CrateRequestState,
    /// Scheduler task id for the requested crate on this target. Absent
    /// when `state` is [`CrateRequestState::Cached`].
    #[serde(default)]
    pub task_id: Option<String>,
    /// 1-based position among pending human-lane tasks in dispatch order;
    /// `None` unless the task is still pending in the human lane.
    #[serde(default)]
    pub human_lane_position: Option<u32>,
}

/// Response of `POST /api/v1/requests`: what the edge resolved and where
/// each supported target stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateRequestOutcome {
    /// Echoed crate name.
    pub crate_name: CrateName,
    /// The resolved version — the requested one, or the newest
    /// non-prerelease, non-yanked crates.io release.
    pub version: CrateVersion,
    /// Current stable rustc version the enqueued tasks target.
    pub rustc_version: WireRustcVersion,
    /// Per-target outcomes in [`CI_TARGET_TRIPLES`] order.
    pub targets: Vec<CrateRequestTarget>,
}

/// Point-in-time view of one scheduler task, returned by
/// `GET /api/v1/requests/{task_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RequestStatus {
    /// Canonical scheduler task id (blake3-derived identity string).
    pub task_id: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Exact crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Which scheduler lane the task is queued in.
    pub lane: TaskLane,
    /// Current task lifecycle state.
    pub status: QueueTaskStatus,
    /// 1-based position among pending human-lane tasks in dispatch order;
    /// `None` unless the task is a pending human-lane task.
    #[serde(default)]
    pub human_lane_position: Option<u32>,
}
