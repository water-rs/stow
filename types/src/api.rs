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
use crate::index::ArtifactIndexRow;
use crate::platform::Profile;

/// The compilation target triples the trusted CI build fleet covers.
///
/// The runner map in `build-crate.yml` builds for exactly this set, so
/// `POST /api/v1/requests` expands every requested crate onto each of
/// them. The set is `WaterUI`'s shipping matrix (water-rs/stow#90);
/// the ESP32 `*-espidf` triples stay out because they need a forked
/// toolchain. Discontinued platforms stay out too — Intel Macs
/// (`x86_64-apple-darwin`, dropped by macOS 27), x86 Android, and
/// 32-bit ARM Android.
pub const CI_TARGET_TRIPLES: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-linux-android",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "wasm32-unknown-unknown",
];

/// Whether trusted CI has a runner that can build this target.
///
/// A target outside the set resolves to an empty `runs-on` in
/// `build-crate.yml`, and the dispatched run then dies before any job
/// starts — no job, no log, no completion report, and the queue slot spent
/// until the stale-dispatch sweep reclaims it. Every path that can put a
/// task in the queue checks this first.
#[must_use]
pub fn is_ci_target(target: &str) -> bool {
    CI_TARGET_TRIPLES.contains(&target)
}

/// The GitHub Actions runner pool a CI target builds on.
///
/// Mirrors the `runs-on` map in `build-crate.yml`: `macos-14` for the
/// Apple targets, `windows-latest` for the MSVC targets, `ubuntu-latest`
/// for the rest. The scheduler caps dispatches per family because the
/// pools are sized very differently — the org's macOS pool is the
/// smallest — and starts the slow Windows legs of a wave first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunnerFamily {
    /// `ubuntu-latest` — also hosts the Android and wasm builds.
    Linux,
    /// `macos-14` — the smallest pool in the org's runner fleet.
    MacOs,
    /// `windows-latest` — the slowest legs of a full wave.
    Windows,
}

impl RunnerFamily {
    /// Every family, for iteration.
    pub const ALL: [Self; 3] = [Self::Linux, Self::MacOs, Self::Windows];

    /// The [`CI_TARGET_TRIPLES`] members that build on this family's
    /// runner.
    #[must_use]
    pub const fn targets(self) -> &'static [&'static str] {
        match self {
            Self::Linux => &[
                "aarch64-linux-android",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "wasm32-unknown-unknown",
            ],
            Self::MacOs => &[
                "aarch64-apple-darwin",
                "aarch64-apple-ios",
                "aarch64-apple-ios-sim",
            ],
            Self::Windows => &["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"],
        }
    }
}

/// Which runner family `build-crate.yml` dispatches this target to, or
/// `None` for a target its `runs-on` map does not name.
#[must_use]
pub fn runner_family(target: &str) -> Option<RunnerFamily> {
    RunnerFamily::ALL
        .into_iter()
        .find(|family| family.targets().contains(&target))
}

/// The task the scheduler dispatches to `stow-build`, carried verbatim as the
/// `workflow_dispatch` input of the trusted build workflow.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BuildTaskPayload {
    /// Opaque scheduler task identifier (blake3 of identity tuple).
    pub task_id: String,
    /// Which queue attempt this dispatch carries. The scheduler bumps a
    /// row's attempt every time a re-request resurrects it out of
    /// failed/completed, and `complete` only applies a report whose attempt
    /// matches the row's live one — a stale or duplicate report is a
    /// conflict, never a silent overwrite of a newer attempt's state.
    /// Defaults to 0 so a payload serialized before the field existed still
    /// decodes; attempt 0 matches no row (attempts start at 1), so such a
    /// report is rejected rather than applied blindly.
    #[serde(default)]
    pub attempt: u32,
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
    /// When set, the trusted build compiles a git checkout — the source a
    /// real project ships — instead of a crates.io tarball. The checkout's
    /// own `Cargo.lock` resolves the graph, so captured artifacts carry the
    /// `dependency_c_metadata` chain that project's consumers compute. This
    /// is the lockfile-seeding mode `stow-admin preheat-binary-overlay
    /// --manifest-path` submits: building the project's real workspace makes
    /// every cached artifact the one the project's graph actually asks for.
    #[serde(default)]
    pub project_source: Option<ProjectSource>,
}

impl BuildTaskPayload {
    /// Whether the build resolves against the lockfile the source ships.
    ///
    /// Always true for project-source tasks: the project's own `Cargo.lock`
    /// is the entire point of the mode, so a task that somehow arrived with
    /// `preserve_lockfile` unset still builds `--locked` rather than
    /// silently drifting to latest-semver resolution.
    #[must_use]
    pub const fn uses_source_lockfile(&self) -> bool {
        self.preserve_lockfile || self.project_source.is_some()
    }
}

/// A git checkout the trusted build compiles instead of a crates.io
/// tarball, resolved by the checkout's own `Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProjectSource {
    /// Git URL the runner clones (https in production; a local path is
    /// accepted so the dev dispatch server can clone a worktree).
    pub url: String,
    /// Full commit SHA the checkout is pinned to. An immutable ref keeps a
    /// moving branch from swapping the compiled code between enqueue and
    /// build.
    pub commit: String,
    /// Manifest path relative to the repository root (`Cargo.toml` for a
    /// workspace-root manifest).
    pub manifest_path: String,
}

/// Artifact record CI POSTs to the edge's register endpoint after a build.
///
/// Sent to `/api/v1/admin/artifacts/register` once the build, sign, and OCI
/// push have all succeeded. The edge worker authenticates the caller's
/// GitHub identity (Actions OIDC for CI, push-user token otherwise) and
/// persists the row in D1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
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
    /// Artifact size in bytes: the sum of the uncompressed output files.
    pub artifact_size: u64,
    /// Digest (`sha256:…`) of the assembled bundle tar the trusted publish
    /// stage pushed as the `<tag>.bundle` layer. The edge streams exactly
    /// this blob to CLIs; it is what the byte path is keyed and fetched by.
    pub bundle_digest: String,
    /// Size in bytes of the bundle tar — the exact `content-length` of a
    /// bundle GET and the input to the Cache API size gate.
    pub bundle_size: u64,
    /// Wall-clock milliseconds the captured rustc invocation took — what a
    /// served hit on this artifact is credited as CPU time saved.
    pub compile_millis: u64,
}

/// Request body for `POST /api/v1/admin/artifacts/register`.
///
/// `task_id` binds the record set to the scheduler task the calling run
/// was dispatched for: the edge requires the task to be in flight and
/// every record to belong to the task's dependency closure before it
/// writes a row. The Actions OIDC identity must name a task; a repo-push
/// caller (the operator/backfill path) may omit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RegisterArtifactsRequest {
    /// Scheduler task id the registering run was dispatched for
    /// (`BuildTaskPayload::task_id`). Required from the Actions OIDC
    /// identity; optional for repo-push callers.
    #[serde(default)]
    pub task_id: Option<String>,
    /// Artifact records to upsert into the catalog.
    pub records: Vec<ArtifactRecord>,
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
    /// Mirrors `BuildTaskPayload::project_source`: when set, the task builds
    /// the named git checkout with its own `Cargo.lock` rather than a
    /// crates.io tarball. Part of the queue identity — a project task and a
    /// crate tarball task for the same `crate_name`/`version` never
    /// deduplicate.
    #[serde(default)]
    pub project_source: Option<ProjectSource>,
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
    /// Queue attempt this report belongs to, echoing
    /// `BuildTaskPayload::attempt`. The scheduler applies the report only
    /// when it matches the row's live attempt in a dispatched/running
    /// state; anything else is a stale or duplicate report and conflicts.
    /// Defaults to 0, which matches no row (attempts start at 1).
    #[serde(default)]
    pub attempt: u32,
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

/// The anonymous-traffic circuit breaker ("panic switch").
///
/// Held by the scheduler Durable Object. `enabled: true` makes every
/// anonymous edge route answer `503 Service Unavailable` while the trusted
/// `/api/v1/admin/*` and `/api/v1/scheduler/*` routes keep working. Wire
/// shape of `GET`/`POST /api/v1/admin/panic` and of the scheduler object's
/// `/panic` routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PanicSwitch {
    /// Whether anonymous traffic is being shed.
    pub enabled: bool,
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
    /// [`FeaturesJson`] representation. The list is taken literally:
    /// `["default", ...]` builds with default features on, and an empty
    /// list is `--no-default-features` with nothing added.
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
    /// Whether the task builds against the bundled `Cargo.lock`
    /// (`EnqueueRequest::preserve_lockfile`). Combined with
    /// `project_source` it tells whether the task's dependency closure is
    /// reproducible from crates.io metadata.
    #[serde(default)]
    pub preserve_lockfile: bool,
    /// Project checkout the task builds instead of a crates.io tarball.
    #[serde(default)]
    pub project_source: Option<ProjectSource>,
}

impl RequestStatus {
    /// Whether the task resolves dependencies from a lockfile the edge
    /// cannot reproduce — a `preserve_lockfile` overlay resolves the
    /// tarball's bundled lockfile, and a project-source task resolves the
    /// checkout's own one. Mirrors
    /// [`BuildTaskPayload::uses_source_lockfile`].
    #[must_use]
    pub const fn uses_source_lockfile(&self) -> bool {
        self.preserve_lockfile || self.project_source.is_some()
    }
}

/// Response body for `GET /api/v1/admin/index/{target}/{rustc_version}`.
///
/// One keyset page of the slice's servable artifact rows — the data
/// `stow-admin index export` assembles into the published
/// [`crate::index::ArtifactIndex`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactIndexPage {
    /// Rows ordered by `c_metadata`, every one strictly after the
    /// request's `after` cursor and carrying a published bundle.
    pub rows: Vec<ArtifactIndexRow>,
    /// The `after` cursor for the next page — the last row's `c_metadata`
    /// when this page was full, `None` once the slice is exhausted.
    pub next_after: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{CI_TARGET_TRIPLES, RunnerFamily, runner_family};

    /// Every CI target must land in exactly one family, and the families'
    /// `targets()` lists together must be exactly `CI_TARGET_TRIPLES` —
    /// drift between this mapping and the `runs-on` map in
    /// `build-crate.yml` would let the scheduler cap and order the wrong
    /// rows.
    #[test]
    fn runner_families_partition_ci_target_triples() {
        let mut mapped: Vec<&str> = Vec::new();
        for family in RunnerFamily::ALL {
            mapped.extend_from_slice(family.targets());
        }
        mapped.sort_unstable();
        let mut all = CI_TARGET_TRIPLES.to_vec();
        all.sort_unstable();
        assert_eq!(mapped, all);
        for target in CI_TARGET_TRIPLES {
            assert!(
                runner_family(target).is_some(),
                "{target} maps to no runner family"
            );
        }
        assert_eq!(runner_family("aarch64-unknown-linux-musl"), None);
    }
}
/// Public aggregate usage statistics served by `GET /api/v1/stats`.
///
/// Every count is derived from anonymized Analytics Engine events: hit
/// events are sampled at one in ten and their published counts are scaled
/// by the stored sample weight, so the numbers are approximate by design.
/// Fields that could publish a dangerously small count are suppressed
/// (`None`) rather than reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct UsageStats {
    /// Estimated distinct installs that served a cache hit in the last 7
    /// days, counted by daily-salted unlinkable install hash. `None` below
    /// the minimum publication threshold — stow never reports small counts.
    pub active_installs_7d: Option<u64>,
    /// Cache hits served in the last 24 hours (sample-scaled estimate).
    pub hits_24h: u64,
    /// Cache misses served in the last 24 hours.
    pub misses_24h: u64,
    /// `hits_24h / (hits_24h + misses_24h)`; `0.0` when nothing was served.
    pub hit_rate_24h: f64,
    /// CPU-hours of rustc compilation saved in the last 30 days: the
    /// recorded compile time of every artifact served, sample-scaled, plus
    /// opt-in `stow stats --share` contributions.
    pub cpu_hours_saved_30d: f64,
    /// Most-served crates over the last 30 days.
    pub top_crates_30d: Vec<UsageStatEntry>,
    /// Hits per compilation target over the last 30 days.
    pub targets_30d: Vec<UsageStatEntry>,
    /// Hits per CLI version over the last 30 days; requests that sent no
    /// `stow-cli` user agent are not counted under any version.
    pub cli_versions_30d: Vec<UsageStatEntry>,
}

/// One `(name, hits)` bucket of a [`UsageStats`] leaderboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UsageStatEntry {
    /// Bucket label: crate name, target triple, or CLI version.
    pub name: String,
    /// Sample-scaled hit count for the bucket.
    pub hits: u64,
}

/// Request body of `POST /api/v1/stats/share`: the opt-in aggregate a
/// `stow stats --share` run contributes. Carries one number and nothing
/// else — no crate names, no counts, no identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatsShare {
    /// Total CPU milliseconds this install's local statistics report as
    /// saved by cache hits.
    pub cpu_millis_saved: u64,
}
