//! HTTP wire types exchanged between the CLI, the edge worker, the
//! scheduler Durable Object, and trusted CI.
//!
//! Field docs describe the wire meaning of each payload; the validated
//! identity newtypes from [`crate::identity`] carry the invariants.

use std::collections::BTreeMap;

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

    /// The triple host-gated units (`proc-macro`, `build-dependencies`,
    /// `build.rs`) compile on for builds dispatched to this family's runner —
    /// the runner's own platform. macOS runners are arm64.
    #[must_use]
    pub const fn host_triple(self) -> &'static str {
        match self {
            Self::Linux => "x86_64-unknown-linux-gnu",
            Self::MacOs => "aarch64-apple-darwin",
            Self::Windows => "x86_64-pc-windows-msvc",
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
    /// the crates.io tarball instead of removing it. Used by the top-binaries
    /// preheat (`stow-admin preheat top-binaries`) so transitive `c_metadata`
    /// matches what `cargo install --locked <bin>` would produce on the user's
    /// machine. Defaults to false to preserve the historical "build against
    /// latest semver-compatible deps" behavior for library preheats.
    #[serde(default)]
    pub preserve_lockfile: bool,
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

/// Request body for `POST /api/v1/admissions`: the misses a client's
/// local index resolution found, plus the resolved graph the edge needs
/// to re-derive the enqueue set with dominator pruning.
///
/// The client's dependency graph never leaves the machine in raw form for
/// *coverage* — this call happens only when the local resolver already
/// decided entries are uncovered, and the edge re-checks coverage against
/// the catalog before minting anything.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdmissionRequest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Direct-dep entries the local resolver found uncovered.
    pub entries: Vec<DependencyGraphEntry>,
    /// The client's resolved transitive graph.
    #[serde(default)]
    pub expanded_entries: Vec<ResolvedDependencyGraphEntry>,
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
    /// The build stopped early: a cargo phase exited non-zero before the
    /// unit graph finished, and the run registered the artifacts it
    /// captured up to the failure instead of nothing at all. Only
    /// meaningful when `success` is false — `artifacts_uploaded` then
    /// counts the published prefix, never the task's whole closure.
    /// Absent from reports written before the field existed.
    #[serde(default)]
    pub partial: bool,
    /// Failure description when `success` is false.
    pub error: Option<String>,
    /// Number of artifacts uploaded (including transitive deps).
    pub artifacts_uploaded: u32,
    /// GitHub Actions run id the report came from. CI leaves it `None`;
    /// the edge overwrites it with the OIDC token's `run_id` claim before
    /// forwarding, so the queue row carries the run that produced it.
    #[serde(default)]
    pub github_run_id: Option<String>,
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
    /// Tasks whose CI run stopped early but registered the artifacts it
    /// produced. Absent from responses written before the field existed.
    #[serde(default)]
    pub partial: u32,
    /// Pending tasks parked behind a terminally failed dependency —
    /// a subset of `pending` counted so operators can tell "waiting for
    /// a publish" from "waiting on something that will never come".
    #[serde(default)]
    pub blocked: u32,
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
    /// Parked behind a terminally failed dependency: every dependency
    /// edge is still unserved and at least one names a `failed`/`partial`
    /// task. Never stored — the scheduler derives it from a `pending`
    /// row at read time, so retrying the dependency returns the row to
    /// `pending` with nothing to reconcile.
    Blocked,
    /// `workflow_dispatch` sent, awaiting the CI job to claim it.
    Dispatched,
    /// A CI run claimed the task but has not reported completion.
    Running,
    /// Build, signing, push, and registration all succeeded.
    Completed,
    /// The CI run reported failure.
    Failed,
    /// The CI run stopped early but registered the artifacts it produced
    /// before cargo failed — the task's own output is still missing, so
    /// it is not a completion, but it did not land empty-handed either.
    Partial,
}

impl QueueTaskStatus {
    /// The stable string a queue row's `status` carries on the wire —
    /// `blocked` only ever appears as that derived read-time value, never
    /// in the stored column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Partial => "partial",
        }
    }

    /// Inverse of [`Self::as_str`] for values read back from queue rows.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "blocked" => Some(Self::Blocked),
            "dispatched" => Some(Self::Dispatched),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "partial" => Some(Self::Partial),
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
    /// The requested crate publishes no library target — a name source,
    /// never a task. Its dependency closure is what the request enqueued.
    ClosureQueued,
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
    /// (`EnqueueRequest::preserve_lockfile`), which decides whether the
    /// task's dependency closure is reproducible from crates.io metadata.
    #[serde(default)]
    pub preserve_lockfile: bool,
    /// What holds this task — the failed dependency's task id, or
    /// `unknown dependency identity` when an edge's identity was never
    /// resolved. Set only when `status` is [`QueueTaskStatus::Blocked`].
    #[serde(default)]
    pub blocked_by: Option<String>,
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

/// The index-publish path's report of what a slice serves.
///
/// Request body for `POST /api/v1/admin/index/{target}/{rustc_version}`,
/// sent after the slice goes live. The scheduler stores the set as the
/// membership the dependency gate checks a dependent's edges against —
/// a dependent dispatches only when every dependency resolves to a row
/// the latest report for that dependency's own `(target, rustc_version)`
/// covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSliceReport {
    /// Semantic identities the published slice serves. Artifact rows
    /// sharing one identity (`c_metadata`/`compile_key` variants)
    /// collapse into it; the order is irrelevant.
    pub rows: Vec<PublishedSliceRow>,
}

/// One servable semantic identity inside a [`PublishedSliceReport`].
///
/// Semantic identity is exactly what a dependency edge names, so the
/// gate compares it directly — no `c_metadata` lookup on either side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSliceRow {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact crate version.
    pub version: CrateVersion,
    /// Canonicalized features list.
    pub features_json: FeaturesJson,
}

/// Body the edge forwards to the scheduler's `/index/published` — one
/// [`PublishedSliceReport`] plus the `(target, rustc_version)` slice it
/// describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSlice {
    /// The slice's compilation target triple.
    pub target: TargetTriple,
    /// The slice's stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Semantic identities the slice serves.
    pub rows: Vec<PublishedSliceRow>,
}

// ===== Operations API (`stow-admin` under `/api/v1/admin/*`) =====

/// Selector for `GET /api/v1/admin/queue` and
/// `POST /api/v1/admin/queue/{retry,cancel,promote,purge}`.
///
/// One flat struct on purpose: the same shape has to decode from a JSON
/// body and from a query string, and a nested or `#[serde(flatten)]`ed
/// half forces serde to buffer the query's values as strings, which no
/// numeric field can then deserialize from. So `{"task_ids": […],
/// "status": "failed"}` and `?task_ids=a&task_ids=b&status=failed&limit=5`
/// decode identically, and the mutation preview lists exactly the rows a
/// selector names.
///
/// Every predicate is optional; a selector with none of them selects
/// every row (and is rejected for mutations — an operator mutation must
/// name either explicit task ids or at least one predicate).
///
/// A non-empty `task_ids` selects exactly those rows and the predicates
/// are ignored; otherwise the predicates select. Either way the verb's
/// own status/lane predicates still apply — a mutation never touches a
/// row outside its transition domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueSelector {
    /// Explicit task ids.
    #[serde(default)]
    pub task_ids: Vec<String>,
    /// Lifecycle status to match.
    #[serde(default)]
    pub status: Option<QueueTaskStatus>,
    /// Compilation target to match.
    #[serde(default)]
    pub target: Option<TargetTriple>,
    /// Crate name to match (`crate` on the wire).
    #[serde(default, rename = "crate", alias = "crate_name")]
    pub crate_name: Option<CrateName>,
    /// Only rows whose `updated_at` is at least this many seconds old
    /// (`older_than` on the wire).
    #[serde(default, rename = "older_than", alias = "older_than_secs")]
    pub older_than_secs: Option<u64>,
    /// Most rows a listing returns (bounded server-side); mutations
    /// ignore it — a mutation selector either matches everything its
    /// predicates describe or is rejected.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Response of the `queue retry|cancel|promote|purge` endpoints: how many
/// rows the transition touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueMutationResult {
    /// Rows the transition affected.
    pub affected: u32,
}

/// One queue row as `GET /api/v1/admin/queue` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueTask {
    /// Scheduler task identifier.
    pub task_id: String,
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target.
    pub target: TargetTriple,
    /// Rustc version the row builds for.
    pub rustc_version: WireRustcVersion,
    /// Dispatch lane the row is queued in.
    pub lane: TaskLane,
    /// Lifecycle status.
    pub status: QueueTaskStatus,
    /// Live enqueue epoch — completion reports only apply to this attempt.
    pub attempt: u32,
    /// Last dispatch/build error, empty when none.
    pub error: String,
    /// crates.io download count captured at enqueue time.
    pub downloads: u64,
    /// Cache misses this row is responsible for.
    pub miss_count: u32,
    /// Cache-hit requests this row has served demand for.
    pub request_count: u32,
    /// Dispatches attempted against this row.
    pub dispatch_attempts: u32,
    /// Whether the row builds against its checked-in lockfile.
    pub preserve_lockfile: bool,
    /// GitHub Actions run id the dispatched build reported back through
    /// its OIDC-claimed register/complete calls.
    #[serde(default)]
    pub github_run_id: Option<String>,
    /// First request timestamp (`YYYY-MM-DD HH:MM:SS` UTC).
    pub first_requested_at: String,
    /// Row creation timestamp.
    pub created_at: String,
    /// Last state-transition timestamp.
    pub updated_at: String,
    /// What holds this row — the failed dependency's task id, or
    /// `unknown dependency identity` when an edge's identity was never
    /// resolved. Set only when `status` is [`QueueTaskStatus::Blocked`].
    #[serde(default)]
    pub blocked_by: Option<String>,
}

/// One in-flight (dispatched/running) queue row in [`AdminStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminInFlight {
    /// Scheduler task identifier.
    pub task_id: String,
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Compilation target.
    pub target: TargetTriple,
    /// Rustc version the row builds for.
    pub rustc_version: WireRustcVersion,
    /// Lifecycle status (`dispatched` or `running`).
    pub status: QueueTaskStatus,
    /// Live enqueue epoch.
    pub attempt: u32,
    /// Dispatches attempted against this row.
    pub dispatch_attempts: u32,
    /// Last state-transition timestamp — the stale-dispatch lease clock.
    pub updated_at: String,
    /// GitHub Actions run id, once the run has reported back.
    #[serde(default)]
    pub github_run_id: Option<String>,
}

/// Per-target completion tallies over the trailing 24 hours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminTargetStats {
    /// Compilation target.
    pub target: TargetTriple,
    /// Rows that completed in the window.
    pub completed_24h: u32,
    /// Rows that failed in the window.
    pub failed_24h: u32,
    /// Rows that stopped early in the window but registered what they
    /// produced. Absent from responses written before the field existed.
    #[serde(default)]
    pub partial_24h: u32,
}

/// Response of `GET /api/v1/admin/status` — the scheduler's operator view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminStatus {
    /// Pending rows in the cache-miss lane.
    pub pending_miss: u32,
    /// Pending rows in the human lane.
    pub pending_human: u32,
    /// Pending rows parked behind a terminally failed dependency.
    #[serde(default)]
    pub blocked: u32,
    /// Age in seconds of the oldest pending row (`first_requested_at`).
    #[serde(default)]
    pub oldest_pending_seconds: Option<u64>,
    /// Dispatched/running rows, oldest transition first.
    pub in_flight: Vec<AdminInFlight>,
    /// Per-target completion tallies over the trailing 24 hours.
    pub targets: Vec<AdminTargetStats>,
    /// Whether the anonymous-traffic circuit breaker is engaged.
    pub panic_enabled: bool,
}

/// Response of `POST /api/v1/scheduler/tasks/submit` — what a request batch
/// became after canonicalization and enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerSubmitResponse {
    /// Requests that canonicalized and were handed to the scheduler.
    pub submitted: u32,
    /// Brand-new queue rows inserted; the rest of `submitted` updated or
    /// merged into existing rows.
    pub inserted: u32,
    /// Requests dropped during canonicalization (unpublished version or
    /// unresolvable `depends_on`).
    pub dropped: u32,
}

/// Response of `GET /api/v1/admin/coverage/{crate}` — per-CI-target
/// servable identities for one crate (one version when `version` was given).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateCoverage {
    /// Crate the coverage describes.
    pub crate_name: CrateName,
    /// Version the coverage is scoped to (`None` = every published version).
    #[serde(default)]
    pub version: Option<CrateVersion>,
    /// One entry per [`CI_TARGET_TRIPLES`] target — or just the requested
    /// target — in canonical order; an empty `artifacts` list means the
    /// target has nothing servable.
    pub targets: Vec<CoverageTarget>,
}

/// One target's servable identities inside [`CrateCoverage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CoverageTarget {
    /// Compilation target.
    pub target: TargetTriple,
    /// Servable identities (published bundle rows) for this target.
    pub artifacts: Vec<CoverageArtifact>,
}

/// One servable artifact identity inside [`CoverageTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CoverageArtifact {
    /// Crate version the artifact serves.
    pub version: CrateVersion,
    /// Canonical features list the artifact was built with.
    pub features_json: FeaturesJson,
    /// Rustc version the artifact was built by.
    pub rustc_version: WireRustcVersion,
    /// Cargo `-C metadata` identity.
    pub c_metadata: CMetadata,
    /// Bundle tar size in bytes.
    pub bundle_size: u64,
}

/// Request body for `POST /api/v1/admin/preheat/plan` — a dry run of the
/// resolver's closure expansion and dominance pruning for one crate
/// request. Nothing is enqueued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatPlanRequest {
    /// Crate name to plan for.
    pub crate_name: CrateName,
    /// Exact version; absent resolves the newest non-prerelease,
    /// non-yanked published release.
    #[serde(default)]
    pub version: Option<CrateVersion>,
    /// Seed features (`[]` = `--no-default-features` semantics).
    pub features_json: FeaturesJson,
    /// One compilation target, or absent for every [`CI_TARGET_TRIPLES`]
    /// target.
    #[serde(default)]
    pub target: Option<TargetTriple>,
    /// Rustc version; absent resolves the scheduler's stable channel
    /// version.
    #[serde(default)]
    pub rustc_version: Option<WireRustcVersion>,
}

/// Response of `POST /api/v1/admin/preheat/plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatPlanResponse {
    /// Crate the plan was computed for.
    pub crate_name: CrateName,
    /// Version the request resolved to.
    pub version: CrateVersion,
    /// Rustc version the plan was computed for.
    pub rustc_version: WireRustcVersion,
    /// One plan per resolved target, in [`CI_TARGET_TRIPLES`] order.
    pub targets: Vec<PreheatPlanTarget>,
}

/// One target's enqueue plan inside [`PreheatPlanResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatPlanTarget {
    /// Compilation target.
    pub target: TargetTriple,
    /// Whether the requested crate already has a servable artifact here.
    pub root_cached: bool,
    /// Tasks the dispatch wave would enqueue — dominance-pruned, so
    /// `depends_on` edges hold dominated rows until their dominator
    /// resolves. Tasks with an empty `depends_on` are the wave's roots.
    pub tasks: Vec<EnqueueRequest>,
}

/// Request body for `POST /api/v1/admin/resolve/crate`.
///
/// Resolves one published `.crate` into the task batch its crates.io
/// dependency graph produces. The tarball's bundled `Cargo.lock` stays
/// in place, so the resolve lands on the pins `cargo install --locked`
/// would use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminResolveCrateRequest {
    /// Crate name on crates.io.
    pub crate_name: CrateName,
    /// Exact published version.
    pub version: CrateVersion,
    /// Compilation targets to resolve (CI triples).
    pub targets: Vec<TargetTriple>,
    /// Stable rustc version the tasks key on.
    pub rustc_version: WireRustcVersion,
    /// Download count carried into each task's priority.
    #[serde(default)]
    pub downloads: u64,
}

/// Request body for `POST /api/v1/admin/resolve/project`.
///
/// Resolves a GitHub repository's workspace into crate tasks. The
/// committed `Cargo.lock` is dropped: a project contributes names and
/// feature sets, never version pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminResolveProjectRequest {
    /// Repository in `owner/name` form (codeload host).
    pub repo: String,
    /// Ref to fetch — a branch, tag, sha, or `HEAD` for the default branch.
    pub git_ref: String,
    /// Compilation targets to resolve (CI triples).
    pub targets: Vec<TargetTriple>,
    /// Stable rustc version the tasks key on.
    pub rustc_version: WireRustcVersion,
    /// Download count carried into each task's priority.
    #[serde(default)]
    pub downloads: u64,
}

/// Response of the admin resolve endpoints: publish-shape flags plus the
/// task batch per requested target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminResolveResponse {
    /// Whether the resolved source ships a `[[bin]]` target — the binaries
    /// lane's skip condition, read from cargo's own target knowledge.
    pub has_binary: bool,
    /// Whether the resolved root package ships a library target.
    pub has_library: bool,
    /// Whether the resolved source shipped a `Cargo.lock` the resolve
    /// honored — kept for the lane's log line.
    pub ships_lockfile: bool,
    /// One task batch per requested target, in request order.
    pub targets: Vec<AdminResolveTarget>,
}

/// One target's task batch inside [`AdminResolveResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminResolveTarget {
    /// Compilation target the batch was resolved for.
    pub target: TargetTriple,
    /// Tasks for every node in the resolved graph — a node inside another
    /// node's closure rides on its dominator's `depends_on`.
    pub tasks: Vec<EnqueueRequest>,
}

/// Response of `GET /api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}`:
/// the D1 catalog row plus the bundle image's OCI manifest read from GHCR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactInspection {
    /// The D1 catalog row.
    pub record: ArtifactRecord,
    /// The bundle image's OCI manifest (`manifests/<tag>.bundle`).
    pub manifest: OciManifest,
}

/// OCI image manifest — the document a `manifests/<reference>` GET serves.
/// Wire field names are camelCase (`schemaVersion`, `mediaType`), the
/// OCI distribution spec's casing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    /// Manifest schema version (`2` for every served document).
    pub schema_version: u32,
    /// Manifest media type.
    #[serde(default)]
    pub media_type: Option<String>,
    /// Config blob descriptor.
    pub config: OciDescriptor,
    /// Layer blob descriptors.
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
    /// Manifest annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// One blob descriptor inside an [`OciManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    /// Blob media type.
    pub media_type: String,
    /// `sha256:…` content digest.
    pub digest: String,
    /// Blob size in bytes.
    pub size: u64,
    /// Descriptor annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// Query for `GET /api/v1/admin/artifacts` — a bounded catalog listing
/// used to preview a prune and for ad-hoc inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactListQuery {
    /// Only rows built by this rustc version.
    #[serde(default)]
    pub rustc_version: Option<WireRustcVersion>,
    /// Only rows for this compilation target.
    #[serde(default)]
    pub target: Option<TargetTriple>,
    /// Only rows for this crate (`crate` on the wire).
    #[serde(default, rename = "crate", alias = "crate_name")]
    pub crate_name: Option<CrateName>,
    /// Most rows to return (bounded server-side).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Request body for `POST /api/v1/admin/artifacts/prune`.
///
/// Deletes every catalog row built by `rustc_version` — the retired
/// toolchain — and invalidates its lookup-cache entries. GHCR image tags
/// are not deleted; they age out under the package's own retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactPruneRequest {
    /// Retired toolchain whose rows are pruned.
    pub rustc_version: WireRustcVersion,
}

/// Response of `POST /api/v1/admin/artifacts/prune`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactPruneResponse {
    /// Catalog rows deleted.
    pub deleted: u32,
}

/// Body for the scheduler DO's `/tasks/observe-run`.
///
/// Stamps the GitHub Actions run id onto an in-flight queue row so
/// `status` can surface a run URL. Stamping does not touch `updated_at`
/// — the stale-dispatch lease clock only moves on real state
/// transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ObserveRun {
    /// Task id the run was dispatched for.
    pub task_id: String,
    /// GitHub Actions run id from the OIDC token's `run_id` claim.
    pub github_run_id: String,
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
    /// Average number of distinct installs served a cache hit per day over
    /// the last 7 days, counted by daily-salted unlinkable install hash (a
    /// hash cannot be joined across days, so the figure is per-day, and
    /// hits are sampled, so it is a lower bound). `None` below the minimum
    /// publication threshold — stow never reports small counts.
    pub daily_active_installs_7d: Option<u64>,
    /// Cache hits served in the last 24 hours (sample-scaled estimate).
    pub hits_24h: u64,
    /// Cache misses served in the last 24 hours.
    pub misses_24h: u64,
    /// `hits_24h / (hits_24h + misses_24h)`; `0.0` when nothing was served.
    pub hit_rate_24h: f64,
    /// CPU-hours of rustc compilation saved in the last 30 days: the
    /// recorded compile time of every artifact served, sample-scaled.
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
