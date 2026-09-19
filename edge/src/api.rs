use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use futures_util::stream::{self, StreamExt};
use skyzen::extract::{Extractor, Query};
use skyzen::header::HeaderValue;
use skyzen::routing::Params;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::api::{
    ArtifactRecord, BatchArtifactRequest, BuildCompleteReport, CI_TARGET_TRIPLES, CrateRequest,
    CrateRequestOutcome, DependencyGraphRequest, DependencyGraphResponse, EnqueueAdmission,
    EnqueueTicket, ResolveLockfileRequest, ResolveLockfileResponse, SemanticArtifactRequest,
};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBatchManifestEntry, STOW_BATCH_BUNDLE_MEDIA_TYPE,
    STOW_BATCH_BUNDLES_DIR, STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MEDIA_TYPE,
};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple};
use tar::{Builder, Header};

use crate::db;
use crate::github_auth;
use crate::registry_auth::RegistryTokens;
use crate::turnstile::{CfTurnstileVerifier, TurnstileVerifier};
use crate::{
    admission, bundle_schema, cache, catalog, crates_io, dependency_resolver, ghcr, miss_logger,
    scheduler, scheduler_client,
};

const EDGE_BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Header value for `x-stow-cache: hit|miss`.
const fn cache_status_header(cache_hit: bool) -> HeaderValue {
    if cache_hit {
        HeaderValue::from_static("hit")
    } else {
        HeaderValue::from_static("miss")
    }
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct OkResponse {
    ok: bool,
}

/// Marker that the request's `Authorization: Bearer` credential cleared the
/// GitHub trust check under [`github_auth::Policy::RepoWriter`]: a GitHub
/// Actions OIDC token minted inside the trusted repo, or a user token whose
/// owner can push to it (`stow-admin`, local dev).
///
/// Verifying inside the extractor — rather than in the handler body —
/// rejects unauthorized requests *before* `Json` deserializes a
/// potentially large body.
#[derive(Debug, Clone)]
pub struct SchedulerCaller(pub github_auth::TrustedCaller);

impl Extractor for SchedulerCaller {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        extract_trusted_caller(request, github_auth::Policy::RepoWriter)
            .await
            .map(Self)
    }
}

/// Marker that the caller cleared [`github_auth::Policy::BuildWorkflow`] —
/// the OIDC pin that lets only `build-crate.yml` runs (or a repo-push user
/// driving the same endpoint in local dev) write `artifacts` rows.
#[derive(Debug, Clone)]
pub struct ArtifactWriteCaller(pub github_auth::TrustedCaller);

impl Extractor for ArtifactWriteCaller {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        extract_trusted_caller(request, github_auth::Policy::BuildWorkflow)
            .await
            .map(Self)
    }
}

/// Pull the bearer credential off `Authorization` and authenticate it
/// against GitHub under `policy`. Upstream failures (JWKS, repo-permission
/// API) surface as `TrustUpstreamUnavailable` — a 502 the CI retries —
/// rather than a 401 that would look like a credential problem.
async fn extract_trusted_caller(
    request: &mut Request,
    policy: github_auth::Policy,
) -> Result<github_auth::TrustedCaller, GetArtifactError> {
    let bearer = request
        .headers()
        .get(skyzen::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(GetArtifactError::Unauthorized)?
        .to_owned();
    let config = State::<github_auth::GitHubTrustConfig>::extract(request)
        .await
        .map_err(|_| {
            GetArtifactError::InternalWithMessage("github trust config binding missing".to_owned())
        })?;
    github_auth::authenticate(
        &config,
        &github_auth::CfGitHubTrust,
        &bearer,
        policy,
        now_unix(),
    )
    .await
    .map_err(|error| match error {
        github_auth::AuthError::Unauthorized => GetArtifactError::Unauthorized,
        github_auth::AuthError::Upstream(reason) => {
            tracing::warn!(%reason, "github trust upstream check failed");
            GetArtifactError::TrustUpstreamUnavailable
        }
    })
}

/// Wall-clock seconds for OIDC `exp`/`nbf` checks — `js_sys::Date` is the
/// only clock available in the wasm worker.
fn now_unix() -> i64 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "js_sys::Date::now() returns positive epoch milliseconds; whole seconds are the intended unit"
    )]
    let seconds = (js_sys::Date::now() / 1_000.0) as i64;
    seconds
}

/// The caller's `CF-Connecting-IP`, forwarded to Turnstile siteverify as
/// `remoteip`. `None` when the request did not come in through Cloudflare's
/// edge (local dev), which siteverify accepts.
#[derive(Debug, Clone)]
pub struct CfConnectingIp(pub Option<String>);

impl Extractor for CfConnectingIp {
    type Error = GetArtifactError;

    fn extract(
        request: &mut Request,
    ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
        let remoteip = request
            .headers()
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        std::future::ready(Ok(Self(remoteip)))
    }
}

/// Enqueue-admission parameters carried via `State<PowAdmission>`: the HMAC
/// secret minting miss challenges (`STOW_POW_CHALLENGE_SECRET`) and the
/// queue-depth scaling factor for proof-of-work difficulty
/// (`STOW_POW_DEPTH_PER_BIT`; 0 disables `PoW`).
#[derive(Debug, Clone)]
pub struct PowAdmission {
    pub challenge_secret: String,
    pub depth_per_bit: u32,
}

/// Wall-clock minute the admission protocol stamps challenges with —
/// `js_sys::Date` is the only clock available in the wasm worker.
fn now_minute() -> u64 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "js_sys::Date::now() returns positive epoch milliseconds; truncating to whole minutes is the intended bucket"
    )]
    let minute = (js_sys::Date::now() / 60_000.0) as u64;
    minute
}

/// Required `PoW` bits for freshly-minted admissions, derived from the
/// scheduler's current pending depth. A status hiccup degrades to
/// zero-difficulty admissions rather than failing the miss response — a
/// dead scheduler cannot accept enqueues anyway.
async fn admission_difficulty(
    scheduler: &CfDurableNamespace,
    admission: &PowAdmission,
) -> Result<u32, GetArtifactError> {
    match scheduler_client::get_status(scheduler).await {
        Ok(status) => Ok(admission::difficulty_for_depth(
            status.pending,
            admission.depth_per_bit,
        )),
        Err(error) => {
            tracing::error!(%error, "failed to read scheduler queue depth for miss admissions");
            Ok(0)
        }
    }
}

/// Mint stateless admissions for `requests`: each carries its canonical
/// request plus a challenge HMAC-binding `(task_id, request)` to this
/// minute, and the queue-depth-derived `difficulty`. Nothing is persisted —
/// `/api/v1/enqueue` recomputes the challenge over the request the client
/// echoes back.
fn mint_admissions(
    admission: &PowAdmission,
    requests: Vec<stow_types::api::EnqueueRequest>,
    difficulty: u32,
) -> Result<Vec<EnqueueAdmission>, GetArtifactError> {
    let minute = now_minute();
    let mut admissions = Vec::with_capacity(requests.len());
    for request in requests {
        let source_json = scheduler::queue::source_json(request.project_source.as_ref())
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &request.version.to_string(),
            request.features_json.raw().as_str(),
            request.target.as_str(),
            request.rustc_version.as_str(),
            &source_json,
        );
        let request_json = serde_json::to_vec(&request)
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
        let challenge = admission::issue_challenge(
            &admission.challenge_secret,
            &task_id,
            &request_json,
            minute,
        );
        admissions.push(EnqueueAdmission {
            task_id,
            challenge,
            difficulty,
            request,
        });
    }
    Ok(admissions)
}

/// 404 response whose body carries the admission the client redeems via
/// `/api/v1/enqueue` — a miss still reports "not found" to clients that
/// ignore the body.
fn admission_miss_response(admission: &EnqueueAdmission) -> Result<Response, GetArtifactError> {
    let mut response = Response::new(
        Body::from_json(admission)
            .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    );
    *response.status_mut() = StatusCode::NOT_FOUND;
    Ok(response)
}

/// Mint the enqueue admission for one semantic miss: canonicalize the
/// request (dropping bogus feature seeds and versions crates.io does not
/// publish), then stamp it with a challenge binding it to this minute.
/// `None` means no canonical task exists — the caller reports a plain 404.
async fn semantic_miss_admission(
    db: &Db,
    scheduler: &CfDurableNamespace,
    admission: &PowAdmission,
    request: &SemanticArtifactRequest,
    fetch_concurrency: usize,
) -> Result<Option<EnqueueAdmission>, GetArtifactError> {
    tracing::warn!(
        crate_name = %request.crate_name,
        version = %request.version,
        features_json = %request.features_json,
        target = %request.target,
        rustc_version = %request.rustc_version,
        profile = ?request.profile,
        emit = ?request.emit,
        kind = %request.kind.as_str(),
        crate_types = ?request.crate_types,
        "semantic artifact lookup miss"
    );
    let canonical = dependency_resolver::canonicalize_enqueue_requests(
        db,
        &crates_io::CfCratesIo,
        vec![stow_types::api::EnqueueRequest {
            crate_name: request.crate_name.clone(),
            version: request.version.clone(),
            features_json: request.features_json.clone(),
            target: request.target.clone(),
            rustc_version: request.rustc_version.clone(),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
            project_source: None,
        }],
        fetch_concurrency,
    )
    .await?;
    let Some(request) = canonical.into_iter().next() else {
        return Ok(None);
    };
    let difficulty = admission_difficulty(scheduler, admission).await?;
    let mut admissions = mint_admissions(admission, vec![request], difficulty)?;
    Ok(admissions.pop())
}

/// POST /api/v1/catalog/resolve-lockfile
///
/// Active stow resolver: synthesize a complete `Cargo.lock` whose every
/// `[[package]]` entry corresponds to a cached artifact. The user submits
/// only their direct deps (with semver requirements + features); we walk
/// the artifacts table greedily, pinning each direct dep to a cached
/// (version, features, `c_metadata`) that satisfies the user's req, then
/// extending the closure by walking each pinned artifact's
/// `dependency_c_metadata_json` to fix the (name, `c_metadata`) of every
/// transitive. On conflict (two paths require different `c_metadata` for
/// the same crate name) we backtrack to a different candidate. When no
/// consistent assignment exists we return `lockfile_toml: None` and the
/// CLI falls back to cargo's own resolver.
///
/// Public endpoint — read-only over cache contents.
pub async fn resolve_lockfile(
    Json(request): Json<ResolveLockfileRequest>,
    db: Db,
) -> Result<Json<ResolveLockfileResponse>, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let outcome = crate::resolver::run_stow_resolver(&db, &request)
        .await
        .map_err(GetArtifactError::from)?;
    Ok(Json(outcome))
}

/// POST /api/v1/admin/artifacts/register
///
/// Trusted CI registers freshly-built artifacts here. CI does NOT write to
/// D1 directly; `ArtifactWriteCaller` pins the OIDC path to
/// `build-crate.yml` runs (a push-user GitHub token also passes, which is
/// what the local dev loop uses) and the edge owns the D1 binding.
/// INSERT OR REPLACE semantics keep registration idempotent across CI
/// retries.
pub async fn register_artifacts(
    ArtifactWriteCaller(caller): ArtifactWriteCaller,
    Json(records): Json<Vec<ArtifactRecord>>,
    db: Db,
) -> Result<Json<OkResponse>, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let count = records.len();
    for record in &records {
        db::insert_artifact_record(&db, record).await?;
    }
    tracing::info!(
        registered = count,
        %caller,
        "registered artifact records via admin endpoint"
    );
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/scheduler/tasks/submit
///
/// Control endpoint that submits arbitrary tasks into the scheduler.
///
/// `SchedulerCaller` extracts first and rejects unauthorized requests
/// before `Json` runs, so an attacker cannot make us deserialize an
/// arbitrary body without a trusted GitHub credential.
pub async fn submit_scheduler_tasks(
    SchedulerCaller(caller): SchedulerCaller,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let requests = dependency_resolver::canonicalize_enqueue_requests(
        &db,
        &crates_io::CfCratesIo,
        requests,
        settings.batch_fetch_concurrency,
    )
    .await?;
    scheduler_client::send_enqueue(&scheduler, &requests).await?;
    tracing::info!(tasks = requests.len(), %caller, "submitted scheduler tasks");
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/scheduler/complete
///
/// CI (or local simulated CI) reports build completion to the scheduler
/// Durable Object. `ArtifactWriteCaller` — the same `build-crate.yml` OIDC
/// pin as register — because a completion report is the other half of the
/// pipeline write: it tells the scheduler the artifacts exist.
pub async fn complete_build(
    ArtifactWriteCaller(caller): ArtifactWriteCaller,
    Json(report): Json<BuildCompleteReport>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    scheduler_client::send_complete(&scheduler, &report)
        .await
        .inspect_err(|error| {
            tracing::error!(%error, %caller, "failed to forward build completion to scheduler");
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// GET /api/v1/scheduler/status
pub async fn scheduler_status(
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerStatus>, GetArtifactError> {
    let status = scheduler_client::get_status(&scheduler).await?;
    Ok(Json(status))
}

/// POST /api/v1/requests
///
/// Public human lane: a Turnstile-verified request to build one crate (and
/// its dependency closure) into the public cache for every supported CI
/// target. Turnstile replaces the miss path's proof-of-work as the
/// admission check, and accepted tasks enter the scheduler's human lane —
/// dispatched ahead of queued misses and exempt from the dispatch minimum
/// age. Re-requesting a queued crate promotes its task into the human
/// lane; nothing in this path demotes one back.
pub async fn submit_crate_request(
    CfConnectingIp(remoteip): CfConnectingIp,
    Json(request): Json<CrateRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(turnstile): State<CfTurnstileVerifier>,
) -> Result<Response, GetArtifactError> {
    let siteverify = match turnstile
        .verify(&request.turnstile_token, remoteip.as_deref())
        .await
    {
        Ok(siteverify) => siteverify,
        Err(error) => {
            // siteverify operational details stay in the log; the client
            // sees only `siteverify-unavailable`.
            tracing::error!(%error, "turnstile siteverify request failed");
            return GetArtifactError::TurnstileRejected {
                error_codes: vec![crate::turnstile::SITEVERIFY_UNAVAILABLE_CODE.to_owned()],
            }
            .rejection_response();
        }
    };
    if let Some(error_codes) =
        crate::turnstile::rejection_error_codes(&siteverify, turnstile.expected_hostname())
    {
        tracing::warn!(
            error_codes = ?error_codes,
            crate_name = %request.crate_name,
            "turnstile rejected request token"
        );
        return GetArtifactError::TurnstileRejected { error_codes }.rejection_response();
    }

    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    let crates_io = crates_io::CfCratesIo;
    let version = resolve_request_version(&db, &crates_io, &request).await?;
    let seed_features = request_seed_features(&request)?;
    let rustc_version = scheduler_client::get_stable_rustc(&scheduler).await?;
    let (plans, enqueue) = expand_request_targets(
        &db,
        &crates_io,
        &request,
        &version,
        &seed_features,
        &rustc_version,
    )
    .await?;
    let enqueued = enqueue.len();
    let targets = submit_and_assemble(&scheduler, enqueue, &plans).await?;
    tracing::info!(
        crate_name = %request.crate_name,
        %version,
        rustc_version = %rustc_version,
        enqueued,
        "human request accepted"
    );
    Ok(Response::new(
        Body::from_json(&CrateRequestOutcome {
            crate_name: request.crate_name,
            version: CrateVersion::new(version),
            rustc_version,
            targets,
        })
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?,
    ))
}

/// Resolve the requested version — exact-published check when given, else
/// the newest non-prerelease, non-yanked release.
async fn resolve_request_version(
    db: &Db,
    crates_io: &crates_io::CfCratesIo,
    request: &CrateRequest,
) -> Result<semver::Version, GetArtifactError> {
    let resolved = match request.version.as_ref() {
        Some(version) => {
            dependency_resolver::published_version(
                db,
                crates_io,
                request.crate_name.as_str(),
                version.as_semver(),
            )
            .await?
        }
        None => {
            dependency_resolver::latest_published_version(
                db,
                crates_io,
                request.crate_name.as_str(),
            )
            .await?
        }
    };
    resolved.ok_or_else(|| GetArtifactError::VersionNotPublished {
        crate_name: request.crate_name.as_str().to_owned(),
        requested: request.version.as_ref().map_or_else(
            || "stable release".to_owned(),
            |version| format!("version {version}"),
        ),
    })
}

/// The feature seeds for the closure walk, taken verbatim from the
/// request.
///
/// An empty list means exactly that: build with no features at all, which
/// is `--no-default-features`. It must not be re-seeded with `default` —
/// the form's only way to ask for a bare build is to untick every box, and
/// silently turning that into the full default closure builds the thing the
/// user just declined, under a task identity they did not ask for.
fn request_seed_features(request: &CrateRequest) -> Result<BTreeSet<String>, GetArtifactError> {
    dependency_resolver::normalize_feature_set(request.features_json.features().to_vec())
        .map_err(|_| GetArtifactError::BadRequest)
}

/// Expand the request's dependency closure once per CI target. Returns the
/// per-target `(target, plan, root_task_id)` triples and the flat list of
/// human-lane tasks to submit; a target whose root is already cached
/// contributes no tasks.
async fn expand_request_targets(
    db: &Db,
    crates_io: &crates_io::CfCratesIo,
    request: &CrateRequest,
    version: &semver::Version,
    seed_features: &BTreeSet<String>,
    rustc_version: &stow_types::identity::WireRustcVersion,
) -> Result<
    (
        Vec<(TargetTriple, dependency_resolver::CrateRequestPlan, String)>,
        Vec<stow_types::api::EnqueueRequest>,
    ),
    GetArtifactError,
> {
    let mut plans = Vec::with_capacity(CI_TARGET_TRIPLES.len());
    let mut enqueue = Vec::new();
    for target in CI_TARGET_TRIPLES {
        let target = TargetTriple::parse(*target).map_err(|error| {
            GetArtifactError::InternalWithMessage(format!("CI target `{target}`: {error}"))
        })?;
        let plan = dependency_resolver::expand_crate_request(
            db,
            crates_io,
            &request.crate_name,
            version,
            seed_features,
            &target,
            rustc_version,
        )
        .await?;
        let root_task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &version.to_string(),
            &plan.root_features_json,
            target.as_str(),
            rustc_version.as_str(),
            // Resolved-lockfile plans always enqueue crates.io tarball tasks.
            "",
        );
        // A cached root means the artifact already exists for this target:
        // report `Cached` and do not enqueue its closure.
        if !plan.root_cached {
            enqueue.extend(plan.enqueue_requests.iter().cloned());
        }
        plans.push((target, plan, root_task_id));
    }
    Ok((plans, enqueue))
}

/// Submit the human-lane tasks and assemble the per-target outcomes. The
/// pre-submit status read distinguishes `AlreadyQueued`/`Building` roots
/// from the ones this request just queued.
async fn submit_and_assemble(
    scheduler: &CfDurableNamespace,
    enqueue: Vec<stow_types::api::EnqueueRequest>,
    plans: &[(TargetTriple, dependency_resolver::CrateRequestPlan, String)],
) -> Result<Vec<stow_types::api::CrateRequestTarget>, GetArtifactError> {
    let root_task_ids = plans
        .iter()
        .filter(|(_, plan, _)| !plan.root_cached)
        .map(|(_, _, task_id)| task_id.clone())
        .collect::<Vec<_>>();
    let was_queued: BTreeSet<String> =
        scheduler_client::get_tasks_status(scheduler, &root_task_ids)
            .await?
            .into_iter()
            .map(|status| status.task_id)
            .collect();
    scheduler_client::send_enqueue(scheduler, &enqueue).await?;
    let statuses: BTreeMap<String, stow_types::api::RequestStatus> =
        scheduler_client::get_tasks_status(scheduler, &root_task_ids)
            .await?
            .into_iter()
            .map(|status| (status.task_id.clone(), status))
            .collect();
    plans
        .iter()
        .map(|(target, plan, task_id)| {
            dependency_resolver::crate_request_target(
                target,
                task_id,
                plan.root_cached,
                was_queued.contains(task_id),
                statuses.get(task_id),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(GetArtifactError::from)
}

/// GET /`api/v1/requests/{task_id}`
///
/// Point-in-time view of one scheduler task: lane, queue status, and the
/// 1-based human-lane position while the task is still pending there.
pub async fn crate_request_status(
    params: Params,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::RequestStatus>, GetArtifactError> {
    let task_id = params
        .get("task_id")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let statuses = scheduler_client::get_tasks_status(&scheduler, &[task_id.to_owned()]).await?;
    let status = statuses
        .into_iter()
        .find(|status| status.task_id == task_id)
        .ok_or_else(|| GetArtifactError::UnknownTask {
            task_id: task_id.to_owned(),
        })?;
    Ok(Json(status))
}

/// Query parameters for `GET /api/v1/crates/search`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct CrateSearchQuery {
    /// Search text, at least [`catalog::MIN_SEARCH_QUERY_LEN`] characters.
    pub q: String,
    /// Result cap, clamped into <code>1..=[catalog::MAX_SEARCH_LIMIT]</code>.
    pub limit: Option<u32>,
}

/// How long a catalog answer may be reused. crates.io publishes
/// continuously, so a stale list costs a user one page reload, while the
/// form issues one lookup per keystroke burst and per version pick.
const CATALOG_SEARCH_MAX_AGE: &str = "public, max-age=300";
const CATALOG_VERSIONS_MAX_AGE: &str = "public, max-age=600";

/// Serialize `body` as a cacheable JSON response.
fn cacheable_json<T: serde::Serialize>(
    body: &T,
    cache_control: &'static str,
) -> Result<Response, GetArtifactError> {
    let payload = serde_json::to_vec(body)
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let mut response = Response::new(Body::from(payload));
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        skyzen::header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    Ok(response)
}

/// Read a path parameter as a validated crate name. The value reaches a
/// crates.io URL, so it is parsed into [`CrateName`] — which admits only
/// crates.io's own character set — before it is interpolated anywhere.
fn path_crate_name(params: &Params) -> Result<CrateName, GetArtifactError> {
    params
        .get("crate_name")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CrateName>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))
}

/// `GET /api/v1/crates/search?q=ser&limit=10`
///
/// crates.io search, proxied so the request form can offer completions
/// without the browser talking to crates.io directly (and without its CORS
/// and user-agent rules applying to every visitor).
pub async fn search_crates(
    Query(query): Query<CrateSearchQuery>,
) -> Result<Response, GetArtifactError> {
    let response = catalog::search_crates(
        &crates_io::CfCratesIo,
        &query.q,
        query.limit.unwrap_or(catalog::DEFAULT_SEARCH_LIMIT),
    )
    .await?;
    cacheable_json(&response, CATALOG_SEARCH_MAX_AGE)
}

/// `GET /api/v1/crates/{crate_name}/versions`
///
/// Every published, non-yanked version, newest first — the version picker's
/// option list.
pub async fn crate_versions(params: Params, db: Db) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let crate_name = path_crate_name(&params)?;
    let response =
        catalog::crate_versions(&db, &crates_io::CfCratesIo, crate_name.as_str()).await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// `GET /api/v1/crates/{crate_name}/versions/{version}/features`
///
/// Every feature the version lets a caller select, `default` first — the
/// feature checkboxes. Selecting `default` is what keeps cargo's default
/// feature set on; leaving it out builds `--no-default-features`.
pub async fn crate_features(params: Params, db: Db) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let crate_name = path_crate_name(&params)?;
    let version = params
        .get("version")
        .map_err(|_| GetArtifactError::BadRequest)?
        .parse::<CrateVersion>()
        .map_err(|error| GetArtifactError::BadRequestWithMessage(error.to_string()))?;
    let response = catalog::crate_features(
        &db,
        &crates_io::CfCratesIo,
        crate_name.as_str(),
        version.as_semver(),
    )
    .await?;
    cacheable_json(&response, CATALOG_VERSIONS_MAX_AGE)
}

/// Query parameters for artifact requests.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct ArtifactQuery {
    /// Crate name (for miss logging and validation).
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
}

/// GET /`api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde`
///
/// Returns the complete artifact bundle for one crate compilation unit.
///
/// Flow:
/// 1. CF Cache API check (free, per-datacenter)
/// 2. Hit → return from CF cache
/// 3. Miss → lookup OCI reference in D1, fetch from GHCR, tee into CF Cache
/// 4. GHCR error → 302 redirect client to GHCR direct URL
/// 5. D1 miss → validate `crate_name`, log miss, return 404
pub async fn get_artifact(
    params: Params,
    query: Option<Query<ArtifactQuery>>,
    db: Db,
    State(cache): State<CfCache>,
    State(ghcr): State<GhcrConfig>,
) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    // 2. Lookup OCI reference from D1
    let artifact_row = db::get_artifact_reference(&db, c_metadata, target, rustc_version)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "D1 query failed");
            GetArtifactError::Internal
        })?;

    let Some(row) = artifact_row else {
        // 404 IS the miss event. Log it server-side.
        if let Some(Query(ref q)) = query
            && let Some(ref crate_name) = q.crate_name
        {
            miss_logger::log_miss(&db, c_metadata, crate_name, target, "").await;
        }
        return Err(GetArtifactError::NotFound);
    };
    let cache_key = exact_cache_key(
        target,
        rustc_version,
        c_metadata,
        &row.oci_digest,
        &row.created_at,
    );

    match load_bundle_bytes(
        &cache,
        &ghcr,
        &cache_key,
        &row.oci_reference,
        &row.oci_digest,
        row.artifact_size,
    )
    .await
    {
        Ok((body, cache_hit)) => {
            let mut response = Response::new(Body::from(body));
            response.headers_mut().insert(
                "content-type",
                HeaderValue::from_static(STOW_BUNDLE_MEDIA_TYPE),
            );
            response
                .headers_mut()
                .insert("x-stow-cache", cache_status_header(cache_hit));
            Ok(response)
        }
        Err(error) if error.indicates_stale_artifact() => {
            tracing::warn!(
                %error,
                oci_reference = %row.oci_reference,
                oci_digest = %row.oci_digest,
                c_metadata,
                target,
                rustc_version,
                "pruning stale artifact row from D1 due to GHCR fetch error"
            );
            prune_stale_artifact_row(&db, c_metadata, target, rustc_version).await?;
            log_exact_miss(&db, query.as_ref(), c_metadata, target).await;
            Err(GetArtifactError::NotFound)
        }
        Err(ghcr::FetchError::Unauthorized { status, .. }) => {
            tracing::error!(
                status,
                oci_reference = %row.oci_reference,
                "GHCR authentication failed — NOT pruning D1 row"
            );
            Err(GetArtifactError::InternalWithMessage(format!(
                "GHCR authentication failed (HTTP {status})"
            )))
        }
        // The served bundle is an edge-assembled multi-blob tar; no single
        // registry URL can stand in for it, so a retryable upstream outage
        // surfaces as 502 and the CLI compiles locally.
        Err(ghcr::FetchError::Unavailable) => {
            tracing::warn!(key = %cache_key, "GHCR unavailable (rate limit or 5xx)");
            Err(GetArtifactError::GhcrUnavailable)
        }
        Err(error) => {
            tracing::error!(error = %error, "GHCR fetch failed");
            Err(GetArtifactError::InternalWithMessage(error.to_string()))
        }
    }
}

/// HEAD /`api/v1/artifacts/{target}/{rustc_version}/{c_metadata`}
///
/// Check if an artifact exists without downloading it.
pub async fn check_artifact(params: Params, db: Db) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    let target = params
        .get("target")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let rustc_version = params
        .get("rustc_version")
        .map_err(|_| GetArtifactError::BadRequest)?;
    let c_metadata = params
        .get("c_metadata")
        .map_err(|_| GetArtifactError::BadRequest)?;

    let artifact_row = db::get_artifact_reference(&db, c_metadata, target, rustc_version)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "D1 query failed");
            GetArtifactError::Internal
        })?;

    match artifact_row {
        Some(row) => {
            let mut response = Response::new(Body::empty());
            // GET on this URL serves an edge-assembled bundle tar whose size
            // differs from the raw artifact bytes, so `content-length` must
            // not claim `artifact_size`; expose it under a stow header.
            if let Some(size) = row.artifact_size {
                response
                    .headers_mut()
                    .insert("x-stow-artifact-size", HeaderValue::from(size));
            }
            Ok(response)
        }
        None => Err(GetArtifactError::NotFound),
    }
}

/// POST /api/v1/artifacts/semantic
pub async fn get_semantic_artifact(
    Json(request): Json<SemanticArtifactRequest>,
    db: Db,
    State(cache): State<CfCache>,
    State(ghcr): State<GhcrConfig>,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;

    let row = db::get_semantic_artifact_reference(&db, &request)
        .await
        .map_err(|error| {
            tracing::error!(
                %error,
                crate_name = %request.crate_name,
                version = %request.version,
                features_json = %request.features_json,
                target = %request.target,
                rustc_version = %request.rustc_version,
                profile = ?request.profile,
                emit = ?request.emit,
                kind = %request.kind.as_str(),
                crate_types = ?request.crate_types,
                "semantic D1 query failed"
            );
            GetArtifactError::InternalWithMessage(error.to_string())
        })?;
    let Some(row) = row else {
        // The miss response carries the enqueue admission — a crates.io or
        // scheduler hiccup during minting must not turn a plain cache miss
        // into a 500, so failures degrade to a bare 404.
        return match semantic_miss_admission(
            &db,
            &scheduler,
            &admission,
            &request,
            settings.batch_fetch_concurrency,
        )
        .await
        {
            Ok(Some(ticket)) => admission_miss_response(&ticket),
            Ok(None) => Err(GetArtifactError::NotFound),
            Err(error) => {
                tracing::error!(%error, "failed to mint enqueue admission for semantic miss");
                Err(GetArtifactError::NotFound)
            }
        };
    };
    let cache_key = semantic_cache_key(&request, &row.oci_digest, &row.created_at);

    let (body, cache_hit) = match load_bundle_bytes(
        &cache,
        &ghcr,
        &cache_key,
        &row.oci_reference,
        &row.oci_digest,
        row.artifact_size,
    )
    .await
    {
        Ok(result) => result,
        Err(error) if error.indicates_stale_artifact() => {
            prune_stale_artifact_row(
                &db,
                &row.c_metadata,
                request.target.as_str(),
                request.rustc_version.as_str(),
            )
            .await?;
            return match semantic_miss_admission(
                &db,
                &scheduler,
                &admission,
                &request,
                settings.batch_fetch_concurrency,
            )
            .await
            {
                Ok(Some(ticket)) => admission_miss_response(&ticket),
                Ok(None) => Err(GetArtifactError::NotFound),
                Err(error) => {
                    tracing::error!(%error, "failed to mint enqueue admission for semantic miss");
                    Err(GetArtifactError::NotFound)
                }
            };
        }
        Err(error) => {
            tracing::error!(%error, "semantic GHCR fetch failed");
            return Err(GetArtifactError::InternalWithMessage(error.to_string()));
        }
    };

    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static(STOW_BUNDLE_MEDIA_TYPE),
    );
    response
        .headers_mut()
        .insert("x-stow-cache", cache_status_header(cache_hit));
    Ok(response)
}

/// POST /api/v1/artifacts/batch
pub async fn get_artifact_batch(
    Json(request): Json<BatchArtifactRequest>,
    db: Db,
    State(cache): State<CfCache>,
    State(ghcr): State<GhcrConfig>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    validate_batch_request(&request).map_err(|error| {
        tracing::warn!(%error, "invalid batch artifact request");
        GetArtifactError::BadRequest
    })?;

    let rows_by_metadata = batch_artifact_rows(&db, &request).await?;
    let fetch_results = stream::iter(request.entries.iter().cloned().enumerate())
        .map(|(index, entry)| {
            let row = rows_by_metadata.get(entry.c_metadata.as_str()).cloned();
            fetch_batch_entry(index, entry, row, &request, &cache, &ghcr)
        })
        .buffer_unordered(settings.batch_fetch_concurrency)
        .collect::<Vec<_>>()
        .await;
    let (manifest_entries, fetched_bundles) =
        collect_batch_results(&db, &request, fetch_results).await?;
    assemble_batch_response(&request, manifest_entries, fetched_bundles)
}

/// Load every requested artifact row in one IN-clause query, keyed by
/// `c_metadata` for the per-entry lookup during the parallel fetch.
async fn batch_artifact_rows(
    db: &Db,
    request: &BatchArtifactRequest,
) -> Result<BTreeMap<String, db::ExactArtifactRow>, GetArtifactError> {
    let c_metadatas = request
        .entries
        .iter()
        .map(|entry| entry.c_metadata.as_str().to_owned())
        .collect::<Vec<_>>();
    let rows = db::get_artifact_references(
        db,
        &c_metadatas,
        request.target.as_str(),
        request.rustc_version.as_str(),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "batch artifact D1 query failed");
        GetArtifactError::Internal
    })?;
    Ok(rows
        .into_iter()
        .map(|row| (row.c_metadata.clone(), row))
        .collect())
}

/// Manifest slot for a batch entry whose bundle could not be served.
fn absent_manifest_entry(
    entry: stow_types::api::BatchArtifactRequestEntry,
) -> ArtifactBatchManifestEntry {
    ArtifactBatchManifestEntry {
        crate_name: entry.crate_name,
        c_metadata: entry.c_metadata,
        bundle_path: None,
    }
}

/// Fetch one batch entry through the CF-cache → GHCR path. Every upstream
/// failure degrades to a manifest entry rather than failing the batch:
/// `Stale` additionally reports the row's `c_metadata` so the caller can
/// prune it from D1.
async fn fetch_batch_entry(
    index: usize,
    entry: stow_types::api::BatchArtifactRequestEntry,
    row: Option<db::ExactArtifactRow>,
    request: &BatchArtifactRequest,
    cache: &CfCache,
    ghcr: &GhcrConfig,
) -> BatchFetchResult {
    let Some(row) = row else {
        return BatchFetchResult::Missing {
            index,
            manifest_entry: absent_manifest_entry(entry),
        };
    };

    let cache_key = exact_cache_key(
        request.target.as_str(),
        request.rustc_version.as_str(),
        entry.c_metadata.as_str(),
        &row.oci_digest,
        &row.created_at,
    );
    let bundle_path = batch_bundle_path(entry.c_metadata.as_str());
    let bundle_bytes = match load_bundle_bytes(
        cache,
        ghcr,
        &cache_key,
        &row.oci_reference,
        &row.oci_digest,
        row.artifact_size,
    )
    .await
    {
        Ok((bytes, _)) => bytes,
        Err(error) if error.indicates_stale_artifact() => {
            tracing::warn!(
                error = %error,
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact was registered in D1 but stale in GHCR; pruning stale row"
            );
            return BatchFetchResult::Stale {
                index,
                c_metadata: entry.c_metadata.as_str().to_owned(),
                manifest_entry: absent_manifest_entry(entry),
            };
        }
        Err(ghcr::FetchError::Unavailable) => {
            tracing::warn!(
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact fetch was temporarily unavailable; treating as miss"
            );
            return BatchFetchResult::Missing {
                index,
                manifest_entry: absent_manifest_entry(entry),
            };
        }
        Err(error) => {
            tracing::warn!(
                %error,
                crate_name = %entry.crate_name,
                c_metadata = %entry.c_metadata,
                "batch artifact fetch failed; treating as miss"
            );
            return BatchFetchResult::Missing {
                index,
                manifest_entry: absent_manifest_entry(entry),
            };
        }
    };

    BatchFetchResult::Present {
        index,
        manifest_entry: ArtifactBatchManifestEntry {
            crate_name: entry.crate_name,
            c_metadata: entry.c_metadata,
            bundle_path: Some(bundle_path.clone()),
        },
        bundle_path,
        bundle_bytes,
    }
}

/// Fold per-entry fetch outcomes into manifest slots and bundle payloads,
/// pruning the D1 rows the registry proved stale.
async fn collect_batch_results(
    db: &Db,
    request: &BatchArtifactRequest,
    fetch_results: Vec<BatchFetchResult>,
) -> Result<
    (
        Vec<Option<ArtifactBatchManifestEntry>>,
        Vec<(usize, String, Vec<u8>)>,
    ),
    GetArtifactError,
> {
    let mut manifest_entries = vec![None::<ArtifactBatchManifestEntry>; request.entries.len()];
    let mut fetched_bundles = Vec::<(usize, String, Vec<u8>)>::new();
    for fetch_result in fetch_results {
        match fetch_result {
            BatchFetchResult::Missing {
                index,
                manifest_entry,
            } => {
                manifest_entries[index] = Some(manifest_entry);
            }
            BatchFetchResult::Present {
                index,
                manifest_entry,
                bundle_path,
                bundle_bytes,
            } => {
                manifest_entries[index] = Some(manifest_entry);
                fetched_bundles.push((index, bundle_path, bundle_bytes));
            }
            BatchFetchResult::Stale {
                index,
                c_metadata,
                manifest_entry,
            } => {
                prune_stale_artifact_row(
                    db,
                    &c_metadata,
                    request.target.as_str(),
                    request.rustc_version.as_str(),
                )
                .await?;
                manifest_entries[index] = Some(manifest_entry);
            }
        }
    }
    Ok((manifest_entries, fetched_bundles))
}

/// Assemble the response tar: bundle payloads in request order followed
/// by the JSON manifest the CLI reads to map each entry.
fn assemble_batch_response(
    request: &BatchArtifactRequest,
    manifest_entries: Vec<Option<ArtifactBatchManifestEntry>>,
    mut fetched_bundles: Vec<(usize, String, Vec<u8>)>,
) -> Result<Response, GetArtifactError> {
    fetched_bundles.sort_by_key(|(index, _, _)| *index);
    let mut tar = Builder::new(Vec::new());
    for (_index, bundle_path, bundle_bytes) in fetched_bundles {
        append_bytes(&mut tar, &bundle_path, &bundle_bytes).map_err(|error| {
            tracing::error!(%error, bundle_path = %bundle_path, "batch tar assembly failed");
            GetArtifactError::Internal
        })?;
    }

    let manifest = ArtifactBatchManifest {
        target: request.target.clone(),
        rustc_version: request.rustc_version.clone(),
        entries: manifest_entries
            .into_iter()
            .map(|entry| {
                entry.ok_or_else(|| {
                    tracing::error!("batch artifact manifest entry was not populated");
                    GetArtifactError::Internal
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        tracing::error!(%error, "serialize batch artifact manifest failed");
        GetArtifactError::Internal
    })?;
    append_bytes(&mut tar, STOW_BATCH_MANIFEST_PATH, &manifest_bytes).map_err(|error| {
        tracing::error!(%error, "append batch artifact manifest failed");
        GetArtifactError::Internal
    })?;
    let body = tar.into_inner().map_err(|error| {
        tracing::error!(%error, "finalize batch artifact archive failed");
        GetArtifactError::Internal
    })?;

    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static(STOW_BATCH_BUNDLE_MEDIA_TYPE),
    );
    Ok(response)
}

enum BatchFetchResult {
    Missing {
        index: usize,
        manifest_entry: ArtifactBatchManifestEntry,
    },
    Stale {
        index: usize,
        c_metadata: String,
        manifest_entry: ArtifactBatchManifestEntry,
    },
    Present {
        index: usize,
        manifest_entry: ArtifactBatchManifestEntry,
        bundle_path: String,
        bundle_bytes: Vec<u8>,
    },
}

/// POST /api/v1/catalog/graph
pub async fn analyze_dependency_graph(
    Json(request): Json<DependencyGraphRequest>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
    State(settings): State<crate::runtime_settings::ResolverSettings>,
) -> Result<Json<DependencyGraphResponse>, GetArtifactError> {
    // Worst-case subrequests for `max_expanded_tasks` (4096) direct
    // entries, every one cache-cold, and 4096 expanded misses:
    //   ceil(4096/49) =   84  crate_version_graph_cache read batches
    //   ≤ 4096        = 4096  sparse-index fetches (one per cold crate)
    //   ceil(4096/33) =  125  crate_version_graph_cache upsert batches
    //   ceil(4096/64) =   64  artifact-catalog reads for direct entries
    //   ceil(4096/64) =   64  expanded-graph artifact reads (chain
    //                          completion adds its referenced rows)
    //   ceil(4096/20) =  205  dependency_graph_misses upsert batches
    //                      ~70  admitted-miss drain statements
    //   ≈ 4.7k total — inside the paid Worker's 10,000-subrequest budget
    //   (Cloudflare raised the old 1,000 cap in Feb 2026), and the ~610
    //   D1 statements among them stay under D1's own 1,000-queries-per-
    //   invocation limit.
    if request.entries.len() > settings.max_expanded_tasks {
        tracing::warn!(
            entries = request.entries.len(),
            max_entries = settings.max_expanded_tasks,
            "dependency list exceeds edge limit"
        );
        return Err(GetArtifactError::from(
            crate::errors::ResolverError::LimitExceeded {
                what: "dependency graph direct entries",
                got: request.entries.len(),
                limit: settings.max_expanded_tasks,
            },
        ));
    }
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    let outcome = db::analyze_dependency_graph(
        &db,
        &crates_io::CfCratesIo,
        request.target.as_str(),
        request.rustc_version.as_str(),
        &request.entries,
        &request.expanded_entries,
        settings.batch_fetch_concurrency,
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "dependency graph analysis failed");
        GetArtifactError::InternalWithMessage(error.to_string())
    })?;
    let db::DependencyGraphAnalysisOutcome {
        mut response,
        enqueue_requests,
    } = outcome;

    // The fetch path never enqueues directly: each miss gets an admission
    // the client redeems through the PoW gate, and minting hiccups degrade
    // to "no admissions" rather than failing the analysis response. A
    // fully-cached analysis has no misses to mint and admits nothing new to
    // drain, so it skips the scheduler round-trip entirely — the status
    // fetch and misses-table scan are pure overhead on a cache hit.
    if !enqueue_requests.is_empty() {
        let difficulty = admission_difficulty(&scheduler, &admission).await?;
        response.miss_admissions = match mint_admissions(&admission, enqueue_requests, difficulty) {
            Ok(admissions) => admissions,
            Err(error) => {
                tracing::error!(%error, "failed to mint dependency-graph miss admissions");
                Vec::new()
            }
        };
        drain_admitted_misses(&db, &scheduler).await;
    }

    Ok(Json(response))
}

/// Internal retry channel for verified admissions: hand misses that already
/// passed the `/api/v1/enqueue` challenge + `PoW` gate back to the scheduler
/// when their direct send failed. Unadmitted misses are never drainable —
/// this is not a second minting channel, so it needs no proof-of-work of
/// its own. Best-effort like every scheduler side-channel: a drain hiccup
/// must not fail the analysis response.
async fn drain_admitted_misses(db: &Db, scheduler: &CfDurableNamespace) {
    const DRAIN_MISS_BATCH: usize = 64;

    let drained = match db::take_dependency_graph_misses(db, DRAIN_MISS_BATCH).await {
        Ok(drained) => drained,
        Err(error) => {
            tracing::error!(%error, "failed to drain admitted dependency-graph misses");
            return;
        }
    };
    if drained.is_empty() {
        return;
    }

    if let Err(error) = scheduler_client::send_enqueue(scheduler, &drained).await {
        tracing::error!(%error, "failed to enqueue admitted dependency-graph misses to scheduler");
        if let Err(restore_error) =
            db::set_dependency_graph_misses_queued(db, &drained, false).await
        {
            tracing::error!(
                %restore_error,
                "failed to restore drained dependency-graph misses after enqueue failure"
            );
        }
    }
}

/// POST /api/v1/enqueue
///
/// Redeem a miss admission statelessly: recompute the HMAC challenge over
/// the request the ticket carries, check the client's proof-of-work against
/// the queue depth current at redemption time (one bit lenient — the queue
/// may have grown since the miss response), then forward that request to
/// the scheduler. Replay is safe — the scheduler deduplicates on task id.
pub async fn enqueue_admitted_task(
    Json(ticket): Json<EnqueueTicket>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
    State(admission): State<PowAdmission>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let request_json = serde_json::to_vec(&ticket.request)
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    if !admission::verify_challenge(
        &admission.challenge_secret,
        &ticket.task_id,
        &request_json,
        &ticket.challenge,
        now_minute(),
    ) {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: invalid challenge");
        return Err(GetArtifactError::Unauthorized);
    }
    // The challenge binds task_id to the request's canonical identity;
    // recompute it so a verified ticket always forwards what it minted.
    let ticket_source_json = scheduler::queue::source_json(ticket.request.project_source.as_ref())
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    let derived_task_id = scheduler::queue::task_id(
        ticket.request.crate_name.as_str(),
        &ticket.request.version.to_string(),
        ticket.request.features_json.raw().as_str(),
        ticket.request.target.as_str(),
        ticket.request.rustc_version.as_str(),
        &ticket_source_json,
    );
    if derived_task_id != ticket.task_id {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: task id mismatch");
        return Err(GetArtifactError::Unauthorized);
    }
    // A client builds for whatever host it runs on, and plenty of those are
    // machines this cache has no runner for. Refuse before the ticket can
    // become a dispatch that cannot run.
    if !stow_types::api::is_ci_target(ticket.request.target.as_str()) {
        tracing::info!(
            task_id = %ticket.task_id,
            target = %ticket.request.target,
            "rejected enqueue ticket: no CI runner builds this target"
        );
        return Err(GetArtifactError::UnsupportedTarget {
            target: ticket.request.target.to_string(),
            supported: CI_TARGET_TRIPLES.join(", "),
        });
    }
    let status = scheduler_client::get_status(&scheduler).await?;
    let required = admission::required_difficulty(status.pending, admission.depth_per_bit);
    let solved =
        stow_types::pow::enqueue_pow_zero_bits(&ticket.task_id, &ticket.challenge, ticket.nonce);
    if solved < required {
        tracing::warn!(
            task_id = %ticket.task_id,
            solved,
            required,
            "enqueue ticket proof-of-work below required difficulty"
        );
        return Err(GetArtifactError::BadRequest);
    }

    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;
    // The ticket is verified: flag the miss row so the internal drain may
    // retry the scheduler send, then deliver the canonical request.
    if let Err(error) = db::mark_dependency_graph_miss_admitted(&db, &ticket.request).await {
        tracing::error!(%error, "failed to mark dependency-graph miss admitted");
    }
    scheduler_client::send_enqueue(&scheduler, std::slice::from_ref(&ticket.request)).await?;
    if let Err(error) =
        db::set_dependency_graph_misses_queued(&db, std::slice::from_ref(&ticket.request), true)
            .await
    {
        tracing::error!(%error, "failed to mark dependency-graph miss queued");
    }
    Ok(Json(OkResponse { ok: true }))
}

fn validate_batch_request(request: &BatchArtifactRequest) -> Result<(), String> {
    if request.entries.is_empty() {
        return Err("batch artifact request entries cannot be empty".to_owned());
    }
    let mut seen = BTreeSet::<&str>::new();
    for entry in &request.entries {
        // CrateName is non-empty by construction (parsed at deserialize time).
        if !seen.insert(entry.c_metadata.as_str()) {
            return Err(format!(
                "batch artifact request contains duplicate c_metadata {}",
                entry.c_metadata
            ));
        }
    }
    Ok(())
}

async fn load_bundle_bytes(
    cache: &CfCache,
    ghcr: &GhcrConfig,
    cache_key: &str,
    oci_reference: &str,
    oci_digest: &str,
    artifact_size: Option<u64>,
) -> Result<(Vec<u8>, bool), ghcr::FetchError> {
    match cache::get(cache, cache_key).await {
        Ok(Some(cached)) => match bundle_schema::validate_bundle_schema(&cached) {
            Ok(()) => {
                tracing::debug!(key = %cache_key, "cf cache hit");
                return Ok((cached, true));
            }
            // A corrupt CF cache entry must not condemn the registry
            // artifact: fall through to a fresh GHCR fetch, which
            // re-validates and overwrites the cache entry on success.
            Err(error) => {
                tracing::warn!(
                    key = %cache_key,
                    error = %error,
                    "cf cache entry failed bundle schema validation; refetching from registry"
                );
            }
        },
        Ok(None) => {
            tracing::debug!(key = %cache_key, "cf cache miss");
        }
        Err(error) => {
            tracing::warn!(key = %cache_key, error = %error, "cf cache error");
        }
    }

    let repository = oci_repository(oci_reference).map_err(|error| {
        tracing::error!(%error, "refusing GHCR fetch for malformed OCI reference");
        ghcr::FetchError::InvalidRequest(error.to_string())
    })?;
    let body = ghcr::fetch_bundle(
        &ghcr.base_url,
        oci_reference,
        repository,
        oci_digest,
        &ghcr.tokens,
    )
    .await
    .map_err(|error| {
        tracing::error!(
            cache_key = %cache_key,
            oci_reference = %oci_reference,
            oci_digest = %oci_digest,
            error = %error,
            "edge failed to assemble artifact bundle from registry"
        );
        error
    })?;
    bundle_schema::validate_bundle_schema(&body)?;
    if let Err(error) = cache::try_put(cache, cache_key, &body, artifact_size).await {
        tracing::warn!(key = %cache_key, error = %error, "cf cache put failed");
    }
    Ok((body, false))
}

fn oci_repository(
    reference: &str,
) -> Result<stow_types::registry::RepositoryPath<'_>, GetArtifactError> {
    // `oci_reference_name` enforces the canonical single-package shape;
    // `repository_path` then yields `water-rs/stow-cache`, the repository
    // the pull scope names.
    stow_types::registry::oci_reference_name(reference)
        .and_then(|_| stow_types::registry::repository_path(reference))
        .ok_or_else(|| {
            GetArtifactError::InternalWithMessage(format!(
                "malformed OCI reference `{reference}` — expected ghcr.io/water-rs/stow-cache:{{crate}}.{{rest}}"
            ))
        })
}

fn exact_cache_key(
    target: &str,
    rustc_version: &str,
    c_metadata: &str,
    oci_digest: &str,
    created_at: &str,
) -> String {
    format!(
        "bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{target}/{rustc_version}/{c_metadata}/{oci_digest}/{created_at}"
    )
}

fn semantic_cache_key(
    request: &SemanticArtifactRequest,
    oci_digest: &str,
    created_at: &str,
) -> String {
    let profile_json =
        serde_json::to_string(&request.profile).expect("semantic profile serialization must work");
    let emit_json =
        serde_json::to_string(&request.emit).expect("semantic emit serialization must work");
    let crate_types_json = serde_json::to_string(&request.crate_types)
        .expect("semantic crate_types serialization must work");
    format!(
        "semantic/bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
        request.target,
        request.rustc_version,
        request.crate_name,
        request.version,
        request.features_json,
        profile_json,
        emit_json,
        request.kind.as_str(),
        crate_types_json,
        oci_digest,
        created_at,
    )
}

fn batch_bundle_path(c_metadata: &str) -> String {
    format!("{STOW_BATCH_BUNDLES_DIR}/{c_metadata}.tar")
}

fn append_bytes(tar: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .map_err(|error| format!("append batch tar entry {path}: {error}"))
}

/// OCI registry configuration for artifact fetching, stored via `State<GhcrConfig>`.
#[derive(Debug, Clone)]
pub struct GhcrConfig {
    pub base_url: String,
    /// Per-isolate bearer cache for the anonymous registry token exchange.
    pub tokens: RegistryTokens,
}

async fn prune_stale_artifact_row(
    db: &Db,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<(), GetArtifactError> {
    tracing::warn!(
        c_metadata = %c_metadata,
        target = %target,
        rustc_version = %rustc_version,
        "pruning stale artifact row after registry miss"
    );
    db::delete_artifact_reference(db, c_metadata, target, rustc_version)
        .await
        .map_err(GetArtifactError::from)
}

async fn log_exact_miss(
    db: &Db,
    query: Option<&Query<ArtifactQuery>>,
    c_metadata: &str,
    target: &str,
) {
    if let Some(Query(q)) = query
        && let Some(ref crate_name) = q.crate_name
    {
        miss_logger::log_miss(db, c_metadata, crate_name, target, "").await;
    }
}

#[skyzen::error]
pub enum GetArtifactError {
    #[error("bad request", status = BAD_REQUEST)]
    BadRequest,
    /// A rejected request whose reason is safe to show the caller — the
    /// request page renders the body's `error` verbatim.
    #[error("{0}", status = BAD_REQUEST)]
    BadRequestWithMessage(String),
    #[error("unauthorized", status = UNAUTHORIZED)]
    Unauthorized,
    /// Turnstile rejected the request. The request-API contract renders
    /// this as `{"error":"turnstile rejected","error-codes":[...]}` — a
    /// shape the shared `{"error": ...}` renderer cannot express — so
    /// handlers return [`Self::rejection_response`] instead of `Err`.
    /// `status = FORBIDDEN` keeps even that fallback path correct.
    #[error("turnstile rejected", status = FORBIDDEN)]
    TurnstileRejected {
        /// Codes surfaced to the client verbatim (`siteverify-unavailable`,
        /// `hostname-mismatch`, or siteverify's own `error-codes`).
        error_codes: Vec<String>,
    },
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    /// The caller asked to build a target trusted CI has no runner for.
    /// Refused here so it can never become a dispatch: `build-crate.yml`
    /// resolves an unknown target to an empty `runs-on`, and the run then
    /// dies before any job starts, spending a queue slot and reporting
    /// nothing.
    #[error(
        "`{target}` is not a target this cache builds; supported: {supported}",
        status = BAD_REQUEST
    )]
    UnsupportedTarget {
        /// The target the caller asked for.
        target: String,
        /// The targets trusted CI can build, comma-separated.
        supported: String,
    },
    /// A request named a crate (or an exact version) crates.io does not
    /// publish; the message names it because the request page shows the
    /// body's `error` verbatim.
    #[error("crate `{crate_name}` is not published on crates.io", status = NOT_FOUND)]
    CrateNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
    },
    /// The crate exists but the requested version does not (or every
    /// candidate is yanked or a prerelease).
    #[error("`{crate_name}` has no published {requested}", status = NOT_FOUND)]
    VersionNotPublished {
        /// The crate the caller asked for.
        crate_name: String,
        /// `version X.Y.Z` when one was asked for, else `stable release`.
        requested: String,
    },
    /// `GET /api/v1/requests/{task_id}` for a task the scheduler does not
    /// know: never enqueued, or already reaped.
    #[error("unknown request task id `{task_id}`", status = NOT_FOUND)]
    UnknownTask {
        /// The id from the request path.
        task_id: String,
    },
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    /// GitHub (OIDC JWKS or the repo-permission API) could not be consulted
    /// — a 502 so CI retries instead of recording a permanent auth failure.
    /// The upstream reason stays in the worker log.
    #[error("github trust upstream unavailable", status = BAD_GATEWAY)]
    TrustUpstreamUnavailable,
    /// A request exceeded a documented edge limit. The message names the
    /// observed count and the limit — a client error (413 renders its
    /// message, 5xx does not), because retrying the same request can
    /// never help.
    #[error("{0}", status = PAYLOAD_TOO_LARGE)]
    TooLarge(String),
    #[error("internal server error")]
    Internal,
    #[error("internal server error: {0}")]
    InternalWithMessage(String),
}

impl GetArtifactError {
    /// Render a [`Self::TurnstileRejected`] with the contract's
    /// `error-codes` body; every other variant passes through as `Err`
    /// for the shared `{"error": ...}` renderer.
    fn rejection_response(self) -> Result<Response, Self> {
        match self {
            Self::TurnstileRejected { error_codes } => {
                Ok(crate::turnstile::rejected_response(&error_codes))
            }
            other => Err(other),
        }
    }
}

impl From<crate::errors::SchedulerClientError> for GetArtifactError {
    fn from(error: crate::errors::SchedulerClientError) -> Self {
        match error {
            // A 4xx from the scheduler is a client problem — e.g. a
            // completion report naming a task the queue never held — and
            // the body is the scheduler's own client-safe message, so it
            // reaches the reporter verbatim instead of as a bare 500.
            crate::errors::SchedulerClientError::Http { status, body, .. }
                if (400..500).contains(&status) =>
            {
                Self::BadRequestWithMessage(format!("scheduler rejected the report: {body}"))
            }
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}

impl From<crate::errors::DbError> for GetArtifactError {
    fn from(error: crate::errors::DbError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<crate::errors::ResolverError> for GetArtifactError {
    fn from(error: crate::errors::ResolverError) -> Self {
        match error {
            crate::errors::ResolverError::CrateNotPublished { crate_name } => {
                Self::CrateNotPublished { crate_name }
            }
            crate::errors::ResolverError::LimitExceeded { .. } => Self::TooLarge(error.to_string()),
            crate::errors::ResolverError::VersionNotPublished {
                crate_name,
                version,
            } => Self::VersionNotPublished {
                crate_name,
                requested: format!("version {version}"),
            },
            crate::errors::ResolverError::BadRequest(message) => {
                Self::BadRequestWithMessage(message)
            }
            other => Self::InternalWithMessage(other.to_string()),
        }
    }
}

impl From<crate::errors::MissLoggerError> for GetArtifactError {
    fn from(error: crate::errors::MissLoggerError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}
