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
    ArtifactRecord, BatchArtifactRequest, BuildCompleteReport, DependencyGraphRequest,
    DependencyGraphResponse, EnqueueAdmission, EnqueueTicket, ResolveLockfileRequest,
    ResolveLockfileResponse, SemanticArtifactRequest,
};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBatchManifestEntry, STOW_BATCH_BUNDLE_MEDIA_TYPE,
    STOW_BATCH_BUNDLES_DIR, STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MEDIA_TYPE,
};
use tar::{Builder, Header};

use crate::db;
use crate::registry_auth::RegistryTokens;
use crate::{
    admission, bundle_schema, cache, crates_io, dependency_resolver, ghcr, miss_logger, scheduler,
    scheduler_client,
};

const SCHEDULER_AUTH_HEADER: &str = "x-stow-scheduler-token";
const REGISTER_AUTH_HEADER: &str = "x-stow-register-token";
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

#[derive(Debug, Clone)]
pub struct SchedulerApiAccess {
    pub auth_token: Option<String>,
}

/// Marker that the scheduler auth header was present, well-formed, and matches
/// the configured token in constant time.
///
/// Verifying the token inside the extractor — rather than in the handler body —
/// guarantees that an unauthorized request is rejected *before* any subsequent
/// extractor runs (e.g. before `Json` deserializes a potentially large body).
#[derive(Debug, Clone)]
pub struct SchedulerAuthToken;

impl Extractor for SchedulerAuthToken {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        use subtle::ConstantTimeEq;

        let token: Vec<u8> = request
            .headers()
            .get(SCHEDULER_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(GetArtifactError::Unauthorized)?
            .as_bytes()
            .to_vec();

        let access = State::<SchedulerApiAccess>::extract(request)
            .await
            .map_err(|_| {
                GetArtifactError::InternalWithMessage(
                    "scheduler auth state binding missing".to_owned(),
                )
            })?;
        let expected = access.auth_token.as_deref().ok_or_else(|| {
            GetArtifactError::InternalWithMessage("scheduler auth token not configured".to_owned())
        })?;

        if token.ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
            return Err(GetArtifactError::Unauthorized);
        }
        Ok(Self)
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
async fn mint_admissions(
    admission: &PowAdmission,
    requests: Vec<stow_types::api::EnqueueRequest>,
    difficulty: u32,
) -> Result<Vec<EnqueueAdmission>, GetArtifactError> {
    let minute = now_minute();
    let mut admissions = Vec::with_capacity(requests.len());
    for request in requests {
        let task_id = scheduler::queue::task_id(
            request.crate_name.as_str(),
            &request.version.to_string(),
            request.features_json.raw().as_str(),
            request.target.as_str(),
            request.rustc_version.as_str(),
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
        }],
    )
    .await?;
    let Some(request) = canonical.into_iter().next() else {
        return Ok(None);
    };
    let difficulty = admission_difficulty(scheduler, admission).await?;
    let mut admissions = mint_admissions(admission, vec![request], difficulty).await?;
    Ok(admissions.pop())
}

/// State binding carrying the trusted CI register auth token.
///
/// The token authorizes writes into the `artifacts` D1 table. It is a
/// shared secret between the trusted CI runner and the edge worker; the
/// edge does not write D1 records on any other path.
#[derive(Debug, Clone)]
pub struct RegisterApiAccess {
    pub auth_token: Option<String>,
}

/// Marker that the register auth header was present, well-formed, and
/// matches the configured token in constant time.
///
/// Mirrors `SchedulerAuthToken`: extraction-time validation guarantees an
/// unauthorized request is rejected before `Json` deserializes the body.
#[derive(Debug, Clone)]
pub struct RegisterAuthToken;

impl Extractor for RegisterAuthToken {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        use subtle::ConstantTimeEq;

        let token: Vec<u8> = request
            .headers()
            .get(REGISTER_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(GetArtifactError::Unauthorized)?
            .as_bytes()
            .to_vec();

        let access = State::<RegisterApiAccess>::extract(request)
            .await
            .map_err(|_| {
                GetArtifactError::InternalWithMessage(
                    "register auth state binding missing".to_owned(),
                )
            })?;
        let expected = access.auth_token.as_deref().ok_or_else(|| {
            GetArtifactError::InternalWithMessage("register auth token not configured".to_owned())
        })?;

        if token.ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
            return Err(GetArtifactError::Unauthorized);
        }
        Ok(Self)
    }
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
    let outcome = run_stow_resolver(&db, &request)
        .await
        .map_err(GetArtifactError::from)?;
    Ok(Json(outcome))
}

async fn run_stow_resolver(
    db: &Db,
    request: &ResolveLockfileRequest,
) -> Result<ResolveLockfileResponse, crate::errors::DbError> {
    // Hard cap on the search budget. The in-memory index makes each step
    // cheap, but a 200k budget can still take 30+ s on a deep tree where
    // every direct dep has dozens of candidates and the closure walks each
    // 50-deep. The CLI's fall-back path runs after we return, so a too-
    // generous budget here just adds wall-clock latency to every "no seed
    // found" project. 20k still covers every realistic top-100 binary
    // closure (cargo-make resolves at ~4k); pathological cases exit
    // quickly and let the fall-back run.
    const MAX_RESOLVER_BUDGET: u32 = 20_000;

    // Empty workspace: no direct deps means nothing to accelerate, and an
    // empty lockfile would mislead the CLI into believing it can use
    // `--locked`. Return None so the CLI falls back unchanged.
    if request.direct.is_empty() {
        return Ok(ResolveLockfileResponse {
            lockfile_toml: None,
            uncovered_direct: Vec::new(),
            candidates_considered: 0,
            seed_diagnostics: Vec::new(),
        });
    }

    let target = request.target.as_str();
    let rustc_version = request.rustc_version.as_str();

    let mut typed_direct: Vec<(
        stow_types::identity::CrateName,
        semver::VersionReq,
        BTreeSet<String>,
    )> = Vec::with_capacity(request.direct.len());
    let mut uncovered_pre = Vec::<stow_types::identity::CrateName>::new();
    for direct in &request.direct {
        match semver::VersionReq::parse(direct.req.as_str()) {
            Ok(req) => typed_direct.push((
                direct.crate_name.clone(),
                req,
                direct.features.iter().cloned().collect(),
            )),
            Err(_) => uncovered_pre.push(direct.crate_name.clone()),
        }
    }
    if !uncovered_pre.is_empty() {
        return Ok(ResolveLockfileResponse {
            lockfile_toml: None,
            uncovered_direct: uncovered_pre,
            candidates_considered: 0,
            seed_diagnostics: Vec::new(),
        });
    }

    // Batch-load every cached artifact for this (target, rustc) once and
    // index it in memory. Backtracking otherwise spends 99% of its time on
    // per-transitive D1 queries — the bench cache (8k+ rows) is small
    // enough that pre-loading is a clean win.
    //
    // Naming-normalization wart: `dependency_c_metadata_json` is captured
    // from rustc `--extern` arg names (underscored — `grep_cli`,
    // `nu_ansi_term`), but `artifacts.crate_name` carries cargo's published
    // name (dashed — `grep-cli`, `nu-ansi-term`). Both forms are cached
    // under the same c_metadata, so we dual-key `by_pair` on both forms.
    // The fix-at-write-time lives in the CI capture path (stow-build's
    // dep_scan); this in-resolver normalization is a forward-compatible
    // bridge.
    let all_artifacts = db::list_resolver_artifacts_for_target(db, target, rustc_version).await?;
    let mut by_pair: BTreeMap<(String, String), &db::ResolverArtifactRow> = BTreeMap::new();
    let mut by_c_metadata: BTreeMap<String, &db::ResolverArtifactRow> = BTreeMap::new();
    let mut by_crate: BTreeMap<String, Vec<&db::ResolverArtifactRow>> = BTreeMap::new();
    for row in &all_artifacts {
        by_pair.insert((row.crate_name.clone(), row.c_metadata.clone()), row);
        let alt = row.crate_name.replace('-', "_");
        if alt != row.crate_name {
            by_pair.insert((alt, row.c_metadata.clone()), row);
        }
        // c_metadata is unique per (target, rustc_version) so this is a
        // 1:1 index. Used as a fallback when a `dependency_c_metadata_json`
        // entry's name disagrees with the cached row's name (Cargo lets a
        // project rename a dep via `package = "..."`; rustc captures the
        // local alias, the cache stores the published name).
        by_c_metadata.insert(row.c_metadata.clone(), row);
        by_crate
            .entry(row.crate_name.clone())
            .or_default()
            .push(row);
    }

    // Filter direct-dep candidates against (a) version req, (b) feature
    // subset, and (c) full transitive coverage in cache. (c) is the
    // critical filter: a candidate whose `dependency_c_metadata_json`
    // references a (name, c_metadata) we haven't preheated will never
    // produce a coherent closure, so reject it before backtracking even
    // touches it.
    let mut considered: u32 = 0;
    let mut direct_candidates: Vec<Vec<&db::ResolverArtifactRow>> =
        Vec::with_capacity(typed_direct.len());
    for (crate_name, req, user_features) in &typed_direct {
        let Some(rows) = by_crate.get(crate_name.as_str()) else {
            direct_candidates.push(Vec::new());
            continue;
        };
        let mut filtered: Vec<&db::ResolverArtifactRow> = Vec::new();
        for row in rows {
            considered = considered.saturating_add(1);
            let Ok(version) = semver::Version::parse(&row.version) else {
                continue;
            };
            if !req.matches(&version) {
                continue;
            }
            let Ok(features) = parse_features_array(&row.features_json) else {
                continue;
            };
            let mut effective = user_features.clone();
            if effective.contains("default") && !features.contains("default") {
                effective.remove("default");
            }
            if !effective.is_subset(&features) {
                continue;
            }
            // Closure-coverage filter: every transitive (name, c_metadata)
            // referenced from this candidate must itself be a cached row.
            // Anything else can't extend into a coherent lockfile.
            if !candidate_closure_is_cached(row, &by_pair, &by_c_metadata) {
                continue;
            }
            filtered.push(*row);
        }
        // Prefer candidates with the largest cached transitive closure
        // (i.e., the candidate that pulls in the most pre-built crates)
        // and, tie-broken, the highest version. The big-closure heuristic
        // anchors search to "binary-style" coherent preheats: a binary's
        // own root row tends to have the deepest tree.
        filtered.sort_by(|a, b| {
            let a_deps = a.dependency_c_metadata_json.matches('\"').count();
            let b_deps = b.dependency_c_metadata_json.matches('\"').count();
            let av = semver::Version::parse(&a.version)
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0));
            let bv = semver::Version::parse(&b.version)
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0));
            b_deps.cmp(&a_deps).then(bv.cmp(&av))
        });
        direct_candidates.push(filtered);
    }

    let mut budget = MAX_RESOLVER_BUDGET;
    // Pinned set keyed by (crate_name, c_metadata): cargo allows multiple
    // versions of the same crate name to coexist when SemVer-incompatible
    // (e.g., `log 0.3` and `log 0.4`), so a name-only key would falsely
    // reject any seed whose closure pulls two such versions through
    // different transitives.
    let mut pinned: BTreeMap<(String, String), ResolverPin> = BTreeMap::new();

    // Phase 1 — seed-artifact fast path. If any cached artifact's own
    // `dependency_c_metadata_json` already covers every user direct dep
    // with semver+features-compatible pins (i.e. the user's project shape
    // matches some preheated closure as a subset), use that closure
    // directly: it is guaranteed coherent because it came from a single
    // cargo build. This is the path that turns "user runs `stow check`
    // against bat 0.26.1's source" into 100% cache hits — bat's own
    // preheat row IS that seed.
    let mut seed_diagnostics = Vec::<String>::new();
    let seed = find_seed_artifact(
        &typed_direct,
        &by_pair,
        &by_c_metadata,
        &all_artifacts,
        &mut considered,
        &mut seed_diagnostics,
    );
    if let Some(seed_row) = seed {
        seed_diagnostics.push(format!(
            "seed found: {} {} ({})",
            seed_row.crate_name, seed_row.version, seed_row.c_metadata
        ));
        if try_extend_closure_in_memory_with_diag(
            &by_pair,
            &by_c_metadata,
            &mut pinned,
            seed_row,
            &mut considered,
            &mut budget,
            Some(&mut seed_diagnostics),
        ) {
            seed_diagnostics.push(format!(
                "extend ok, pinned {} crates pre-remove-self",
                pinned.len()
            ));
            pinned.remove(&(seed_row.crate_name.clone(), seed_row.c_metadata.clone()));
        } else {
            seed_diagnostics.push("extend failed for selected seed".to_owned());
            pinned.clear();
        }
    }

    let solved = if pinned.is_empty() {
        backtrack_solve(
            &typed_direct,
            &direct_candidates,
            &by_pair,
            &by_c_metadata,
            0,
            &mut pinned,
            &mut considered,
            &mut budget,
        )
    } else {
        true
    };

    if !solved {
        let pinned_names: BTreeSet<&str> = pinned.keys().map(|(name, _)| name.as_str()).collect();
        let uncovered: Vec<stow_types::identity::CrateName> = typed_direct
            .into_iter()
            .filter_map(|(name, _, _)| {
                if pinned_names.contains(name.as_str()) {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();
        return Ok(ResolveLockfileResponse {
            lockfile_toml: None,
            uncovered_direct: uncovered,
            candidates_considered: considered,
            seed_diagnostics,
        });
    }

    let lockfile_toml = render_lockfile(&pinned)?;
    Ok(ResolveLockfileResponse {
        lockfile_toml: Some(lockfile_toml),
        uncovered_direct: Vec::new(),
        candidates_considered: considered,
        seed_diagnostics: Vec::new(),
    })
}

/// Reject candidates whose transitive closure (recursive) contains a
/// (name, `c_metadata`) pair we have no cached row for. Pre-filtering this
/// before backtracking enters its inner loop turns the search from
/// "explore every dead-end version" into "search only over coherent
/// candidates", which is what makes large user dep graphs solvable.
fn candidate_closure_is_cached(
    candidate: &db::ResolverArtifactRow,
    by_pair: &BTreeMap<(String, String), &db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &db::ResolverArtifactRow>,
) -> bool {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    closure_is_cached_recursive(candidate, by_pair, by_c_metadata, &mut visited)
}

/// Diagnostic version of `candidate_closure_is_cached` — returns the first
/// `(name, c_metadata)` along the closure walk that has no cached row.
/// Used by the seed-search diagnostic so a "passed user-direct cover but
/// transitive closure has uncached pin" failure tells the operator
/// *which* pin to preheat.
fn first_uncached_in_closure<'a>(
    candidate: &'a db::ResolverArtifactRow,
    by_pair: &BTreeMap<(String, String), &'a db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &'a db::ResolverArtifactRow>,
) -> Option<(String, String)> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    first_uncached_recursive(candidate, by_pair, by_c_metadata, &mut visited)
}

fn first_uncached_recursive<'a>(
    candidate: &'a db::ResolverArtifactRow,
    by_pair: &BTreeMap<(String, String), &'a db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &'a db::ResolverArtifactRow>,
    visited: &mut BTreeSet<String>,
) -> Option<(String, String)> {
    if !visited.insert(candidate.c_metadata.clone()) {
        return None;
    }
    let deps = parse_dep_c_metadata(&candidate.dependency_c_metadata_json).ok()?;
    for (name, c_metadata) in &deps {
        let Some(dep_row) = lookup_dep_row(name, c_metadata, by_pair, by_c_metadata) else {
            return Some((name.clone(), c_metadata.clone()));
        };
        if let Some(miss) = first_uncached_recursive(dep_row, by_pair, by_c_metadata, visited) {
            return Some(miss);
        }
    }
    None
}

fn closure_is_cached_recursive(
    candidate: &db::ResolverArtifactRow,
    by_pair: &BTreeMap<(String, String), &db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &db::ResolverArtifactRow>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if !visited.insert(candidate.c_metadata.clone()) {
        return true;
    }
    let Ok(deps) = parse_dep_c_metadata(&candidate.dependency_c_metadata_json) else {
        return false;
    };
    for (name, c_metadata) in &deps {
        let dep_row = lookup_dep_row(name, c_metadata, by_pair, by_c_metadata);
        let Some(dep_row) = dep_row else {
            return false;
        };
        if !closure_is_cached_recursive(dep_row, by_pair, by_c_metadata, visited) {
            return false;
        }
    }
    true
}

/// Look up a cached row by (name, `c_metadata`), trying the verbatim name
/// first, then the dash↔underscore alt, then — for renamed deps where the
/// rustc alias diverges from the cargo-published name entirely — by
/// `c_metadata` alone (1:1 in this target/rustc index).
fn lookup_dep_row<'a>(
    name: &str,
    c_metadata: &str,
    by_pair: &BTreeMap<(String, String), &'a db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &'a db::ResolverArtifactRow>,
) -> Option<&'a db::ResolverArtifactRow> {
    if let Some(row) = by_pair.get(&(name.to_owned(), c_metadata.to_owned())) {
        return Some(*row);
    }
    let alt = name.replace('_', "-");
    if alt != name
        && let Some(row) = by_pair.get(&(alt, c_metadata.to_owned()))
    {
        return Some(*row);
    }
    let alt = name.replace('-', "_");
    if alt != name
        && let Some(row) = by_pair.get(&(alt, c_metadata.to_owned()))
    {
        return Some(*row);
    }
    by_c_metadata.get(c_metadata).copied()
}

/// Search the artifacts table for a "seed" row whose own
/// `dependency_c_metadata_json` already covers every user direct dep with
/// semver+features-compatible pins. When the user's project IS one of the
/// preheated binaries (or shares its dep shape exactly), this finds it in
/// one pass and gives the resolver a guaranteed-coherent full closure to
/// walk, with no backtracking needed.
fn find_seed_artifact<'a>(
    typed_direct: &[(
        stow_types::identity::CrateName,
        semver::VersionReq,
        BTreeSet<String>,
    )],
    by_pair: &BTreeMap<(String, String), &'a db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &'a db::ResolverArtifactRow>,
    all_artifacts: &'a [db::ResolverArtifactRow],
    considered: &mut u32,
    diagnostics: &mut Vec<String>,
) -> Option<&'a db::ResolverArtifactRow> {
    let direct_index: BTreeMap<&str, (&semver::VersionReq, &BTreeSet<String>)> = typed_direct
        .iter()
        .map(|(name, req, features)| (name.as_str(), (req, features)))
        .collect();
    let mut best: Option<(&db::ResolverArtifactRow, usize)> = None;
    let mut diagnostic_size_pass = 0_usize;
    let mut diagnostic_partial_match: Vec<(String, String, usize, String)> = Vec::new();
    for row in all_artifacts {
        *considered = considered.saturating_add(1);
        let Ok(deps) = parse_dep_c_metadata(&row.dependency_c_metadata_json) else {
            continue;
        };
        if deps.len() < typed_direct.len() {
            continue;
        }
        diagnostic_size_pass += 1;
        let mut covered_count = 0_usize;
        let mut row_dep_index: BTreeMap<String, &str> = BTreeMap::new();
        for (dep_name, dep_c_metadata) in &deps {
            row_dep_index.insert(dep_name.clone(), dep_c_metadata.as_str());
            // Also accept normalized form (rustc underscored vs. cargo
            // dashed) so user direct deps named with dashes match a row
            // whose extern was captured with underscores.
            row_dep_index.insert(dep_name.replace('_', "-"), dep_c_metadata.as_str());
        }
        let mut all_user_covered = true;
        let mut fail_reason = String::new();
        for (user_name, (user_req, user_features)) in &direct_index {
            let lookup_keys = [
                (*user_name).to_owned(),
                user_name.replace('-', "_"),
                user_name.replace('_', "-"),
            ];
            let mut hit = None;
            for key in &lookup_keys {
                if let Some(c_metadata) = row_dep_index.get(key) {
                    hit = Some(c_metadata);
                    break;
                }
            }
            let Some(c_metadata) = hit else {
                all_user_covered = false;
                fail_reason = format!("name `{user_name}` not in row_dep_index");
                break;
            };
            let lookup_pair = lookup_keys
                .iter()
                .find_map(|key| {
                    by_pair
                        .get(&((*key).clone(), (*c_metadata).to_owned()))
                        .copied()
                })
                .or_else(|| by_c_metadata.get(*c_metadata).copied());
            let Some(pinned_row) = lookup_pair else {
                all_user_covered = false;
                fail_reason = format!("by_pair miss for `{user_name}`/{c_metadata}");
                break;
            };
            let Ok(pinned_version) = semver::Version::parse(&pinned_row.version) else {
                all_user_covered = false;
                fail_reason = format!("unparseable pinned version for {user_name}");
                break;
            };
            if !user_req.matches(&pinned_version) {
                all_user_covered = false;
                fail_reason =
                    format!("req `{user_req}` does not match pinned {user_name} {pinned_version}");
                break;
            }
            let Ok(pinned_features) = parse_features_array(&pinned_row.features_json) else {
                all_user_covered = false;
                fail_reason = format!("unparseable pinned features for {user_name}");
                break;
            };
            // "default" is a meta-feature: cargo only passes --cfg
            // feature="default" to rustc when the crate actually defines a
            // `default` feature. For crates with no `default` declared
            // (e.g., bincode 1.3.3), the cache stores features=[] regardless
            // of whether the user said default-features=true. Treat user's
            // "default" request as satisfied when the candidate has no
            // "default" feature recorded — it's a no-op.
            let mut effective_user_features: BTreeSet<String> = (*user_features).clone();
            if effective_user_features.contains("default") && !pinned_features.contains("default") {
                effective_user_features.remove("default");
            }
            if !effective_user_features.is_subset(&pinned_features) {
                let user_set: Vec<&String> = user_features.iter().collect();
                let pinned_set: Vec<&String> = pinned_features.iter().collect();
                fail_reason = format!(
                    "features mismatch for {user_name}: user wants {user_set:?} but cache has {pinned_set:?}"
                );
                all_user_covered = false;
                break;
            }
            covered_count += 1;
        }
        if !all_user_covered {
            // Record every size-pass failure so a 0-coverage seed (the
            // common case for "wrong artifact name happens to have many
            // deps") still surfaces *why* it didn't seed — not just that
            // 14 candidates passed the size filter and silently failed.
            diagnostic_partial_match.push((
                row.crate_name.clone(),
                row.version.clone(),
                covered_count,
                fail_reason,
            ));
            continue;
        }
        // Confirm the seed's own full transitive closure is cached — a row
        // with a missing transitive can't actually be walked.
        if !candidate_closure_is_cached(row, by_pair, by_c_metadata) {
            let miss = first_uncached_in_closure(row, by_pair, by_c_metadata);
            let reason = match miss {
                Some((name, c_metadata)) => format!("transitive uncached: {name}/{c_metadata}"),
                None => "transitive closure walk failed".to_owned(),
            };
            diagnostic_partial_match.push((
                row.crate_name.clone(),
                row.version.clone(),
                covered_count,
                reason,
            ));
            continue;
        }
        // Prefer larger seeds (more transitives covered) so we lock in the
        // most amount of cache work per pin. Tie-break by version DESC.
        let dep_count = deps.len();
        let take_this = match best {
            None => true,
            Some((current, current_deps)) => match dep_count.cmp(&current_deps) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    let cv = semver::Version::parse(&current.version).ok();
                    let nv = semver::Version::parse(&row.version).ok();
                    nv > cv
                }
            },
        };
        if take_this {
            best = Some((row, dep_count));
        }
    }
    if best.is_none() {
        diagnostic_partial_match.sort_by(|a, b| b.2.cmp(&a.2));
        diagnostics.push(format!(
            "size_pass={} user_direct={}",
            diagnostic_size_pass,
            typed_direct.len()
        ));
        for (name, version, cov, reason) in diagnostic_partial_match.iter().take(20) {
            diagnostics.push(format!(
                "{name} {version}: covered={cov}/{total} fail={reason}",
                total = typed_direct.len()
            ));
        }
    }
    best.map(|(row, _)| row)
}

/// Recursive backtracking solver running entirely on the in-memory index.
/// For each direct dep at position `index`, try every viable candidate
/// (already filtered for req+features+full-closure-coverage); on conflict
/// downstream the per-candidate `pinned` snapshot is restored before
/// trying the next.
fn backtrack_solve(
    typed_direct: &[(
        stow_types::identity::CrateName,
        semver::VersionReq,
        BTreeSet<String>,
    )],
    direct_candidates: &[Vec<&db::ResolverArtifactRow>],
    by_pair: &BTreeMap<(String, String), &db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &db::ResolverArtifactRow>,
    index: usize,
    pinned: &mut BTreeMap<(String, String), ResolverPin>,
    considered: &mut u32,
    budget: &mut u32,
) -> bool {
    if index >= typed_direct.len() {
        return true;
    }
    let (crate_name, _, _) = &typed_direct[index];
    // A direct dep is "satisfied" when ANY (name, c_metadata) for this name
    // is already in pinned (the seed search or earlier direct-dep iteration
    // already pulled it into the closure).
    let already_pinned = pinned.keys().any(|(name, _)| name == crate_name.as_str());
    if already_pinned {
        return backtrack_solve(
            typed_direct,
            direct_candidates,
            by_pair,
            by_c_metadata,
            index + 1,
            pinned,
            considered,
            budget,
        );
    }
    for candidate in &direct_candidates[index] {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        *considered = considered.saturating_add(1);
        let snapshot = pinned.clone();
        if try_extend_closure_in_memory(
            by_pair,
            by_c_metadata,
            pinned,
            candidate,
            considered,
            budget,
        ) && backtrack_solve(
            typed_direct,
            direct_candidates,
            by_pair,
            by_c_metadata,
            index + 1,
            pinned,
            considered,
            budget,
        ) {
            return true;
        }
        *pinned = snapshot;
    }
    false
}

/// In-memory port of the original async `try_extend_closure`: pin a
/// candidate plus every (transitively-pinned) `dep_c_metadata`, returning
/// false on (name → different `c_metadata`) conflicts. Walks `by_pair`
/// instead of touching D1.
fn try_extend_closure_in_memory(
    by_pair: &BTreeMap<(String, String), &db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &db::ResolverArtifactRow>,
    pinned: &mut BTreeMap<(String, String), ResolverPin>,
    candidate: &db::ResolverArtifactRow,
    considered: &mut u32,
    budget: &mut u32,
) -> bool {
    try_extend_closure_in_memory_with_diag(
        by_pair,
        by_c_metadata,
        pinned,
        candidate,
        considered,
        budget,
        None,
    )
}

fn try_extend_closure_in_memory_with_diag(
    by_pair: &BTreeMap<(String, String), &db::ResolverArtifactRow>,
    by_c_metadata: &BTreeMap<String, &db::ResolverArtifactRow>,
    pinned: &mut BTreeMap<(String, String), ResolverPin>,
    candidate: &db::ResolverArtifactRow,
    considered: &mut u32,
    budget: &mut u32,
    mut diag: Option<&mut Vec<String>>,
) -> bool {
    let pin_key = (candidate.crate_name.clone(), candidate.c_metadata.clone());
    if pinned.contains_key(&pin_key) {
        return true;
    }
    let deps = match parse_dep_c_metadata(&candidate.dependency_c_metadata_json) {
        Ok(deps) => deps,
        Err(error) => {
            if let Some(d) = diag.as_deref_mut() {
                d.push(format!(
                    "parse_dep failed for {} {}: {error}",
                    candidate.crate_name, candidate.version
                ));
            }
            return false;
        }
    };
    let features = match parse_features_array(&candidate.features_json) {
        Ok(features) => features,
        Err(error) => {
            if let Some(d) = diag.as_deref_mut() {
                d.push(format!(
                    "parse_features failed for {} {}: {error}",
                    candidate.crate_name, candidate.version
                ));
            }
            return false;
        }
    };
    pinned.insert(
        pin_key.clone(),
        ResolverPin {
            version: candidate.version.clone(),
            features,
            c_metadata: candidate.c_metadata.clone(),
            deps: deps.clone(),
        },
    );
    for (dep_name, dep_c_metadata) in &deps {
        if *budget == 0 {
            pinned.remove(&pin_key);
            if let Some(d) = diag.as_deref_mut() {
                d.push("budget exhausted".to_owned());
            }
            return false;
        }
        *budget -= 1;
        *considered = considered.saturating_add(1);
        // Pinning is keyed on (name, c_metadata), so two SemVer-incompatible
        // versions of the same crate can coexist. We only short-circuit
        // when this exact (name, c_metadata) pair is already pinned —
        // distinct c_metadata for the same name is a legitimate diamond.
        let lookup_dep_key = (dep_name.clone(), dep_c_metadata.clone());
        if pinned.contains_key(&lookup_dep_key) {
            continue;
        }
        let Some(dep_row) = lookup_dep_row(dep_name, dep_c_metadata, by_pair, by_c_metadata) else {
            pinned.remove(&pin_key);
            if let Some(d) = diag.as_deref_mut() {
                d.push(format!(
                    "lookup miss for {} c={} (referenced from {})",
                    dep_name, dep_c_metadata, candidate.crate_name
                ));
            }
            return false;
        };
        // The dep_row's actual crate_name might differ from `dep_name` (a
        // renamed-dep alias). Pin under the row's real name; subsequent
        // (alias, c_metadata) lookups land here too because pin_key uses
        // c_metadata which is unique.
        if !try_extend_closure_in_memory_with_diag(
            by_pair,
            by_c_metadata,
            pinned,
            dep_row,
            considered,
            budget,
            diag.as_deref_mut(),
        ) {
            pinned.remove(&pin_key);
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
struct ResolverPin {
    version: String,
    features: BTreeSet<String>,
    c_metadata: String,
    /// Sorted (`dep_name`, `dep_c_metadata`) pairs from the cached artifact's
    /// `dependency_c_metadata_json`. Stored verbatim so the lockfile-render
    /// step can resolve them to (name, version) via `pinned`.
    deps: Vec<(String, String)>,
}

#[derive(Debug, serde::Deserialize)]
struct DepCMetadataIdentity {
    crate_name: String,
    c_metadata: String,
}

fn parse_features_array(features_json: &str) -> Result<BTreeSet<String>, serde_json::Error> {
    let entries: Vec<String> = serde_json::from_str(features_json)?;
    Ok(entries.into_iter().collect())
}

fn parse_dep_c_metadata(json: &str) -> Result<Vec<(String, String)>, serde_json::Error> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<DepCMetadataIdentity> = serde_json::from_str(json)?;
    Ok(entries
        .into_iter()
        .map(|entry| (entry.crate_name, entry.c_metadata))
        .collect())
}

const CRATES_IO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn render_lockfile(
    pinned: &BTreeMap<(String, String), ResolverPin>,
) -> Result<String, crate::errors::DbError> {
    // Cargo's lockfile keys packages by (name, version, source). Two pins
    // that share (name, version) but differ on c_metadata are functionally
    // the SAME package compiled with different feature unifications;
    // cargo would build them as ONE entry with feature union. Reduce
    // multi-c_metadata pins to one canonical entry per (name, version)
    // before rendering — picking the pin with the largest feature set so
    // any user that wanted the smaller set still finds everything it
    // needs in the chosen entry's compile.
    let mut canonical: BTreeMap<(String, String), &ResolverPin> = BTreeMap::new();
    for ((name, _), pin) in pinned {
        let key = (name.clone(), pin.version.clone());
        match canonical.get(&key) {
            Some(existing) if existing.features.len() >= pin.features.len() => {}
            _ => {
                canonical.insert(key, pin);
            }
        }
    }
    // Build a `c_metadata → canonical (name, version)` index. Both pins of
    // a (name, version) duplicate land here, mapping to the same canonical
    // entry — so any dep reference by either c_metadata renders to the
    // same `(name, version)` line.
    let by_c_metadata: BTreeMap<&str, (&str, &ResolverPin)> = pinned
        .iter()
        .map(|((name, _), pin)| {
            let canonical_pin = canonical
                .get(&(name.clone(), pin.version.clone()))
                .copied()
                .unwrap_or(pin);
            (pin.c_metadata.as_str(), (name.as_str(), canonical_pin))
        })
        .collect();
    let mut entries: Vec<((&str, &str), &ResolverPin)> = canonical
        .iter()
        .map(|((name, version), pin)| ((name.as_str(), version.as_str()), *pin))
        .collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    let package = entries
        .iter()
        .map(|((name, version), pin)| {
            let mut dependencies: Vec<String> = pin
                .deps
                .iter()
                .filter_map(|(_, dep_c_metadata)| {
                    by_c_metadata
                        .get(dep_c_metadata.as_str())
                        .map(|(canonical_name, dep_pin)| {
                            format!(
                                "{} {} ({})",
                                canonical_name, dep_pin.version, CRATES_IO_REGISTRY_SOURCE
                            )
                        })
                })
                .collect();
            dependencies.sort();
            dependencies.dedup();
            RenderedLockPackage {
                name: (*name).to_owned(),
                version: (*version).to_owned(),
                source: CRATES_IO_REGISTRY_SOURCE.to_owned(),
                dependencies,
            }
        })
        .collect();
    let body = toml::to_string(&RenderedLockfile {
        version: 3,
        package,
    })
    .map_err(|error| {
        crate::errors::DbError::Invariant(format!("serialize synthesized lockfile: {error}"))
    })?;
    Ok(format!(
        "# This file is automatically @generated by stow.\n# It is not intended for manual editing.\n{body}"
    ))
}

/// Serde shape of the synthesized Cargo.lock (v3).
#[derive(serde::Serialize)]
struct RenderedLockfile {
    version: u32,
    package: Vec<RenderedLockPackage>,
}

#[derive(serde::Serialize)]
struct RenderedLockPackage {
    name: String,
    version: String,
    source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<String>,
}

/// POST /api/v1/admin/artifacts/register
///
/// Trusted CI registers freshly-built artifacts here. CI does NOT write to
/// D1 directly; the auth token guards this endpoint and the edge owns the
/// D1 binding. INSERT OR REPLACE semantics keep registration idempotent
/// across CI retries.
pub async fn register_artifacts(
    _auth: RegisterAuthToken,
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
        "registered artifact records via admin endpoint"
    );
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/scheduler/tasks/submit
///
/// Control endpoint that submits arbitrary tasks into the scheduler.
///
/// `SchedulerAuthToken` extracts first and rejects unauthorized requests
/// before `Json` runs, so an attacker cannot make us deserialize an arbitrary
/// body without a valid token.
pub async fn submit_scheduler_tasks(
    _auth: SchedulerAuthToken,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
    db: Db,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    db::ensure_schema(&db).await?;
    let requests =
        dependency_resolver::canonicalize_enqueue_requests(&db, &crates_io::CfCratesIo, requests)
            .await?;
    scheduler_client::send_enqueue(&scheduler, &requests).await?;
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/scheduler/complete
///
/// CI (or local simulated CI) reports build completion to the scheduler Durable Object.
pub async fn complete_build(
    _auth: SchedulerAuthToken,
    Json(report): Json<BuildCompleteReport>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    scheduler_client::send_complete(&scheduler, &report)
        .await
        .inspect_err(|error| {
            tracing::error!(%error, "failed to forward build completion to scheduler");
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
        return match semantic_miss_admission(&db, &scheduler, &admission, &request).await {
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
            return match semantic_miss_admission(&db, &scheduler, &admission, &request).await {
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

    let c_metadatas = request
        .entries
        .iter()
        .map(|entry| entry.c_metadata.as_str().to_owned())
        .collect::<Vec<_>>();
    let rows = db::get_artifact_references(
        &db,
        &c_metadatas,
        request.target.as_str(),
        request.rustc_version.as_str(),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "batch artifact D1 query failed");
        GetArtifactError::Internal
    })?;
    let rows_by_metadata = rows
        .into_iter()
        .map(|row| (row.c_metadata.clone(), row))
        .collect::<BTreeMap<_, _>>();
    let batch_target = request.target.clone();
    let batch_rustc_version = request.rustc_version.clone();

    let fetch_results = stream::iter(request.entries.iter().cloned().enumerate())
        .map(|(index, entry)| {
            let row = rows_by_metadata.get(entry.c_metadata.as_str()).cloned();
            let target = batch_target.clone();
            let rustc_version = batch_rustc_version.clone();
            let cache = cache.clone();
            let ghcr = ghcr.clone();
            async move {
                let Some(row) = row else {
                    return Ok::<_, GetArtifactError>(BatchFetchResult::Missing {
                        index,
                        manifest_entry: ArtifactBatchManifestEntry {
                            crate_name: entry.crate_name,
                            c_metadata: entry.c_metadata,
                            bundle_path: None,
                        },
                    });
                };

                let cache_key = exact_cache_key(
                    target.as_str(),
                    rustc_version.as_str(),
                    entry.c_metadata.as_str(),
                    &row.oci_digest,
                    &row.created_at,
                );
                let bundle_path = batch_bundle_path(entry.c_metadata.as_str());
                let bundle_bytes = load_bundle_bytes(
                    &cache,
                    &ghcr,
                    &cache_key,
                    &row.oci_reference,
                    &row.oci_digest,
                    row.artifact_size,
                )
                .await
                .map(|(bytes, _)| bytes);
                let bundle_bytes = match bundle_bytes {
                    Ok(bytes) => bytes,
                    Err(error) if error.indicates_stale_artifact() => {
                        tracing::warn!(
                            error = %error,
                            crate_name = %entry.crate_name,
                            c_metadata = %entry.c_metadata,
                            "batch artifact was registered in D1 but stale in GHCR; pruning stale row"
                        );
                        return Ok(BatchFetchResult::Stale {
                            index,
                            c_metadata: entry.c_metadata.as_str().to_owned(),
                            manifest_entry: ArtifactBatchManifestEntry {
                                crate_name: entry.crate_name,
                                c_metadata: entry.c_metadata,
                                bundle_path: None,
                            },
                        });
                    }
                    Err(ghcr::FetchError::Unavailable) => {
                        tracing::warn!(
                            crate_name = %entry.crate_name,
                            c_metadata = %entry.c_metadata,
                            "batch artifact fetch was temporarily unavailable; treating as miss"
                        );
                        return Ok(BatchFetchResult::Missing {
                            index,
                            manifest_entry: ArtifactBatchManifestEntry {
                                crate_name: entry.crate_name,
                                c_metadata: entry.c_metadata,
                                bundle_path: None,
                            },
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            crate_name = %entry.crate_name,
                            c_metadata = %entry.c_metadata,
                            "batch artifact fetch failed; treating as miss"
                        );
                        return Ok(BatchFetchResult::Missing {
                            index,
                            manifest_entry: ArtifactBatchManifestEntry {
                                crate_name: entry.crate_name,
                                c_metadata: entry.c_metadata,
                                bundle_path: None,
                            },
                        });
                    }
                };

                Ok(BatchFetchResult::Present {
                    index,
                    manifest_entry: ArtifactBatchManifestEntry {
                        crate_name: entry.crate_name,
                        c_metadata: entry.c_metadata,
                        bundle_path: Some(bundle_path.clone()),
                    },
                    bundle_path,
                    bundle_bytes,
                })
            }
        })
        .buffer_unordered(settings.batch_fetch_concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut manifest_entries = vec![None::<ArtifactBatchManifestEntry>; request.entries.len()];
    let mut fetched_bundles = Vec::<(usize, String, Vec<u8>)>::new();
    for fetch_result in fetch_results {
        match fetch_result? {
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
                    &db,
                    &c_metadata,
                    request.target.as_str(),
                    request.rustc_version.as_str(),
                )
                .await?;
                manifest_entries[index] = Some(manifest_entry);
            }
        }
    }

    fetched_bundles.sort_by(|left, right| left.0.cmp(&right.0));
    let mut tar = Builder::new(Vec::new());
    for (_index, bundle_path, bundle_bytes) in fetched_bundles {
        append_bytes(&mut tar, &bundle_path, &bundle_bytes).map_err(|error| {
            tracing::error!(%error, bundle_path = %bundle_path, "batch tar assembly failed");
            GetArtifactError::Internal
        })?;
    }

    let manifest = ArtifactBatchManifest {
        target: batch_target,
        rustc_version: batch_rustc_version,
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
    if request.entries.len() > settings.max_expanded_tasks {
        tracing::warn!(
            entries = request.entries.len(),
            max_entries = settings.max_expanded_tasks,
            "dependency list exceeds edge limit"
        );
        return Err(GetArtifactError::BadRequest);
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
    // to "no admissions" rather than failing the analysis response.
    let difficulty = admission_difficulty(&scheduler, &admission).await?;
    response.miss_admissions = match mint_admissions(&admission, enqueue_requests, difficulty).await
    {
        Ok(admissions) => admissions,
        Err(error) => {
            tracing::error!(%error, "failed to mint dependency-graph miss admissions");
            Vec::new()
        }
    };
    drain_admitted_misses(&db, &scheduler).await;

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
    let derived_task_id = scheduler::queue::task_id(
        ticket.request.crate_name.as_str(),
        &ticket.request.version.to_string(),
        ticket.request.features_json.raw().as_str(),
        ticket.request.target.as_str(),
        ticket.request.rustc_version.as_str(),
    );
    if derived_task_id != ticket.task_id {
        tracing::warn!(task_id = %ticket.task_id, "rejected enqueue ticket: task id mismatch");
        return Err(GetArtifactError::Unauthorized);
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

    let name = oci_name(oci_reference).map_err(|error| {
        tracing::error!(%error, "refusing GHCR fetch for malformed OCI reference");
        ghcr::FetchError::InvalidRequest(error.to_string())
    })?;
    let body = ghcr::fetch_bundle(
        &ghcr.base_url,
        oci_reference,
        name,
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

fn oci_name(reference: &str) -> Result<&str, GetArtifactError> {
    stow_types::registry::oci_reference_name(reference).ok_or_else(|| {
        GetArtifactError::InternalWithMessage(format!(
            "malformed OCI reference `{reference}` — expected ghcr.io/water-rs/stow-cache/{{name}}:{{tag}}"
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
    #[error("unauthorized", status = UNAUTHORIZED)]
    Unauthorized,
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    #[error("internal server error")]
    Internal,
    #[error("internal server error: {0}")]
    InternalWithMessage(String),
}

impl From<crate::errors::SchedulerClientError> for GetArtifactError {
    fn from(error: crate::errors::SchedulerClientError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<crate::errors::DbError> for GetArtifactError {
    fn from(error: crate::errors::DbError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<crate::errors::ResolverError> for GetArtifactError {
    fn from(error: crate::errors::ResolverError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}

impl From<crate::errors::MissLoggerError> for GetArtifactError {
    fn from(error: crate::errors::MissLoggerError) -> Self {
        Self::InternalWithMessage(error.to_string())
    }
}
