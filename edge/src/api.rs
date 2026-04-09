use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use futures_util::stream::{self, StreamExt};
use skyzen::extract::{Extractor, Query};
use skyzen::routing::Params;
use skyzen::utils::{Json, State};
use skyzen::{Body, Request, Response, StatusCode};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::api::{
    ArtifactRecord, BatchArtifactRequest, BuildCompleteReport, DependencyGraphRequest,
    DependencyGraphResponse, SemanticArtifactRequest,
};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBatchManifestEntry, ArtifactBlobConfig, ArtifactBundleManifest,
    STOW_BATCH_BUNDLE_MEDIA_TYPE, STOW_BATCH_BUNDLES_DIR, STOW_BATCH_MANIFEST_PATH,
    STOW_BUNDLE_MANIFEST_PATH, STOW_BUNDLE_MEDIA_TYPE, STOW_DYLIB_MEDIA_TYPE,
    STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE,
};
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use tar::{Builder, Header};

use crate::db;
use crate::{cache, dependency_resolver, ghcr, miss_logger, scheduler_client};

const MAX_DEPENDENCY_LIST_ENTRIES: usize = 4096;
const BATCH_FETCH_CONCURRENCY: usize = 32;
const SCHEDULER_AUTH_HEADER: &str = "x-stow-scheduler-token";
const EDGE_BUNDLE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, serde::Serialize)]
pub(crate) struct OkResponse {
    ok: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SchedulerApiAccess {
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SchedulerAuthToken(String);

impl Extractor for SchedulerAuthToken {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let token = request
            .headers()
            .get(SCHEDULER_AUTH_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(GetArtifactError::Unauthorized)?;
        Ok(Self(token.to_owned()))
    }
}

/// POST /api/v1/scheduler/tasks/submit
///
/// Control endpoint that submits arbitrary tasks into the scheduler.
pub async fn submit_scheduler_tasks(
    SchedulerAuthToken(token): SchedulerAuthToken,
    Json(requests): Json<Vec<stow_types::api::EnqueueRequest>>,
    db: Db,
    State(access): State<SchedulerApiAccess>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    require_scheduler_token(&token, &access)?;
    db::ensure_schema(&db)
        .await
        .map_err(GetArtifactError::InternalWithMessage)?;
    let requests = dependency_resolver::canonicalize_enqueue_requests(&db, requests)
        .await
        .map_err(GetArtifactError::InternalWithMessage)?;
    scheduler_client::send_enqueue(&scheduler, &requests)
        .await
        .map_err(GetArtifactError::InternalWithMessage)?;
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/admin/register
///
/// Local/mock CI registers trusted artifact records directly into edge D1.
pub async fn register_artifacts(
    Json(records): Json<Vec<ArtifactRecord>>,
    db: Db,
) -> Result<Json<OkResponse>, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema before artifact registration");
        GetArtifactError::InternalWithMessage(error)
    })?;
    crate::db::register_artifacts(&db, &records)
        .await
        .map_err(|error| {
            tracing::error!(%error, records = records.len(), "failed to register artifact records");
            GetArtifactError::InternalWithMessage(error)
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// POST /api/v1/scheduler/complete
///
/// CI (or local simulated CI) reports build completion to the scheduler Durable Object.
pub async fn complete_build(
    SchedulerAuthToken(token): SchedulerAuthToken,
    Json(report): Json<BuildCompleteReport>,
    State(access): State<SchedulerApiAccess>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    require_scheduler_token(&token, &access)?;
    scheduler_client::send_complete(&scheduler, &report)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to forward build completion to scheduler");
            GetArtifactError::InternalWithMessage(error)
        })?;
    Ok(Json(OkResponse { ok: true }))
}

/// GET /api/v1/scheduler/status
pub async fn scheduler_status(
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<stow_types::api::SchedulerStatus>, GetArtifactError> {
    let status = scheduler_client::get_status(&scheduler)
        .await
        .map_err(GetArtifactError::InternalWithMessage)?;
    Ok(Json(status))
}

/// Query parameters for artifact requests.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactQuery {
    /// Crate name (for miss logging and validation).
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
}

/// GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde
///
/// Returns the complete artifact bundle for one crate compilation unit.
///
/// Flow:
/// 1. CF Cache API check (free, per-datacenter)
/// 2. Hit → return from CF cache
/// 3. Miss → lookup OCI reference in D1, fetch from GHCR, tee into CF Cache
/// 4. GHCR error → 302 redirect client to GHCR direct URL
/// 5. D1 miss → validate crate_name, log miss, return 404
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
        if let Some(Query(ref q)) = query {
            if let Some(ref crate_name) = q.crate_name {
                miss_logger::log_miss(&db, c_metadata, crate_name, target, "").await;
            }
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
            response
                .headers_mut()
                .insert("content-type", STOW_BUNDLE_MEDIA_TYPE.parse().unwrap());
            response.headers_mut().insert(
                "x-stow-cache",
                if cache_hit { "hit" } else { "miss" }.parse().unwrap(),
            );
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
            log_exact_miss(&db, &query, c_metadata, target).await;
            Err(GetArtifactError::NotFound)
        }
        Err(ghcr::FetchError::Unauthorized(status)) => {
            tracing::error!(
                status,
                oci_reference = %row.oci_reference,
                "GHCR authentication failed — NOT pruning D1 row"
            );
            Err(GetArtifactError::InternalWithMessage(format!(
                "GHCR authentication failed (HTTP {status})"
            )))
        }
        Err(ghcr::FetchError::Unavailable) => {
            tracing::warn!(key = %cache_key, "GHCR unavailable, redirecting client");
            match ghcr::resolve_blob_redirect_url(
                &ghcr.base_url,
                oci_name(&row.oci_reference),
                &row.oci_digest,
                &ghcr.token,
            )
            .await
            {
                Ok(redirect_url) => {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::FOUND;
                    response
                        .headers_mut()
                        .insert("location", redirect_url.parse().unwrap());
                    Ok(response)
                }
                Err(e) => {
                    tracing::error!(error = %e, "GHCR redirect resolution failed");
                    Err(GetArtifactError::GhcrUnavailable)
                }
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "GHCR fetch failed");
            Err(GetArtifactError::InternalWithMessage(error.to_string()))
        }
    }
}

/// HEAD /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}
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
            if let Some(size) = row.artifact_size {
                response
                    .headers_mut()
                    .insert("content-length", size.to_string().parse().unwrap());
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
            GetArtifactError::InternalWithMessage(error)
        })?;
    let Some(row) = row else {
        enqueue_semantic_miss(&db, &scheduler, &request).await?;
        return Err(GetArtifactError::NotFound);
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
                &request.target,
                &request.rustc_version,
            )
            .await?;
            enqueue_semantic_miss(&db, &scheduler, &request).await?;
            return Err(GetArtifactError::NotFound);
        }
        Err(error) => {
            tracing::error!(%error, "semantic GHCR fetch failed");
            return Err(GetArtifactError::InternalWithMessage(error.to_string()));
        }
    };

    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert("content-type", STOW_BUNDLE_MEDIA_TYPE.parse().unwrap());
    response.headers_mut().insert(
        "x-stow-cache",
        if cache_hit { "hit" } else { "miss" }.parse().unwrap(),
    );
    Ok(response)
}

/// POST /api/v1/artifacts/batch
pub async fn get_artifact_batch(
    Json(request): Json<BatchArtifactRequest>,
    db: Db,
    State(cache): State<CfCache>,
    State(ghcr): State<GhcrConfig>,
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
        .map(|entry| entry.c_metadata.clone())
        .collect::<Vec<_>>();
    let rows =
        db::get_artifact_references(&db, &c_metadatas, &request.target, &request.rustc_version)
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
            let row = rows_by_metadata.get(&entry.c_metadata).cloned();
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
                    &target,
                    &rustc_version,
                    &entry.c_metadata,
                    &row.oci_digest,
                    &row.created_at,
                );
                let bundle_path = batch_bundle_path(&entry.c_metadata);
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
                            c_metadata: entry.c_metadata.clone(),
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
        .buffer_unordered(BATCH_FETCH_CONCURRENCY)
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
                prune_stale_artifact_row(&db, &c_metadata, &request.target, &request.rustc_version)
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
        STOW_BATCH_BUNDLE_MEDIA_TYPE.parse().unwrap(),
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
) -> Result<Json<DependencyGraphResponse>, GetArtifactError> {
    if request.entries.len() > MAX_DEPENDENCY_LIST_ENTRIES {
        tracing::warn!(
            entries = request.entries.len(),
            max_entries = MAX_DEPENDENCY_LIST_ENTRIES,
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
        &request.target,
        &request.rustc_version,
        &request.entries,
        &request.expanded_entries,
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "dependency graph analysis failed");
        GetArtifactError::InternalWithMessage(error)
    })?;
    scheduler_client::send_enqueue(&scheduler, &outcome.enqueue_requests)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to enqueue dependency-list misses to scheduler");
            GetArtifactError::InternalWithMessage(error)
        })?;

    Ok(Json(outcome.response))
}

fn validate_batch_request(request: &BatchArtifactRequest) -> Result<(), String> {
    if request.entries.is_empty() {
        return Err("batch artifact request entries cannot be empty".to_owned());
    }
    let mut seen = BTreeSet::<&str>::new();
    for entry in &request.entries {
        if entry.crate_name.is_empty() {
            return Err("batch artifact request crate_name cannot be empty".to_owned());
        }
        if !seen.insert(&entry.c_metadata) {
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
        Ok(Some(cached)) => {
            tracing::debug!(key = %cache_key, "cf cache hit");
            validate_bundle_schema(&cached)?;
            return Ok((cached, true));
        }
        Ok(None) => {
            tracing::debug!(key = %cache_key, "cf cache miss");
        }
        Err(error) => {
            tracing::warn!(key = %cache_key, error = %error, "cf cache error");
        }
    }

    let body = ghcr::fetch_bundle(
        &ghcr.base_url,
        oci_reference,
        oci_name(oci_reference),
        oci_digest,
        &ghcr.token,
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
    validate_bundle_schema(&body)?;
    if let Err(error) = cache::try_put(cache, cache_key, &body, artifact_size).await {
        tracing::warn!(key = %cache_key, error = %error, "cf cache put failed");
    }
    Ok((body, false))
}

fn validate_bundle_schema(bytes: &[u8]) -> Result<(), ghcr::FetchError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut manifest_bytes = None::<Vec<u8>>;
    for entry in archive
        .entries()
        .map_err(|error| ghcr::FetchError::InvalidBundle(format!("read bundle entries: {error}")))?
    {
        let mut entry = entry.map_err(|error| {
            ghcr::FetchError::InvalidBundle(format!("read bundle entry: {error}"))
        })?;
        let path = entry
            .path()
            .map_err(|error| ghcr::FetchError::InvalidBundle(format!("read bundle path: {error}")))?
            .to_string_lossy()
            .to_string();
        if path != STOW_BUNDLE_MANIFEST_PATH {
            continue;
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|error| {
            ghcr::FetchError::InvalidBundle(format!("read bundle manifest payload: {error}"))
        })?;
        manifest_bytes = Some(bytes);
        break;
    }
    let manifest_bytes = manifest_bytes.ok_or_else(|| {
        ghcr::FetchError::InvalidBundle("bundle is missing manifest.json".to_owned())
    })?;
    let manifest =
        serde_json::from_slice::<ArtifactBundleManifest>(&manifest_bytes).map_err(|error| {
            ghcr::FetchError::InvalidBundle(format!("parse bundle manifest json: {error}"))
        })?;
    validate_bundle_config_identity(&manifest.config)?;
    Ok(())
}

fn validate_bundle_config_identity(config: &ArtifactBlobConfig) -> Result<(), ghcr::FetchError> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&config.compile_key).map_err(|error| {
            ghcr::FetchError::InvalidBundle(format!(
                "bundle compile_key {} is not a valid stable public-cache identity: {error}",
                config.compile_key
            ))
        })?;
    if stable_c_metadata != config.c_metadata {
        return Err(ghcr::FetchError::InvalidBundle(format!(
            "bundle c_metadata {} does not match stable compile_key prefix {}",
            config.c_metadata, stable_c_metadata
        )));
    }

    let canonical_crate_name = config.crate_name.replace('-', "_");
    let canonical_stem = format!(
        "lib{}{extra}",
        canonical_crate_name,
        extra = config.extra_filename
    );
    let mut saw_canonical_rlib = false;
    let mut saw_canonical_rmeta = false;
    let mut saw_canonical_dynamic = false;

    for output in &config.outputs {
        let file_name = std::path::Path::new(&output.file_name);
        if file_name.components().count() != 1 {
            return Err(ghcr::FetchError::InvalidBundle(format!(
                "bundle output {} is not a single path component",
                output.file_name
            )));
        }
        match output.media_type.as_str() {
            STOW_RLIB_MEDIA_TYPE => {
                saw_canonical_rlib |= output.file_name == format!("{canonical_stem}.rlib");
            }
            STOW_RMETA_MEDIA_TYPE => {
                saw_canonical_rmeta |= output.file_name == format!("{canonical_stem}.rmeta");
            }
            STOW_DYLIB_MEDIA_TYPE | STOW_PROC_MACRO_MEDIA_TYPE => {
                saw_canonical_dynamic |=
                    output.file_name.starts_with(&format!("{canonical_stem}."));
            }
            other => {
                return Err(ghcr::FetchError::InvalidBundle(format!(
                    "bundle output {} has unsupported media type {}",
                    output.file_name, other
                )));
            }
        }
    }

    if config
        .outputs
        .iter()
        .any(|output| output.media_type == STOW_RLIB_MEDIA_TYPE)
        && !saw_canonical_rlib
    {
        return Err(ghcr::FetchError::InvalidBundle(format!(
            "bundle is missing canonical rlib output for stable metadata {}",
            config.c_metadata
        )));
    }
    if config
        .outputs
        .iter()
        .any(|output| output.media_type == STOW_RMETA_MEDIA_TYPE)
        && !saw_canonical_rmeta
    {
        return Err(ghcr::FetchError::InvalidBundle(format!(
            "bundle is missing canonical rmeta output for stable metadata {}",
            config.c_metadata
        )));
    }
    if config.outputs.iter().any(|output| {
        output.media_type == STOW_DYLIB_MEDIA_TYPE
            || output.media_type == STOW_PROC_MACRO_MEDIA_TYPE
    }) && !saw_canonical_dynamic
    {
        return Err(ghcr::FetchError::InvalidBundle(format!(
            "bundle is missing canonical dynamic output for stable metadata {}",
            config.c_metadata
        )));
    }

    Ok(())
}

fn oci_name(reference: &str) -> &str {
    reference
        .strip_prefix("ghcr.io/stow-rs/cache/")
        .and_then(|value| value.split(':').next())
        .unwrap_or_else(|| {
            debug_assert!(false, "malformed OCI reference: {reference}");
            tracing::error!(reference, "malformed OCI reference — expected ghcr.io/stow-rs/cache/ prefix");
            reference
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
    pub token: String,
    pub base_url: String,
}

fn require_scheduler_token(
    token: &str,
    access: &SchedulerApiAccess,
) -> Result<(), GetArtifactError> {
    let expected = access.auth_token.as_deref().ok_or_else(|| {
        GetArtifactError::InternalWithMessage("missing scheduler auth token binding".to_owned())
    })?;
    if token != expected {
        return Err(GetArtifactError::Unauthorized);
    }
    Ok(())
}

async fn enqueue_semantic_miss(
    db: &Db,
    scheduler: &CfDurableNamespace,
    request: &SemanticArtifactRequest,
) -> Result<(), GetArtifactError> {
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
    let enqueue_requests = dependency_resolver::canonicalize_enqueue_requests(
        db,
        vec![stow_types::api::EnqueueRequest {
            crate_name: request.crate_name.clone(),
            version: request.version.clone(),
            features_json: request.features_json.clone(),
            target: request.target.clone(),
            rustc_version: request.rustc_version.clone(),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
        }],
    )
    .await
    .map_err(GetArtifactError::InternalWithMessage)?;
    scheduler_client::send_enqueue(scheduler, &enqueue_requests)
        .await
        .map_err(GetArtifactError::InternalWithMessage)
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
        .map_err(GetArtifactError::InternalWithMessage)
}

async fn log_exact_miss(
    db: &Db,
    query: &Option<Query<ArtifactQuery>>,
    c_metadata: &str,
    target: &str,
) {
    if let Some(Query(q)) = query
        && let Some(ref crate_name) = q.crate_name
    {
        miss_logger::log_miss(db, c_metadata, crate_name, target, "").await;
    }
}

#[skyzen::error(message = "artifact error")]
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::validate_bundle_schema;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH,
        STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE,
    };
    use stow_types::platform::{PanicStrategy, Profile};
    use tar::{Builder, Header};

    fn profile() -> Profile {
        Profile {
            opt_level: "0".to_owned(),
            debuginfo: 1,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
        }
    }

    fn bundle_bytes(config: ArtifactBlobConfig) -> Vec<u8> {
        let manifest = ArtifactBundleManifest {
            oci_reference: "ghcr.io/stow-rs/cache/proc-macro2:test".to_owned(),
            oci_digest: "sha256:test".to_owned(),
            config,
            sigstore_signatures: Vec::new(),
        };
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let mut tar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(manifest_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(
            &mut header,
            STOW_BUNDLE_MANIFEST_PATH,
            Cursor::new(manifest_json),
        )
        .unwrap();
        tar.into_inner().unwrap()
    }

    #[test]
    fn validate_bundle_schema_rejects_stable_bundle_without_canonical_output_names() {
        let bytes = bundle_bytes(ArtifactBlobConfig {
            compile_key: "df1c5df8d44a9ede068e852b56a99270d4d6b905ee849e7f4861e2c13699f43e"
                .to_owned(),
            crate_name: "proc-macro2".to_owned(),
            crate_version: "1.0.106".to_owned(),
            c_metadata: "df1c5df8d44a9ede".to_owned(),
            extra_filename: "-df1c5df8d44a9ede".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            features_json: "[\"default\",\"proc-macro\"]".to_owned(),
            dependency_c_metadata_json:
                "[{\"crate_name\":\"unicode_ident\",\"c_metadata\":\"0e63365407e7f07c2be3d7da23fc1e46fdf371b2b1e7030e54325461657e757f\"}]"
                    .to_owned(),
            profile: profile(),
            emit: vec!["dep-info".to_owned(), "link".to_owned(), "metadata".to_owned()],
            artifact_size: 1,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![
                ArtifactBundleFile {
                    file_name: "libproc_macro2-68afcc2f66100859.rlib".to_owned(),
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
                ArtifactBundleFile {
                    file_name: "libproc_macro2-68afcc2f66100859.rmeta".to_owned(),
                    media_type: STOW_RMETA_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
            ],
            native: None,
        });

        assert!(validate_bundle_schema(&bytes).is_err());
    }

    #[test]
    fn validate_bundle_schema_accepts_stable_bundle_with_canonical_output_names() {
        let bytes = bundle_bytes(ArtifactBlobConfig {
            compile_key: "df1c5df8d44a9ede068e852b56a99270d4d6b905ee849e7f4861e2c13699f43e"
                .to_owned(),
            crate_name: "proc-macro2".to_owned(),
            crate_version: "1.0.106".to_owned(),
            c_metadata: "df1c5df8d44a9ede".to_owned(),
            extra_filename: "-df1c5df8d44a9ede".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            features_json: "[\"default\",\"proc-macro\"]".to_owned(),
            dependency_c_metadata_json:
                "[{\"crate_name\":\"unicode_ident\",\"c_metadata\":\"0e63365407e7f07c2be3d7da23fc1e46fdf371b2b1e7030e54325461657e757f\"}]"
                    .to_owned(),
            profile: profile(),
            emit: vec!["dep-info".to_owned(), "link".to_owned(), "metadata".to_owned()],
            artifact_size: 1,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![
                ArtifactBundleFile {
                    file_name: "libproc_macro2-57f123ce754eb51b.rlib".to_owned(),
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
                ArtifactBundleFile {
                    file_name: "libproc_macro2-df1c5df8d44a9ede.rlib".to_owned(),
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
                ArtifactBundleFile {
                    file_name: "libproc_macro2-57f123ce754eb51b.rmeta".to_owned(),
                    media_type: STOW_RMETA_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
                ArtifactBundleFile {
                    file_name: "libproc_macro2-df1c5df8d44a9ede.rmeta".to_owned(),
                    media_type: STOW_RMETA_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                },
            ],
            native: None,
        });

        validate_bundle_schema(&bytes).unwrap();
    }
}
