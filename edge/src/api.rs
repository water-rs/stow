use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use futures_util::stream::{self, StreamExt};
use skyzen::extract::Query;
use skyzen::routing::Params;
use skyzen::utils::{Json, State};
use skyzen::{Body, Response, StatusCode};
use skyzen_cloudflare::{CfCache, CfDurableNamespace};
use skyzen_services::Db;
use stow_types::api::{
    BatchArtifactRequest, DependencyGraphRequest, DependencyGraphResponse, SemanticArtifactRequest,
};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBatchManifestEntry, STOW_BATCH_BUNDLE_MEDIA_TYPE,
    STOW_BATCH_BUNDLES_DIR, STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MEDIA_TYPE,
};
use tar::{Builder, Header};

use crate::db;
use crate::{cache, ghcr, miss_logger, scheduler_client};

const MAX_DEPENDENCY_LIST_ENTRIES: usize = 4096;
const BATCH_FETCH_CONCURRENCY: usize = 32;

/// Query parameters for artifact requests.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactQuery {
    /// Crate name (for miss logging and validation).
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// Crate version (for miss logging).
    pub v: Option<String>,
}

/// GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}?crate=serde&v=1.0.210
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
    State(scheduler): State<CfDurableNamespace>,
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
                miss_logger::log_miss(&db, c_metadata, crate_name, target, "", Some(&scheduler))
                    .await;
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
        Err(e) => {
            tracing::error!(error = %e, "GHCR fetch failed");
            Err(GetArtifactError::GhcrUnavailable)
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

/// GET /api/v1/status/{crate_name}
pub async fn get_status(params: Params) -> Result<&'static str, GetArtifactError> {
    let _crate_name = params
        .get("crate_name")
        .map_err(|_| GetArtifactError::BadRequest)?;
    Ok("ok")
}

/// POST /api/v1/artifacts/semantic
pub async fn get_semantic_artifact(
    Json(request): Json<SemanticArtifactRequest>,
    db: Db,
    State(cache): State<CfCache>,
    State(ghcr): State<GhcrConfig>,
) -> Result<Response, GetArtifactError> {
    db::ensure_schema(&db).await.map_err(|error| {
        tracing::error!(%error, "failed to ensure edge schema");
        GetArtifactError::Internal
    })?;

    let row = db::get_semantic_artifact_reference(&db, &request)
        .await
        .map_err(|error| {
            tracing::error!(%error, "semantic D1 query failed");
            GetArtifactError::Internal
        })?
        .ok_or(GetArtifactError::NotFound)?;
    let cache_key = semantic_cache_key(&request, &row.oci_digest, &row.created_at);

    let (body, cache_hit) = load_bundle_bytes(
        &cache,
        &ghcr,
        &cache_key,
        &row.oci_reference,
        &row.oci_digest,
        row.artifact_size,
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "semantic GHCR fetch failed");
        GetArtifactError::GhcrUnavailable
    })?;

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
                    Err(ghcr::FetchError::NotFound) => {
                        tracing::warn!(
                            crate_name = %entry.crate_name,
                            c_metadata = %entry.c_metadata,
                            "batch artifact was registered in D1 but missing in GHCR; treating as miss"
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
                        tracing::error!(
                            %error,
                            crate_name = %entry.crate_name,
                            c_metadata = %entry.c_metadata,
                            "batch artifact fetch failed"
                        );
                        return Err(GetArtifactError::GhcrUnavailable);
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

    let mut manifest_entries =
        vec![None::<ArtifactBatchManifestEntry>; request.entries.len()];
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
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "dependency graph analysis failed");
        GetArtifactError::Internal
    })?;
    scheduler_client::send_enqueue(&scheduler, &outcome.enqueue_requests)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to enqueue dependency-list misses to scheduler");
            GetArtifactError::Internal
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
    .await?;
    if let Err(error) = cache::try_put(cache, cache_key, &body, artifact_size).await {
        tracing::warn!(key = %cache_key, error = %error, "cf cache put failed");
    }
    Ok((body, false))
}

fn oci_name(reference: &str) -> &str {
    reference
        .strip_prefix("ghcr.io/stow-rs/cache/")
        .and_then(|value| value.split(':').next())
        .unwrap_or("unknown")
}

fn exact_cache_key(
    target: &str,
    rustc_version: &str,
    c_metadata: &str,
    oci_digest: &str,
    created_at: &str,
) -> String {
    format!("{target}/{rustc_version}/{c_metadata}/{oci_digest}/{created_at}")
}

fn semantic_cache_key(
    request: &SemanticArtifactRequest,
    oci_digest: &str,
    created_at: &str,
) -> String {
    format!(
        "semantic/{}/{}/{}/{}/{}/{}/{}",
        request.target,
        request.rustc_version,
        request.crate_name,
        request.version,
        request.features_json,
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

#[skyzen::error(message = "artifact error")]
pub enum GetArtifactError {
    #[error("bad request", status = BAD_REQUEST)]
    BadRequest,
    #[error("artifact not found", status = NOT_FOUND)]
    NotFound,
    #[error("GHCR unavailable", status = BAD_GATEWAY)]
    GhcrUnavailable,
    #[error("internal server error")]
    Internal,
}
