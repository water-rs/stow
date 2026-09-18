use sqlx::FromRow;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphAnalysisEntry, DependencyGraphArtifact,
    DependencyGraphEntry, DependencyGraphRequest, DependencyGraphResponse,
    RecommendedDependencyVersion,
};
use stow_types::error::Context;

use crate::config::StowConfig;
use crate::state_db::{db_int, duration_millis, now_millis};

#[tracing::instrument(name = "stow.graph_cache.load", skip_all)]
pub async fn load(
    config: &StowConfig,
    request: &DependencyGraphRequest,
) -> stow_types::error::Result<Option<DependencyGraphResponse>> {
    let pool = config.state_db_pool().await?;
    let key = cache_key(request)?;
    evict_expired_entries(&pool, config.graph_cache_ttl).await?;

    let Some(entry) = sqlx::query_as::<_, GraphCacheEntryRow>(
        "SELECT cache_key, expanded_cached, expanded_total \
         FROM graph_cache_entries \
         WHERE cache_key = ?",
    )
    .bind(&key)
    .fetch_optional(&pool)
    .await?
    else {
        return Ok(None);
    };

    Ok(Some(DependencyGraphResponse {
        entries: load_analysis_entries(&pool, &entry.cache_key).await?,
        expanded_cached: db_int(entry.expanded_cached, "cached expanded_cached")?,
        expanded_total: db_int(entry.expanded_total, "cached expanded_total")?,
        expanded_entries: load_expanded_entries(&pool, &entry.cache_key).await?,
        prefetch_artifacts: load_prefetch_artifacts(&pool, &entry.cache_key).await?,
    }))
}

/// Delete entry rows older than `ttl`. Both `load` and `store` evict first so
/// a stale row can never be read back or mask a fresh write.
async fn evict_expired_entries(
    pool: &sqlx::SqlitePool,
    ttl: std::time::Duration,
) -> stow_types::error::Result<()> {
    let now_ms: i64 = db_int(now_millis(), "graph cache current time")?;
    let ttl_ms: i64 = db_int(duration_millis(ttl), "graph cache TTL")?;
    sqlx::query(
        "DELETE FROM graph_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Rebuild the per-dependency analysis entries for one cache entry: one row
/// per dependency, with its feature list, current artifact identities, and
/// optional recommended upgrade joined back on by ordinal.
async fn load_analysis_entries(
    pool: &sqlx::SqlitePool,
    cache_key: &str,
) -> stow_types::error::Result<Vec<DependencyGraphAnalysisEntry>> {
    let analysis_rows = sqlx::query_as::<_, GraphCacheAnalysisEntryRow>(
        "SELECT ordinal, crate_name, version, current_artifact_count, recommended_version, recommended_artifact_count \
         FROM graph_cache_analysis_entries \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;
    let feature_rows = sqlx::query_as::<_, GraphCacheFeatureRow>(
        "SELECT entry_ordinal, feature_name \
         FROM graph_cache_analysis_features \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;
    let artifact_rows = sqlx::query_as::<_, GraphCacheArtifactRow>(
        "SELECT entry_ordinal, c_metadata \
         FROM graph_cache_current_artifacts \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;

    analysis_rows
        .iter()
        .map(|row| analysis_entry(row, &feature_rows, &artifact_rows))
        .collect()
}

/// Assemble one analysis entry from its row plus the feature and artifact
/// rows that share its ordinal.
fn analysis_entry(
    row: &GraphCacheAnalysisEntryRow,
    feature_rows: &[GraphCacheFeatureRow],
    artifact_rows: &[GraphCacheArtifactRow],
) -> stow_types::error::Result<DependencyGraphAnalysisEntry> {
    let features = feature_rows
        .iter()
        .filter(|feature_row| feature_row.entry_ordinal == row.ordinal)
        .map(|feature_row| feature_row.feature_name.clone())
        .collect();
    let current_artifacts = artifact_rows
        .iter()
        .filter(|artifact_row| artifact_row.entry_ordinal == row.ordinal)
        .map(|artifact_row| {
            Ok::<_, stow_types::error::Error>(DependencyGraphArtifact {
                c_metadata: stow_types::identity::CMetadata::parse(
                    artifact_row.c_metadata.as_str(),
                )
                .map_err(|error| {
                    stow_types::stow_error!(
                        "cached artifact c_metadata `{}`: {error}",
                        artifact_row.c_metadata
                    )
                })?,
            })
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let recommended = match (
        row.recommended_version.as_ref(),
        row.recommended_artifact_count,
    ) {
        (Some(version), Some(artifact_count)) => Some(RecommendedDependencyVersion {
            version: semver::Version::parse(version)
                .wrap_err_with(|| format!("parse cached recommended semver version `{version}`"))?,
            artifact_count: db_int(artifact_count, "cached recommended_artifact_count")?,
        }),
        (None, None) => None,
        _ => {
            return Err(stow_types::stow_error!(
                "cached graph analysis entry has inconsistent recommended version fields"
            ));
        }
    };
    Ok(DependencyGraphAnalysisEntry {
        dependency: DependencyGraphEntry {
            crate_name: stow_types::identity::CrateName::parse(row.crate_name.as_str())
                .wrap_err_with(|| {
                    format!("cached graph analysis crate_name `{}`", row.crate_name)
                })?,
            version: semver::Version::parse(&row.version)
                .wrap_err_with(|| format!("parse cached semver version `{}`", row.version))?,
            features,
        },
        current_artifact_count: db_int(
            row.current_artifact_count,
            "cached current_artifact_count",
        )?,
        current_artifacts,
        recommended,
    })
}

/// Rebuild the expanded dependency list, joining each entry's features back
/// on by ordinal.
async fn load_expanded_entries(
    pool: &sqlx::SqlitePool,
    cache_key: &str,
) -> stow_types::error::Result<Vec<DependencyGraphEntry>> {
    let expanded_rows = sqlx::query_as::<_, GraphCacheExpandedEntryRow>(
        "SELECT ordinal, crate_name, version \
         FROM graph_cache_expanded_entries \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;
    let expanded_feature_rows = sqlx::query_as::<_, GraphCacheExpandedFeatureRow>(
        "SELECT entry_ordinal, feature_name \
         FROM graph_cache_expanded_features \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;

    expanded_rows
        .into_iter()
        .map(|row| {
            let crate_name = stow_types::identity::CrateName::parse(row.crate_name.as_str())
                .wrap_err_with(|| format!("cached expanded crate_name `{}`", row.crate_name))?;
            Ok::<_, stow_types::error::Error>(DependencyGraphEntry {
                crate_name,
                version: semver::Version::parse(&row.version).wrap_err_with(|| {
                    format!("parse cached expanded semver version `{}`", row.version)
                })?,
                features: expanded_feature_rows
                    .iter()
                    .filter(|feature_row| feature_row.entry_ordinal == row.ordinal)
                    .map(|feature_row| feature_row.feature_name.clone())
                    .collect(),
            })
        })
        .collect()
}

/// Rebuild the exact-artifact prefetch list in stored order.
async fn load_prefetch_artifacts(
    pool: &sqlx::SqlitePool,
    cache_key: &str,
) -> stow_types::error::Result<Vec<BatchArtifactRequestEntry>> {
    let prefetch_rows = sqlx::query_as::<_, GraphCachePrefetchRow>(
        "SELECT crate_name, c_metadata \
         FROM graph_cache_prefetch_artifacts \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(cache_key)
    .fetch_all(pool)
    .await?;

    prefetch_rows
        .into_iter()
        .map(|row| {
            let crate_name = stow_types::identity::CrateName::parse(row.crate_name.as_str())
                .wrap_err_with(|| format!("cached prefetch crate_name `{}`", row.crate_name))?;
            let c_metadata = stow_types::identity::CMetadata::parse(row.c_metadata.as_str())
                .wrap_err_with(|| format!("cached prefetch c_metadata `{}`", row.c_metadata))?;
            Ok::<_, stow_types::error::Error>(BatchArtifactRequestEntry {
                crate_name,
                c_metadata,
            })
        })
        .collect()
}

#[tracing::instrument(name = "stow.graph_cache.store", skip_all)]
pub async fn store(
    config: &StowConfig,
    request: &DependencyGraphRequest,
    response: &DependencyGraphResponse,
) -> stow_types::error::Result<()> {
    let pool = config.state_db_pool().await?;
    let key = cache_key(request)?;
    evict_expired_entries(&pool, config.graph_cache_ttl).await?;
    upsert_entry(&pool, &key, response).await?;
    delete_child_rows(&pool, &key).await?;
    insert_analysis_entries(&pool, &key, &response.entries).await?;
    insert_prefetch_artifacts(&pool, &key, &response.prefetch_artifacts).await?;
    insert_expanded_entries(&pool, &key, &response.expanded_entries).await?;
    Ok(())
}

/// Insert or refresh the summary row: the cache key, its write timestamp, and
/// the expanded-graph coverage counters.
async fn upsert_entry(
    pool: &sqlx::SqlitePool,
    key: &str,
    response: &DependencyGraphResponse,
) -> stow_types::error::Result<()> {
    let now_ms: i64 = db_int(now_millis(), "graph cache current time")?;
    sqlx::query(
        "INSERT INTO graph_cache_entries (cache_key, inserted_at_ms, expanded_cached, expanded_total) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(cache_key) DO UPDATE SET \
             inserted_at_ms = excluded.inserted_at_ms, \
             expanded_cached = excluded.expanded_cached, \
             expanded_total = excluded.expanded_total",
    )
    .bind(key)
    .bind(now_ms)
    .bind(db_int::<_, i64>(response.expanded_cached, "expanded_cached")?)
    .bind(db_int::<_, i64>(response.expanded_total, "expanded_total")?)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clear every child row for `key` so a rewrite replaces the entry's detail
/// tables wholesale instead of appending to them.
async fn delete_child_rows(pool: &sqlx::SqlitePool, key: &str) -> stow_types::error::Result<()> {
    for table in [
        "graph_cache_expanded_features",
        "graph_cache_expanded_entries",
        "graph_cache_analysis_features",
        "graph_cache_current_artifacts",
        "graph_cache_analysis_entries",
        "graph_cache_prefetch_artifacts",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE cache_key = ?"))
            .bind(key)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Persist the per-dependency analysis entries: one row per entry plus its
/// feature and current-artifact child rows keyed by the entry's ordinal.
async fn insert_analysis_entries(
    pool: &sqlx::SqlitePool,
    key: &str,
    entries: &[DependencyGraphAnalysisEntry],
) -> stow_types::error::Result<()> {
    for (entry_ordinal, analysis_entry) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_analysis_entries \
             (cache_key, ordinal, crate_name, version, current_artifact_count, recommended_version, recommended_artifact_count) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(key)
        .bind(db_int::<_, i64>(entry_ordinal, "graph cache entry ordinal")?)
        .bind(analysis_entry.dependency.crate_name.as_str())
        .bind(analysis_entry.dependency.version.to_string())
        .bind(i64::from(analysis_entry.current_artifact_count))
        .bind(
            analysis_entry
                .recommended
                .as_ref()
                .map(|value| value.version.to_string()),
        )
        .bind(
            analysis_entry
                .recommended
                .as_ref()
                .map(|value| i64::from(value.artifact_count)),
        )
        .execute(pool)
        .await?;

        for (feature_ordinal, feature_name) in analysis_entry.dependency.features.iter().enumerate()
        {
            sqlx::query(
                "INSERT INTO graph_cache_analysis_features \
                 (cache_key, entry_ordinal, ordinal, feature_name) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(key)
            .bind(db_int::<_, i64>(
                entry_ordinal,
                "graph cache entry ordinal",
            )?)
            .bind(db_int::<_, i64>(
                feature_ordinal,
                "graph cache feature ordinal",
            )?)
            .bind(feature_name)
            .execute(pool)
            .await?;
        }

        for (artifact_ordinal, artifact) in analysis_entry.current_artifacts.iter().enumerate() {
            sqlx::query(
                "INSERT INTO graph_cache_current_artifacts \
                 (cache_key, entry_ordinal, ordinal, c_metadata) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(key)
            .bind(db_int::<_, i64>(
                entry_ordinal,
                "graph cache entry ordinal",
            )?)
            .bind(db_int::<_, i64>(
                artifact_ordinal,
                "graph cache artifact ordinal",
            )?)
            .bind(artifact.c_metadata.as_str())
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Persist the exact-artifact prefetch list in request order.
async fn insert_prefetch_artifacts(
    pool: &sqlx::SqlitePool,
    key: &str,
    artifacts: &[BatchArtifactRequestEntry],
) -> stow_types::error::Result<()> {
    for (ordinal, artifact) in artifacts.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_prefetch_artifacts \
             (cache_key, ordinal, crate_name, c_metadata) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(key)
        .bind(db_int::<_, i64>(ordinal, "graph cache prefetch ordinal")?)
        .bind(artifact.crate_name.as_str())
        .bind(artifact.c_metadata.as_str())
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Persist the expanded dependency list, one row per entry plus its feature
/// child rows keyed by the entry's ordinal.
async fn insert_expanded_entries(
    pool: &sqlx::SqlitePool,
    key: &str,
    entries: &[DependencyGraphEntry],
) -> stow_types::error::Result<()> {
    for (entry_ordinal, entry) in entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_expanded_entries \
             (cache_key, ordinal, crate_name, version) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(key)
        .bind(db_int::<_, i64>(
            entry_ordinal,
            "graph cache entry ordinal",
        )?)
        .bind(entry.crate_name.as_str())
        .bind(entry.version.to_string())
        .execute(pool)
        .await?;

        for (feature_ordinal, feature_name) in entry.features.iter().enumerate() {
            sqlx::query(
                "INSERT INTO graph_cache_expanded_features \
                 (cache_key, entry_ordinal, ordinal, feature_name) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(key)
            .bind(db_int::<_, i64>(
                entry_ordinal,
                "graph cache entry ordinal",
            )?)
            .bind(db_int::<_, i64>(
                feature_ordinal,
                "graph cache feature ordinal",
            )?)
            .bind(feature_name)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

fn cache_key(request: &DependencyGraphRequest) -> stow_types::error::Result<String> {
    const GRAPH_CACHE_SCHEMA_VERSION: &str = "v3";
    let bytes = serde_json::to_vec(request).map_err(|error| {
        stow_types::stow_error!("serialize dependency graph cache key: {error}")
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(GRAPH_CACHE_SCHEMA_VERSION.as_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheEntryRow {
    cache_key: String,
    expanded_cached: i64,
    expanded_total: i64,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheAnalysisEntryRow {
    ordinal: i64,
    crate_name: String,
    version: String,
    current_artifact_count: i64,
    recommended_version: Option<String>,
    recommended_artifact_count: Option<i64>,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheFeatureRow {
    entry_ordinal: i64,
    feature_name: String,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheArtifactRow {
    entry_ordinal: i64,
    c_metadata: String,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCachePrefetchRow {
    crate_name: String,
    c_metadata: String,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheExpandedEntryRow {
    ordinal: i64,
    crate_name: String,
    version: String,
}

#[derive(Debug, Clone, FromRow)]
struct GraphCacheExpandedFeatureRow {
    entry_ordinal: i64,
    feature_name: String,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use semver::Version;
    use stow_types::api::{
        BatchArtifactRequestEntry, DependencyGraphAnalysisEntry, DependencyGraphArtifact,
        DependencyGraphEntry, DependencyGraphRequest, DependencyGraphResponse,
        ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry,
    };
    use stow_types::identity::{CMetadata, CrateName, TargetTriple, WireRustcVersion};
    use tempfile::TempDir;

    use super::{load, store};
    use crate::config::{StowConfig, VerifyMode};

    #[tokio::test]
    async fn graph_cache_round_trips_expanded_entries() {
        let cache_dir = TempDir::new().unwrap();
        let config = test_config(cache_dir.path().to_path_buf());
        let humansize = CrateName::parse("humansize").unwrap();
        let libm = CrateName::parse("libm").unwrap();
        let request = DependencyGraphRequest {
            target: TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            entries: vec![DependencyGraphEntry {
                crate_name: humansize.clone(),
                version: Version::parse("2.1.3").unwrap(),
                features: vec!["std".to_owned()],
            }],
            expanded_entries: vec![
                ResolvedDependencyGraphEntry {
                    crate_name: humansize.clone(),
                    version: Version::parse("2.1.3").unwrap(),
                    features: vec!["std".to_owned()],
                    dependencies: vec![ResolvedDependencyGraphDependency {
                        crate_name: libm.clone(),
                        version: Version::parse("0.2.8").unwrap(),
                    }],
                },
                ResolvedDependencyGraphEntry {
                    crate_name: libm.clone(),
                    version: Version::parse("0.2.8").unwrap(),
                    features: vec!["arch".to_owned()],
                    dependencies: Vec::new(),
                },
            ],
        };
        let response = DependencyGraphResponse {
            entries: vec![DependencyGraphAnalysisEntry {
                dependency: request.entries[0].clone(),
                current_artifact_count: 1,
                current_artifacts: vec![DependencyGraphArtifact {
                    c_metadata: CMetadata::parse("a1b2c3d4").unwrap(),
                }],
                recommended: None,
            }],
            expanded_cached: 1,
            expanded_total: 2,
            expanded_entries: vec![
                DependencyGraphEntry {
                    crate_name: humansize.clone(),
                    version: Version::parse("2.1.3").unwrap(),
                    features: vec!["std".to_owned()],
                },
                DependencyGraphEntry {
                    crate_name: libm.clone(),
                    version: Version::parse("0.2.8").unwrap(),
                    features: vec!["arch".to_owned()],
                },
            ],
            prefetch_artifacts: vec![BatchArtifactRequestEntry {
                crate_name: libm.clone(),
                c_metadata: CMetadata::parse("ee5577ff").unwrap(),
            }],
        };

        store(&config, &request, &response).await.unwrap();
        let cached = load(&config, &request).await.unwrap().unwrap();

        assert_eq!(
            serde_json::to_value(&cached).unwrap(),
            serde_json::to_value(&response).unwrap(),
        );
    }

    fn test_config(cache_dir: std::path::PathBuf) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir,
            request_timeout: Duration::from_secs(15),
            negative_cache_ttl: Duration::from_secs(300),
            graph_cache_ttl: Duration::from_secs(300),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            verify_mode: VerifyMode::GithubCi,
            mock_public_key_path: None,
            state_db_pool: StowConfig::default_state_db_pool(),
        }
    }
}
