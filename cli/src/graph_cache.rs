use sqlx::FromRow;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphAnalysisEntry, DependencyGraphArtifact,
    DependencyGraphEntry, DependencyGraphRequest, DependencyGraphResponse,
    RecommendedDependencyVersion,
};
use stow_types::error::Context;

use crate::config::StowConfig;
use crate::state_db::{connect, duration_millis, now_millis};

pub async fn load(
    config: &StowConfig,
    request: &DependencyGraphRequest,
) -> stow_types::error::Result<Option<DependencyGraphResponse>> {
    let pool = connect(&config.cache_dir).await?;
    let key = cache_key(request)?;
    let now_ms = now_millis() as i64;
    let ttl_ms = duration_millis(config.graph_cache_ttl) as i64;
    sqlx::query(
        "DELETE FROM graph_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(&pool)
    .await?;

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

    let analysis_rows = sqlx::query_as::<_, GraphCacheAnalysisEntryRow>(
        "SELECT ordinal, crate_name, version, current_artifact_count, recommended_version, recommended_artifact_count \
         FROM graph_cache_analysis_entries \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;
    let feature_rows = sqlx::query_as::<_, GraphCacheFeatureRow>(
        "SELECT entry_ordinal, feature_name \
         FROM graph_cache_analysis_features \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;
    let artifact_rows = sqlx::query_as::<_, GraphCacheArtifactRow>(
        "SELECT entry_ordinal, c_metadata \
         FROM graph_cache_current_artifacts \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;
    let prefetch_rows = sqlx::query_as::<_, GraphCachePrefetchRow>(
        "SELECT crate_name, c_metadata \
         FROM graph_cache_prefetch_artifacts \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;
    let expanded_rows = sqlx::query_as::<_, GraphCacheExpandedEntryRow>(
        "SELECT ordinal, crate_name, version \
         FROM graph_cache_expanded_entries \
         WHERE cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;
    let expanded_feature_rows = sqlx::query_as::<_, GraphCacheExpandedFeatureRow>(
        "SELECT entry_ordinal, feature_name \
         FROM graph_cache_expanded_features \
         WHERE cache_key = ? \
         ORDER BY entry_ordinal, ordinal",
    )
    .bind(&entry.cache_key)
    .fetch_all(&pool)
    .await?;

    let mut entries = Vec::with_capacity(analysis_rows.len());
    for analysis_row in analysis_rows {
        let features = feature_rows
            .iter()
            .filter(|row| row.entry_ordinal == analysis_row.ordinal)
            .map(|row| row.feature_name.clone())
            .collect::<Vec<_>>();
        let current_artifacts = artifact_rows
            .iter()
            .filter(|row| row.entry_ordinal == analysis_row.ordinal)
            .map(|row| DependencyGraphArtifact {
                c_metadata: row.c_metadata.clone(),
            })
            .collect::<Vec<_>>();
        let recommended = match (
            analysis_row.recommended_version.as_ref(),
            analysis_row.recommended_artifact_count,
        ) {
            (Some(version), Some(artifact_count)) => Some(RecommendedDependencyVersion {
                version: semver::Version::parse(version).wrap_err_with(|| {
                    format!("parse cached recommended semver version `{version}`")
                })?,
                artifact_count: artifact_count as u32,
            }),
            (None, None) => None,
            _ => {
                return Err(stow_types::stow_error!(
                    "cached graph analysis entry has inconsistent recommended version fields"
                ));
            }
        };
        entries.push(DependencyGraphAnalysisEntry {
            dependency: DependencyGraphEntry {
                crate_name: analysis_row.crate_name,
                version: semver::Version::parse(&analysis_row.version).wrap_err_with(|| {
                    format!("parse cached semver version `{}`", analysis_row.version)
                })?,
                features,
            },
            current_artifact_count: analysis_row.current_artifact_count as u32,
            current_artifacts,
            recommended,
        });
    }

    Ok(Some(DependencyGraphResponse {
        entries,
        expanded_cached: entry.expanded_cached as usize,
        expanded_total: entry.expanded_total as usize,
        expanded_entries: expanded_rows
            .into_iter()
            .map(|row| {
                Ok::<_, stow_types::error::Error>(DependencyGraphEntry {
                    crate_name: row.crate_name,
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
            .collect::<stow_types::error::Result<Vec<_>>>()?,
        prefetch_artifacts: prefetch_rows
            .into_iter()
            .map(|row| BatchArtifactRequestEntry {
                crate_name: row.crate_name,
                c_metadata: row.c_metadata,
            })
            .collect(),
    }))
}

pub async fn store(
    config: &StowConfig,
    request: &DependencyGraphRequest,
    response: &DependencyGraphResponse,
) -> stow_types::error::Result<()> {
    let pool = connect(&config.cache_dir).await?;
    let key = cache_key(request)?;
    let now_ms = now_millis() as i64;
    let ttl_ms = duration_millis(config.graph_cache_ttl) as i64;
    sqlx::query(
        "DELETE FROM graph_cache_entries \
         WHERE ? - inserted_at_ms >= ?",
    )
    .bind(now_ms)
    .bind(ttl_ms)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO graph_cache_entries (cache_key, inserted_at_ms, expanded_cached, expanded_total) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(cache_key) DO UPDATE SET \
             inserted_at_ms = excluded.inserted_at_ms, \
             expanded_cached = excluded.expanded_cached, \
             expanded_total = excluded.expanded_total",
    )
    .bind(&key)
    .bind(now_ms)
    .bind(response.expanded_cached as i64)
    .bind(response.expanded_total as i64)
    .execute(&pool)
    .await?;

    for table in [
        "graph_cache_expanded_features",
        "graph_cache_expanded_entries",
        "graph_cache_analysis_features",
        "graph_cache_current_artifacts",
        "graph_cache_analysis_entries",
        "graph_cache_prefetch_artifacts",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE cache_key = ?"))
            .bind(&key)
            .execute(&pool)
            .await?;
    }

    for (entry_ordinal, analysis_entry) in response.entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_analysis_entries \
             (cache_key, ordinal, crate_name, version, current_artifact_count, recommended_version, recommended_artifact_count) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&key)
        .bind(entry_ordinal as i64)
        .bind(&analysis_entry.dependency.crate_name)
        .bind(analysis_entry.dependency.version.to_string())
        .bind(analysis_entry.current_artifact_count as i64)
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
                .map(|value| value.artifact_count as i64),
        )
        .execute(&pool)
        .await?;

        for (feature_ordinal, feature_name) in analysis_entry.dependency.features.iter().enumerate()
        {
            sqlx::query(
                "INSERT INTO graph_cache_analysis_features \
                 (cache_key, entry_ordinal, ordinal, feature_name) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&key)
            .bind(entry_ordinal as i64)
            .bind(feature_ordinal as i64)
            .bind(feature_name)
            .execute(&pool)
            .await?;
        }

        for (artifact_ordinal, artifact) in analysis_entry.current_artifacts.iter().enumerate() {
            sqlx::query(
                "INSERT INTO graph_cache_current_artifacts \
                 (cache_key, entry_ordinal, ordinal, c_metadata) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&key)
            .bind(entry_ordinal as i64)
            .bind(artifact_ordinal as i64)
            .bind(&artifact.c_metadata)
            .execute(&pool)
            .await?;
        }
    }

    for (ordinal, artifact) in response.prefetch_artifacts.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_prefetch_artifacts \
             (cache_key, ordinal, crate_name, c_metadata) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&key)
        .bind(ordinal as i64)
        .bind(&artifact.crate_name)
        .bind(&artifact.c_metadata)
        .execute(&pool)
        .await?;
    }

    for (entry_ordinal, entry) in response.expanded_entries.iter().enumerate() {
        sqlx::query(
            "INSERT INTO graph_cache_expanded_entries \
             (cache_key, ordinal, crate_name, version) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&key)
        .bind(entry_ordinal as i64)
        .bind(&entry.crate_name)
        .bind(entry.version.to_string())
        .execute(&pool)
        .await?;

        for (feature_ordinal, feature_name) in entry.features.iter().enumerate() {
            sqlx::query(
                "INSERT INTO graph_cache_expanded_features \
                 (cache_key, entry_ordinal, ordinal, feature_name) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&key)
            .bind(entry_ordinal as i64)
            .bind(feature_ordinal as i64)
            .bind(feature_name)
            .execute(&pool)
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
    use tempfile::TempDir;

    use super::{load, store};
    use crate::config::{StowConfig, VerifyMode};

    #[tokio::test]
    async fn graph_cache_round_trips_expanded_entries() {
        let cache_dir = TempDir::new().unwrap();
        let config = test_config(cache_dir.path().to_path_buf());
        let request = DependencyGraphRequest {
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            entries: vec![DependencyGraphEntry {
                crate_name: "humansize".to_owned(),
                version: Version::parse("2.1.3").unwrap(),
                features: vec!["std".to_owned()],
            }],
            expanded_entries: vec![
                ResolvedDependencyGraphEntry {
                    crate_name: "humansize".to_owned(),
                    version: Version::parse("2.1.3").unwrap(),
                    features: vec!["std".to_owned()],
                    dependencies: vec![ResolvedDependencyGraphDependency {
                        crate_name: "libm".to_owned(),
                        version: Version::parse("0.2.8").unwrap(),
                    }],
                },
                ResolvedDependencyGraphEntry {
                    crate_name: "libm".to_owned(),
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
                    c_metadata: "humansize-meta".to_owned(),
                }],
                recommended: None,
            }],
            expanded_cached: 1,
            expanded_total: 2,
            expanded_entries: vec![
                DependencyGraphEntry {
                    crate_name: "humansize".to_owned(),
                    version: Version::parse("2.1.3").unwrap(),
                    features: vec!["std".to_owned()],
                },
                DependencyGraphEntry {
                    crate_name: "libm".to_owned(),
                    version: Version::parse("0.2.8").unwrap(),
                    features: vec!["arch".to_owned()],
                },
            ],
            prefetch_artifacts: vec![BatchArtifactRequestEntry {
                crate_name: "libm".to_owned(),
                c_metadata: "libm-meta".to_owned(),
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
        }
    }
}
