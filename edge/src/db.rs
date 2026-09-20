use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use skyzen_services::Db;
use stow_types::api::{
    ArtifactRecord, DependencyGraphAnalysisEntry, DependencyGraphArtifact, DependencyGraphEntry,
    DependencyGraphResponse, EnqueueRequest, RecommendedDependencyVersion,
    ResolvedDependencyGraphEntry, SemanticArtifactRequest,
};
use stow_types::identity::validate_emit_sorted;
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use stow_types::versioning::is_semver_compatible_upgrade;

use crate::dependency_resolver;
use crate::errors::DbError;
use crate::sql_batch;

/// Result of looking up an artifact by composite key.
#[derive(Debug, Clone, skyzen::FromRow, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub created_at: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, skyzen::FromRow)]
struct SemanticArtifactRow {
    compile_key: String,
    version: String,
    c_metadata: String,
    oci_reference: String,
    oci_digest: String,
    created_at: String,
    artifact_size: Option<u64>,
    emit_json: String,
}

#[derive(Debug)]
struct SemanticArtifactCandidate {
    version: Version,
    row: SemanticArtifactRow,
}

#[derive(Debug, Clone, skyzen::FromRow)]
pub struct ExactArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, skyzen::FromRow)]
struct CachedArtifactRow {
    compile_key: String,
    crate_name: String,
    version: String,
    features_json: String,
    c_metadata: String,
}

#[derive(Debug, skyzen::FromRow)]
struct QueuedDependencyGraphMissRow {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    seen_count: u64,
}

pub struct DependencyGraphAnalysisOutcome {
    pub response: DependencyGraphResponse,
    pub enqueue_requests: Vec<EnqueueRequest>,
}

// URL-path inputs (from `Params::get(...)`) come in as `&str` and have not
// yet been routed through `serde::Deserialize`, so the structured wire
// newtypes can't validate them automatically. The shells below delegate to
// the canonical parsers in `stow_types::identity` so the rules live in one
// place even when the call site only has `&str`.

fn validate_c_metadata(value: &str) -> Result<(), DbError> {
    stow_types::identity::CMetadata::parse(value)
        .map(|_| ())
        .map_err(|error| DbError::from(error.to_string()))
}

fn validate_target(value: &str) -> Result<(), DbError> {
    stow_types::identity::TargetTriple::parse(value)
        .map(|_| ())
        .map_err(|error| DbError::from(error.to_string()))
}

fn validate_rustc_version(value: &str) -> Result<(), DbError> {
    stow_types::identity::WireRustcVersion::parse(value)
        .map(|_| ())
        .map_err(|error| DbError::from(error.to_string()))
}

fn validate_crate_name(value: &str) -> Result<(), DbError> {
    stow_types::identity::CrateName::parse(value)
        .map(|_| ())
        .map_err(|error| DbError::from(error.to_string()))
}

fn validate_crate_types(
    crate_types: &[stow_types::artifact::RustCrateType],
) -> Result<(), DbError> {
    let mut previous: Option<&str> = None;
    for crate_type in crate_types {
        let value = crate_type.as_str();
        if previous.is_some_and(|last| last >= value) {
            return Err(DbError::Invariant(
                "crate_types must be strictly sorted and deduplicated".to_owned(),
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn parse_semver(raw: &str) -> Result<Version, DbError> {
    Version::parse(raw).map_err(|error| DbError::Semver {
        raw: raw.to_owned(),
        source: error,
    })
}

/// Insert (or update) one trusted artifact record into D1.
///
/// Called by the authenticated `/api/v1/admin/artifacts/register` endpoint
/// after CI has already produced and signed the OCI bundle. The composite
/// uniqueness key is `(c_metadata, target, rustc_version)`; an upsert
/// keeps the registration path idempotent so CI retries do not duplicate
/// rows, and `created_at` is excluded from the update list so a
/// re-register preserves the first-registration timestamp.
pub async fn insert_artifact_record(db: &Db, record: &ArtifactRecord) -> Result<(), DbError> {
    validate_crate_name(record.crate_name.as_str())?;
    validate_c_metadata(record.c_metadata.as_str())?;
    validate_target(record.target.as_str())?;
    validate_rustc_version(record.rustc_version.as_str())?;
    validate_emit_sorted(&record.emit).map_err(|error| DbError::Invariant(error.to_string()))?;
    validate_crate_types(&record.crate_types)?;
    if stow_types::registry::oci_reference_name(&record.oci_reference).is_none() {
        return Err(DbError::Invariant(format!(
            "oci_reference `{}` is not a canonical ghcr.io/water-rs/stow-cache:{{crate}}.{{rest}} reference",
            record.oci_reference
        )));
    }

    let crate_types_json = serde_json::to_string(&record.crate_types)
        .map_err(|error| DbError::Invariant(format!("encode crate_types_json: {error}")))?;
    let profile_json = serde_json::to_string(&record.profile)
        .map_err(|error| DbError::Invariant(format!("encode profile_json: {error}")))?;
    let emit_json = serde_json::to_string(&record.emit)
        .map_err(|error| DbError::Invariant(format!("encode emit_json: {error}")))?;
    let artifact_size = i64::try_from(record.artifact_size).map_err(|_| {
        DbError::Invariant(format!(
            "artifact_size {} exceeds i64 range for D1",
            record.artifact_size
        ))
    })?;

    let dependency_count = i64::try_from(record.dependency_c_metadata_json.entries().len())
        .map_err(|_| DbError::Invariant("dependency count exceeds i64 range".to_owned()))?;

    db.query(include_str!("sql/insert_artifact.sql"))
        .bind(record.compile_key.as_str())
        .bind(record.c_metadata.as_str())
        .bind(record.extra_filename.as_str())
        .bind(record.target.as_str())
        .bind(record.rustc_version.as_str())
        .bind(record.crate_name.as_str())
        .bind(record.version.to_string())
        .bind(record.features_json.raw())
        .bind(record.dependency_c_metadata_json.raw())
        .bind(dependency_count)
        .bind(record.oci_reference.as_str())
        .bind(record.oci_digest.as_str())
        .bind(i32::from(record.has_native))
        .bind(record.artifact_kind.as_str())
        .bind(crate_types_json.as_str())
        .bind(profile_json.as_str())
        .bind(emit_json.as_str())
        .bind(artifact_size)
        .execute()
        .await
        .map_err(|error| DbError::Query(format!("insert artifact record: {error}")))?;

    Ok(())
}

pub async fn get_artifact_reference(
    db: &Db,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<Option<ArtifactRow>, DbError> {
    validate_c_metadata(c_metadata)?;
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;

    db.query(
        "SELECT c_metadata, oci_reference, oci_digest, created_at, artifact_size \
         FROM artifacts \
         WHERE c_metadata = ? AND target = ? AND rustc_version = ?",
    )
    .bind(c_metadata)
    .bind(target)
    .bind(rustc_version)
    .fetch_optional::<ArtifactRow>()
    .await
    .map_err(|error| DbError::Query(format!("db query: {error}")))
}

pub async fn get_artifact_references(
    db: &Db,
    c_metadatas: &[String],
    target: &str,
    rustc_version: &str,
) -> Result<Vec<ExactArtifactRow>, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    if c_metadatas.is_empty() {
        return Ok(Vec::new());
    }
    for c_metadata in c_metadatas {
        validate_c_metadata(c_metadata)?;
    }

    let mut rows = Vec::with_capacity(c_metadatas.len());
    for batch in c_metadatas.chunks(sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT c_metadata, oci_reference, oci_digest, artifact_size \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND c_metadata IN ({})",
            sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql).bind(target).bind(rustc_version);
        for c_metadata in batch {
            query = query.bind(c_metadata.as_str());
        }
        let mut batch_rows = query
            .fetch_all::<ExactArtifactRow>()
            .await
            .map_err(|error| DbError::Query(format!("db query: {error}")))?;
        rows.append(&mut batch_rows);
    }
    rows.sort_by(|left, right| left.c_metadata.cmp(&right.c_metadata));
    Ok(rows)
}

/// One cached artifact's full identity, surfaced for the stow-resolver
/// endpoint. Includes the dep-c_metadata chain so the resolver can walk
/// the transitive closure without further queries until conflict-checks.
#[derive(Debug, Clone, skyzen::FromRow)]
pub struct ResolverArtifactRow {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub c_metadata: String,
    pub dependency_c_metadata_json: String,
    pub dependency_count: i64,
}

/// Load the resolver's candidate rows for a (target, `rustc_version`) pair:
/// every row named by a direct dep, plus every row whose recorded
/// `dependency_count` could cover the whole direct set (the seed fast
/// path). Both sides of the `OR` are index-seeked, so the query reads only
/// plausible rows instead of the whole artifact table.
pub async fn list_resolver_candidates(
    db: &Db,
    target: &str,
    rustc_version: &str,
    direct_names: &[&str],
    min_seed_deps: i64,
) -> Result<Vec<ResolverArtifactRow>, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    let mut rows = Vec::new();
    for batch in direct_names.chunks(crate::sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT crate_name, version, features_json, c_metadata, dependency_c_metadata_json, dependency_count \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? \
               AND (crate_name IN ({}) OR dependency_count >= ?)",
            crate::sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql).bind(target).bind(rustc_version);
        for name in batch {
            query = query.bind(*name);
        }
        rows.extend(
            query
                .bind(min_seed_deps)
                .fetch_all::<ResolverArtifactRow>()
                .await
                .map_err(|error| {
                    DbError::Query(format!("list resolver candidates for target: {error}"))
                })?,
        );
    }
    Ok(rows)
}

/// Load artifact rows by `c_metadata` in IN-clause batches — the
/// resolver's closure-expansion step, bounded to the `c_metadata` set the
/// already-loaded rows reference.
pub async fn list_artifacts_by_c_metadata(
    db: &Db,
    target: &str,
    rustc_version: &str,
    c_metadatas: &BTreeSet<String>,
) -> Result<Vec<ResolverArtifactRow>, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    let c_metadatas = c_metadatas.iter().collect::<Vec<_>>();
    let mut rows = Vec::new();
    for batch in c_metadatas.chunks(crate::sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT crate_name, version, features_json, c_metadata, dependency_c_metadata_json, dependency_count \
             FROM artifacts \
             WHERE c_metadata IN ({}) AND target = ? AND rustc_version = ?",
            crate::sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql);
        for c_metadata in batch {
            query = query.bind(c_metadata.as_str());
        }
        rows.extend(
            query
                .bind(target)
                .bind(rustc_version)
                .fetch_all::<ResolverArtifactRow>()
                .await
                .map_err(|error| {
                    DbError::Query(format!("list artifacts by c_metadata for target: {error}"))
                })?,
        );
    }
    Ok(rows)
}

pub async fn get_semantic_artifact_reference(
    db: &Db,
    request: &SemanticArtifactRequest,
) -> Result<Option<ArtifactRow>, DbError> {
    validate_emit_sorted(&request.emit).map_err(|e| e.to_string())?;
    validate_crate_types(&request.crate_types)?;

    let profile_json = serde_json::to_string(&request.profile)
        .map_err(|error| format!("serialize semantic profile: {error}"))?;
    let crate_types_json = serde_json::to_string(&request.crate_types)
        .map_err(|error| format!("serialize semantic crate_types: {error}"))?;
    let requested_version = request.version.as_semver().clone();

    let rows = db
        .query(
            "SELECT compile_key, version, c_metadata, oci_reference, oci_digest, created_at, artifact_size, emit_json \
             FROM artifacts \
             WHERE crate_name = ? AND features_json = ? AND target = ? AND rustc_version = ? \
               AND artifact_kind = ? AND crate_types_json = ? AND profile_json = ? \
               AND dependency_c_metadata_json = ?",
        )
        .bind(request.crate_name.as_str())
        .bind(request.features_json.raw())
        .bind(request.target.as_str())
        .bind(request.rustc_version.as_str())
        .bind(request.kind.as_str())
        .bind(crate_types_json)
        .bind(profile_json)
        .bind(request.dependency_c_metadata_json.raw())
        .fetch_all::<SemanticArtifactRow>()
        .await
        .map_err(|error| format!("semantic artifact db query: {error}"))?;

    let mut candidates = rows
        .into_iter()
        .filter_map(|row| {
            match semantic_candidate_from_row(row, &requested_version, &request.emit) {
                Ok(Some(candidate)) => Some(Ok(candidate)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_by(|left, right| {
        right
            .version
            .cmp(&left.version)
            .then(
                semantic_row_prefers_canonical_metadata(&right.row)
                    .cmp(&semantic_row_prefers_canonical_metadata(&left.row)),
            )
            .then(
                emit_entry_count(&left.row.emit_json).cmp(&emit_entry_count(&right.row.emit_json)),
            )
            .then(right.row.created_at.cmp(&left.row.created_at))
            .then(right.row.oci_digest.cmp(&left.row.oci_digest))
    });

    Ok(candidates.into_iter().next().map(|candidate| ArtifactRow {
        c_metadata: candidate.row.c_metadata,
        oci_reference: candidate.row.oci_reference,
        oci_digest: candidate.row.oci_digest,
        created_at: candidate.row.created_at,
        artifact_size: candidate.row.artifact_size,
    }))
}

fn semantic_row_prefers_canonical_metadata(row: &SemanticArtifactRow) -> bool {
    stable_c_metadata_for_compile_key(&row.compile_key).is_ok_and(|stable| stable == row.c_metadata)
}

pub async fn delete_artifact_reference(
    db: &Db,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<(), DbError> {
    validate_c_metadata(c_metadata)?;
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;

    db.query("DELETE FROM artifacts WHERE c_metadata = ? AND target = ? AND rustc_version = ?")
        .bind(c_metadata)
        .bind(target)
        .bind(rustc_version)
        .execute()
        .await
        .map_err(|error| {
            format!("delete stale artifact {c_metadata} {target} {rustc_version}: {error}")
        })?;

    Ok(())
}

fn semantic_candidate_from_row(
    row: SemanticArtifactRow,
    requested_version: &Version,
    requested_emit: &[String],
) -> Result<Option<SemanticArtifactCandidate>, DbError> {
    let candidate_version = parse_semver(&row.version)?;
    if candidate_version != *requested_version
        && !is_semver_compatible_upgrade(requested_version, &candidate_version)
    {
        return Ok(None);
    }
    match emit_covers_request(&row.emit_json, requested_emit) {
        Ok(true) => Ok(Some(SemanticArtifactCandidate {
            version: candidate_version,
            row,
        })),
        Ok(false) => Ok(None),
        Err(error) => Err(error),
    }
}

pub async fn analyze_dependency_graph(
    db: &Db,
    crates_io: &impl dependency_resolver::CratesIo,
    target: &str,
    rustc_version: &str,
    entries: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
    fetch_concurrency: usize,
) -> Result<DependencyGraphAnalysisOutcome, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    if entries.is_empty() {
        return Ok(DependencyGraphAnalysisOutcome {
            response: DependencyGraphResponse {
                entries: Vec::new(),
                expanded_cached: 0,
                expanded_total: 0,
                expanded_entries: Vec::new(),
                prefetch_artifacts: Vec::new(),
                miss_admissions: Vec::new(),
            },
            enqueue_requests: Vec::new(),
        });
    }

    // `entry.crate_name` is `CrateName` — already shape-validated at deserialize time.
    let feature_requests = entries
        .iter()
        .map(|entry| dependency_resolver::RootFeatureRequest {
            crate_name: entry.crate_name.clone(),
            version: entry.version.clone(),
            seed_features: entry.features.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();
    let resolved_features = dependency_resolver::resolve_root_features_batch(
        db,
        crates_io,
        &feature_requests,
        fetch_concurrency,
    )
    .await?;
    let mut crate_names = BTreeSet::<String>::new();
    let mut exact_entries = Vec::<ExactDependencyEntry>::with_capacity(entries.len());
    for (entry, resolved_features) in entries.iter().zip(resolved_features) {
        let encoded_features = dependency_resolver::serialize_feature_set(&resolved_features)?;
        crate_names.insert(entry.crate_name.as_str().to_owned());
        exact_entries.push(ExactDependencyEntry {
            dependency: entry.clone(),
            features_json: encoded_features,
        });
    }

    let cached_rows =
        query_cached_artifact_rows(db, target, rustc_version, crate_names.into_iter().collect())
            .await?;
    let semantic_catalog = build_semantic_catalog(&cached_rows)?;
    let exact_artifacts = build_exact_artifact_catalog(&cached_rows)?;
    let response_entries = exact_entries
        .iter()
        .map(|entry| {
            let semantic_key = semantic_key(
                entry.dependency.crate_name.as_str(),
                &entry.dependency.version,
                &entry.features_json,
            );
            let current_artifact_count = semantic_catalog
                .artifact_counts
                .get(&semantic_key)
                .copied()
                .unwrap_or(0);
            let current_artifacts = exact_artifacts
                .get(&semantic_key)
                .cloned()
                .unwrap_or_default();
            let recommended = best_upgrade_for(entry, &semantic_catalog);
            Ok(DependencyGraphAnalysisEntry {
                dependency: entry.dependency.clone(),
                current_artifact_count,
                current_artifacts,
                recommended,
            })
        })
        .collect::<Result<Vec<_>, DbError>>()?;

    let expanded_plan = dependency_resolver::expand_scheduler_requests(
        db,
        target,
        rustc_version,
        entries,
        expanded_entries,
    )
    .await?;

    Ok(DependencyGraphAnalysisOutcome {
        response: DependencyGraphResponse {
            entries: response_entries,
            expanded_cached: expanded_plan.expanded_cached,
            expanded_total: expanded_plan.expanded_total,
            expanded_entries: expanded_plan.expanded_entries,
            prefetch_artifacts: expanded_plan.prefetch_artifacts,
            miss_admissions: Vec::new(),
        },
        enqueue_requests: expanded_plan.enqueue_requests,
    })
}

async fn query_cached_artifact_rows(
    db: &Db,
    target: &str,
    rustc_version: &str,
    crate_names: Vec<String>,
) -> Result<Vec<CachedArtifactRow>, DbError> {
    let mut rows = Vec::<CachedArtifactRow>::new();
    for batch in crate_names.chunks(sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT compile_key, crate_name, version, features_json, c_metadata \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND crate_name IN ({}) \
             ORDER BY crate_name, version, features_json, compile_key, c_metadata",
            sql_batch::placeholders(batch.len())
        );

        let mut query = db.query(&sql).bind(target).bind(rustc_version);
        for crate_name in batch {
            query = query.bind(crate_name.as_str());
        }

        let mut batch_rows = query
            .fetch_all::<CachedArtifactRow>()
            .await
            .map_err(|error| format!("db query: {error}"))?;
        rows.append(&mut batch_rows);
    }

    rows.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.version.cmp(&right.version))
            .then(left.features_json.cmp(&right.features_json))
            .then(left.compile_key.cmp(&right.compile_key))
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    Ok(rows)
}

fn cached_artifact_row_has_canonical_metadata(row: &CachedArtifactRow) -> Result<bool, DbError> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&row.compile_key).map_err(|error| {
            format!(
                "compute stable c_metadata for {} {} {}: {error}",
                row.crate_name, row.version, row.compile_key
            )
        })?;
    Ok(stable_c_metadata == row.c_metadata)
}

fn build_semantic_catalog(rows: &[CachedArtifactRow]) -> Result<SemanticCatalog, DbError> {
    let mut artifact_counts = BTreeMap::<(String, Version, String), u32>::new();
    let mut feature_versions = BTreeMap::<(String, String), Vec<CachedVersion>>::new();

    for row in rows {
        if !cached_artifact_row_has_canonical_metadata(row)? {
            continue;
        }
        let version = parse_semver(&row.version)?;
        let artifact_key = semantic_key(&row.crate_name, &version, &row.features_json);
        let artifact_count = artifact_counts.entry(artifact_key).or_insert(0);
        *artifact_count = artifact_count.saturating_add(1);
    }

    for ((crate_name, cached_version, features_json), artifact_count) in &artifact_counts {
        feature_versions
            .entry((crate_name.clone(), features_json.clone()))
            .or_default()
            .push(CachedVersion {
                version: cached_version.clone(),
                artifact_count: *artifact_count,
            });
    }

    for cached_versions in feature_versions.values_mut() {
        cached_versions.sort_by(|left, right| {
            right
                .artifact_count
                .cmp(&left.artifact_count)
                .then(right.version.cmp(&left.version))
        });
    }

    Ok(SemanticCatalog {
        artifact_counts,
        feature_versions,
    })
}

/// Semantic identity `(crate_name, version, features_json)` used as a catalog key.
type SemanticKey = (String, Version, String);
/// Exact artifacts grouped by semantic identity.
type ExactArtifactCatalog = BTreeMap<SemanticKey, Vec<DependencyGraphArtifact>>;

fn build_exact_artifact_catalog(
    rows: &[CachedArtifactRow],
) -> Result<ExactArtifactCatalog, DbError> {
    let mut artifacts = ExactArtifactCatalog::new();

    for row in rows {
        if !cached_artifact_row_has_canonical_metadata(row)? {
            continue;
        }
        let c_metadata = stow_types::identity::CMetadata::parse(row.c_metadata.as_str())
            .map_err(|error| format!("cached row c_metadata `{}`: {error}", row.c_metadata))?;
        let version = parse_semver(&row.version)?;
        let key = semantic_key(&row.crate_name, &version, &row.features_json);
        let entry = artifacts.entry(key).or_default();
        if entry
            .last()
            .is_some_and(|last| last.c_metadata == c_metadata)
        {
            continue;
        }
        entry.push(DependencyGraphArtifact { c_metadata });
    }

    Ok(artifacts)
}

fn best_upgrade_for(
    entry: &ExactDependencyEntry,
    catalog: &SemanticCatalog,
) -> Option<RecommendedDependencyVersion> {
    let current_key = semantic_key(
        entry.dependency.crate_name.as_str(),
        &entry.dependency.version,
        &entry.features_json,
    );
    let current_artifact_count = catalog
        .artifact_counts
        .get(&current_key)
        .copied()
        .unwrap_or(0);
    let candidates = catalog.feature_versions.get(&(
        entry.dependency.crate_name.as_str().to_owned(),
        entry.features_json.clone(),
    ));
    let candidates = candidates?;

    for candidate in candidates {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &candidate.version) {
            continue;
        }
        if candidate.artifact_count <= current_artifact_count {
            continue;
        }
        return Some(RecommendedDependencyVersion {
            version: candidate.version.clone(),
            artifact_count: candidate.artifact_count,
        });
    }

    None
}

pub async fn take_dependency_graph_misses(
    db: &Db,
    limit: usize,
) -> Result<Vec<EnqueueRequest>, DbError> {
    let limit =
        i64::try_from(limit).map_err(|_| format!("miss drain limit exceeds i64: {limit}"))?;
    // Opportunistic cleanup: rows already handed to the scheduler stop
    // mattering once the queue has owned them for a while. Rows with no
    // `admitted_at` are leftovers from when analysis persisted every miss —
    // they age out, and no new ones are written.
    db.query(
        "DELETE FROM dependency_graph_misses \
         WHERE (queued_at IS NOT NULL AND queued_at <= datetime('now', '-7 days')) \
            OR (admitted_at IS NULL AND last_seen_at <= datetime('now', '-30 days'))",
    )
    .execute()
    .await
    .map_err(|error| format!("prune drained dependency graph misses: {error}"))?;
    // Only misses whose admission ticket passed the challenge + PoW gate are
    // drainable: this drain is the internal retry path for a verified
    // enqueue that failed to reach the scheduler, never a second minting
    // channel for unadmitted misses.
    let rows = db
        .query(
            "SELECT crate_name, version, features_json, target, rustc_version, seen_count \
             FROM dependency_graph_misses \
             WHERE admitted_at IS NOT NULL AND queued_at IS NULL \
             ORDER BY seen_count DESC, last_seen_at DESC, first_seen_at ASC \
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all::<QueuedDependencyGraphMissRow>()
        .await
        .map_err(|error| format!("select dependency graph misses for draining: {error}"))?;

    let mut requests = Vec::with_capacity(rows.len());
    for row in rows {
        db.query(
            "UPDATE dependency_graph_misses \
             SET queued_at = datetime('now') \
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? \
               AND queued_at IS NULL",
        )
        .bind(row.crate_name.as_str())
        .bind(row.version.as_str())
        .bind(row.features_json.as_str())
        .bind(row.target.as_str())
        .bind(row.rustc_version.as_str())
        .execute()
        .await
        .map_err(|error| format!("mark dependency graph miss queued: {error}"))?;

        let crate_name = stow_types::identity::CrateName::parse(row.crate_name.as_str())
            .map_err(|error| format!("draining miss crate_name `{}`: {error}", row.crate_name))?;
        let version = stow_types::identity::CrateVersion::new(
            Version::parse(row.version.as_str())
                .map_err(|error| format!("draining miss version `{}`: {error}", row.version))?,
        );
        let features_json: Vec<String> = serde_json::from_str(row.features_json.as_str())
            .map_err(|error| format!("draining miss features_json: {error}"))?;
        let features_json = stow_types::identity::FeaturesJson::from_sorted(features_json)
            .map_err(|error| format!("draining miss features_json: {error}"))?;
        let target = stow_types::identity::TargetTriple::parse(row.target.as_str())
            .map_err(|error| format!("draining miss target `{}`: {error}", row.target))?;
        let rustc_version = stow_types::identity::WireRustcVersion::parse(
            row.rustc_version.as_str(),
        )
        .map_err(|error| {
            format!(
                "draining miss rustc_version `{}`: {error}",
                row.rustc_version
            )
        })?;
        requests.push(EnqueueRequest {
            crate_name,
            version,
            features_json,
            target,
            rustc_version,
            downloads: row.seen_count,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
            project_source: None,
        });
    }
    Ok(requests)
}

/// Flip the `queued_at` marker for the misses matching `requests`.
///
/// `queued` = true marks them as handed to the scheduler; false restores
/// them for a later drain (used when the scheduler send fails after a
/// drain already claimed them).
pub async fn set_dependency_graph_misses_queued(
    db: &Db,
    requests: &[EnqueueRequest],
    queued: bool,
) -> Result<(), DbError> {
    let sql = if queued {
        "UPDATE dependency_graph_misses \
         SET queued_at = datetime('now') \
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?"
    } else {
        "UPDATE dependency_graph_misses \
         SET queued_at = NULL \
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?"
    };
    for request in requests {
        db.query(sql)
            .bind(request.crate_name.as_str())
            .bind(request.version.to_string())
            .bind(request.features_json.raw())
            .bind(request.target.as_str())
            .bind(request.rustc_version.as_str())
            .execute()
            .await
            .map_err(|error| format!("update dependency graph miss queued marker: {error}"))?;
    }
    Ok(())
}

/// Insert-or-update the miss row for a verified admission. `/api/v1/enqueue`
/// calls this only after the challenge + `PoW` checks pass, so a row exists
/// exactly when a miss was admitted — born with `admitted_at` set — and the
/// internal drain may hand it to the scheduler when the direct send fails.
/// Repeat admissions re-mark the same row (`seen_count`/`last_seen_at`
/// track demand) without touching `queued_at`: a miss already handed to the
/// scheduler stays marked as sent.
pub async fn record_admitted_miss(db: &Db, request: &EnqueueRequest) -> Result<(), DbError> {
    db.query(
        "INSERT INTO dependency_graph_misses \
         (crate_name, version, features_json, target, rustc_version, seen_count, first_seen_at, last_seen_at, admitted_at) \
         VALUES (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'), datetime('now')) \
         ON CONFLICT(crate_name, version, features_json, target, rustc_version) \
         DO UPDATE SET seen_count = seen_count + 1, last_seen_at = datetime('now'), admitted_at = datetime('now')",
    )
    .bind(request.crate_name.as_str())
    .bind(request.version.to_string())
    .bind(request.features_json.raw())
    .bind(request.target.as_str())
    .bind(request.rustc_version.as_str())
    .execute()
    .await
    .map_err(|error| format!("record admitted miss: {error}"))?;
    Ok(())
}

fn semantic_key(crate_name: &str, version: &Version, features_json: &str) -> SemanticKey {
    (
        crate_name.to_owned(),
        version.clone(),
        features_json.to_owned(),
    )
}

fn emit_covers_request(
    candidate_emit_json: &str,
    requested_emit: &[String],
) -> Result<bool, DbError> {
    let candidate_emit = serde_json::from_str::<Vec<String>>(candidate_emit_json)
        .map_err(|error| format!("parse stored artifact emit_json: {error}"))?;
    validate_emit_sorted(&candidate_emit).map_err(|e| e.to_string())?;
    let candidate_set = candidate_emit.into_iter().collect::<BTreeSet<_>>();
    Ok(requested_emit
        .iter()
        .all(|requested| candidate_set.contains(requested)))
}

fn emit_entry_count(candidate_emit_json: &str) -> usize {
    match serde_json::from_str::<Vec<String>>(candidate_emit_json) {
        Ok(emit) => emit.len(),
        Err(error) => {
            tracing::warn!(
                emit_json = candidate_emit_json,
                %error,
                "malformed emit_json in artifact row — deprioritizing"
            );
            usize::MAX
        }
    }
}

#[derive(Debug, Clone)]
struct ExactDependencyEntry {
    dependency: DependencyGraphEntry,
    features_json: String,
}

#[derive(Debug, Clone)]
struct CachedVersion {
    version: Version,
    artifact_count: u32,
}

#[derive(Debug, Clone)]
struct SemanticCatalog {
    artifact_counts: BTreeMap<(String, Version, String), u32>,
    feature_versions: BTreeMap<(String, String), Vec<CachedVersion>>,
}

#[cfg(test)]
mod tests {
    use super::{
        CachedArtifactRow, SemanticArtifactRow, build_exact_artifact_catalog,
        build_semantic_catalog, semantic_candidate_from_row,
    };
    use semver::Version;

    fn row(version: &str, emit: &[&str]) -> SemanticArtifactRow {
        SemanticArtifactRow {
            compile_key: "abcdef0123456789abcdef0123456789".to_owned(),
            version: version.to_owned(),
            c_metadata: "candidate".to_owned(),
            oci_reference: "oci".to_owned(),
            oci_digest: "sha256:test".to_owned(),
            created_at: "2026-03-24 00:00:00".to_owned(),
            artifact_size: Some(1),
            emit_json: serde_json::to_string(&emit).unwrap(),
        }
    }

    #[test]
    fn semantic_candidate_accepts_exact_and_compatible_upgrade() {
        let requested = Version::parse("1.4.3").unwrap();
        assert!(
            semantic_candidate_from_row(
                row("1.4.3", &["dep-info", "metadata"]),
                &requested,
                &["dep-info".to_owned(), "metadata".to_owned()],
            )
            .unwrap()
            .is_some()
        );
        assert!(
            semantic_candidate_from_row(
                row("1.4.9", &["dep-info", "link", "metadata"]),
                &requested,
                &["dep-info".to_owned(), "metadata".to_owned()],
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn semantic_candidate_rejects_incompatible_version_or_emit() {
        let requested = Version::parse("1.4.3").unwrap();
        assert!(
            semantic_candidate_from_row(
                row("2.0.0", &["dep-info", "metadata"]),
                &requested,
                &["dep-info".to_owned(), "metadata".to_owned()],
            )
            .unwrap()
            .is_none()
        );
        assert!(
            semantic_candidate_from_row(
                row("1.4.9", &["dep-info"]),
                &requested,
                &["dep-info".to_owned(), "metadata".to_owned()],
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn dependency_graph_catalogs_ignore_noncanonical_duplicate_rows() {
        let compile_key = "1234567890abcdef1234567890abcdef".to_owned();
        let rows = vec![
            CachedArtifactRow {
                compile_key: compile_key.clone(),
                crate_name: "proc-macro2".to_owned(),
                version: "1.0.106".to_owned(),
                features_json: "[\"proc-macro\"]".to_owned(),
                c_metadata: "ffffffffffffffff".to_owned(),
            },
            CachedArtifactRow {
                compile_key,
                crate_name: "proc-macro2".to_owned(),
                version: "1.0.106".to_owned(),
                features_json: "[\"proc-macro\"]".to_owned(),
                c_metadata: "1234567890abcdef".to_owned(),
            },
        ];

        let semantic_catalog = build_semantic_catalog(&rows).unwrap();
        let semantic_key = (
            "proc-macro2".to_owned(),
            Version::parse("1.0.106").unwrap(),
            "[\"proc-macro\"]".to_owned(),
        );
        assert_eq!(
            semantic_catalog.artifact_counts.get(&semantic_key),
            Some(&1)
        );

        let exact_catalog = build_exact_artifact_catalog(&rows).unwrap();
        let artifacts = exact_catalog.get(&semantic_key).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].c_metadata, "1234567890abcdef");
    }
}

/// Apply the migration files to a test database — the same SQL the deploy
/// pipeline hands to `wrangler d1 execute --file`. `Db::query` prepares one
/// statement at a time, so the file is split on `;`.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub async fn apply_migrations(db: &Db) {
    const FILES: &[&str] = &[
        include_str!("../migrations/0001_schema.sql"),
        include_str!("../migrations/0002_drop_subscriptions.sql"),
    ];
    for file in FILES {
        let sql = file
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        for statement in sql.split(';') {
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            db.query(statement)
                .execute()
                .await
                .expect("apply migration statement");
        }
    }
}

/// Miss-drain tests against a real in-memory `SQLite`: the admitted-only
/// drain gate is the load-bearing wall of the `/api/v1/enqueue` retry path,
/// so it runs the same statements production runs.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use stow_types::api::{ArtifactRecord, EnqueueRequest};
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};

    use super::{
        apply_migrations, get_artifact_reference, insert_artifact_record, record_admitted_miss,
        set_dependency_graph_misses_queued, take_dependency_graph_misses,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";
    const C_METADATA: &str = "eeeeeeeeeeeeeeee";
    const FIRST_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECOND_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn artifact_record(oci_digest: &str) -> ArtifactRecord {
        ArtifactRecord {
            compile_key: format!("{C_METADATA}{C_METADATA}"),
            c_metadata: CMetadata::parse(C_METADATA).expect("c_metadata"),
            extra_filename: format!("-{C_METADATA}"),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse("serde").expect("name"),
            version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            oci_reference: format!(
                "ghcr.io/water-rs/stow-cache:serde.1.0.0-x86_64-linux-{RUSTC}-abcdef012345-{C_METADATA}"
            ),
            oci_digest: oci_digest.to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 1,
        }
    }

    fn enqueue_request(crate_name: &str, version: &str, features: &[&str]) -> EnqueueRequest {
        EnqueueRequest {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: version.parse().expect("valid semver"),
            features_json: stow_types::identity::FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("valid features"),
            target: TARGET.parse().expect("valid target"),
            rustc_version: RUSTC.parse().expect("valid rustc version"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
            project_source: None,
        }
    }

    async fn miss_count_where(db: &skyzen_services::Db, predicate: &str) -> u64 {
        db.query(&format!(
            "SELECT COUNT(*) FROM dependency_graph_misses WHERE {predicate}"
        ))
        .fetch_scalar::<u64>()
        .await
        .expect("miss count")
    }

    /// The `/api/v1/enqueue` order — verify the ticket, upsert the miss
    /// row, forward to the scheduler, mark it queued — replayed at the D1
    /// layer: admission is what creates the row, and only then can the
    /// failed-send drain pick it up.
    #[tokio::test]
    async fn admission_creates_the_row_the_drain_retries() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let request = enqueue_request("serde", "1.0.5", &["derive"]);

        // No admission has been recorded — nothing is drainable, and no
        // rows exist at all.
        assert_eq!(
            take_dependency_graph_misses(&db, 10)
                .await
                .expect("take misses"),
            Vec::<EnqueueRequest>::new()
        );

        record_admitted_miss(&db, &request)
            .await
            .expect("record admitted miss");
        assert_eq!(
            miss_count_where(&db, "admitted_at IS NOT NULL AND queued_at IS NULL").await,
            1,
            "a verified admission creates the row already admitted"
        );

        let drained = take_dependency_graph_misses(&db, 10)
            .await
            .expect("take misses");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].crate_name.as_str(), "serde");
        // Draining marks the row queued, so a later drain cannot resend it.
        assert_eq!(
            take_dependency_graph_misses(&db, 10)
                .await
                .expect("take misses"),
            Vec::<EnqueueRequest>::new()
        );

        // The send-failure path restores the marker and the next drain
        // picks the miss up again.
        set_dependency_graph_misses_queued(&db, &drained, false)
            .await
            .expect("restore queued marker");
        let redrained = take_dependency_graph_misses(&db, 10)
            .await
            .expect("take misses");
        assert_eq!(redrained.len(), 1);
    }

    /// A second verified admission for the same miss identity updates the
    /// one row instead of inserting a duplicate — demand stays counted in
    /// `seen_count` — and an already-queued row keeps its `queued_at`.
    #[tokio::test]
    async fn re_admission_upserts_the_same_row() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let request = enqueue_request("serde", "1.0.5", &["derive"]);

        record_admitted_miss(&db, &request)
            .await
            .expect("record admitted miss");
        record_admitted_miss(&db, &request)
            .await
            .expect("re-record admitted miss");

        assert_eq!(miss_count_where(&db, "1 = 1").await, 1);
        assert_eq!(miss_count_where(&db, "seen_count = 2").await, 1);

        // A re-admission for a miss the drain already sent must not clear
        // its `queued_at` marker — the scheduler still owns it.
        let drained = take_dependency_graph_misses(&db, 10)
            .await
            .expect("take misses");
        assert_eq!(drained.len(), 1);
        record_admitted_miss(&db, &request)
            .await
            .expect("re-record after queueing");
        assert_eq!(
            miss_count_where(&db, "queued_at IS NOT NULL AND seen_count = 3").await,
            1
        );
        assert_eq!(
            take_dependency_graph_misses(&db, 10)
                .await
                .expect("take misses"),
            Vec::<EnqueueRequest>::new()
        );
    }

    /// A re-register must update the mutable columns while preserving
    /// `created_at` — resetting it on every idempotent retry was the
    /// `INSERT OR REPLACE` behavior that orphaned CF-cached bundles keyed
    /// on it (#170).
    #[tokio::test]
    async fn reregister_updates_row_but_preserves_created_at() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;

        insert_artifact_record(&db, &artifact_record(FIRST_DIGEST))
            .await
            .expect("insert");

        // Pin `created_at` to a sentinel so the assertion does not depend
        // on `datetime('now')` granularity.
        db.query("UPDATE artifacts SET created_at = '2001-02-03 04:05:06'")
            .execute()
            .await
            .expect("pin created_at");

        insert_artifact_record(&db, &artifact_record(SECOND_DIGEST))
            .await
            .expect("re-register");

        let rows = db
            .query("SELECT COUNT(*) FROM artifacts")
            .fetch_scalar::<u64>()
            .await
            .expect("row count");
        assert_eq!(rows, 1);

        let row = get_artifact_reference(&db, C_METADATA, TARGET, RUSTC)
            .await
            .expect("lookup")
            .expect("row present");
        assert_eq!(row.created_at, "2001-02-03 04:05:06");
        assert_eq!(row.oci_digest, SECOND_DIGEST);
    }
}
