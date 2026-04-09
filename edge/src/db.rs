use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use skyzen_services::Db;
use stow_types::api::{
    DependencyGraphAnalysisEntry, DependencyGraphArtifact, DependencyGraphEntry,
    DependencyGraphMiss, DependencyGraphResponse, EnqueueRequest, RecommendedDependencyVersion,
    ResolvedDependencyGraphEntry, SemanticArtifactRequest,
};
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use stow_types::versioning::{breaking_line, is_semver_compatible_upgrade};
#[path = "../../shared/artifact_table_schema.rs"]
mod artifact_table_schema;
use crate::dependency_resolver;
use crate::sql_batch;

/// Result of looking up an artifact by composite key.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub created_at: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct SemanticArtifactRow {
    compile_key: String,
    version: String,
    c_metadata: String,
    oci_reference: String,
    oci_digest: String,
    created_at: String,
    artifact_size: Option<u64>,
    emit_json: String,
    dependency_c_metadata_json: String,
}

#[derive(Debug)]
struct SemanticArtifactCandidate {
    version: Version,
    row: SemanticArtifactRow,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExactArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub created_at: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct SubscribedRow {
    crate_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct CachedArtifactRow {
    compile_key: String,
    crate_name: String,
    version: String,
    features_json: String,
    c_metadata: String,
}

#[derive(Debug, serde::Deserialize)]
struct CountRow {
    count: u64,
}

#[derive(Debug, serde::Deserialize)]
struct ArtifactTableInfoRow {
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct DependencyGraphMissTableInfoRow {
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct QueuedDependencyGraphMissRow {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    seen_count: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct DependencyCMetadataIdentity {
    crate_name: String,
    c_metadata: String,
}

pub struct DependencyGraphAnalysisOutcome {
    pub response: DependencyGraphResponse,
    pub enqueue_requests: Vec<EnqueueRequest>,
}

/// Validate that a c_metadata string is a cargo-generated hex hash.
fn validate_c_metadata(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("invalid c_metadata format".to_owned());
    }
    Ok(())
}

/// Validate a target triple.
fn validate_target(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("invalid target format".to_owned());
    }
    Ok(())
}

/// Validate stable rustc version strings such as `1.83.0`.
fn validate_rustc_version(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err("invalid rustc_version format".to_owned());
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err("invalid rustc_version format".to_owned());
    }
    Ok(())
}

/// Validate a crates.io crate name.
fn validate_crate_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("invalid crate_name format".to_owned());
    }
    Ok(())
}

fn validate_features(features: &[String]) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for feature in features {
        if feature.is_empty()
            || feature.len() > 128
            || !feature
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err("invalid feature name".to_owned());
        }
        if previous.is_some_and(|last| last >= feature.as_str()) {
            return Err("features must be strictly sorted and deduplicated".to_owned());
        }
        previous = Some(feature.as_str());
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+' | '_'))
    {
        return Err("invalid version format".to_owned());
    }
    Ok(())
}

fn validate_emit(emit: &[String]) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for value in emit {
        if value.is_empty()
            || value.len() > 32
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err("invalid emit entry".to_owned());
        }
        if previous.is_some_and(|last| last >= value.as_str()) {
            return Err("emit entries must be strictly sorted and deduplicated".to_owned());
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn validate_crate_types(crate_types: &[stow_types::artifact::RustCrateType]) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for crate_type in crate_types {
        let value = crate_type.as_str();
        if previous.is_some_and(|last| last >= value) {
            return Err("crate_types must be strictly sorted and deduplicated".to_owned());
        }
        previous = Some(value);
    }
    Ok(())
}

fn features_json(features: &[String]) -> Result<String, String> {
    validate_features(features)?;
    serde_json::to_string(features).map_err(|error| format!("serialize features: {error}"))
}

fn validate_features_json(value: &str) -> Result<(), String> {
    let parsed = serde_json::from_str::<Vec<String>>(value)
        .map_err(|_| "invalid features_json format".to_owned())?;
    validate_features(&parsed)
}

fn validate_dependency_c_metadata_json(value: &str) -> Result<(), String> {
    let parsed = serde_json::from_str::<Vec<DependencyCMetadataIdentity>>(value)
        .map_err(|_| "invalid dependency_c_metadata_json format".to_owned())?;
    let mut previous: Option<(&str, &str)> = None;
    for identity in &parsed {
        validate_crate_name(&identity.crate_name)?;
        validate_c_metadata(&identity.c_metadata)?;
        let current = (identity.crate_name.as_str(), identity.c_metadata.as_str());
        if previous.is_some_and(|last| last >= current) {
            return Err(
                "dependency_c_metadata_json entries must be strictly sorted and deduplicated"
                    .to_owned(),
            );
        }
        previous = Some(current);
    }
    Ok(())
}

fn parse_semver(raw: &str) -> Result<Version, String> {
    Version::parse(raw).map_err(|error| format!("parse semver version `{raw}`: {error}"))
}

pub async fn ensure_schema(db: &Db) -> Result<(), String> {
    db.query(include_str!("schema.sql"))
        .execute()
        .await
        .map_err(|error| format!("ensure edge schema: {error}"))?;
    ensure_artifact_table_columns(db).await?;
    ensure_dependency_graph_miss_columns(db).await?;
    Ok(())
}

async fn ensure_artifact_table_columns(db: &Db) -> Result<(), String> {
    let existing_columns = db
        .query("PRAGMA table_info(artifacts)")
        .fetch_all::<ArtifactTableInfoRow>()
        .await
        .map_err(|error| format!("load artifacts table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();

    for column in artifact_table_schema::REQUIRED_ARTIFACT_COLUMNS {
        if existing_columns.contains(column.name) {
            continue;
        }
        db.query(column.add_sql).execute().await.map_err(|error| {
            format!(
                "migrate artifacts table add column {}: {error}",
                column.name
            )
        })?;
    }

    db.query(
        "CREATE INDEX IF NOT EXISTS idx_artifacts_compile_key \
         ON artifacts (compile_key)",
    )
    .execute()
    .await
    .map_err(|error| format!("ensure artifacts compile_key index: {error}"))?;

    let corrupt = db
        .query("SELECT count(*) AS count FROM artifacts WHERE compile_key = '' OR compile_key IS NULL")
        .fetch_one::<CountRow>()
        .await
        .map_err(|error| format!("count corrupt artifacts with empty compile_key: {error}"))?;
    if corrupt.count > 0 {
        tracing::warn!(
            count = corrupt.count,
            "deleting artifacts with empty compile_key — this indicates data corruption"
        );
        db.query("DELETE FROM artifacts WHERE compile_key = '' OR compile_key IS NULL")
            .execute()
            .await
            .map_err(|error| format!("delete artifacts with empty compile_key: {error}"))?;
    }

    Ok(())
}

async fn ensure_dependency_graph_miss_columns(db: &Db) -> Result<(), String> {
    let existing_columns = db
        .query("PRAGMA table_info(dependency_graph_misses)")
        .fetch_all::<DependencyGraphMissTableInfoRow>()
        .await
        .map_err(|error| format!("load dependency_graph_misses table_info: {error}"))?
        .into_iter()
        .map(|row| row.name)
        .collect::<BTreeSet<_>>();

    if existing_columns.contains("queued_at") {
        return Ok(());
    }

    db.query("ALTER TABLE dependency_graph_misses ADD COLUMN queued_at TEXT")
        .execute()
        .await
        .map_err(|error| format!("migrate dependency_graph_misses add queued_at: {error}"))?;
    Ok(())
}

pub async fn register_artifacts(
    db: &Db,
    records: &[stow_types::api::ArtifactRecord],
) -> Result<(), String> {
    for record in records {
        let artifact_size = i64::try_from(record.artifact_size)
            .map_err(|_| format!("artifact size exceeds i64 for {}", record.compile_key))?;
        let profile_json = serde_json::to_string(&record.profile).map_err(|error| {
            format!("serialize artifact profile {}: {error}", record.compile_key)
        })?;
        let emit_json = serde_json::to_string(&record.emit)
            .map_err(|error| format!("serialize artifact emit {}: {error}", record.compile_key))?;
        validate_c_metadata(&record.c_metadata)?;
        validate_target(&record.target)?;
        validate_rustc_version(&record.rustc_version)?;
        validate_crate_name(&record.crate_name)?;
        validate_version(&record.version)?;
        validate_features_json(&record.features_json)?;
        validate_dependency_c_metadata_json(&record.dependency_c_metadata_json)?;
        db.query(
            "INSERT OR REPLACE INTO artifacts \
             (compile_key, c_metadata, extra_filename, target, rustc_version, crate_name, version, features_json, dependency_c_metadata_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, profile_json, emit_json, artifact_size, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(record.compile_key.as_str())
        .bind(record.c_metadata.as_str())
        .bind(record.extra_filename.as_str())
        .bind(record.target.as_str())
        .bind(record.rustc_version.as_str())
        .bind(record.crate_name.as_str())
        .bind(record.version.as_str())
        .bind(record.features_json.as_str())
        .bind(record.dependency_c_metadata_json.as_str())
        .bind(record.oci_reference.as_str())
        .bind(record.oci_digest.as_str())
        .bind(if record.has_native { 1 } else { 0 })
        .bind(record.artifact_kind.as_str())
        .bind(
            serde_json::to_string(&record.crate_types)
                .map_err(|error| format!("serialize artifact crate_types {}: {error}", record.compile_key))?,
        )
        .bind(profile_json)
        .bind(emit_json)
        .bind(artifact_size)
        .execute()
        .await
        .map_err(|error| format!("register artifact {} {} {}: {error}", record.crate_name, record.target, record.c_metadata))?;
    }
    Ok(())
}

pub async fn get_artifact_reference(
    db: &Db,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<Option<ArtifactRow>, String> {
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
    .map_err(|error| format!("db query: {error}"))
}

pub async fn get_artifact_references(
    db: &Db,
    c_metadatas: &[String],
    target: &str,
    rustc_version: &str,
) -> Result<Vec<ExactArtifactRow>, String> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    if c_metadatas.is_empty() {
        return Ok(Vec::new());
    }
    for c_metadata in c_metadatas {
        validate_c_metadata(c_metadata)?;
    }

    let placeholders = c_metadatas
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT c_metadata, oci_reference, oci_digest, created_at, artifact_size \
         FROM artifacts \
         WHERE target = ? AND rustc_version = ? AND c_metadata IN ({placeholders}) \
         ORDER BY c_metadata"
    );
    let mut query = db.query(&sql).bind(target).bind(rustc_version);
    for c_metadata in c_metadatas {
        query = query.bind(c_metadata.as_str());
    }

    query
        .fetch_all::<ExactArtifactRow>()
        .await
        .map_err(|error| format!("db query: {error}"))
}

pub async fn get_semantic_artifact_reference(
    db: &Db,
    request: &SemanticArtifactRequest,
) -> Result<Option<ArtifactRow>, String> {
    validate_crate_name(&request.crate_name)?;
    validate_version(&request.version)?;
    validate_target(&request.target)?;
    validate_rustc_version(&request.rustc_version)?;
    validate_features_json(&request.features_json)?;
    validate_dependency_c_metadata_json(&request.dependency_c_metadata_json)?;
    validate_emit(&request.emit)?;
    validate_crate_types(&request.crate_types)?;

    let profile_json = serde_json::to_string(&request.profile)
        .map_err(|error| format!("serialize semantic profile: {error}"))?;
    let crate_types_json = serde_json::to_string(&request.crate_types)
        .map_err(|error| format!("serialize semantic crate_types: {error}"))?;
    let requested_version = parse_semver(&request.version)?;

    let rows = db
        .query(
            "SELECT compile_key, version, c_metadata, oci_reference, oci_digest, created_at, artifact_size, emit_json, dependency_c_metadata_json \
             FROM artifacts \
             WHERE crate_name = ? AND features_json = ? AND target = ? AND rustc_version = ? \
               AND artifact_kind = ? AND crate_types_json = ? AND profile_json = ? \
               AND dependency_c_metadata_json = ?",
        )
        .bind(request.crate_name.as_str())
        .bind(request.features_json.as_str())
        .bind(request.target.as_str())
        .bind(request.rustc_version.as_str())
        .bind(request.kind.as_str())
        .bind(crate_types_json)
        .bind(profile_json)
        .bind(request.dependency_c_metadata_json.as_str())
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
    stable_c_metadata_for_compile_key(&row.compile_key)
        .map(|stable| stable == row.c_metadata)
        .unwrap_or(false)
}

pub async fn delete_artifact_reference(
    db: &Db,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<(), String> {
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
) -> Result<Option<SemanticArtifactCandidate>, String> {
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

pub async fn is_subscribed_crate(db: &Db, crate_name: &str) -> Result<bool, String> {
    validate_crate_name(crate_name)?;

    let row = db
        .query("SELECT crate_name FROM subscriptions WHERE crate_name = ?")
        .bind(crate_name)
        .fetch_optional::<SubscribedRow>()
        .await
        .map_err(|error| format!("db query: {error}"))?;

    Ok(row.is_some())
}

pub async fn log_cache_miss(
    db: &Db,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
) -> Result<(), String> {
    validate_c_metadata(c_metadata)?;
    validate_crate_name(crate_name)?;
    validate_target(target)?;

    let city_code = sanitize_city_code(city_code);

    db.query(
        "INSERT INTO cache_misses (crate_name, c_metadata, target, city_code) VALUES (?, ?, ?, ?)",
    )
    .bind(crate_name)
    .bind(c_metadata)
    .bind(target)
    .bind(city_code)
    .execute()
    .await
    .map_err(|error| format!("db execute: {error}"))?;

    Ok(())
}

pub async fn analyze_dependency_graph(
    db: &Db,
    target: &str,
    rustc_version: &str,
    entries: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> Result<DependencyGraphAnalysisOutcome, String> {
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
            },
            enqueue_requests: Vec::new(),
        });
    }

    let mut crate_names = BTreeSet::<String>::new();
    let mut exact_entries = Vec::<ExactDependencyEntry>::with_capacity(entries.len());
    for entry in entries {
        validate_crate_name(&entry.crate_name)?;
        let seed_features = entry.features.iter().cloned().collect::<BTreeSet<_>>();
        let resolved_features = dependency_resolver::resolve_root_features(
            db,
            &entry.crate_name,
            &entry.version,
            &seed_features,
        )
        .await?;
        let encoded_features = dependency_resolver::serialize_feature_set(&resolved_features)?;
        crate_names.insert(entry.crate_name.clone());
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
                &entry.dependency.crate_name,
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
            let recommended = best_upgrade_for(entry, &semantic_catalog)?;
            Ok(DependencyGraphAnalysisEntry {
                dependency: entry.dependency.clone(),
                current_artifact_count,
                current_artifacts,
                recommended,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let expanded_plan = dependency_resolver::expand_scheduler_requests(
        db,
        target,
        rustc_version,
        entries,
        expanded_entries,
    )
    .await?;
    let misses =
        enqueue_requests_to_misses(&expanded_plan.enqueue_requests, target, rustc_version)?;
    record_dependency_graph_misses(db, &misses).await?;

    Ok(DependencyGraphAnalysisOutcome {
        response: DependencyGraphResponse {
            entries: response_entries,
            expanded_cached: expanded_plan.expanded_cached,
            expanded_total: expanded_plan.expanded_total,
            expanded_entries: expanded_plan.expanded_entries,
            prefetch_artifacts: expanded_plan.prefetch_artifacts,
        },
        enqueue_requests: expanded_plan.enqueue_requests,
    })
}

fn sanitize_city_code(city_code: &str) -> String {
    city_code
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(16)
        .collect()
}

async fn query_cached_artifact_rows(
    db: &Db,
    target: &str,
    rustc_version: &str,
    crate_names: Vec<String>,
) -> Result<Vec<CachedArtifactRow>, String> {
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

fn cached_artifact_row_has_canonical_metadata(row: &CachedArtifactRow) -> Result<bool, String> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&row.compile_key).map_err(|error| {
            format!(
                "compute stable c_metadata for {} {} {}: {error}",
                row.crate_name, row.version, row.compile_key
            )
        })?;
    Ok(stable_c_metadata == row.c_metadata)
}

fn build_semantic_catalog(rows: &[CachedArtifactRow]) -> Result<SemanticCatalog, String> {
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

fn build_exact_artifact_catalog(
    rows: &[CachedArtifactRow],
) -> Result<BTreeMap<(String, Version, String), Vec<DependencyGraphArtifact>>, String> {
    let mut artifacts = BTreeMap::<(String, Version, String), Vec<DependencyGraphArtifact>>::new();

    for row in rows {
        if !cached_artifact_row_has_canonical_metadata(row)? {
            continue;
        }
        validate_c_metadata(&row.c_metadata)?;
        let version = parse_semver(&row.version)?;
        let key = semantic_key(&row.crate_name, &version, &row.features_json);
        let entry = artifacts.entry(key).or_default();
        if entry
            .last()
            .is_some_and(|last| last.c_metadata == row.c_metadata)
        {
            continue;
        }
        entry.push(DependencyGraphArtifact {
            c_metadata: row.c_metadata.clone(),
        });
    }

    Ok(artifacts)
}

fn best_upgrade_for(
    entry: &ExactDependencyEntry,
    catalog: &SemanticCatalog,
) -> Result<Option<RecommendedDependencyVersion>, String> {
    let current_key = semantic_key(
        &entry.dependency.crate_name,
        &entry.dependency.version,
        &entry.features_json,
    );
    let current_artifact_count = catalog
        .artifact_counts
        .get(&current_key)
        .copied()
        .unwrap_or(0);
    let candidates = catalog.feature_versions.get(&(
        entry.dependency.crate_name.clone(),
        entry.features_json.clone(),
    ));
    let Some(candidates) = candidates else {
        return Ok(None);
    };

    for candidate in candidates {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &candidate.version) {
            continue;
        }
        if candidate.artifact_count <= current_artifact_count {
            continue;
        }
        return Ok(Some(RecommendedDependencyVersion {
            version: candidate.version.clone(),
            artifact_count: candidate.artifact_count,
        }));
    }

    Ok(None)
}

fn enqueue_requests_to_misses(
    requests: &[EnqueueRequest],
    target: &str,
    rustc_version: &str,
) -> Result<Vec<DependencyGraphMiss>, String> {
    let mut misses = Vec::<DependencyGraphMiss>::with_capacity(requests.len());
    for request in requests {
        let features = serde_json::from_str::<Vec<String>>(&request.features_json)
            .map_err(|error| format!("parse enqueue features_json: {error}"))?;
        let version = parse_semver(&request.version)?;
        misses.push(DependencyGraphMiss {
            dependency: DependencyGraphEntry {
                crate_name: request.crate_name.clone(),
                version: version.clone(),
                features,
            },
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            breaking_line: breaking_line(&version),
        });
    }
    Ok(misses)
}

async fn record_dependency_graph_misses(
    db: &Db,
    misses: &[DependencyGraphMiss],
) -> Result<(), String> {
    for miss in misses {
        let encoded_features = features_json(&miss.dependency.features)?;
        db.query(
            "INSERT INTO dependency_graph_misses \
             (crate_name, version, features_json, target, rustc_version, seen_count, first_seen_at, last_seen_at, queued_at) \
             VALUES (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'), NULL) \
             ON CONFLICT(crate_name, version, features_json, target, rustc_version) \
             DO UPDATE SET seen_count = seen_count + 1, last_seen_at = datetime('now')",
        )
        .bind(miss.dependency.crate_name.as_str())
        .bind(miss.dependency.version.to_string())
        .bind(encoded_features)
        .bind(miss.target.as_str())
        .bind(miss.rustc_version.as_str())
        .execute()
        .await
        .map_err(|error| format!("db execute: {error}"))?;
    }
    Ok(())
}

pub async fn take_dependency_graph_misses(
    db: &Db,
    limit: usize,
) -> Result<Vec<EnqueueRequest>, String> {
    let limit =
        i64::try_from(limit).map_err(|_| format!("miss drain limit exceeds i64: {limit}"))?;
    let rows = db
        .query(
            "SELECT crate_name, version, features_json, target, rustc_version, seen_count \
             FROM dependency_graph_misses \
             WHERE queued_at IS NULL \
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

        requests.push(EnqueueRequest {
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            target: row.target,
            rustc_version: row.rustc_version,
            downloads: row.seen_count,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
        });
    }
    Ok(requests)
}

fn semantic_key(
    crate_name: &str,
    version: &Version,
    features_json: &str,
) -> (String, Version, String) {
    (
        crate_name.to_owned(),
        version.clone(),
        features_json.to_owned(),
    )
}

fn emit_covers_request(
    candidate_emit_json: &str,
    requested_emit: &[String],
) -> Result<bool, String> {
    let candidate_emit = serde_json::from_str::<Vec<String>>(candidate_emit_json)
        .map_err(|error| format!("parse stored artifact emit_json: {error}"))?;
    validate_emit(&candidate_emit)?;
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
            dependency_c_metadata_json: "[]".to_owned(),
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
