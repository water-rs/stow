use std::collections::{BTreeMap, BTreeSet};

use semver::Version;
use skyzen_services::Db;
use stow_types::api::{
    DependencyGraphAnalysisEntry, DependencyGraphArtifact, DependencyGraphEntry,
    DependencyGraphMiss, DependencyGraphResponse, RecommendedDependencyVersion,
    SemanticArtifactRequest,
};
use stow_types::versioning::{
    breaking_line, is_semver_compatible_upgrade, is_within_recent_breaking_lines,
};
#[path = "../../shared/artifact_table_schema.rs"]
mod artifact_table_schema;

const RECENT_BREAKING_LINE_LIMIT: usize = 3;

/// Result of looking up an artifact by composite key.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactRow {
    pub oci_reference: String,
    pub oci_digest: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExactArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub artifact_size: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct SubscribedRow {
    crate_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct CachedArtifactRow {
    crate_name: String,
    version: String,
    features_json: String,
    c_metadata: String,
}

#[derive(Debug, serde::Deserialize)]
struct ArtifactTableInfoRow {
    name: String,
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
    if value.is_empty()
        || value.len() > 32
        || !value.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
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

fn features_json(features: &[String]) -> Result<String, String> {
    validate_features(features)?;
    serde_json::to_string(features).map_err(|error| format!("serialize features: {error}"))
}

fn validate_features_json(value: &str) -> Result<(), String> {
    let parsed = serde_json::from_str::<Vec<String>>(value)
        .map_err(|_| "invalid features_json format".to_owned())?;
    validate_features(&parsed)
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
        db.query(column.add_sql)
            .execute()
            .await
            .map_err(|error| format!("migrate artifacts table add column {}: {error}", column.name))?;
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
        "SELECT oci_reference, oci_digest, artifact_size \
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
        "SELECT c_metadata, oci_reference, oci_digest, artifact_size \
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

    let rows = db
        .query(
            "SELECT oci_reference, oci_digest, artifact_size \
             FROM artifacts \
             WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ?",
        )
        .bind(request.crate_name.as_str())
        .bind(request.version.as_str())
        .bind(request.features_json.as_str())
        .bind(request.target.as_str())
        .bind(request.rustc_version.as_str())
        .fetch_all::<ArtifactRow>()
        .await
        .map_err(|error| format!("db query: {error}"))?;

    Ok(rows
        .into_iter()
        .find(|row| artifact_kind_matches_reference(&row.oci_reference, &request.kind)))
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
) -> Result<DependencyGraphResponse, String> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    if entries.is_empty() {
        return Ok(DependencyGraphResponse {
            entries: Vec::new(),
        });
    }

    let mut crate_names = BTreeSet::<String>::new();
    let mut exact_entries = Vec::<ExactDependencyEntry>::with_capacity(entries.len());
    for entry in entries {
        validate_crate_name(&entry.crate_name)?;
        let encoded_features = features_json(&entry.features)?;
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

    let misses =
        collect_dependency_graph_misses(&exact_entries, &semantic_catalog, target, rustc_version)?;
    record_dependency_graph_misses(db, &misses).await?;

    Ok(DependencyGraphResponse {
        entries: response_entries,
    })
}

fn sanitize_city_code(city_code: &str) -> String {
    city_code
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(16)
        .collect()
}

fn artifact_kind_matches_reference(
    reference: &str,
    kind: &stow_types::artifact::ArtifactKind,
) -> bool {
    match kind {
        stow_types::artifact::ArtifactKind::Rlib => {
            !reference.ends_with("-pm") && !reference.ends_with("-dy")
        }
        stow_types::artifact::ArtifactKind::Dylib => reference.ends_with("-dy"),
        stow_types::artifact::ArtifactKind::ProcMacro => reference.ends_with("-pm"),
    }
}

async fn query_cached_artifact_rows(
    db: &Db,
    target: &str,
    rustc_version: &str,
    crate_names: Vec<String>,
) -> Result<Vec<CachedArtifactRow>, String> {
    let placeholders = crate_names
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT crate_name, version, features_json, c_metadata \
         FROM artifacts \
         WHERE target = ? AND rustc_version = ? AND crate_name IN ({placeholders}) \
         ORDER BY crate_name, version, features_json, c_metadata"
    );

    let mut query = db.query(&sql).bind(target).bind(rustc_version);
    for crate_name in &crate_names {
        query = query.bind(crate_name.as_str());
    }

    query
        .fetch_all::<CachedArtifactRow>()
        .await
        .map_err(|error| format!("db query: {error}"))
}

fn build_semantic_catalog(rows: &[CachedArtifactRow]) -> Result<SemanticCatalog, String> {
    let mut artifact_counts = BTreeMap::<(String, Version, String), u32>::new();
    let mut crate_versions = BTreeMap::<String, BTreeSet<Version>>::new();
    let mut feature_versions = BTreeMap::<(String, String), Vec<CachedVersion>>::new();

    for row in rows {
        let version = parse_semver(&row.version)?;
        let artifact_key = semantic_key(&row.crate_name, &version, &row.features_json);
        let artifact_count = artifact_counts.entry(artifact_key).or_insert(0);
        *artifact_count = artifact_count.saturating_add(1);
        crate_versions
            .entry(row.crate_name.clone())
            .or_default()
            .insert(version.clone());
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
        crate_versions,
        feature_versions,
    })
}

fn build_exact_artifact_catalog(
    rows: &[CachedArtifactRow],
) -> Result<BTreeMap<(String, Version, String), Vec<DependencyGraphArtifact>>, String> {
    let mut artifacts = BTreeMap::<(String, Version, String), Vec<DependencyGraphArtifact>>::new();

    for row in rows {
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

fn collect_dependency_graph_misses(
    entries: &[ExactDependencyEntry],
    catalog: &SemanticCatalog,
    target: &str,
    rustc_version: &str,
) -> Result<Vec<DependencyGraphMiss>, String> {
    let mut misses = Vec::<DependencyGraphMiss>::new();
    let mut seen = BTreeSet::<(String, Version, String)>::new();

    for entry in entries {
        let key = semantic_key(
            &entry.dependency.crate_name,
            &entry.dependency.version,
            &entry.features_json,
        );
        if catalog.artifact_counts.get(&key).copied().unwrap_or(0) > 0 {
            continue;
        }

        let mut known_versions = catalog
            .crate_versions
            .get(&entry.dependency.crate_name)
            .cloned()
            .unwrap_or_default();
        known_versions.insert(entry.dependency.version.clone());
        let known_versions = known_versions.into_iter().collect::<Vec<_>>();
        if !is_within_recent_breaking_lines(
            &entry.dependency.version,
            known_versions.iter(),
            RECENT_BREAKING_LINE_LIMIT,
        ) {
            continue;
        }

        if !seen.insert(key.clone()) {
            continue;
        }

        misses.push(DependencyGraphMiss {
            dependency: entry.dependency.clone(),
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            breaking_line: breaking_line(&entry.dependency.version),
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
             (crate_name, version, features_json, target, rustc_version, seen_count, first_seen_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now')) \
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
    crate_versions: BTreeMap<String, BTreeSet<Version>>,
    feature_versions: BTreeMap<(String, String), Vec<CachedVersion>>,
}
