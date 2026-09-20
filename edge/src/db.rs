use std::collections::BTreeSet;

use semver::Version;
use skyzen_services::Db;
use stow_types::api::{ArtifactRecord, EnqueueRequest};
use stow_types::identity::validate_emit_sorted;
use stow_types::index::ArtifactIndexRow;

use crate::errors::DbError;
use crate::scheduler::queue::SemanticTaskIdentity;
use crate::sql_batch;

/// Result of looking up an artifact by composite key.
#[derive(Debug, Clone, skyzen::FromRow, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRow {
    pub c_metadata: String,
    pub oci_reference: String,
    pub oci_digest: String,
    pub created_at: String,
    pub artifact_size: Option<u64>,
    /// Digest of the `<tag>.bundle` blob the edge streams; empty on rows
    /// registered before bundles were published, which the serve path
    /// prunes.
    pub bundle_digest: String,
    /// Byte length of that blob — the response `content-length`.
    pub bundle_size: u64,
    /// Crate name — the hit-event dimension for top-crates statistics.
    /// Defaults keep lookup entries cached before the field existed
    /// parseable.
    #[serde(default)]
    pub crate_name: String,
    /// Crate version — the hit-event dimension for version-leaderboard
    /// statistics.
    #[serde(default)]
    pub version: String,
    /// Wall-clock milliseconds the captured rustc invocation took — the
    /// CPU time a served hit is credited as saving.
    #[serde(default)]
    pub compile_millis: u64,
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

    let bundle_size = i64::try_from(record.bundle_size).map_err(|_| {
        DbError::Invariant(format!(
            "bundle_size {} exceeds i64 range for D1",
            record.bundle_size
        ))
    })?;
    let compile_millis = i64::try_from(record.compile_millis).map_err(|_| {
        DbError::Invariant(format!(
            "compile_millis {} exceeds i64 range for D1",
            record.compile_millis
        ))
    })?;
    if !record.bundle_digest.starts_with("sha256:") {
        return Err(DbError::Invariant(format!(
            "bundle_digest `{}` is not a sha256 OCI digest",
            record.bundle_digest
        )));
    }

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
        .bind(record.oci_reference.as_str())
        .bind(record.oci_digest.as_str())
        .bind(i32::from(record.has_native))
        .bind(record.artifact_kind.as_str())
        .bind(crate_types_json.as_str())
        .bind(profile_json.as_str())
        .bind(emit_json.as_str())
        .bind(artifact_size)
        .bind(record.bundle_digest.as_str())
        .bind(bundle_size)
        .bind(compile_millis)
        .execute()
        .await
        .map_err(|error| DbError::Query(format!("insert artifact record: {error}")))?;

    Ok(())
}

/// Every stored column of an `artifacts` row, for rebuilding the
/// [`ArtifactRecord`] that registered it.
#[derive(Debug, skyzen::FromRow)]
struct FullArtifactRow {
    compile_key: String,
    c_metadata: String,
    extra_filename: String,
    target: String,
    rustc_version: String,
    crate_name: String,
    version: String,
    features_json: String,
    dependency_c_metadata_json: String,
    oci_reference: String,
    oci_digest: String,
    has_native: i64,
    artifact_kind: String,
    crate_types_json: String,
    profile_json: String,
    emit_json: String,
    artifact_size: Option<u64>,
    bundle_digest: String,
    bundle_size: u64,
    compile_millis: u64,
}

/// The raw columns every `artifacts` row decode needs: the identity
/// strings plus the JSON-encoded columns (`features_json`,
/// `dependency_c_metadata_json`, `crate_types_json`, `profile_json`,
/// `emit_json`).
struct ArtifactColumns<'a> {
    c_metadata: &'a str,
    target: &'a str,
    rustc_version: &'a str,
    crate_name: &'a str,
    version: &'a str,
    features_json: &'a str,
    dependency_c_metadata_json: &'a str,
    artifact_kind: &'a str,
    crate_types_json: &'a str,
    profile_json: &'a str,
    emit_json: &'a str,
}

/// The typed form of [`ArtifactColumns`], decoded once per row.
struct DecodedArtifactColumns {
    c_metadata: stow_types::identity::CMetadata,
    target: stow_types::identity::TargetTriple,
    rustc_version: stow_types::identity::WireRustcVersion,
    crate_name: stow_types::identity::CrateName,
    version: stow_types::identity::CrateVersion,
    features_json: stow_types::identity::FeaturesJson,
    dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson,
    artifact_kind: stow_types::artifact::ArtifactKind,
    crate_types: Vec<stow_types::artifact::RustCrateType>,
    profile: stow_types::platform::Profile,
    emit: Vec<String>,
}

/// Decode the identity and JSON columns every row read shares, so
/// [`FullArtifactRow::into_record`] and [`IndexArtifactRow::into_index_row`]
/// cannot drift on the storage contract.
fn decode_artifact_columns(
    columns: &ArtifactColumns<'_>,
) -> Result<DecodedArtifactColumns, DbError> {
    let invalid = |what: &str, error: String| {
        DbError::Invariant(format!(
            "artifact row {}/{}/{}: {what}: {error}",
            columns.c_metadata, columns.target, columns.rustc_version
        ))
    };
    Ok(DecodedArtifactColumns {
        c_metadata: stow_types::identity::CMetadata::parse(columns.c_metadata)
            .map_err(|error| invalid("c_metadata", error.to_string()))?,
        target: stow_types::identity::TargetTriple::parse(columns.target)
            .map_err(|error| invalid("target", error.to_string()))?,
        rustc_version: stow_types::identity::WireRustcVersion::parse(columns.rustc_version)
            .map_err(|error| invalid("rustc_version", error.to_string()))?,
        crate_name: stow_types::identity::CrateName::parse(columns.crate_name)
            .map_err(|error| invalid("crate_name", error.to_string()))?,
        version: columns.version.parse().map_err(
            |error: stow_types::identity::IdentityError| invalid("version", error.to_string()),
        )?,
        features_json: serde_json::from_value(serde_json::Value::String(
            columns.features_json.to_owned(),
        ))
        .map_err(|error| invalid("features_json", error.to_string()))?,
        dependency_c_metadata_json: serde_json::from_value(serde_json::Value::String(
            columns.dependency_c_metadata_json.to_owned(),
        ))
        .map_err(|error| invalid("dependency_c_metadata_json", error.to_string()))?,
        artifact_kind: stow_types::artifact::ArtifactKind::parse(columns.artifact_kind)
            .ok_or_else(|| {
                invalid(
                    "artifact_kind",
                    format!("unknown kind `{}`", columns.artifact_kind),
                )
            })?,
        crate_types: serde_json::from_str(columns.crate_types_json)
            .map_err(|error| invalid("crate_types_json", error.to_string()))?,
        profile: serde_json::from_str(columns.profile_json)
            .map_err(|error| invalid("profile_json", error.to_string()))?,
        emit: serde_json::from_str(columns.emit_json)
            .map_err(|error| invalid("emit_json", error.to_string()))?,
    })
}

impl FullArtifactRow {
    fn columns(&self) -> ArtifactColumns<'_> {
        ArtifactColumns {
            c_metadata: &self.c_metadata,
            target: &self.target,
            rustc_version: &self.rustc_version,
            crate_name: &self.crate_name,
            version: &self.version,
            features_json: &self.features_json,
            dependency_c_metadata_json: &self.dependency_c_metadata_json,
            artifact_kind: &self.artifact_kind,
            crate_types_json: &self.crate_types_json,
            profile_json: &self.profile_json,
            emit_json: &self.emit_json,
        }
    }

    fn into_record(self) -> Result<ArtifactRecord, DbError> {
        let invalid = |what: &str, error: String| {
            DbError::Invariant(format!(
                "artifact row {}/{}/{}: {what}: {error}",
                self.c_metadata, self.target, self.rustc_version
            ))
        };
        let decoded = decode_artifact_columns(&self.columns())?;
        let artifact_size = self
            .artifact_size
            .ok_or_else(|| invalid("artifact_size", "NULL".to_owned()))?;
        Ok(ArtifactRecord {
            compile_key: self.compile_key,
            c_metadata: decoded.c_metadata,
            extra_filename: self.extra_filename,
            target: decoded.target,
            rustc_version: decoded.rustc_version,
            profile: decoded.profile,
            emit: decoded.emit,
            crate_name: decoded.crate_name,
            version: decoded.version,
            features_json: decoded.features_json,
            dependency_c_metadata_json: decoded.dependency_c_metadata_json,
            oci_reference: self.oci_reference,
            oci_digest: self.oci_digest,
            has_native: self.has_native != 0,
            artifact_kind: decoded.artifact_kind,
            crate_types: decoded.crate_types,
            artifact_size,
            bundle_digest: self.bundle_digest,
            bundle_size: self.bundle_size,
            compile_millis: self.compile_millis,
        })
    }
}

/// Rows registered before bundle publishing — no `bundle_digest` — oldest
/// first, as the records that registered them, so a backfill can push the
/// missing bundle and re-register each one.
pub async fn unbundled_artifact_records(
    db: &Db,
    limit: usize,
) -> Result<Vec<ArtifactRecord>, DbError> {
    let limit = i64::try_from(limit)
        .map_err(|_| DbError::Invariant(format!("unbundled limit {limit} exceeds i64")))?;
    let rows = db
        .query(&format!(
            "SELECT {FULL_ARTIFACT_COLUMNS} FROM artifacts \
             WHERE bundle_digest = '' ORDER BY created_at, c_metadata LIMIT ?"
        ))
        .bind(limit)
        .fetch_all::<FullArtifactRow>()
        .await
        .map_err(|error| DbError::Query(format!("db query: {error}")))?;
    rows.into_iter().map(FullArtifactRow::into_record).collect()
}

/// One servable artifact row as the published index needs it — every
/// field [`stow_types::index::ArtifactIndexRow`] carries, with the
/// JSON-encoded columns still raw for the shared decode.
#[derive(Debug, skyzen::FromRow)]
struct IndexArtifactRow {
    crate_name: String,
    version: String,
    features_json: String,
    dependency_c_metadata_json: String,
    c_metadata: String,
    compile_key: String,
    // Selected only so the shared decode's invariant messages can name
    // the slice — the index row itself does not carry them.
    target: String,
    rustc_version: String,
    bundle_digest: String,
    bundle_size: u64,
    artifact_kind: String,
    crate_types_json: String,
    profile_json: String,
    emit_json: String,
}

impl IndexArtifactRow {
    fn columns(&self) -> ArtifactColumns<'_> {
        ArtifactColumns {
            c_metadata: &self.c_metadata,
            target: &self.target,
            rustc_version: &self.rustc_version,
            crate_name: &self.crate_name,
            version: &self.version,
            features_json: &self.features_json,
            dependency_c_metadata_json: &self.dependency_c_metadata_json,
            artifact_kind: &self.artifact_kind,
            crate_types_json: &self.crate_types_json,
            profile_json: &self.profile_json,
            emit_json: &self.emit_json,
        }
    }

    fn into_index_row(self) -> Result<ArtifactIndexRow, DbError> {
        let decoded = decode_artifact_columns(&self.columns())?;
        Ok(ArtifactIndexRow {
            crate_name: decoded.crate_name,
            version: decoded.version,
            features_json: decoded.features_json,
            dependency_c_metadata_json: decoded.dependency_c_metadata_json,
            c_metadata: decoded.c_metadata,
            compile_key: self.compile_key,
            bundle_digest: self.bundle_digest,
            bundle_size: self.bundle_size,
            artifact_kind: decoded.artifact_kind,
            crate_types: decoded.crate_types,
            profile: decoded.profile,
            emit: decoded.emit,
        })
    }
}

/// One page of the servable `(target, rustc_version)` slice for the
/// published artifact index: every row with a pushed bundle (non-empty
/// `bundle_digest`), ordered by `c_metadata`, starting strictly
/// after the `after` cursor. `limit` bounds the page; the caller turns a
/// full page into a `next_after` cursor.
pub async fn artifact_index_page(
    db: &Db,
    target: &str,
    rustc_version: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<ArtifactIndexRow>, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    if let Some(after) = after {
        validate_c_metadata(after)?;
    }
    let limit = i64::try_from(limit)
        .map_err(|_| DbError::Invariant(format!("index page limit {limit} exceeds i64")))?;
    let rows = db
        .query(
            "SELECT crate_name, version, features_json, dependency_c_metadata_json, c_metadata, \
                    compile_key, target, rustc_version, bundle_digest, bundle_size, artifact_kind, \
                    crate_types_json, profile_json, emit_json \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND bundle_digest != '' AND c_metadata > ? \
             ORDER BY c_metadata LIMIT ?",
        )
        .bind(target)
        .bind(rustc_version)
        .bind(after.unwrap_or(""))
        .bind(limit)
        .fetch_all::<IndexArtifactRow>()
        .await
        .map_err(|error| DbError::Query(format!("index page query: {error}")))?;
    rows.into_iter()
        .map(IndexArtifactRow::into_index_row)
        .collect()
}

// ===== Admin catalog reads (`stow-admin` coverage/artifacts commands) =====

/// Every stored column `FullArtifactRow` decodes — shared by the
/// full-record reads so no listing can drift on the storage contract.
const FULL_ARTIFACT_COLUMNS: &str = "compile_key, c_metadata, extra_filename, target, \
     rustc_version, crate_name, version, features_json, dependency_c_metadata_json, \
     oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, \
     profile_json, emit_json, artifact_size, bundle_digest, bundle_size, compile_millis";

/// One servable-identity row for the coverage listing.
#[derive(Debug, skyzen::FromRow)]
struct CoverageRow {
    target: String,
    version: String,
    features_json: String,
    rustc_version: String,
    c_metadata: String,
    bundle_size: u64,
}

/// Servable identities for one crate — every `(target, artifact)` pair
/// with a published bundle, optionally scoped to one version. The handler
/// groups these by CI target into [`stow_types::api::CrateCoverage`].
pub async fn artifact_coverage(
    db: &Db,
    crate_name: &str,
    version: Option<&str>,
) -> Result<
    Vec<(
        stow_types::identity::TargetTriple,
        stow_types::api::CoverageArtifact,
    )>,
    DbError,
> {
    validate_crate_name(crate_name)?;
    let mut sql = String::from(
        "SELECT target, version, features_json, rustc_version, c_metadata, bundle_size \
         FROM artifacts WHERE crate_name = ? AND bundle_digest != ''",
    );
    if let Some(version) = version {
        parse_semver(version)?;
        sql.push_str(" AND version = ?");
    }
    sql.push_str(" ORDER BY target, version, features_json, c_metadata");
    let mut query = db.query(&sql).bind(crate_name);
    if let Some(version) = version {
        query = query.bind(version);
    }
    let rows = query
        .fetch_all::<CoverageRow>()
        .await
        .map_err(|error| DbError::Query(format!("coverage query: {error}")))?;
    rows.into_iter()
        .map(|row| {
            let row_label = format!("{}/{}/{}", row.c_metadata, row.target, row.rustc_version);
            let invalid = |what: &str, error: String| {
                DbError::Invariant(format!("artifact row {row_label}: {what}: {error}"))
            };
            Ok((
                stow_types::identity::TargetTriple::parse(row.target)
                    .map_err(|error| invalid("target", error.to_string()))?,
                stow_types::api::CoverageArtifact {
                    version: row
                        .version
                        .parse::<stow_types::identity::CrateVersion>()
                        .map_err(|error| invalid("version", error.to_string()))?,
                    features_json: serde_json::from_value(serde_json::Value::String(
                        row.features_json,
                    ))
                    .map_err(|error| invalid("features_json", error.to_string()))?,
                    rustc_version: stow_types::identity::WireRustcVersion::parse(row.rustc_version)
                        .map_err(|error| invalid("rustc_version", error.to_string()))?,
                    c_metadata: stow_types::identity::CMetadata::parse(row.c_metadata)
                        .map_err(|error| invalid("c_metadata", error.to_string()))?,
                    bundle_size: row.bundle_size,
                },
            ))
        })
        .collect()
}

/// The full catalog row for one `(target, rustc_version, c_metadata)`
/// identity — the record `stow-admin artifacts inspect` renders.
pub async fn artifact_record(
    db: &Db,
    target: &str,
    rustc_version: &str,
    c_metadata: &str,
) -> Result<Option<ArtifactRecord>, DbError> {
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;
    validate_c_metadata(c_metadata)?;
    let row = db
        .query(&format!(
            "SELECT {FULL_ARTIFACT_COLUMNS} FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND c_metadata = ?"
        ))
        .bind(target)
        .bind(rustc_version)
        .bind(c_metadata)
        .fetch_optional::<FullArtifactRow>()
        .await
        .map_err(|error| DbError::Query(format!("artifact record query: {error}")))?;
    row.map(FullArtifactRow::into_record).transpose()
}

/// Catalog rows matching the admin list query — the bounded listing the
/// CLI's prune preview and ad-hoc inspection page through.
pub async fn list_artifact_records(
    db: &Db,
    query: &stow_types::api::ArtifactListQuery,
    limit: usize,
) -> Result<Vec<ArtifactRecord>, DbError> {
    let mut predicates: Vec<&'static str> = Vec::new();
    let mut values: Vec<skyzen_services::DbValue> = Vec::new();
    if let Some(rustc_version) = &query.rustc_version {
        predicates.push("rustc_version = ?");
        values.push(rustc_version.as_str().into());
    }
    if let Some(target) = &query.target {
        predicates.push("target = ?");
        values.push(target.as_str().into());
    }
    if let Some(crate_name) = &query.crate_name {
        predicates.push("crate_name = ?");
        values.push(crate_name.as_str().into());
    }
    let where_clause = if predicates.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", predicates.join(" AND "))
    };
    let limit = i64::try_from(limit)
        .map_err(|_| DbError::Invariant(format!("artifacts list limit {limit} exceeds i64")))?;
    let sql = format!(
        "SELECT {FULL_ARTIFACT_COLUMNS} FROM artifacts {where_clause} \
         ORDER BY created_at DESC LIMIT {limit}"
    );
    let mut statement = db.query(&sql);
    for value in values {
        statement = statement.bind(value);
    }
    let rows = statement
        .fetch_all::<FullArtifactRow>()
        .await
        .map_err(|error| DbError::Query(format!("artifacts list query: {error}")))?;
    rows.into_iter().map(FullArtifactRow::into_record).collect()
}

/// Every catalog row built by `rustc_version` — the prune set whose
/// lookup-cache entries the caller invalidates before the delete lands.
pub async fn artifact_records_for_rustc(
    db: &Db,
    rustc_version: &str,
) -> Result<Vec<ArtifactRecord>, DbError> {
    validate_rustc_version(rustc_version)?;
    let rows = db
        .query(&format!(
            "SELECT {FULL_ARTIFACT_COLUMNS} FROM artifacts \
             WHERE rustc_version = ? ORDER BY created_at, c_metadata"
        ))
        .bind(rustc_version)
        .fetch_all::<FullArtifactRow>()
        .await
        .map_err(|error| DbError::Query(format!("artifacts for rustc query: {error}")))?;
    rows.into_iter().map(FullArtifactRow::into_record).collect()
}

/// Delete every catalog row built by `rustc_version` — the second half of
/// `artifacts prune`, after the caller has invalidated each row's lookup
/// cache entries. Returns the deleted row count.
pub async fn delete_artifacts_for_rustc(db: &Db, rustc_version: &str) -> Result<u32, DbError> {
    validate_rustc_version(rustc_version)?;
    let result = db
        .query("DELETE FROM artifacts WHERE rustc_version = ?")
        .bind(rustc_version)
        .execute()
        .await
        .map_err(|error| DbError::Query(format!("delete artifacts for rustc: {error}")))?;
    u32::try_from(result.rows_written).map_err(|_| {
        DbError::Invariant(format!(
            "deleted row count {} exceeds u32",
            result.rows_written
        ))
    })
}

/// The servable row for an exact identity. Rows without a published
/// bundle (registered before bundles existed, see
/// [`unbundled_artifact_records`]) are a miss on every serving lookup —
/// there is no blob to stream until a backfill or rebuild re-registers
/// them.
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
        "SELECT c_metadata, crate_name, version, oci_reference, oci_digest, created_at, artifact_size, bundle_digest, bundle_size, compile_millis \
         FROM artifacts \
         WHERE c_metadata = ? AND target = ? AND rustc_version = ? AND bundle_digest != ''",
    )
    .bind(c_metadata)
    .bind(target)
    .bind(rustc_version)
    .fetch_optional::<ArtifactRow>()
    .await
    .map_err(|error| DbError::Query(format!("db query: {error}")))
}

/// The subset of `identities` the catalog serves: a servable row (one
/// with a published bundle) exists for the exact crate, version, features,
/// target and rustc. One `IN (VALUES ...)` statement per batch of five
/// identities keeps every statement under D1's bound-parameter ceiling.
pub async fn covered_semantic_identities(
    db: &Db,
    identities: &[SemanticTaskIdentity],
) -> Result<BTreeSet<SemanticTaskIdentity>, DbError> {
    const PARAMS_PER_IDENTITY: usize = 5;
    const BATCH: usize = sql_batch::D1_MAX_BOUND_PARAMS / PARAMS_PER_IDENTITY;
    let mut covered = BTreeSet::new();
    for batch in identities.chunks(BATCH) {
        let sql = format!(
            "SELECT crate_name, version, features_json, target, rustc_version \
             FROM artifacts \
             WHERE bundle_digest != '' \
               AND (crate_name, version, features_json, target, rustc_version) IN (VALUES {})",
            sql_batch::values_rows("(?, ?, ?, ?, ?)", batch.len())
        );
        let mut query = db.query(&sql);
        for identity in batch {
            query = query
                .bind(identity.crate_name.as_str())
                .bind(identity.version.as_str())
                .bind(identity.features_json.as_str())
                .bind(identity.target.as_str())
                .bind(identity.rustc_version.as_str());
        }
        let rows = query
            .fetch_all::<CoveredIdentityRow>()
            .await
            .map_err(|error| DbError::Query(format!("db query: {error}")))?;
        covered.extend(rows.into_iter().map(|row| SemanticTaskIdentity {
            crate_name: row.crate_name,
            version: row.version,
            features_json: row.features_json,
            target: row.target,
            rustc_version: row.rustc_version,
        }));
    }
    Ok(covered)
}

#[derive(Debug, skyzen::FromRow)]
struct CoveredIdentityRow {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
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

/// Apply the migration files to a test database — the same SQL the deploy
/// pipeline hands to `wrangler d1 execute --file`. `Db::query` prepares one
/// statement at a time, so the file is split on `;`.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub async fn apply_migrations(db: &Db) {
    const FILES: &[&str] = &[
        include_str!("../migrations/0001_schema.sql"),
        include_str!("../migrations/0002_drop_subscriptions.sql"),
        include_str!("../migrations/0003_bundle_digest.sql"),
        include_str!("../migrations/0004_index_page.sql"),
        include_str!("../migrations/0005_compile_millis.sql"),
        include_str!("../migrations/0006_drop_dependency_count.sql"),
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
    use std::collections::BTreeSet;

    use crate::scheduler::queue::SemanticTaskIdentity;

    use stow_types::api::{ArtifactRecord, EnqueueRequest};
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};

    use super::{
        apply_migrations, artifact_index_page, covered_semantic_identities, get_artifact_reference,
        insert_artifact_record, record_admitted_miss, set_dependency_graph_misses_queued,
        take_dependency_graph_misses, unbundled_artifact_records,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";
    const C_METADATA: &str = "eeeeeeeeeeeeeeee";
    const FIRST_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECOND_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn artifact_record(oci_digest: &str) -> ArtifactRecord {
        artifact_record_with(C_METADATA, oci_digest)
    }

    fn artifact_record_with(c_metadata: &str, oci_digest: &str) -> ArtifactRecord {
        ArtifactRecord {
            compile_key: format!("{c_metadata}{c_metadata}"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            extra_filename: format!("-{c_metadata}"),
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
                "ghcr.io/water-rs/stow-cache:serde.1.0.0-x86_64-linux-{RUSTC}-abcdef012345-{c_metadata}"
            ),
            oci_digest: oci_digest.to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 1,
            bundle_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            bundle_size: 1,
            compile_millis: 1_234,
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

    /// A row registered before bundles existed is invisible to serving
    /// lookups, and the backfill listing hands back the record that
    /// registered it so the bundle can be published and re-registered.
    #[tokio::test]
    async fn unbundled_rows_are_a_miss_until_backfilled() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let record = artifact_record(FIRST_DIGEST);
        insert_artifact_record(&db, &record).await.expect("insert");
        db.query("UPDATE artifacts SET bundle_digest = '', bundle_size = 0")
            .execute()
            .await
            .expect("age the row to the pre-bundle schema");

        assert!(
            get_artifact_reference(&db, C_METADATA, TARGET, RUSTC)
                .await
                .expect("lookup")
                .is_none()
        );
        let unbundled = unbundled_artifact_records(&db, 10)
            .await
            .expect("unbundled listing");
        assert_eq!(
            unbundled,
            vec![ArtifactRecord {
                bundle_digest: String::new(),
                bundle_size: 0,
                ..record.clone()
            }]
        );

        insert_artifact_record(&db, &record)
            .await
            .expect("re-register with the bundle");
        assert_eq!(
            unbundled_artifact_records(&db, 10)
                .await
                .expect("unbundled listing"),
            Vec::new()
        );
        assert!(
            get_artifact_reference(&db, C_METADATA, TARGET, RUSTC)
                .await
                .expect("lookup")
                .is_some()
        );
    }

    /// Coverage is exact on every identity column and ignores rows without
    /// a published bundle, which serving lookups treat as a miss too.
    #[tokio::test]
    async fn covered_identities_match_servable_rows_exactly() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let record = artifact_record(FIRST_DIGEST);
        insert_artifact_record(&db, &record).await.expect("insert");
        let identity = |features_json: &str, target: &str| SemanticTaskIdentity {
            crate_name: record.crate_name.as_str().to_owned(),
            version: record.version.to_string(),
            features_json: features_json.to_owned(),
            target: target.to_owned(),
            rustc_version: RUSTC.to_owned(),
        };
        let exact = identity(&record.features_json.raw(), TARGET);
        let other_features = identity("[\"extra\"]", TARGET);
        let other_target = identity(&record.features_json.raw(), "aarch64-apple-darwin");

        let covered =
            covered_semantic_identities(&db, &[exact.clone(), other_features, other_target])
                .await
                .expect("coverage");
        assert_eq!(covered, BTreeSet::from([exact.clone()]));

        db.query("UPDATE artifacts SET bundle_digest = ''")
            .execute()
            .await
            .expect("age the row to the pre-bundle schema");
        assert_eq!(
            covered_semantic_identities(&db, std::slice::from_ref(&exact))
                .await
                .expect("coverage"),
            BTreeSet::new()
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
        assert_eq!(row.crate_name, "serde");
        assert_eq!(row.version, "1.0.0");
        assert_eq!(row.compile_millis, 1_234);
    }

    /// Two pages walk every servable row of the slice exactly once, in
    /// `c_metadata` order; the one pre-bundle row — sorted first so an
    /// off-by-one at the slice head would surface it — never appears.
    #[tokio::test]
    async fn index_pages_walk_every_servable_row_once() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;

        for c_metadata in ["aaaaaaaaaaaaaaaa", "cccccccccccccccc", "eeeeeeeeeeeeeeee"] {
            insert_artifact_record(&db, &artifact_record_with(c_metadata, FIRST_DIGEST))
                .await
                .expect("insert servable row");
        }
        let unbundled = "0f0f0f0f0f0f0f0f";
        insert_artifact_record(&db, &artifact_record_with(unbundled, FIRST_DIGEST))
            .await
            .expect("insert unbundled row");
        db.query(&format!(
            "UPDATE artifacts SET bundle_digest = '', bundle_size = 0 \
             WHERE c_metadata = '{unbundled}'"
        ))
        .execute()
        .await
        .expect("age the row to the pre-bundle schema");

        let first = artifact_index_page(&db, TARGET, RUSTC, None, 2)
            .await
            .expect("first page");
        assert_eq!(first.len(), 2);
        let cursor = first.last().expect("first page tail").c_metadata.clone();
        let second = artifact_index_page(&db, TARGET, RUSTC, Some(cursor.as_str()), 2)
            .await
            .expect("second page");
        assert_eq!(second.len(), 1);
        let tail = artifact_index_page(
            &db,
            TARGET,
            RUSTC,
            Some(second.last().expect("second page tail").c_metadata.as_str()),
            2,
        )
        .await
        .expect("page past the end");
        assert_eq!(tail, []);

        let walked: Vec<String> = first
            .iter()
            .chain(&second)
            .map(|row| row.c_metadata.as_str().to_owned())
            .collect();
        assert_eq!(
            walked,
            vec!["aaaaaaaaaaaaaaaa", "cccccccccccccccc", "eeeeeeeeeeeeeeee"],
            "pages must cover each servable row exactly once, in order"
        );
    }
}
