use std::collections::{BTreeMap, BTreeSet};

use futures_util::stream::{self, StreamExt as _, TryStreamExt as _};
use semver::Version;
use skyzen_services::{BatchStatement, Db};
use stow_types::api::{ArtifactRecord, EnqueueRequest};
use stow_types::identity::validate_emit_sorted;
use stow_types::index::ArtifactIndexRow;
use stow_types::public_cache::{UnitInvocation, UnitShape, UnitSide, required_unit_shapes};

use crate::errors::DbError;
use crate::scheduler::queue::SemanticTaskIdentity;
use crate::sql_batch;

#[derive(Debug, skyzen::FromRow)]
struct QueuedDependencyGraphMissRow {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    host_side: i64,
    seen_count: u64,
    depends_on_json: String,
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

/// Build the upsert statement for one artifact record — all of
/// `insert_artifact_records`' checks and encodes, expressed as a
/// [`BatchStatement`] so a sync request writes every row through one
/// [`Db::execute_batch`] call.
///
/// The composite uniqueness key is `(c_metadata, target, rustc_version)`;
/// the upsert keeps syncs idempotent so replays do not
/// duplicate rows, and `created_at` is excluded from the update list so
/// a re-register preserves the first-registration timestamp.
fn artifact_record_statement(record: &ArtifactRecord) -> Result<BatchStatement, DbError> {
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
    // `min_glibc` stores the floor as text: `''` for a measured artifact
    // with no glibc requirement, `'x.y'` for the floor itself. NULL means
    // "not yet measured" and is reserved for rows that predate the
    // column — a sync write always writes a concrete value.
    let min_glibc = record
        .min_glibc
        .map_or_else(String::new, |floor| floor.to_string());

    Ok(BatchStatement::new(include_str!("sql/insert_artifact.sql"))
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
        .bind(record.unit_shape.map_or(-1, |shape| shape.side.to_int()))
        .bind(
            record
                .unit_shape
                .map_or(-1, |shape| shape.invocation.to_int()),
        )
        .bind(record.unit_shape.map_or(-1, |shape| shape.kind.to_int()))
        .bind(min_glibc.as_str()))
}

/// Insert (or update) every record of a sync request in one
/// [`Db::execute_batch`] call — a single D1 round trip rather than one
/// per record. The batch is D1's transaction: a failed statement rolls
/// the whole request's writes back, so a request that fails at the
/// database leaves no partial rows behind.
///
/// # Errors
///
/// Returns the validation error of the first offending record, or the
/// `DbError` of the statement that failed the batch.
pub async fn insert_artifact_records(db: &Db, records: &[ArtifactRecord]) -> Result<(), DbError> {
    if records.is_empty() {
        return Ok(());
    }
    let statements = records
        .iter()
        .map(artifact_record_statement)
        .collect::<Result<Vec<_>, _>>()?;
    db.execute_batch(statements)
        .await
        .map_err(|error| DbError::Query(format!("insert artifact records: {error}")))?;
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
    /// The builder-recorded unit shape — `-1` on a row registered
    /// before the columns existed.
    unit_side: i64,
    unit_invocation: i64,
    unit_linked: i64,
    /// The measured glibc floor — `''` when measured with no
    /// requirement, NULL on rows the measurement predates.
    min_glibc: Option<String>,
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

/// The stored unit-shape triplet decoded back to a [`UnitShape`]:
/// `-1` on all three legs is the legacy marker — a row registered
/// before the columns existed is shapeless and covers nothing.
/// Anything else off-enum, or `-1` mixed with real values, is a corrupt
/// row — an invariant violation, not a quiet miss.
///
/// # Errors
///
/// Returns an invariant message for any corrupt triplet.
fn decode_unit_shape(side: i64, invocation: i64, linked: i64) -> Result<Option<UnitShape>, String> {
    if (side, invocation, linked) == (-1, -1, -1) {
        return Ok(None);
    }
    match (
        UnitSide::from_int(side),
        UnitInvocation::from_int(invocation),
        stow_types::public_cache::UnitKind::from_int(linked),
    ) {
        (Some(side), Some(invocation), Some(kind)) => Ok(Some(UnitShape {
            side,
            invocation,
            kind,
        })),
        _ => Err(format!(
            "corrupt unit shape ({side}, {invocation}, {linked}): -1 is the \
             legacy marker and must appear on all three legs or none"
        )),
    }
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
            // stow#588: the artifacts table stores no digest column —
            // a row decoded here is the archive's older shape, so its
            // contextual coverage answer is `None`.
            dependency_identity: None,
            oci_reference: self.oci_reference,
            oci_digest: self.oci_digest,
            has_native: self.has_native != 0,
            artifact_kind: decoded.artifact_kind,
            crate_types: decoded.crate_types,
            artifact_size,
            bundle_digest: self.bundle_digest,
            bundle_size: self.bundle_size,
            compile_millis: self.compile_millis,
            unit_shape: decode_unit_shape(self.unit_side, self.unit_invocation, self.unit_linked)
                .map_err(|error| invalid("unit_shape", error))?,
            min_glibc: decode_min_glibc(self.min_glibc.as_deref())
                .map_err(|error| invalid("min_glibc", error))?,
        })
    }
}

/// The stored form of a row's glibc floor back into the typed field:
/// `''` and NULL both decode to `None` — a record carries no
/// "unmeasured" state, so an unmeasured row reads as floorless and the
/// unmeasured listing keys on NULL in SQL, not on this value.
fn decode_min_glibc(raw: Option<&str>) -> Result<Option<stow_types::glibc::GlibcVersion>, String> {
    match raw {
        None | Some("") => Ok(None),
        Some(text) => text
            .parse::<stow_types::glibc::GlibcVersion>()
            .map(Some)
            .map_err(|error| format!("unparseable min_glibc `{text}`: {error}")),
    }
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
    /// The builder-recorded unit shape — `-1` on a row registered
    /// before the columns existed.
    unit_side: i64,
    unit_invocation: i64,
    unit_linked: i64,
    min_glibc: Option<String>,
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
            // stow#588: same archive row shape — no digest column.
            dependency_identity: None,
            c_metadata: decoded.c_metadata,
            compile_key: self.compile_key,
            bundle_digest: self.bundle_digest,
            bundle_size: self.bundle_size,
            artifact_kind: decoded.artifact_kind,
            crate_types: decoded.crate_types,
            profile: decoded.profile,
            emit: decoded.emit,
            unit_shape: decode_unit_shape(self.unit_side, self.unit_invocation, self.unit_linked)
                .map_err(|error| {
                DbError::Invariant(format!(
                    "artifact row {}/{}/{}: {error}",
                    self.c_metadata, self.target, self.rustc_version
                ))
            })?,
            min_glibc: decode_min_glibc(self.min_glibc.as_deref()).map_err(|error| {
                DbError::Invariant(format!(
                    "artifact row {}/{}/{}: min_glibc: {error}",
                    self.c_metadata, self.target, self.rustc_version
                ))
            })?,
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
    } else {
        // The page query drops unmeasured rows, so exporting a slice
        // that still has any would sign an index missing rows it used
        // to carry. Refuse instead — a NULL floor means a row older
        // than the column survived into the mirror, which should not
        // exist: fix the row before re-exporting.
        let unmeasured = unmeasured_glibc_count_in_slice(db, target, rustc_version).await?;
        if unmeasured > 0 {
            return Err(DbError::Invariant(format!(
                "slice {target}/{rustc_version} has {unmeasured} artifact rows with \
                 no measured glibc floor",
            )));
        }
    }
    let limit = i64::try_from(limit)
        .map_err(|_| DbError::Invariant(format!("index page limit {limit} exceeds i64")))?;
    let rows = db
        .query(
            "SELECT crate_name, version, features_json, dependency_c_metadata_json, c_metadata, \
                    compile_key, target, rustc_version, bundle_digest, bundle_size, artifact_kind, \
                    crate_types_json, profile_json, emit_json, unit_side, unit_invocation, unit_linked, \
                    min_glibc \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND bundle_digest != '' \
                   AND min_glibc IS NOT NULL AND c_metadata > ? \
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
     profile_json, emit_json, artifact_size, bundle_digest, bundle_size, compile_millis, \
     unit_side, unit_invocation, unit_linked, min_glibc";

/// How many bundled rows in one `(target, rustc_version)` slice still
/// have no measured floor — the rows the index page's `min_glibc IS NOT
/// NULL` filter would silently drop from a signed export.
async fn unmeasured_glibc_count_in_slice(
    db: &Db,
    target: &str,
    rustc_version: &str,
) -> Result<u64, DbError> {
    db.query(
        "SELECT COUNT(*) FROM artifacts \
         WHERE target = ? AND rustc_version = ? AND bundle_digest != '' \
               AND min_glibc IS NULL",
    )
    .bind(target)
    .bind(rustc_version)
    .fetch_scalar::<u64>()
    .await
    .map_err(|error| DbError::Query(format!("unmeasured count query: {error}")))
}

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

/// Delete every catalog row built by `rustc_version` — the mutation half
/// of `artifacts prune`. Returns the deleted row count.
pub async fn delete_artifacts_for_rustc(db: &Db, rustc_version: &str) -> Result<u32, DbError> {
    validate_rustc_version(rustc_version)?;
    // `RETURNING` carries the deleted rows' identities inside the one
    // statement — the billed `rows_written` would include the indexes'
    // writes, and `changes()` cannot be used: every D1 query is its own
    // async request, so a follow-up `SELECT changes()` is not provably
    // the DELETE's count.
    let deleted = db
        .query("DELETE FROM artifacts WHERE rustc_version = ? RETURNING c_metadata")
        .bind(rustc_version)
        .fetch_scalars::<String>()
        .await
        .map_err(|error| DbError::Query(format!("delete artifacts for rustc: {error}")))?;
    u32::try_from(deleted.len())
        .map_err(|_| DbError::Invariant(format!("deleted row count {} exceeds u32", deleted.len())))
}

/// The subset of `identities` the catalog serves: servable rows (each
/// with a published bundle) exist for the exact crate, version, features,
/// target and rustc at every unit shape the identity's side requires —
/// see `required_unit_shapes`: a host-side identity is covered only when
/// the slice serves both the native-shape and the `--target`-shape host
/// units its consumers' builds look up. One `IN (VALUES ...)` statement
/// per batch of twenty identities keeps every statement at D1's
/// 100-bound-parameter ceiling (five params per identity); the floor and
/// shape filters apply in memory, on the rows the semantic match
/// returned.
///
/// The batches are independent reads, so they issue concurrently under
/// the invocation's outbound ceiling
/// ([`crate::fetch_guard::MAX_OUTBOUND_INFLIGHT`]) rather than serially:
/// a claim page over twenty identities would otherwise pay one catalog
/// round trip per batch while its invocation sits open, on a latency its
/// frontier size alone sets. Each batch's covered set unions into the
/// result — `buffer_unordered` completion order cannot leak into a
/// `BTreeSet` merge.
///
/// A measured glibc floor above [`stow_types::glibc::GLIBC_BASELINE`]
/// breaks servability on a baseline host — the row publishes, but the
/// pending rebuild that exists to replace it must not be retired as
/// covered. Floors compare as `GlibcVersion`, never as text (`'2.4'`
/// sorts above `'2.28'`); an unmeasured (NULL) row covers as before.
/// Rows registered before the unit shape columns existed carry `-1` —
/// shapeless, they match no required shape and the identity stays
/// uncovered until the node rebuilds and re-registers.
pub async fn covered_semantic_identities(
    db: &Db,
    identities: &[SemanticTaskIdentity],
) -> Result<BTreeSet<SemanticTaskIdentity>, DbError> {
    const PARAMS_PER_IDENTITY: usize = 5;
    const BATCH: usize = sql_batch::D1_MAX_BOUND_PARAMS / PARAMS_PER_IDENTITY;
    // Each batch future owns its `Db` clone and `Vec` of identities, so
    // the oracle's `impl Future + Send` proof rests on owned data and
    // never on the chunk borrows' lifetimes. Ownership stays bounded:
    // the stream materializes one chunk at a time, so live owned data
    // never exceeds the buffer's active futures.
    stream::iter(
        identities
            .chunks(BATCH)
            .map(<[SemanticTaskIdentity]>::to_vec),
    )
    .map(|batch| covered_batch(db.clone(), batch))
    .buffer_unordered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
    .try_fold(BTreeSet::new(), |mut covered, batch_covered| async move {
        covered.extend(batch_covered);
        Ok::<BTreeSet<SemanticTaskIdentity>, DbError>(covered)
    })
    .await
}

/// One coverage batch, run as a unit of
/// [`covered_semantic_identities`]' bounded fan-out: query, fetch and
/// the pure fold are per-batch independent, so each future yields the
/// subset of `batch` the catalog covers.
async fn covered_batch(
    db: Db,
    batch: Vec<SemanticTaskIdentity>,
) -> Result<BTreeSet<SemanticTaskIdentity>, DbError> {
    let sql = format!(
        "SELECT crate_name, version, features_json, target, rustc_version, min_glibc, \
                unit_side, unit_invocation, unit_linked \
         FROM artifacts \
         WHERE bundle_digest != '' \
           AND (crate_name, version, features_json, target, rustc_version) IN (VALUES {})",
        sql_batch::values_rows("(?, ?, ?, ?, ?)", batch.len())
    );
    let mut query = db.query(&sql);
    for identity in &batch {
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
    // Rows are the semantic matches; coverage requires every shape
    // the identity's side needs, and every contributing row must be
    // loadable on a baseline host — an over-floor row serves nothing.
    let mut shapes_by_identity =
        BTreeMap::<(String, String, String, String, String), BTreeSet<UnitShape>>::new();
    for row in rows {
        let floor = decode_min_glibc(row.min_glibc.as_deref()).map_err(|error| {
            DbError::Invariant(format!(
                "artifact row {}/{}: min_glibc: {error}",
                row.target, row.rustc_version
            ))
        })?;
        if floor.is_some_and(|floor| floor > stow_types::glibc::GLIBC_BASELINE) {
            continue;
        }
        if let Some(shape) = decode_unit_shape(row.unit_side, row.unit_invocation, row.unit_linked)
            .map_err(|error| {
                DbError::Invariant(format!(
                    "artifact row {}/{}: {error}",
                    row.target, row.rustc_version
                ))
            })?
        {
            shapes_by_identity
                .entry((
                    row.crate_name,
                    row.version,
                    row.features_json,
                    row.target,
                    row.rustc_version,
                ))
                .or_default()
                .insert(shape);
        }
    }
    let mut covered = BTreeSet::new();
    for identity in batch {
        // The invocation the identity's own task spells: native on
        // the runner family's host triple, `--target` otherwise. A
        // host-side identity needs every consumer shape regardless.
        let invocation = stow_types::api::runner_family(identity.target.as_str())
            .map_or(UnitInvocation::Target, |family| {
                UnitInvocation::for_task(identity.target.as_str(), family.host_triple())
            });
        let required = required_unit_shapes(identity.host_side, invocation);
        let covered_all = required.iter().all(|shape| {
            shapes_by_identity
                .get(&(
                    identity.crate_name.clone(),
                    identity.version.clone(),
                    identity.features_json.clone(),
                    identity.target.clone(),
                    identity.rustc_version.clone(),
                ))
                .is_some_and(|shapes| shapes.contains(shape))
        });
        if covered_all {
            covered.insert(identity);
        }
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
    unit_side: i64,
    unit_invocation: i64,
    unit_linked: i64,
    min_glibc: Option<String>,
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
            "SELECT crate_name, version, features_json, target, rustc_version, host_side, seen_count, depends_on_json \
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
               AND host_side = ? AND queued_at IS NULL",
        )
        .bind(row.crate_name.as_str())
        .bind(row.version.as_str())
        .bind(row.features_json.as_str())
        .bind(row.target.as_str())
        .bind(row.rustc_version.as_str())
        .bind(row.host_side)
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
        let depends_on: Vec<stow_types::api::EnqueueDependency> =
            serde_json::from_str(row.depends_on_json.as_str())
                .map_err(|error| format!("draining miss depends_on_json: {error}"))?;
        // stow#588 edge-placeholder: the miss table stores only direct
        // dep edges, so the subgraph is the leaf-only shape it can
        // carry (the scheduler storage rework owns recording the full
        // closure); the request derives its edges and digest from it.
        let dependency_subgraph = stow_types::api::TaskSubgraph {
            root_deps: (0..depends_on.len() as u32).collect(),
            nodes: depends_on
                .iter()
                .map(|dep| stow_types::api::SubgraphNode {
                    crate_name: dep.crate_name.clone(),
                    version: dep.version.clone(),
                    features_json: dep.features_json.clone(),
                    host_side: dep.host_side,
                    deps: Vec::new(),
                })
                .collect(),
        };
        requests.push(EnqueueRequest {
            crate_name,
            version,
            features_json,
            target,
            rustc_version,
            downloads: row.seen_count,
            source: stow_types::api::EnqueueSource::CacheMiss,
            dependency_subgraph,
            preserve_lockfile: false,
            host_side: row.host_side != 0,
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
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? \
           AND host_side = ?"
    } else {
        "UPDATE dependency_graph_misses \
         SET queued_at = NULL \
         WHERE crate_name = ? AND version = ? AND features_json = ? AND target = ? AND rustc_version = ? \
           AND host_side = ?"
    };
    for request in requests {
        db.query(sql)
            .bind(request.crate_name.as_str())
            .bind(request.version.to_string())
            .bind(request.features_json.raw())
            .bind(request.target.as_str())
            .bind(request.rustc_version.as_str())
            .bind(i64::from(request.host_side))
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
    let depends_on = request
        .depends_on()
        .map_err(|error| format!("derive admitted miss depends_on: {error}"))?;
    let depends_on_json = serde_json::to_string(&depends_on)
        .map_err(|error| format!("serialize admitted miss depends_on: {error}"))?;
    db.query(
        "INSERT INTO dependency_graph_misses \
         (crate_name, version, features_json, target, rustc_version, host_side, depends_on_json, seen_count, first_seen_at, last_seen_at, admitted_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'), datetime('now')) \
         ON CONFLICT(crate_name, version, features_json, target, rustc_version, host_side) \
         DO UPDATE SET seen_count = seen_count + 1, last_seen_at = datetime('now'), admitted_at = datetime('now'), \
             depends_on_json = CASE WHEN excluded.depends_on_json IN ('', '[]') \
                 THEN dependency_graph_misses.depends_on_json \
                 ELSE excluded.depends_on_json END",
    )
    .bind(request.crate_name.as_str())
    .bind(request.version.to_string())
    .bind(request.features_json.raw())
    .bind(request.target.as_str())
    .bind(request.rustc_version.as_str())
    .bind(i64::from(request.host_side))
    .bind(depends_on_json)
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
        include_str!("../migrations/0007_miss_depends_on.sql"),
        include_str!("../migrations/0008_min_glibc.sql"),
        include_str!("../migrations/0009_unit_shape.sql"),
        include_str!("../migrations/0010_miss_host_side.sql"),
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
        apply_migrations, artifact_index_page, artifact_record as fetch_artifact_record,
        covered_semantic_identities, insert_artifact_records, record_admitted_miss,
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
        artifact_record_with(C_METADATA, oci_digest)
    }

    fn artifact_record_with(c_metadata: &str, oci_digest: &str) -> ArtifactRecord {
        ArtifactRecord {
            dependency_identity: None,
            compile_key: format!("{c_metadata}{c_metadata}"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            extra_filename: format!("-{c_metadata}"),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            unit_shape: None,
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
            min_glibc: None,
        }
    }

    fn enqueue_request(crate_name: &str, version: &str, features: &[&str]) -> EnqueueRequest {
        EnqueueRequest {
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
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
            preserve_lockfile: false,
            host_side: false,
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
        let mut request = enqueue_request("serde", "1.0.5", &["derive"]);
        // stow#317: the recorded miss keeps the edges the admitting
        // request carried so the drain re-mints it with them.
        request.dependency_subgraph = stow_types::api::TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![stow_types::api::SubgraphNode {
                crate_name: CrateName::parse("syn").expect("dep name"),
                version: CrateVersion::new(semver::Version::parse("3.0.6").expect("dep version")),
                features_json: FeaturesJson::canonicalize(vec!["derive".to_owned()])
                    .expect("dep features"),
                host_side: false,
                deps: Vec::new(),
            }],
        };

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
        assert_eq!(
            drained[0].depends_on().expect("drained deps"),
            request.depends_on().expect("request deps")
        );
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

    /// A host miss and a target miss at one semantic identity are two
    /// nodes: neither upserts the other, and each drains as its own
    /// side (stow#367 — the 5-tuple primary key used to merge them and
    /// re-mint whichever lost the collision as `host_side: false`).
    #[tokio::test]
    async fn host_and_target_misses_at_one_identity_drain_as_both_sides() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let mut request = enqueue_request("heck", "0.5.0", &[]);
        let mut host_request = request.clone();
        host_request.host_side = true;
        request.dependency_subgraph = stow_types::api::TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![stow_types::api::SubgraphNode {
                crate_name: CrateName::parse("heck").expect("dep name"),
                version: CrateVersion::new(semver::Version::parse("0.5.0").expect("dep version")),
                features_json: FeaturesJson::canonicalize(Vec::new()).expect("dep features"),
                host_side: true,
                deps: Vec::new(),
            }],
        };

        record_admitted_miss(&db, &request)
            .await
            .expect("record target-side miss");
        record_admitted_miss(&db, &host_request)
            .await
            .expect("record host-side miss");

        assert_eq!(miss_count_where(&db, "1 = 1").await, 2);
        let mut drained = take_dependency_graph_misses(&db, 10)
            .await
            .expect("take misses");
        drained.sort_by_key(|drain| drain.host_side);
        assert_eq!(drained.len(), 2);
        assert!(!drained[0].host_side);
        assert!(drained[1].host_side);

        // The send-failure restore must also key on the side: restoring
        // the host request touches only the host row.
        set_dependency_graph_misses_queued(&db, &[drained[1].clone()], false)
            .await
            .expect("restore host row");
        assert_eq!(
            miss_count_where(&db, "host_side = 1 AND queued_at IS NULL").await,
            1
        );
        assert_eq!(
            miss_count_where(&db, "host_side = 0 AND queued_at IS NOT NULL").await,
            1
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
        // A target-side node is covered when both shapes its task
        // publishes are servable: the build unit and the check unit —
        // a second row at a different `c_metadata` (the check unit's
        // compile identity differs from the build unit's).
        let unit_shape = |kind| {
            Some(stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Target,
                invocation: stow_types::public_cache::UnitInvocation::Native,
                kind,
            })
        };
        let record = ArtifactRecord {
            unit_shape: unit_shape(stow_types::public_cache::UnitKind::Linked),
            ..record.clone()
        };
        let check_record = ArtifactRecord {
            c_metadata: CMetadata::parse("bbbb0000bbbb0000").expect("check c_metadata"),
            extra_filename: "-bbbb0000bbbb0000".to_owned(),
            compile_key: "checkcheckcheckcheck".to_owned(),
            emit: vec!["dep-info".to_owned(), "metadata".to_owned()],
            unit_shape: unit_shape(stow_types::public_cache::UnitKind::Unlinked),
            oci_reference: format!("{}.check", record.oci_reference),
            ..record.clone()
        };
        insert_artifact_records(&db, &[record.clone(), check_record])
            .await
            .expect("insert");
        let identity = |features_json: &str, target: &str| SemanticTaskIdentity {
            crate_name: record.crate_name.as_str().to_owned(),
            version: record.version.to_string(),
            features_json: features_json.to_owned(),
            target: target.to_owned(),
            rustc_version: RUSTC.to_owned(),
            host_side: false,
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

    /// A host-side node is covered only when the slice serves every
    /// host-unit shape — both kinds under both invocation spellings,
    /// since consumers on either spelling look host units up at
    /// different keys. One spelling alone leaves one consumer shape
    /// unserved.
    #[tokio::test]
    async fn covered_host_side_identity_needs_both_host_shapes() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let mut identity = SemanticTaskIdentity {
            crate_name: "heck".to_owned(),
            version: "0.5.0".to_owned(),
            features_json: "[]".to_owned(),
            target: TARGET.to_owned(),
            rustc_version: RUSTC.to_owned(),
            host_side: true,
        };

        let base = artifact_record(FIRST_DIGEST);
        let host_unit = |c_metadata: &str, invocation, kind| ArtifactRecord {
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            extra_filename: format!("-{c_metadata}"),
            compile_key: format!("{c_metadata}{c_metadata}"),
            crate_name: CrateName::parse("heck").expect("name"),
            version: CrateVersion::new(semver::Version::parse("0.5.0").expect("version")),
            features_json: FeaturesJson::canonicalize(Vec::<String>::new()).expect("features"),
            unit_shape: Some(stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Host,
                invocation,
                kind,
            }),
            oci_reference: format!("{}.{}", base.oci_reference, c_metadata),
            ..base.clone()
        };
        let native_invocation = stow_types::public_cache::UnitInvocation::Native;
        let target_invocation = stow_types::public_cache::UnitInvocation::Target;
        let linked = stow_types::public_cache::UnitKind::Linked;
        let unlinked = stow_types::public_cache::UnitKind::Unlinked;

        // One invocation spelling's pair covers neither the native nor
        // the `--target` consumer completely.
        insert_artifact_records(
            &db,
            &[
                host_unit("cccc0000cccc0000", target_invocation, linked),
                host_unit("cccc0000cccc0001", target_invocation, unlinked),
            ],
        )
        .await
        .expect("insert");
        assert_eq!(
            covered_semantic_identities(&db, std::slice::from_ref(&identity))
                .await
                .expect("coverage"),
            BTreeSet::new(),
            "the `--target` spelling alone does not serve a native consumer's host dep"
        );

        insert_artifact_records(
            &db,
            &[
                host_unit("cccc0000cccc0002", native_invocation, linked),
                host_unit("cccc0000cccc0003", native_invocation, unlinked),
            ],
        )
        .await
        .expect("insert");
        assert_eq!(
            covered_semantic_identities(&db, std::slice::from_ref(&identity))
                .await
                .expect("coverage"),
            BTreeSet::from([identity.clone()]),
            "both host shapes cover the host-side identity"
        );

        // A target-side identity over the same rows is not covered:
        // every row serves the host side, which the target side's
        // required set does not match.
        identity.host_side = false;
        assert_eq!(
            covered_semantic_identities(&db, std::slice::from_ref(&identity))
                .await
                .expect("coverage"),
            BTreeSet::new()
        );
    }

    /// A published row whose measured floor exceeds the builder baseline
    /// publishes in the index but is not servable on a baseline host —
    /// it must not count as coverage, or the retire oracle would kill
    /// the pending rebuild that exists to replace it. The compare is
    /// `GlibcVersion`, never text: `'2.4'` sorts above `'2.28'` as a
    /// string. An unmeasured NULL row covers as before.
    ///
    /// Coverage needs both rules at once: each identity's rows carry the
    /// two target-side shapes a native invocation requires, so only the
    /// floor distinguishes them.
    #[tokio::test]
    async fn over_floor_rows_do_not_cover_their_identity() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        apply_migrations(&db).await;
        let floor = |minor: u32| {
            Some(stow_types::glibc::GlibcVersion {
                major: 2,
                minor,
                patch: 0,
            })
        };
        // A target-side native identity is covered by the linked and
        // unlinked shapes together — each floor variant gets both rows.
        let shaped_pair =
            |c_metadata_prefix: &str, version: &str, min_glibc| -> Vec<ArtifactRecord> {
                [
                    stow_types::public_cache::UnitKind::Linked,
                    stow_types::public_cache::UnitKind::Unlinked,
                ]
                .iter()
                .enumerate()
                .map(|(i, kind)| ArtifactRecord {
                    c_metadata: CMetadata::parse(format!("{c_metadata_prefix}{i}"))
                        .expect("c_metadata"),
                    extra_filename: format!("-{c_metadata_prefix}{i}"),
                    compile_key: format!("{c_metadata_prefix}{i}{c_metadata_prefix}{i}"),
                    version: CrateVersion::new(semver::Version::parse(version).expect("version")),
                    unit_shape: Some(stow_types::public_cache::UnitShape {
                        side: stow_types::public_cache::UnitSide::Target,
                        invocation: stow_types::public_cache::UnitInvocation::Native,
                        kind: *kind,
                    }),
                    min_glibc,
                    oci_reference: format!(
                        "{}.{c_metadata_prefix}{i}",
                        artifact_record(FIRST_DIGEST).oci_reference
                    ),
                    ..artifact_record(FIRST_DIGEST)
                })
                .collect()
            };
        // Four identities at distinct floors: 2.39 (over), 2.28 (at
        // baseline), measured-no-floor (''), and NULL (unmeasured —
        // pre-column rows).
        let mut rows: Vec<ArtifactRecord> = Vec::new();
        rows.extend(shaped_pair("bbbbbbbbbbbbbbb", "1.0.0", floor(39)));
        rows.extend(shaped_pair("ccccccccccccccc", "1.0.1", floor(28)));
        rows.extend(shaped_pair("ddddddddddddddd", "1.0.2", None));
        rows.extend(shaped_pair("fffffffffffffff", "1.0.3", floor(39)));
        insert_artifact_records(&db, &rows).await.expect("insert");
        db.query("UPDATE artifacts SET min_glibc = NULL WHERE c_metadata LIKE 'fffffffffffffff%'")
            .execute()
            .await
            .expect("unmeasure the fourth identity's rows");
        // The over-floor identity also carries a baseline sibling pair:
        // coverage is any-servable-row per shape, so it covers after
        // all — only the 2.39-alone identity must not.
        insert_artifact_records(&db, &shaped_pair("999999999999999", "1.0.0", floor(28)))
            .await
            .expect("insert baseline sibling");

        let covered = covered_semantic_identities(
            &db,
            &[
                over_identity(),
                baseline_identity(),
                no_floor_identity(),
                null_identity(),
            ],
        )
        .await
        .expect("coverage");
        assert_eq!(
            covered.len(),
            4,
            "over-floor-alone, at-baseline, no-floor and NULL identities all cover — but see below"
        );

        // Removing the baseline sibling leaves the 1.0.0 identity with
        // only the 2.39 rows — now it must not cover.
        db.query("DELETE FROM artifacts WHERE c_metadata LIKE '999999999999999%'")
            .execute()
            .await
            .expect("drop sibling");
        let covered = covered_semantic_identities(
            &db,
            &[
                over_identity(),
                baseline_identity(),
                no_floor_identity(),
                null_identity(),
            ],
        )
        .await
        .expect("coverage");
        assert_eq!(covered.len(), 3);
        assert!(!covered.contains(&over_identity()));
    }

    fn over_identity() -> SemanticTaskIdentity {
        identity_at("1.0.0")
    }
    fn baseline_identity() -> SemanticTaskIdentity {
        identity_at("1.0.1")
    }
    fn no_floor_identity() -> SemanticTaskIdentity {
        identity_at("1.0.2")
    }
    fn null_identity() -> SemanticTaskIdentity {
        identity_at("1.0.3")
    }
    fn identity_at(version: &str) -> SemanticTaskIdentity {
        SemanticTaskIdentity {
            crate_name: "serde".to_owned(),
            version: version.to_owned(),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features")
                .raw(),
            target: TARGET.to_owned(),
            rustc_version: RUSTC.to_owned(),
            host_side: false,
        }
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

        insert_artifact_records(&db, &[artifact_record(FIRST_DIGEST)])
            .await
            .expect("insert");

        // Pin `created_at` to a sentinel so the assertion does not depend
        // on `datetime('now')` granularity.
        db.query("UPDATE artifacts SET created_at = '2001-02-03 04:05:06'")
            .execute()
            .await
            .expect("pin created_at");

        insert_artifact_records(&db, &[artifact_record(SECOND_DIGEST)])
            .await
            .expect("re-register");

        let rows = db
            .query("SELECT COUNT(*) FROM artifacts")
            .fetch_scalar::<u64>()
            .await
            .expect("row count");
        assert_eq!(rows, 1);

        let created_at = db
            .query("SELECT created_at FROM artifacts")
            .fetch_scalar::<String>()
            .await
            .expect("created_at");
        assert_eq!(created_at, "2001-02-03 04:05:06");

        let row = fetch_artifact_record(&db, TARGET, RUSTC, C_METADATA)
            .await
            .expect("lookup")
            .expect("row present");
        assert_eq!(row.oci_digest, SECOND_DIGEST);
        assert_eq!(row.crate_name.as_str(), "serde");
        assert_eq!(row.version.to_string(), "1.0.0");
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
            insert_artifact_records(&db, &[artifact_record_with(c_metadata, FIRST_DIGEST)])
                .await
                .expect("insert servable row");
        }
        let unbundled = "0f0f0f0f0f0f0f0f";
        insert_artifact_records(&db, &[artifact_record_with(unbundled, FIRST_DIGEST)])
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
/// Coverage-batch concurrency tests against a scripted `DbBackend`. The
/// question this module answers — do independent batches overlap, and is
/// the overlap bounded — is about when statements enter the backend,
/// which only a controlled fake reports deterministically: it counts
/// admissions and holds every query at one yield point, so a serial
/// caller peaks at one in-flight statement while the bounded fan-out
/// fills its ceiling — no timers, no network.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod coverage_concurrency_tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use skyzen_services::sql::{
        DbBackend, DbDialect, DbError as BackendError, DbExecResult, DbValue,
    };
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitSide};

    use crate::errors::DbError;
    use crate::fetch_guard::MAX_OUTBOUND_INFLIGHT;
    use crate::scheduler::queue::SemanticTaskIdentity;

    use super::covered_semantic_identities;

    /// A `DbBackend` that measures overlap: `in_flight` is bumped when
    /// a statement enters and released only after a yield point, so
    /// `max_in_flight` is the count of statements the caller held open
    /// at one instant.
    #[derive(Clone)]
    struct HeldBackend {
        state: Arc<HeldState>,
        response: HeldResponse,
    }

    #[derive(Default)]
    struct HeldState {
        /// Statements the caller issued.
        issued: AtomicUsize,
        /// Statements inside the backend right now.
        in_flight: AtomicUsize,
        /// The peak `in_flight` ever observed.
        max_in_flight: AtomicUsize,
    }

    /// What a held query answers once released.
    #[derive(Clone)]
    enum HeldResponse {
        /// Fail every query with a backend error.
        Fail,
        /// Answer every query with these rows verbatim.
        Rows(Vec<serde_json::Value>),
        /// Answer every bound identity with its covering shape pair —
        /// the unlinked and linked target-side rows a native
        /// invocation requires, synthesized per five-param tuple.
        ServeBound,
    }

    impl DbBackend for HeldBackend {
        fn dialect(&self) -> DbDialect {
            DbDialect::Sqlite
        }

        async fn query(
            &self,
            _query: &str,
            params: &[DbValue],
        ) -> Result<DbExecResult, BackendError> {
            let in_flight = self.state.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.state
                .max_in_flight
                .fetch_max(in_flight, Ordering::SeqCst);
            self.state.issued.fetch_add(1, Ordering::SeqCst);
            // Suspend so sibling batches reach admission before this
            // one completes — under a serial caller the next batch
            // cannot exist yet, so `in_flight` never passes 1.
            tokio::task::yield_now().await;
            self.state.in_flight.fetch_sub(1, Ordering::SeqCst);
            match &self.response {
                HeldResponse::Fail => Err(BackendError::Backend {
                    message: "d1 unavailable".to_owned(),
                    source: None,
                }),
                HeldResponse::Rows(rows) => Ok(DbExecResult {
                    rows: rows.clone(),
                    ..DbExecResult::default()
                }),
                HeldResponse::ServeBound => Ok(DbExecResult {
                    rows: covering_rows(params),
                    ..DbExecResult::default()
                }),
            }
        }

        fn execute(
            &self,
            _query: &str,
            _params: &[DbValue],
        ) -> impl std::future::Future<Output = Result<DbExecResult, BackendError>> + Send {
            std::future::ready(Err(BackendError::Backend {
                message: "coverage reads never execute".to_owned(),
                source: None,
            }))
        }
    }

    /// The two rows that cover one bound identity: a target-side
    /// identity's native invocation requires the unlinked and linked
    /// target shapes, so every five-param tuple maps to both.
    fn covering_rows(params: &[DbValue]) -> Vec<serde_json::Value> {
        let text = |value: &DbValue| match value {
            DbValue::Text(text) => text.clone(),
            _ => panic!("identity params bind as text"),
        };
        params
            .chunks(5)
            .flat_map(|bound| {
                [UnitKind::Unlinked, UnitKind::Linked].map(|kind| {
                    serde_json::json!({
                        "crate_name": text(&bound[0]),
                        "version": text(&bound[1]),
                        "features_json": text(&bound[2]),
                        "target": text(&bound[3]),
                        "rustc_version": text(&bound[4]),
                        "unit_side": UnitSide::Target.to_int(),
                        "unit_invocation": UnitInvocation::Native.to_int(),
                        "unit_linked": kind.to_int(),
                        "min_glibc": null,
                    })
                })
            })
            .collect()
    }

    fn held_db(response: HeldResponse) -> (skyzen_services::Db, Arc<HeldState>) {
        let backend = HeldBackend {
            state: Arc::new(HeldState::default()),
            response,
        };
        let state = Arc::clone(&backend.state);
        (skyzen_services::Db::new(backend), state)
    }

    fn identity(index: usize) -> SemanticTaskIdentity {
        SemanticTaskIdentity {
            crate_name: format!("crate{index}"),
            version: "1.0.0".to_owned(),
            features_json: "[]".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            rustc_version: "1.85.0".to_owned(),
            host_side: false,
        }
    }

    /// Twenty identities fit one batch; twenty-one force a second. Both
    /// batches must be inside the backend together — `max_in_flight`
    /// bumps on admission and releases only after the held query
    /// completes, so 2 proves overlap where a serial loop peaks at 1.
    /// Both batch results still merge into one covered set.
    #[tokio::test]
    async fn independent_batches_overlap_admission() {
        let (db, state) = held_db(HeldResponse::ServeBound);
        let identities: Vec<SemanticTaskIdentity> = (0..21).map(identity).collect();
        let covered = covered_semantic_identities(&db, &identities)
            .await
            .expect("coverage");
        assert_eq!(covered, identities.iter().cloned().collect::<BTreeSet<_>>());
        assert_eq!(
            state.issued.load(Ordering::SeqCst),
            2,
            "21 identities is exactly two 20-identity statements"
        );
        assert_eq!(
            state.max_in_flight.load(Ordering::SeqCst),
            2,
            "both batches were admitted before either completed"
        );
    }

    /// One hundred and one identities fan out to six batches: the peak
    /// admission equals the outbound ceiling — never more — and every
    /// batch's covered identities still merge into the result.
    #[tokio::test]
    async fn concurrency_stays_at_the_outbound_bound() {
        let (db, state) = held_db(HeldResponse::ServeBound);
        let identities: Vec<SemanticTaskIdentity> = (0..101).map(identity).collect();
        let covered = covered_semantic_identities(&db, &identities)
            .await
            .expect("coverage");
        assert_eq!(covered.len(), 101, "every served identity covers");
        assert_eq!(state.issued.load(Ordering::SeqCst), 6);
        assert_eq!(
            state.max_in_flight.load(Ordering::SeqCst),
            MAX_OUTBOUND_INFLIGHT,
            "peak in-flight statements hit the bound and never pass it"
        );
    }

    /// A backend failure still fails the whole lookup — the fan-out
    /// does not swallow the first error it meets.
    #[tokio::test]
    async fn a_failed_batch_fails_the_lookup() {
        let (db, _state) = held_db(HeldResponse::Fail);
        let identities: Vec<SemanticTaskIdentity> = (0..21).map(identity).collect();
        let error = covered_semantic_identities(&db, &identities)
            .await
            .expect_err("a failed query must fail the lookup");
        assert!(
            matches!(&error, DbError::Query(message) if message.contains("d1 unavailable")),
            "unexpected error: {error}"
        );
    }

    /// A corrupt unit-shape triplet stays an invariant error on
    /// whatever batch it lands in — the concurrent fold keeps the same
    /// failure contract the serial loop had.
    #[tokio::test]
    async fn a_corrupt_shape_row_fails_the_lookup() {
        let corrupt = serde_json::json!({
            "crate_name": "crate0",
            "version": "1.0.0",
            "features_json": "[]",
            "target": "x86_64-unknown-linux-gnu",
            "rustc_version": "1.85.0",
            "unit_side": 9,
            "unit_invocation": 0,
            "unit_linked": 0,
            "min_glibc": null,
        });
        let (db, _state) = held_db(HeldResponse::Rows(vec![corrupt]));
        let identities: Vec<SemanticTaskIdentity> = (0..21).map(identity).collect();
        let error = covered_semantic_identities(&db, &identities)
            .await
            .expect_err("a corrupt shape must fail the lookup");
        assert!(
            matches!(&error, DbError::Invariant(message) if message.contains("corrupt unit shape")),
            "unexpected error: {error}"
        );
    }

    /// Batches that answer no rows leave every identity uncovered —
    /// merging empty batch sets stays empty, and the statement count
    /// is still one per batch.
    #[tokio::test]
    async fn empty_batches_merge_to_no_coverage() {
        let (db, state) = held_db(HeldResponse::Rows(Vec::new()));
        let identities: Vec<SemanticTaskIdentity> = (0..41).map(identity).collect();
        let covered = covered_semantic_identities(&db, &identities)
            .await
            .expect("coverage");
        assert!(covered.is_empty());
        assert_eq!(state.issued.load(Ordering::SeqCst), 3);
    }
}
