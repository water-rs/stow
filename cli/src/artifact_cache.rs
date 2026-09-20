use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use fs2::FileExt;
use semver::Version;
use sqlx::FromRow;
use stow_types::artifact::{ArtifactKind, NativeArtifacts, NativeLib, OutDirFile, RustCrateType};
use stow_types::bundle::{
    ArtifactBundleFile, STOW_DYLIB_MEDIA_TYPE, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE,
    STOW_RMETA_MEDIA_TYPE, SigstoreSignature,
};
use stow_types::error::Context;
use stow_types::identity::{DependencyCMetadataJson, DependencyCompileKeyIdentity};
use stow_types::platform::Profile;
use stow_types::public_cache::{
    StableRegistryArtifactIdentity, normalized_cache_profile, stable_c_metadata_for_compile_key,
};
use stow_types::versioning::is_semver_compatible_upgrade;

use crate::config::StowConfig;
use crate::fetch::{
    ArtifactBundle, FetchRequest, SemanticFetchRequest, bundle_file_path,
    decode_bundle_output_bytes,
};
use crate::inject::parsed_with_stable_identity;
use crate::rustc_args::ParsedRustcArgs;
use crate::state_db::{db_int, now_millis};

const BUNDLES_DIR: &str = "bundles";
const NATIVE_DIR: &str = "native";
const NATIVE_OUT_DIR: &str = "native/out";
const VERSION_LEASES_DIR: &str = "leases";
const ARTIFACT_CACHE_LAYOUT_VERSION: &str = "v3";
/// `oci_reference`/`oci_digest` placeholder for local entries: the columns
/// are `NOT NULL` and describe the remote a remote bundle was fetched from,
/// which a locally-built artifact by definition never had.
const LOCAL_ENTRY_SENTINEL: &str = "local";

/// Where a cached artifact bundle came from.
///
/// `remote` entries were produced by trusted CI, pushed to the OCI registry,
/// and fetched through the signed-bundle path; they may carry sigstore
/// signatures and a verified trust marker. `local` entries were captured from
/// a rustc passthrough build on this machine: they share the same
/// `compile_key` / `c_metadata` identity space but are trusted by construction
/// — never signature-verified, never marked verified, and never uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactProvenance {
    Remote,
    Local,
}

impl ArtifactProvenance {
    /// Parse the persisted `provenance` column. An unrecognized value means
    /// the row was not written by this build, so fail fast rather than guess.
    pub fn from_column(value: &str) -> stow_types::error::Result<Self> {
        match value {
            "remote" => Ok(Self::Remote),
            "local" => Ok(Self::Local),
            other => Err(stow_types::stow_error!(
                "artifact cache entry has unknown provenance `{other}`"
            )),
        }
    }

    /// The persisted `provenance` column value.
    pub const fn as_column(self) -> &'static str {
        match self {
            Self::Remote => "remote",
            Self::Local => "local",
        }
    }
}

#[derive(Debug)]
pub struct RustcVersionLease {
    _file: File,
}

/// Everything the rustc wrapper resolved about a finished local build that
/// [`store_local_build_outputs`] needs to cache it under the same identity a
/// remote bundle would carry.
#[derive(Debug)]
pub struct LocalBuildArtifact {
    /// The compilation target triple.
    pub target: String,
    /// The rustc version that produced the outputs.
    pub rustc_version: String,
    /// The stable registry identity (`compile_key` + 16-hex `c_metadata`).
    pub identity: StableRegistryArtifactIdentity,
    /// Canonical features JSON as fed into the compile key.
    pub features_json: String,
    /// Canonical dependency `c_metadata` identities JSON.
    pub dependency_c_metadata_json: String,
    /// The crate's own build-script `OUT_DIR` (cargo exports it on the
    /// library's rustc invocation so `env!("OUT_DIR")` resolves in source),
    /// when the crate has a build script. `links=` crates keep their native
    /// products here — captured into the entry so a later hit replays them.
    pub build_script_out_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct CachedArtifactBundle {
    pub provenance: ArtifactProvenance,
    pub oci_reference: String,
    pub oci_digest: String,
    pub compile_key: String,
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub features_json: String,
    pub dependency_c_metadata_json: String,
    pub dependency_compile_keys_json: String,
    /// Compile time the publisher recorded for this artifact — `0` for
    /// locally produced entries, which carry no measurement.
    pub compile_millis: u64,
    /// Total bytes of the staged cache entry — what `stow stats` reports
    /// as downloaded bytes on a hit.
    pub size_bytes: u64,
    pub profile: Profile,
    pub emit: Vec<String>,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ArtifactBundleFile>,
    pub native: Option<NativeArtifacts>,
    pub sigstore_signatures: Vec<SigstoreSignature>,
    pub(crate) entry_dir: PathBuf,
    pub(crate) rustc_version: String,
    pub(crate) cache_key: String,
    pub(crate) verified_marker_version: Option<u8>,
    pub(crate) verified_marker_policy: Option<String>,
    pub(crate) _lease_lock: File,
}

impl CachedArtifactBundle {
    pub fn output_source_path(&self, file: &ArtifactBundleFile) -> PathBuf {
        self.entry_dir.join(bundle_file_path(&file.file_name))
    }

    pub fn native_output_source_path(&self, relative_path: &str) -> PathBuf {
        self.entry_dir.join(NATIVE_OUT_DIR).join(relative_path)
    }
}

#[tracing::instrument(name = "stow.cache.prepare_local", skip_all)]
pub async fn prepare_local_cache(
    config: &StowConfig,
    rustc_version: &str,
) -> stow_types::error::Result<RustcVersionLease> {
    let artifact_cache_root = config.artifact_cache_root();
    let purge_root = config.artifact_cache_purge_root();
    let rustc_version = rustc_version.to_owned();
    let connection = config.state_db_pool().await?;
    let active_rustc_version = sqlx::query_scalar::<_, String>(
        "SELECT value FROM metadata_values WHERE key = 'active_rustc_version'",
    )
    .fetch_optional(&connection)
    .await?;
    let active_version_matches = active_rustc_version.as_deref() == Some(rustc_version.as_str());
    let rustc_version_for_prepare = rustc_version.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare_local_cache_blocking(
            &artifact_cache_root,
            &purge_root,
            &rustc_version_for_prepare,
            active_version_matches,
        )
    })
    .await
    .wrap_err("join prepare_local_cache blocking task")??;
    if !active_version_matches {
        sqlx::query(
            "INSERT INTO metadata_values (key, value) VALUES ('active_rustc_version', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(&rustc_version)
        .execute(&connection)
        .await?;
    }
    let stale_dirs = prepared.stale_dirs;
    if !stale_dirs.is_empty() {
        spawn_purge_worker(stale_dirs)?;
    }
    Ok(prepared.version_lease)
}

#[tracing::instrument(name = "stow.cache.load_cached_bundle", skip_all)]
pub async fn load_cached_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    let version_dir = config.artifact_cache_version_dir(request.rustc_version);
    let entry_relative_dir = entry_relative_dir(request);
    let cache_key = cache_key(request);
    let rustc_version = request.rustc_version.to_owned();
    let entry_dir = version_dir.join(&entry_relative_dir);
    if !entry_dir.exists() {
        return Ok(None);
    }
    let lease_lock = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = cache_key.clone();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join load_cached_bundle lock task")??;
    if !entry_dir.exists() {
        return Ok(None);
    }

    let connection = config.state_db_pool().await?;
    touch_artifact_cache_entry(&connection, &rustc_version, &cache_key, now_millis()).await?;
    let entry = load_artifact_cache_entry(&connection, &rustc_version, &cache_key)
        .await?
        .ok_or_else(|| {
            stow_types::stow_error!(
                "artifact cache entry {cache_key} for rustc {rustc_version} is missing from the state database"
            )
        })?;
    let outputs = load_artifact_outputs(&connection, &rustc_version, &cache_key).await?;
    let sigstore_signatures =
        load_sigstore_signatures(&connection, &rustc_version, &cache_key).await?;
    let native = load_native_artifacts(&connection, &rustc_version, &cache_key).await?;
    let profile = serde_json::from_str::<Profile>(&entry.profile_json).wrap_err_with(|| {
        format!("parse artifact cache profile_json for rustc {rustc_version} cache key {cache_key}")
    })?;
    let emit = serde_json::from_str::<Vec<String>>(&entry.emit_json).wrap_err_with(|| {
        format!("parse artifact cache emit_json for rustc {rustc_version} cache key {cache_key}")
    })?;
    let kind = serde_json::from_str::<ArtifactKind>(&entry.kind_json).wrap_err_with(|| {
        format!("parse artifact cache kind_json for rustc {rustc_version} cache key {cache_key}")
    })?;
    let crate_types = serde_json::from_str::<Vec<RustCrateType>>(&entry.crate_types_json)
        .wrap_err_with(|| {
            format!(
                "parse artifact cache crate_types_json for rustc {rustc_version} cache key {cache_key}"
            )
        })?;
    Ok(Some(CachedArtifactBundle {
        provenance: ArtifactProvenance::from_column(&entry.provenance)?,
        oci_reference: entry.oci_reference,
        oci_digest: entry.oci_digest,
        compile_key: entry.compile_key,
        crate_name: entry.crate_name,
        crate_version: entry.crate_version,
        c_metadata: entry.c_metadata,
        features_json: entry.features_json,
        dependency_c_metadata_json: entry.dependency_c_metadata_json,
        dependency_compile_keys_json: entry.dependency_compile_keys_json,
        compile_millis: db_int(entry.compile_millis, "artifact cache entry compile_millis")?,
        size_bytes: db_int(entry.size_bytes, "artifact cache entry size_bytes")?,
        profile,
        emit,
        kind,
        crate_types,
        outputs,
        native,
        sigstore_signatures,
        entry_dir,
        rustc_version,
        cache_key,
        verified_marker_version: entry
            .verified_marker_version
            .and_then(|value| u8::try_from(value).ok()),
        verified_marker_policy: entry.verified_marker_policy,
        _lease_lock: lease_lock,
    }))
}

#[derive(Debug, Clone, FromRow)]
struct CompileKeyLookupRow {
    crate_name: String,
    target: String,
    c_metadata: String,
}

pub async fn load_cached_bundle_by_compile_key(
    config: &StowConfig,
    rustc_version: &str,
    compile_key: &str,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    let connection = config.state_db_pool().await?;
    let lookup = sqlx::query_as::<_, CompileKeyLookupRow>(
        "SELECT crate_name, target, c_metadata \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND compile_key = ?",
    )
    .bind(rustc_version)
    .bind(compile_key)
    .fetch_optional(&connection)
    .await?;
    let Some(lookup) = lookup else {
        return Ok(None);
    };

    load_cached_bundle(
        config,
        &FetchRequest {
            target: &lookup.target,
            rustc_version,
            c_metadata: &lookup.c_metadata,
            crate_name: &lookup.crate_name,
        },
    )
    .await
}

#[tracing::instrument(name = "stow.cache.load_semantic_cached_bundle", skip_all)]
pub async fn load_semantic_cached_bundle(
    config: &StowConfig,
    request: &SemanticFetchRequest,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    let connection = config.state_db_pool().await?;
    let profile_json = serde_json::to_string(&request.profile)?;
    let kind_json = serde_json::to_string(&request.kind)?;
    let crate_types_json = serde_json::to_string(&request.crate_types)?;
    let requested_version = Version::parse(&request.version)
        .wrap_err_with(|| format!("parse semantic cache request version {}", request.version))?;
    let rows = sqlx::query_as::<_, SemanticCacheCandidateRow>(
        "SELECT c_metadata, crate_version, emit_json \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND target = ? AND crate_name = ? AND features_json = ? \
           AND dependency_c_metadata_json = ? AND profile_json = ? AND kind_json = ? AND crate_types_json = ?",
    )
    .bind(&request.rustc_version)
    .bind(&request.target)
    .bind(&request.crate_name)
    .bind(&request.features_json)
    .bind(&request.dependency_c_metadata_json)
    .bind(profile_json)
    .bind(kind_json)
    .bind(crate_types_json)
    .fetch_all(&connection)
    .await?;
    let mut candidates = rows
        .into_iter()
        .filter_map(|row| {
            match semantic_candidate_from_row(row, &requested_version, &request.emit) {
                Ok(Some(candidate)) => Some(Ok(candidate)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| {
        right
            .version
            .cmp(&left.version)
            .then(left.emit_len.cmp(&right.emit_len))
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    let Some(candidate) = candidates.into_iter().next() else {
        return Ok(None);
    };
    load_cached_bundle(
        config,
        &FetchRequest {
            target: &request.target,
            rustc_version: &request.rustc_version,
            c_metadata: &candidate.c_metadata,
            crate_name: &request.crate_name,
        },
    )
    .await
}

pub async fn load_semantic_cached_bundle_candidates(
    config: &StowConfig,
    request: &SemanticFetchRequest,
) -> stow_types::error::Result<Vec<CachedArtifactBundle>> {
    let connection = config.state_db_pool().await?;
    let profile_json = serde_json::to_string(&request.profile)?;
    let kind_json = serde_json::to_string(&request.kind)?;
    let crate_types_json = serde_json::to_string(&request.crate_types)?;
    let requested_version = Version::parse(&request.version)
        .wrap_err_with(|| format!("parse semantic cache request version {}", request.version))?;
    let rows = sqlx::query_as::<_, SemanticCacheCandidateRow>(
        "SELECT c_metadata, crate_version, emit_json \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND target = ? AND crate_name = ? AND features_json = ? \
           AND profile_json = ? AND kind_json = ? AND crate_types_json = ?",
    )
    .bind(&request.rustc_version)
    .bind(&request.target)
    .bind(&request.crate_name)
    .bind(&request.features_json)
    .bind(profile_json)
    .bind(kind_json)
    .bind(crate_types_json)
    .fetch_all(&connection)
    .await?;
    let mut candidates = rows
        .into_iter()
        .filter_map(|row| {
            match semantic_candidate_from_row(row, &requested_version, &request.emit) {
                Ok(Some(candidate)) => Some(Ok(candidate)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| {
        right
            .version
            .cmp(&left.version)
            .then(left.emit_len.cmp(&right.emit_len))
            .then(left.c_metadata.cmp(&right.c_metadata))
    });

    let mut bundles = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if let Some(bundle) = load_cached_bundle(
            config,
            &FetchRequest {
                target: &request.target,
                rustc_version: &request.rustc_version,
                c_metadata: &candidate.c_metadata,
                crate_name: &request.crate_name,
            },
        )
        .await?
        {
            bundles.push(bundle);
        }
    }
    Ok(bundles)
}

pub async fn store_downloaded_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<CachedArtifactBundle> {
    let request = OwnedFetchRequest::from(request);
    let bundle = bundle.clone();
    let version_dir = config.artifact_cache_version_dir(&request.rustc_version);
    let bundles_dir = version_dir.join(BUNDLES_DIR);
    async_fs::create_dir_all(&bundles_dir)
        .await
        .wrap_err_with(|| format!("create bundle cache directory {}", bundles_dir.display()))?;

    let entry_relative_dir = entry_relative_dir_owned(&request);
    let entry_dir = version_dir.join(&entry_relative_dir);
    let entry_parent = entry_dir.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "artifact cache entry dir {} has no parent",
            entry_dir.display()
        )
    })?;
    async_fs::create_dir_all(entry_parent)
        .await
        .wrap_err_with(|| format!("create artifact cache parent {}", entry_parent.display()))?;
    let cache_key = cache_key_owned(&request);
    let connection = config.state_db_pool().await?;

    // Serialize writers on the fs2 entry lock: a concurrent local store or a
    // second download of the same identity must not interleave temp dirs or
    // row writes.
    let mut write_lease = acquire_entry_exclusive_lock_async(&version_dir, &cache_key).await?;
    let entry_has_row = loop {
        let existing =
            load_artifact_cache_entry(&connection, &request.rustc_version, &cache_key).await?;
        // Local-first: a self-produced entry already serves this identity, so
        // a later remote bundle must not displace it.
        if !local_entry_covers(existing.as_ref(), &entry_dir)? {
            break existing.is_some();
        }
        // The reload goes through the normal read path, which needs the
        // shared lock — the exclusive lock has to be dropped first or the
        // load deadlocks on itself.
        drop(write_lease);
        if let Some(cached) = load_existing_local_bundle(config, &connection, &request).await? {
            return Ok(cached);
        }
        // The entry vanished between the check and the reload (a concurrent
        // eviction raced us); re-lock and re-evaluate under the fresh lease.
        write_lease = acquire_entry_exclusive_lock_async(&version_dir, &cache_key).await?;
    };

    // A leftover entry dir with no row is a crashed writer's stage output:
    // it is not an entry, and must not be silently adopted by the row the
    // insert below is about to write.
    if !entry_has_row && entry_dir.exists() {
        remove_orphaned_entry_dir(entry_dir.clone()).await?;
    }

    let size_bytes = tokio::task::spawn_blocking({
        let entry_parent = entry_parent.to_path_buf();
        let entry_dir = entry_dir.clone();
        let bundle = bundle.clone();
        let c_metadata = request.c_metadata.clone();
        move || write_bundle_entry_blocking(&entry_parent, &entry_dir, &bundle, &c_metadata)
    })
    .await
    .wrap_err("join store_downloaded_bundle file task")??;

    replace_artifact_cache_metadata(
        &connection,
        &request.rustc_version,
        &cache_key,
        &path_to_string(&entry_relative_dir)?,
        size_bytes,
        now_millis(),
        &CacheEntryMetadata::remote(&bundle),
    )
    .await?;
    drop(write_lease);
    // Hold the shared lease BEFORE running eviction: `protected_key` only
    // shields the fresh entry from our own eviction pass, while the lease is
    // what stops a concurrent process's eviction from acquiring the
    // exclusive lock and deleting the entry we are about to hand out.
    let lease_lock = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = cache_key.clone();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join store_downloaded_bundle lock task")??;
    evict_entries(
        &connection,
        &request.rustc_version,
        &version_dir,
        config.artifact_cache_max_bytes,
        &cache_key,
    )
    .await?;
    Ok(CachedArtifactBundle {
        provenance: ArtifactProvenance::Remote,
        oci_reference: bundle.manifest.oci_reference.clone(),
        oci_digest: bundle.manifest.oci_digest.clone(),
        compile_key: bundle.manifest.config.compile_key.clone(),
        crate_name: bundle.manifest.config.crate_name.as_str().to_owned(),
        crate_version: bundle.manifest.config.crate_version.to_string(),
        c_metadata: bundle.manifest.config.c_metadata.as_str().to_owned(),
        features_json: bundle.manifest.config.features_json.raw(),
        dependency_c_metadata_json: bundle.manifest.config.dependency_c_metadata_json.raw(),
        dependency_compile_keys_json: bundle.manifest.config.dependency_compile_keys_json.clone(),
        compile_millis: bundle.manifest.config.compile_millis,
        size_bytes,
        profile: bundle.manifest.config.profile.clone(),
        emit: bundle.manifest.config.emit.clone(),
        kind: bundle.manifest.config.kind.clone(),
        crate_types: bundle.manifest.config.crate_types.clone(),
        outputs: bundle.manifest.config.outputs.clone(),
        native: bundle.manifest.config.native.clone(),
        sigstore_signatures: bundle.manifest.sigstore_signatures.clone(),
        entry_dir,
        rustc_version: request.rustc_version,
        cache_key,
        verified_marker_version: None,
        verified_marker_policy: None,
        _lease_lock: lease_lock,
    })
}

/// Cache the outputs of a successful rustc passthrough build under the same
/// identity a remote bundle would carry, so the next worktree / `cargo
/// clean` / branch switch hits the local entry instead of recompiling.
///
/// Returns `true` when an entry was written and `false` when there was
/// nothing worth storing — no restorable outputs, or an entry of either
/// provenance already covers the key.
///
/// Only clean builds are stored: the caller gates on rustc exit 0 and every
/// expected output must be present on disk. The entry is staged under a temp
/// name in the same directory and renamed into place, so readers never see a
/// half-written entry; concurrent writers serialize on the fs2 entry lock
/// rather than double-storing.
#[tracing::instrument(name = "stow.cache.store_local_build", skip_all, fields(crate_name = %parsed.crate_name))]
pub async fn store_local_build_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
) -> stow_types::error::Result<bool> {
    let stable_parsed = parsed_with_stable_identity(parsed, &build.identity);
    let outputs = local_build_output_specs(parsed, &stable_parsed)?;
    if outputs.is_empty() {
        return Ok(false);
    }
    for output in &outputs {
        if !output.source.exists() {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                output = %output.source.display(),
                "skipping local artifact cache store: expected rustc output is missing"
            );
            return Ok(false);
        }
    }

    let version_dir = config.artifact_cache_version_dir(&build.rustc_version);
    let entry_relative_dir = PathBuf::from(BUNDLES_DIR)
        .join(ARTIFACT_CACHE_LAYOUT_VERSION)
        .join(&build.target)
        .join(build.identity.c_metadata.as_str());
    let entry_dir = version_dir.join(&entry_relative_dir);
    let entry_parent = entry_dir.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "local artifact cache entry dir {} has no parent",
            entry_dir.display()
        )
    })?;
    async_fs::create_dir_all(entry_parent)
        .await
        .wrap_err_with(|| {
            format!(
                "create local artifact cache parent {}",
                entry_parent.display()
            )
        })?;
    let cache_key = artifact_cache_key(&build.target, build.identity.c_metadata.as_str());
    let connection = config.state_db_pool().await?;

    let write_lease = acquire_entry_exclusive_lock_async(&version_dir, &cache_key).await?;
    let existing = load_artifact_cache_entry(&connection, &build.rustc_version, &cache_key).await?;
    if let Some(entry) = existing.as_ref() {
        // Surface corrupt rows even when the entry is already covered.
        ArtifactProvenance::from_column(&entry.provenance)?;
        if entry_dir.exists() {
            // Another writer — a local store or a completed download — already
            // covers this identity; either provenance serves future hits.
            return Ok(false);
        }
    }
    if existing.is_none() && entry_dir.exists() {
        // Same orphan-dir rule as the download path: a leftover stage dir is
        // not an entry and must not be adopted by the row written below.
        remove_orphaned_entry_dir(entry_dir.clone()).await?;
    }

    let written = tokio::task::spawn_blocking({
        let entry_parent = entry_parent.to_path_buf();
        let entry_dir = entry_dir.clone();
        let crate_name = build.identity.crate_name.clone();
        let native_out_dir = build.build_script_out_dir.clone();
        move || {
            write_local_build_entry_blocking(
                &entry_parent,
                &entry_dir,
                &outputs,
                &crate_name,
                native_out_dir.as_deref(),
            )
        }
    })
    .await
    .wrap_err("join store_local_build_outputs file task")??;

    record_local_entry_metadata(
        &connection,
        parsed,
        build,
        &cache_key,
        &entry_relative_dir,
        &written,
    )
    .await?;
    drop(write_lease);

    // Same post-insert discipline as the download path: the new entry joins
    // the shared LRU budget immediately, protected from this eviction pass.
    evict_entries(
        &connection,
        &build.rustc_version,
        &version_dir,
        config.artifact_cache_max_bytes,
        &cache_key,
    )
    .await?;
    Ok(true)
}

/// Persist the `artifact_cache_entries` row for a freshly staged local entry:
/// local provenance, no signatures, no verified marker, and dependency
/// compile keys resolved against the entries that produced the deps.
async fn record_local_entry_metadata(
    connection: &sqlx::SqlitePool,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    cache_key: &str,
    entry_relative_dir: &Path,
    written: &LocalEntryWrite,
) -> stow_types::error::Result<()> {
    let dependency_compile_keys_json = resolve_dependency_compile_keys_json(
        connection,
        &build.rustc_version,
        &build.target,
        &build.dependency_c_metadata_json,
    )
    .await?;
    let profile = normalized_cache_profile(parsed)?;
    let kind = crate::parsed_artifact_kind(parsed)?;
    let crate_types = crate::parsed_crate_types(parsed)?;
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
    replace_artifact_cache_metadata(
        connection,
        &build.rustc_version,
        cache_key,
        &path_to_string(entry_relative_dir)?,
        written.size_bytes,
        now_millis(),
        &CacheEntryMetadata {
            oci_reference: LOCAL_ENTRY_SENTINEL,
            oci_digest: LOCAL_ENTRY_SENTINEL,
            provenance: ArtifactProvenance::Local,
            compile_key: &build.identity.compile_key,
            crate_name: build.identity.crate_name.as_str(),
            crate_version: build.identity.version.clone(),
            c_metadata: build.identity.c_metadata.as_str(),
            features_json: build.features_json.clone(),
            dependency_c_metadata_json: build.dependency_c_metadata_json.clone(),
            dependency_compile_keys_json: &dependency_compile_keys_json,
            compile_millis: 0,
            target: &build.target,
            profile: &profile,
            emit: &emit,
            kind: &kind,
            crate_types: &crate_types,
            outputs: &written.outputs,
            sigstore_signatures: &[],
            native: written.native.as_ref(),
        },
    )
    .await
}

pub async fn record_materialized_bundle_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let out_dir = parsed.out_dir.as_ref().ok_or_else(|| {
        stow_types::stow_error!("materialized bundle outputs require rustc --out-dir")
    })?;
    let connection = config.state_db_pool().await?;
    let updated_at_ms: i64 = db_int(now_millis(), "materialized output timestamp")?;
    let stable_c_metadata = stable_c_metadata_for_compile_key(&bundle.compile_key)?;
    let dependency_identity = stable_c_metadata.as_str();
    let stable_identity = StableRegistryArtifactIdentity {
        compile_key: bundle.compile_key.clone(),
        c_metadata: stable_c_metadata.clone(),
        extra_filename: format!("-{stable_c_metadata}"),
        crate_name: bundle.crate_name.clone(),
        version: bundle.crate_version.clone(),
    };
    let stable_parsed = parsed_with_stable_identity(parsed, &stable_identity);

    for file in &bundle.outputs {
        let output_path = crate::inject::expected_output_path(parsed, out_dir, file)?;
        record_materialized_output(
            &connection,
            &output_path,
            dependency_identity,
            updated_at_ms,
        )
        .await?;
        let original_path = crate::inject::original_output_path(out_dir, file)?;
        if original_path != output_path {
            record_materialized_output(
                &connection,
                &original_path,
                dependency_identity,
                updated_at_ms,
            )
            .await?;
        }
        let stable_output_path =
            crate::inject::expected_output_path(&stable_parsed, out_dir, file)?;
        if stable_output_path != output_path && stable_output_path != original_path {
            record_materialized_output(
                &connection,
                &stable_output_path,
                dependency_identity,
                updated_at_ms,
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn record_materialized_local_build_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    identity: &StableRegistryArtifactIdentity,
) -> stow_types::error::Result<()> {
    if parsed.c_metadata.is_none() {
        return Ok(());
    }
    if !parsed.is_restorable_artifact() {
        return Ok(());
    }

    let connection = config.state_db_pool().await?;
    let updated_at_ms: i64 = db_int(now_millis(), "materialized output timestamp")?;
    let dependency_identity = identity.c_metadata.as_str();
    let stable_parsed = parsed_with_stable_identity(parsed, identity);

    if let Some(path) = parsed.output_rlib_path() {
        record_materialized_output(&connection, &path, dependency_identity, updated_at_ms).await?;
    }
    if let Some(path) = stable_parsed.output_rlib_path() {
        record_materialized_output(&connection, &path, dependency_identity, updated_at_ms).await?;
    }
    if let Some(path) = parsed.output_rmeta_path() {
        record_materialized_output(&connection, &path, dependency_identity, updated_at_ms).await?;
    }
    if let Some(path) = stable_parsed.output_rmeta_path() {
        record_materialized_output(&connection, &path, dependency_identity, updated_at_ms).await?;
    }
    if let Some(path) = parsed
        .output_dynamic_library_path()
        .map_err(stow_types::error::Error::msg)?
    {
        record_materialized_output(&connection, &path, dependency_identity, updated_at_ms).await?;
        let stable_path = stable_parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "stable parsed rustc args are missing dynamic library path for crate {}",
                    stable_parsed.crate_name
                )
            })?;
        record_materialized_output(
            &connection,
            &stable_path,
            dependency_identity,
            updated_at_ms,
        )
        .await?;
    }

    Ok(())
}

pub async fn resolve_dependency_c_metadata_json(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Option<String>> {
    let connection = config.state_db_pool().await?;
    let mut identities = parsed
        .extern_crates
        .iter()
        .map(|extern_crate| {
            let path = path_to_string(&extern_crate.path)?;
            Ok((extern_crate.crate_name.clone(), path))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    identities.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut resolved = Vec::with_capacity(identities.len());
    for (crate_name, output_path) in identities {
        let c_metadata = sqlx::query_scalar::<_, String>(
            "SELECT c_metadata FROM materialized_outputs WHERE output_path = ?",
        )
        .bind(output_path)
        .fetch_optional(&connection)
        .await?;
        let Some(c_metadata) = c_metadata else {
            return Ok(None);
        };
        resolved.push(DependencyCMetadataIdentity {
            crate_name,
            c_metadata,
        });
    }

    Ok(Some(serde_json::to_string(&resolved)?))
}

async fn record_materialized_output(
    connection: &sqlx::SqlitePool,
    path: &Path,
    c_metadata: &str,
    updated_at_ms: i64,
) -> stow_types::error::Result<()> {
    sqlx::query(
        "INSERT INTO materialized_outputs (output_path, c_metadata, updated_at_ms) \
         VALUES (?, ?, ?) \
         ON CONFLICT(output_path) DO UPDATE SET \
             c_metadata = excluded.c_metadata, \
             updated_at_ms = excluded.updated_at_ms",
    )
    .bind(path_to_string(path)?)
    .bind(c_metadata)
    .bind(updated_at_ms)
    .execute(connection)
    .await?;
    Ok(())
}

pub async fn remove_cached_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> stow_types::error::Result<()> {
    let version_dir = config.artifact_cache_version_dir(request.rustc_version);
    let cache_key = cache_key(request);
    let rustc_version = request.rustc_version.to_owned();
    let connection = config.state_db_pool().await?;
    remove_cached_bundle_locked(&connection, &version_dir, &rustc_version, &cache_key).await
}

fn prepare_local_cache_blocking(
    artifact_cache_root: &Path,
    purge_root: &Path,
    rustc_version: &str,
    active_version_matches: bool,
) -> stow_types::error::Result<PreparedLocalCache> {
    std::fs::create_dir_all(artifact_cache_root).wrap_err_with(|| {
        format!(
            "create artifact cache root {}",
            artifact_cache_root.display()
        )
    })?;
    std::fs::create_dir_all(purge_root)
        .wrap_err_with(|| format!("create artifact purge root {}", purge_root.display()))?;
    let leases_root = artifact_cache_root.join(VERSION_LEASES_DIR);
    std::fs::create_dir_all(&leases_root)
        .wrap_err_with(|| format!("create artifact lease root {}", leases_root.display()))?;

    let version_dir = artifact_cache_root.join(rustc_version);
    std::fs::create_dir_all(version_dir.join(BUNDLES_DIR)).wrap_err_with(|| {
        format!(
            "create rustc artifact cache directory {}",
            version_dir.display()
        )
    })?;
    std::fs::create_dir_all(version_dir.join("locks")).wrap_err_with(|| {
        format!(
            "create rustc artifact cache lock directory {}",
            version_dir.display()
        )
    })?;
    let version_lease = RustcVersionLease {
        _file: acquire_version_shared_lock(&leases_root, rustc_version)?,
    };

    if active_version_matches {
        return Ok(PreparedLocalCache {
            stale_dirs: Vec::new(),
            version_lease,
        });
    }

    let mut stale_dirs = Vec::new();
    for entry in std::fs::read_dir(artifact_cache_root)
        .wrap_err_with(|| format!("read artifact cache root {}", artifact_cache_root.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        if file_name == rustc_version || file_name == VERSION_LEASES_DIR {
            continue;
        }
        let stale_path = entry.path();
        let stale_version = file_name.to_string_lossy().to_string();
        let Some(_stale_lease) = try_acquire_version_exclusive_lock(&leases_root, &stale_version)?
        else {
            continue;
        };
        let purge_path =
            purge_root.join(format!("{}-{}", file_name.to_string_lossy(), now_millis()));
        std::fs::rename(&stale_path, &purge_path).wrap_err_with(|| {
            format!(
                "move stale rustc cache directory {} to {}",
                stale_path.display(),
                purge_path.display()
            )
        })?;
        stale_dirs.push(purge_path);
    }

    Ok(PreparedLocalCache {
        stale_dirs,
        version_lease,
    })
}

fn write_bundle_entry_blocking(
    entry_parent: &Path,
    entry_dir: &Path,
    bundle: &ArtifactBundle,
    c_metadata: &str,
) -> stow_types::error::Result<u64> {
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("{c_metadata}-"))
        .tempdir_in(entry_parent)
        .wrap_err_with(|| format!("create temp cache directory for {}", entry_dir.display()))?;
    let size_bytes = write_downloaded_bundle_to_entry(tempdir.path(), bundle)?;
    if !entry_dir.exists() {
        if let Some(parent) = entry_dir.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create artifact cache parent {}", parent.display()))?;
        }
        std::fs::rename(tempdir.path(), entry_dir).wrap_err_with(|| {
            format!(
                "move artifact cache entry {} into place at {}",
                tempdir.path().display(),
                entry_dir.display()
            )
        })?;
    }
    Ok(size_bytes)
}

/// One rustc output file captured into a local cache entry.
struct LocalBuildOutput {
    /// Where the passthrough build wrote the artifact.
    source: PathBuf,
    /// The file name inside the entry's `files/` dir — the stable-name form
    /// a remote bundle would have carried.
    file_name: String,
    media_type: &'static str,
}

/// The files a local store captured into the staged entry, plus its size.
struct LocalEntryWrite {
    outputs: Vec<ArtifactBundleFile>,
    /// Build-script `OUT_DIR` products (`links=` crates), mirroring the
    /// native layer a remote bundle carries.
    native: Option<NativeArtifacts>,
    size_bytes: u64,
}

/// The artifacts a successful rustc invocation produced, paired with the
/// stable-name file names they carry inside the cache entry. The dep-info
/// file is not an output: like remote bundles it is synthesized on restore.
fn local_build_output_specs(
    parsed: &ParsedRustcArgs,
    stable_parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Vec<LocalBuildOutput>> {
    let mut outputs = Vec::new();
    if parsed.emit.contains("link") && parsed.produces_rlib() {
        outputs.push(LocalBuildOutput {
            source: parsed.output_rlib_path().ok_or_else(|| {
                stow_types::stow_error!(
                    "rlib output path unavailable for crate {}",
                    parsed.crate_name
                )
            })?,
            file_name: output_file_name(&stable_parsed.output_rlib_path().ok_or_else(|| {
                stow_types::stow_error!(
                    "stable rlib output path unavailable for crate {}",
                    stable_parsed.crate_name
                )
            })?)?,
            media_type: STOW_RLIB_MEDIA_TYPE,
        });
    }
    if parsed.emit.contains("metadata") {
        outputs.push(LocalBuildOutput {
            source: parsed.output_rmeta_path().ok_or_else(|| {
                stow_types::stow_error!(
                    "rmeta output path unavailable for crate {}",
                    parsed.crate_name
                )
            })?,
            file_name: output_file_name(&stable_parsed.output_rmeta_path().ok_or_else(|| {
                stow_types::stow_error!(
                    "stable rmeta output path unavailable for crate {}",
                    stable_parsed.crate_name
                )
            })?)?,
            media_type: STOW_RMETA_MEDIA_TYPE,
        });
    }
    if parsed.emit.contains("link") && parsed.produces_dynamic_library() {
        let source = parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "dynamic library output path unavailable for crate {}",
                    parsed.crate_name
                )
            })?;
        let file_name = output_file_name(
            &stable_parsed
                .output_dynamic_library_path()
                .map_err(stow_types::error::Error::msg)?
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "stable dynamic library output path unavailable for crate {}",
                        stable_parsed.crate_name
                    )
                })?,
        )?;
        outputs.push(LocalBuildOutput {
            source,
            file_name,
            media_type: match crate::parsed_artifact_kind(parsed)? {
                ArtifactKind::ProcMacro => STOW_PROC_MACRO_MEDIA_TYPE,
                ArtifactKind::Rlib | ArtifactKind::Dylib => STOW_DYLIB_MEDIA_TYPE,
            },
        });
    }
    Ok(outputs)
}

/// Stage a locally-built entry under a temp name and rename it into place.
/// Runs under the exclusive fs2 entry lock, so a partial stage never lands:
/// a failed stage drops the `TempDir`, and a crash between rename and row
/// insert leaves an orphan `entry_dir` the next store removes.
fn write_local_build_entry_blocking(
    entry_parent: &Path,
    entry_dir: &Path,
    outputs: &[LocalBuildOutput],
    crate_name: &str,
    native_out_dir: Option<&Path>,
) -> stow_types::error::Result<LocalEntryWrite> {
    let entry_name = entry_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            stow_types::stow_error!(
                "local artifact cache entry dir {} has no UTF-8 name",
                entry_dir.display()
            )
        })?;
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("{entry_name}-"))
        .tempdir_in(entry_parent)
        .wrap_err_with(|| {
            format!(
                "create temp local cache directory for {}",
                entry_dir.display()
            )
        })?;
    let files_dir = tempdir.path().join("files");
    std::fs::create_dir_all(&files_dir)
        .wrap_err_with(|| format!("create local cache entry files dir {}", files_dir.display()))?;

    let mut written_outputs = Vec::with_capacity(outputs.len());
    let mut size_bytes = 0u64;
    for output in outputs {
        let dest = files_dir.join(&output.file_name);
        reflink::reflink_or_copy(&output.source, &dest).wrap_err_with(|| {
            format!(
                "materialize {} into local cache entry",
                output.source.display()
            )
        })?;
        // Hash the staged bytes, not the source: the recorded digest must
        // describe what the entry actually holds.
        let (sha256, len) = sha256_file_bytes(&dest)?;
        size_bytes = size_bytes.saturating_add(len);
        written_outputs.push(ArtifactBundleFile {
            file_name: output.file_name.clone(),
            media_type: output.media_type.to_owned(),
            sha256,
        });
    }

    // `links=` crates keep their build-script products under OUT_DIR. Capture
    // and stage them exactly where a downloaded bundle's native layer lands,
    // so the restore path is identical for both provenances.
    let native = stow_types::native_capture::capture_native_artifacts(crate_name, native_out_dir)?;
    if let (Some(native), Some(out_dir)) = (native.as_ref(), native_out_dir) {
        let out_root = tempdir.path().join(NATIVE_OUT_DIR);
        for file in &native.out_dir_files {
            let source = out_dir.join(&file.relative_path);
            let dest = join_relative_path(&out_root, &file.relative_path)?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .wrap_err_with(|| format!("create native cache parent {}", parent.display()))?;
            }
            reflink::reflink_or_copy(&source, &dest).wrap_err_with(|| {
                format!(
                    "materialize native out-dir file {} into local cache entry",
                    source.display()
                )
            })?;
            size_bytes = size_bytes.saturating_add(dest.metadata().map_or(0, |meta| meta.len()));
        }
    }

    if !entry_dir.exists() {
        std::fs::rename(tempdir.path(), entry_dir).wrap_err_with(|| {
            format!(
                "move local artifact cache entry {} into place at {}",
                tempdir.path().display(),
                entry_dir.display()
            )
        })?;
    }
    Ok(LocalEntryWrite {
        outputs: written_outputs,
        native,
        size_bytes,
    })
}

/// Resolve `dependency_c_metadata_json` identities to the compile keys of
/// the cache entries that produced them, so a later hit can materialize a
/// dependency's original-named outputs through the closure path.
///
/// Dependencies without a cache entry — built locally but never stored —
/// are omitted rather than listed: a locally-produced artifact is never
/// uploaded, so recording its key would only set up a doomed remote fetch on
/// every hit. The dep's own outputs already sit in the shared `deps` dir.
async fn resolve_dependency_compile_keys_json(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    target: &str,
    dependency_c_metadata_json: &str,
) -> stow_types::error::Result<String> {
    let dependencies =
        serde_json::from_str::<Vec<stow_types::identity::DependencyCMetadataIdentity>>(
            dependency_c_metadata_json,
        )
        .wrap_err("parse dependency c_metadata identities")?;
    let dependencies = DependencyCMetadataJson::canonicalize(dependencies).map_err(|error| {
        stow_types::stow_error!("invalid dependency c_metadata identities: {error}")
    })?;
    let mut resolved = Vec::with_capacity(dependencies.entries().len());
    for dependency in dependencies.entries() {
        let compile_key = sqlx::query_scalar::<_, String>(
            "SELECT compile_key FROM artifact_cache_entries \
             WHERE rustc_version = ? AND target = ? AND c_metadata = ?",
        )
        .bind(rustc_version)
        .bind(target)
        .bind(dependency.c_metadata.as_str())
        .fetch_optional(connection)
        .await?;
        if let Some(compile_key) = compile_key {
            resolved.push(DependencyCompileKeyIdentity {
                crate_name: dependency.crate_name.clone(),
                compile_key,
            });
        }
    }
    serde_json::to_string(&DependencyCompileKeyIdentity::canonicalize_list(resolved))
        .wrap_err("serialize dependency compile keys")
}

fn output_file_name(path: &Path) -> stow_types::error::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "rustc output path {} has no UTF-8 file name",
                path.display()
            )
        })
}

fn sha256_file_bytes(path: &Path) -> stow_types::error::Result<(String, u64)> {
    let bytes = std::fs::read(path)
        .wrap_err_with(|| format!("read staged cache file {}", path.display()))?;
    Ok((
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
        bytes.len() as u64,
    ))
}

async fn remove_cached_bundle_locked(
    connection: &sqlx::SqlitePool,
    version_dir: &Path,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    let Some(entry) = load_artifact_cache_entry(connection, rustc_version, cache_key).await? else {
        return Ok(());
    };
    // Acquire the exclusive lock BEFORE deleting the row: if another process
    // holds a lease we bail with the entry fully intact, instead of having to
    // reconstruct the row (a reconstruction that historically drifted from
    // the canonical insert and silently dropped dependency metadata columns).
    let entry_dir = version_dir.join(&entry.relative_dir);
    let Some(eviction_lock) = tokio::task::spawn_blocking({
        let version_dir = version_dir.to_path_buf();
        let cache_key = cache_key.to_owned();
        move || try_acquire_entry_exclusive_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join remove_cached_bundle lock task")??
    else {
        return Err(stow_types::stow_error!(
            "artifact cache entry {cache_key} is in use by another stow process"
        ));
    };
    delete_artifact_cache_entry(connection, rustc_version, cache_key).await?;
    if entry_dir.exists() {
        tokio::task::spawn_blocking({
            let entry_dir = entry_dir.clone();
            move || {
                std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
                    format!("remove cached artifact entry {}", entry_dir.display())
                })
            }
        })
        .await
        .wrap_err("join remove_cached_bundle remove_dir task")??;
    }
    drop(eviction_lock);
    Ok(())
}

async fn evict_entries(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    version_dir: &Path,
    max_bytes: u64,
    protected_key: &str,
) -> stow_types::error::Result<()> {
    let mut entries = list_artifact_cache_entries(connection, rustc_version).await?;
    let mut total_bytes = entries
        .values()
        .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
    if total_bytes <= max_bytes {
        return Ok(());
    }

    let mut eviction_order = entries
        .iter()
        .filter(|(key, _)| key.as_str() != protected_key)
        .map(|(key, entry)| (key.clone(), entry.last_accessed_ms))
        .collect::<Vec<_>>();
    eviction_order.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));

    for (cache_key, _) in eviction_order {
        let Some(entry) = entries.remove(&cache_key) else {
            continue;
        };
        let Some(eviction_lock) = tokio::task::spawn_blocking({
            let version_dir = version_dir.to_path_buf();
            let cache_key = cache_key.clone();
            move || try_acquire_entry_exclusive_lock(&version_dir, &cache_key)
        })
        .await
        .wrap_err("join evict_entries lock task")??
        else {
            continue;
        };
        delete_artifact_cache_entry(connection, rustc_version, &cache_key).await?;
        let entry_dir = version_dir.join(&entry.relative_dir);
        if entry_dir.exists() {
            tokio::task::spawn_blocking({
                let entry_dir = entry_dir.clone();
                move || {
                    std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
                        format!("evict artifact cache entry {}", entry_dir.display())
                    })
                }
            })
            .await
            .wrap_err("join evict_entries remove_dir task")??;
        }
        drop(eviction_lock);
        total_bytes = total_bytes.saturating_sub(entry.size_bytes);
        if total_bytes <= max_bytes {
            return Ok(());
        }
    }

    if total_bytes > max_bytes
        && let Some(entry) = entries.remove(protected_key)
    {
        let Some(eviction_lock) = tokio::task::spawn_blocking({
            let version_dir = version_dir.to_path_buf();
            let protected_key = protected_key.to_owned();
            move || try_acquire_entry_exclusive_lock(&version_dir, &protected_key)
        })
        .await
        .wrap_err("join evict_entries protected lock task")??
        else {
            return Err(stow_types::stow_error!(
                "artifact cache is full and the protected entry {protected_key} is in use by another stow process"
            ));
        };
        delete_artifact_cache_entry(connection, rustc_version, protected_key).await?;
        let entry_dir = version_dir.join(&entry.relative_dir);
        if entry_dir.exists() {
            tokio::task::spawn_blocking({
                let entry_dir = entry_dir.clone();
                move || {
                    std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
                        format!(
                            "evict oversized protected artifact cache entry {}",
                            entry_dir.display()
                        )
                    })
                }
            })
            .await
            .wrap_err("join evict_entries protected remove_dir task")??;
        }
        drop(eviction_lock);
        return Err(stow_types::stow_error!(
            "artifact cache entry {protected_key} exceeds max local cache size {} bytes",
            max_bytes
        ));
    }

    Err(stow_types::stow_error!(
        "artifact cache is full but all eviction candidates are currently in use by other stow processes"
    ))
}

fn write_downloaded_bundle_to_entry(
    entry_dir: &Path,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<u64> {
    let mut total_bytes = 0u64;
    let output_files = bundle
        .manifest
        .config
        .outputs
        .iter()
        .map(|file| (bundle_file_path(&file.file_name), file))
        .collect::<BTreeMap<_, _>>();
    for (relative_path, contents) in &bundle.files {
        let path = join_relative_path(entry_dir, relative_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create cache parent {}", parent.display()))?;
        }
        let decoded = match output_files.get(relative_path) {
            Some(file) => decode_bundle_output_bytes(file, contents)?,
            None => contents.clone(),
        };
        std::fs::write(&path, &decoded)
            .wrap_err_with(|| format!("write cached bundle file {}", path.display()))?;
        total_bytes = total_bytes.saturating_add(decoded.len() as u64);
    }

    if let Some(native) = bundle.manifest.config.native.as_ref() {
        let archive_bytes = match bundle.manifest.config.native_archive.as_ref() {
            Some(file) => {
                let raw = bundle
                    .files
                    .get(&bundle_file_path(&file.file_name))
                    .ok_or_else(|| {
                        stow_types::stow_error!(
                            "bundle is missing native archive {}",
                            file.file_name
                        )
                    })?;
                Some(decode_bundle_output_bytes(file, raw)?)
            }
            None => None,
        };
        total_bytes = total_bytes.saturating_add(write_native_cache_entry(
            entry_dir,
            native,
            archive_bytes.as_deref(),
        )?);
    }

    Ok(total_bytes)
}

/// Unpack the bundle's native archive layer into the cache entry.
///
/// The archive is a tar of the build script's `OUT_DIR`, carried as its own
/// zstd layer. Every file the signed config lists is extracted and checked
/// against the digest recorded there, so a tampered or truncated archive
/// cannot quietly produce a short `OUT_DIR`.
fn write_native_cache_entry(
    entry_dir: &Path,
    native: &NativeArtifacts,
    archive_bytes: Option<&[u8]>,
) -> stow_types::error::Result<u64> {
    let native_root = entry_dir.join(NATIVE_DIR);
    let out_root = native_root.join("out");
    std::fs::create_dir_all(&out_root)
        .wrap_err_with(|| format!("create native cache root {}", native_root.display()))?;

    if native.out_dir_files.is_empty() {
        return Ok(0);
    }
    let Some(archive_bytes) = archive_bytes else {
        return Err(stow_types::stow_error!(
            "bundle declares {} native out-dir files but carries no native archive",
            native.out_dir_files.len()
        ));
    };

    let expected = native
        .out_dir_files
        .iter()
        .map(|file| (file.relative_path.as_str(), file.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut written = BTreeSet::new();
    let mut total_bytes = 0u64;
    let mut archive = tar::Archive::new(std::io::Cursor::new(archive_bytes));
    for entry in archive.entries().wrap_err("read native archive entries")? {
        let mut entry = entry.wrap_err("read native archive entry")?;
        let relative_path = entry
            .path()
            .wrap_err("read native archive entry path")?
            .to_string_lossy()
            .into_owned();
        let Some(expected_sha256) = expected.get(relative_path.as_str()) else {
            return Err(stow_types::stow_error!(
                "native archive contains {relative_path}, which the signed config does not list"
            ));
        };
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut contents)
            .wrap_err_with(|| format!("read native archive entry {relative_path}"))?;
        let actual_sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&contents));
        if actual_sha256 != *expected_sha256 {
            return Err(stow_types::stow_error!(
                "native archive entry {relative_path} does not match its recorded digest"
            ));
        }
        let path = join_relative_path(&out_root, &relative_path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create native cache parent {}", parent.display()))?;
        }
        std::fs::write(&path, &contents)
            .wrap_err_with(|| format!("write native cache file {}", path.display()))?;
        total_bytes = total_bytes.saturating_add(contents.len() as u64);
        written.insert(relative_path);
    }

    if written.len() != expected.len() {
        return Err(stow_types::stow_error!(
            "native archive carries {} of the {} out-dir files the signed config lists",
            written.len(),
            expected.len()
        ));
    }

    Ok(total_bytes)
}

fn join_relative_path(root: &Path, relative_path: &str) -> stow_types::error::Result<PathBuf> {
    let path = Path::new(relative_path);
    if relative_path.is_empty()
        || !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(stow_types::stow_error!(
            "invalid relative cache path {relative_path}"
        ));
    }
    Ok(root.join(path))
}

fn cache_key(request: &FetchRequest<'_>) -> String {
    format!(
        "{}/{}/{}",
        ARTIFACT_CACHE_LAYOUT_VERSION, request.target, request.c_metadata
    )
}

fn cache_key_owned(request: &OwnedFetchRequest) -> String {
    format!(
        "{}/{}/{}",
        ARTIFACT_CACHE_LAYOUT_VERSION, request.target, request.c_metadata
    )
}

fn entry_relative_dir(request: &FetchRequest<'_>) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
        .join(ARTIFACT_CACHE_LAYOUT_VERSION)
        .join(request.target)
        .join(request.c_metadata)
}

fn entry_relative_dir_owned(request: &OwnedFetchRequest) -> PathBuf {
    PathBuf::from(BUNDLES_DIR)
        .join(ARTIFACT_CACHE_LAYOUT_VERSION)
        .join(&request.target)
        .join(&request.c_metadata)
}

fn path_to_string(path: &Path) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("path {} is not UTF-8", path.display()))
}

fn acquire_version_shared_lock(
    leases_root: &Path,
    rustc_version: &str,
) -> stow_types::error::Result<File> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open version lease {}", lock_path.display()))?;
    file.lock_shared()
        .wrap_err_with(|| format!("lock version lease {}", lock_path.display()))?;
    Ok(file)
}

/// Whether a `try_lock_exclusive` failure means another process holds the
/// lock. The platform error differs (`EWOULDBLOCK` on Unix,
/// `ERROR_LOCK_VIOLATION` on Windows, which maps to no `ErrorKind`), so the
/// comparison goes through fs2's own contended-error value.
fn is_lock_contended(error: &std::io::Error) -> bool {
    error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

fn try_acquire_version_exclusive_lock(
    leases_root: &Path,
    rustc_version: &str,
) -> stow_types::error::Result<Option<File>> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open stale version lease {}", lock_path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if is_lock_contended(&error) => Ok(None),
        Err(error) => Err(stow_types::stow_error!(
            "lock stale version lease {}: {error}",
            lock_path.display()
        )),
    }
}

fn version_lease_path(leases_root: &Path, rustc_version: &str) -> PathBuf {
    leases_root.join(format!("{rustc_version}.lock"))
}

fn acquire_entry_shared_lock(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<File> {
    let lock_path = entry_lock_path(version_dir, cache_key);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create cache lock parent {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open cache lease lock {}", lock_path.display()))?;
    file.lock_shared()
        .wrap_err_with(|| format!("lock cache lease {}", lock_path.display()))?;
    Ok(file)
}

fn acquire_entry_exclusive_lock(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<File> {
    let lock_path = entry_lock_path(version_dir, cache_key);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create cache lock parent {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open cache write lock {}", lock_path.display()))?;
    file.lock_exclusive()
        .wrap_err_with(|| format!("lock cache entry writer {}", lock_path.display()))?;
    Ok(file)
}

async fn acquire_entry_exclusive_lock_async(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<File> {
    tokio::task::spawn_blocking({
        let version_dir = version_dir.to_path_buf();
        let cache_key = cache_key.to_owned();
        move || acquire_entry_exclusive_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join entry exclusive lock task")?
}

/// Under a held exclusive entry lock: does a local entry already cover this
/// identity? The `entry_dir.exists()` conjunct matters — a local row whose
/// directory was pruned underneath us does not shield the store.
fn local_entry_covers(
    existing: Option<&ArtifactCacheEntryRow>,
    entry_dir: &Path,
) -> stow_types::error::Result<bool> {
    match existing {
        Some(entry) => Ok(ArtifactProvenance::from_column(&entry.provenance)?
            == ArtifactProvenance::Local
            && entry_dir.exists()),
        None => Ok(false),
    }
}

/// Reload the local entry that already covers `request` through the shared
/// read path. `None` means the entry vanished between the existence check
/// and the reload — a concurrent eviction raced us.
async fn load_existing_local_bundle(
    config: &StowConfig,
    connection: &sqlx::SqlitePool,
    request: &OwnedFetchRequest,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    let Some(existing) = load_artifact_cache_entry(
        connection,
        &request.rustc_version,
        &cache_key_owned(request),
    )
    .await?
    else {
        return Ok(None);
    };
    load_cached_bundle(
        config,
        &FetchRequest {
            target: &request.target,
            rustc_version: &request.rustc_version,
            c_metadata: &request.c_metadata,
            crate_name: &existing.crate_name,
        },
    )
    .await
}

/// A leftover entry dir with no row is a crashed writer's stage output: not
/// an entry, and never silently adopted by the row about to be written.
async fn remove_orphaned_entry_dir(entry_dir: PathBuf) -> stow_types::error::Result<()> {
    tokio::task::spawn_blocking(move || {
        std::fs::remove_dir_all(&entry_dir).wrap_err_with(|| {
            format!(
                "remove orphaned artifact cache entry dir {}",
                entry_dir.display()
            )
        })
    })
    .await
    .wrap_err("join orphaned entry cleanup task")?
}

fn try_acquire_entry_exclusive_lock(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<Option<File>> {
    let lock_path = entry_lock_path(version_dir, cache_key);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create cache lock parent {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open cache eviction lock {}", lock_path.display()))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error) if is_lock_contended(&error) => Ok(None),
        Err(error) => Err(stow_types::stow_error!(
            "lock cache eviction {}: {error}",
            lock_path.display()
        )),
    }
}

fn entry_lock_path(version_dir: &Path, cache_key: &str) -> PathBuf {
    let mut path = version_dir.join("locks").join(cache_key);
    path.set_extension("lock");
    path
}

fn spawn_purge_worker(paths: Vec<PathBuf>) -> stow_types::error::Result<()> {
    let current_exe = std::env::current_exe().wrap_err("resolve current stow executable")?;
    let mut command = std::process::Command::new(current_exe);
    command
        .arg("__purge-cache-dir")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for path in paths {
        command.arg(path);
    }
    command
        .spawn()
        .wrap_err("spawn detached artifact cache purge worker")?;
    Ok(())
}

#[derive(Debug, Clone)]
struct OwnedFetchRequest {
    target: String,
    rustc_version: String,
    c_metadata: String,
}

impl From<&FetchRequest<'_>> for OwnedFetchRequest {
    fn from(value: &FetchRequest<'_>) -> Self {
        Self {
            target: value.target.to_owned(),
            rustc_version: value.rustc_version.to_owned(),
            c_metadata: value.c_metadata.to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
struct ArtifactCacheIndexEntry {
    relative_dir: String,
    size_bytes: u64,
    last_accessed_ms: u64,
}

#[derive(Debug)]
struct PreparedLocalCache {
    stale_dirs: Vec<PathBuf>,
    version_lease: RustcVersionLease,
}

#[derive(Debug, Clone, FromRow)]
struct ArtifactCacheEntryRow {
    relative_dir: String,
    oci_reference: String,
    oci_digest: String,
    compile_key: String,
    crate_name: String,
    crate_version: String,
    c_metadata: String,
    features_json: String,
    dependency_c_metadata_json: String,
    dependency_compile_keys_json: String,
    compile_millis: i64,
    size_bytes: i64,
    profile_json: String,
    emit_json: String,
    kind_json: String,
    crate_types_json: String,
    verified_marker_version: Option<i64>,
    verified_marker_policy: Option<String>,
    provenance: String,
}

#[derive(Debug, Clone, FromRow)]
struct SemanticCacheCandidateRow {
    c_metadata: String,
    crate_version: String,
    emit_json: String,
}

#[derive(Debug, Clone)]
struct SemanticCacheCandidate {
    version: Version,
    c_metadata: String,
    emit_len: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DependencyCMetadataIdentity {
    crate_name: String,
    c_metadata: String,
}

#[derive(Debug, Clone, FromRow)]
struct OutputRow {
    file_name: String,
    media_type: String,
    sha256: String,
}

#[derive(Debug, Clone, FromRow)]
struct SigstoreSignatureRow {
    payload_path: String,
    signature: String,
    certificate_pem: String,
    rekor_bundle_json: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
struct NativeStaticLibRow {
    lib_name: String,
    bytes_sha256: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeDirectiveRow {
    directive: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeDepEnvVarRow {
    env_key: String,
    env_value: String,
}

#[derive(Debug, Clone, FromRow)]
struct NativeOutDirFileRow {
    relative_path: String,
    sha256: String,
}

async fn load_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<Option<ArtifactCacheEntryRow>> {
    sqlx::query_as::<_, ArtifactCacheEntryRow>(
        "SELECT relative_dir, oci_reference, oci_digest, \
                compile_key, crate_name, crate_version, c_metadata, features_json, dependency_c_metadata_json, dependency_compile_keys_json, \
                compile_millis, size_bytes, \
                profile_json, emit_json, kind_json, crate_types_json, \
                verified_marker_version, verified_marker_policy, provenance \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_optional(connection)
    .await
    .map_err(Into::into)
}

async fn list_artifact_cache_entries(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
) -> stow_types::error::Result<BTreeMap<String, ArtifactCacheIndexEntry>> {
    let rows = sqlx::query_as::<_, (String, String, i64, i64)>(
        "SELECT cache_key, relative_dir, size_bytes, last_accessed_ms \
         FROM artifact_cache_entries \
         WHERE rustc_version = ?",
    )
    .bind(rustc_version)
    .fetch_all(connection)
    .await?;
    let mut entries = BTreeMap::new();
    for (cache_key, relative_dir, size_bytes, last_accessed_ms) in rows {
        entries.insert(
            cache_key,
            ArtifactCacheIndexEntry {
                relative_dir,
                size_bytes: db_int(size_bytes, "artifact cache entry size_bytes")?,
                last_accessed_ms: db_int(
                    last_accessed_ms,
                    "artifact cache entry last_accessed_ms",
                )?,
            },
        );
    }
    Ok(entries)
}

fn semantic_candidate_from_row(
    row: SemanticCacheCandidateRow,
    requested_version: &Version,
    requested_emit: &[String],
) -> stow_types::error::Result<Option<SemanticCacheCandidate>> {
    let candidate_version = Version::parse(&row.crate_version)
        .wrap_err_with(|| format!("parse cached semantic crate version {}", row.crate_version))?;
    if candidate_version != *requested_version
        && !is_semver_compatible_upgrade(requested_version, &candidate_version)
    {
        return Ok(None);
    }
    let candidate_emit =
        serde_json::from_str::<Vec<String>>(&row.emit_json).wrap_err("parse cached emit_json")?;
    let candidate_emit_set = candidate_emit
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if !requested_emit
        .iter()
        .all(|requested| candidate_emit_set.contains(requested))
    {
        return Ok(None);
    }
    Ok(Some(SemanticCacheCandidate {
        version: candidate_version,
        c_metadata: row.c_metadata,
        emit_len: candidate_emit.len(),
    }))
}

async fn load_artifact_outputs(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<Vec<ArtifactBundleFile>> {
    let rows = sqlx::query_as::<_, OutputRow>(
        "SELECT file_name, media_type, sha256 \
         FROM artifact_cache_outputs \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ArtifactBundleFile {
            file_name: row.file_name,
            media_type: row.media_type,
            sha256: row.sha256,
        })
        .collect())
}

async fn load_sigstore_signatures(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<Vec<SigstoreSignature>> {
    let rows = sqlx::query_as::<_, SigstoreSignatureRow>(
        "SELECT payload_path, signature, certificate_pem, rekor_bundle_json \
         FROM artifact_cache_sigstore_signatures \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| SigstoreSignature {
            payload_path: row.payload_path,
            signature: row.signature,
            certificate_pem: row.certificate_pem,
            rekor_bundle_json: row.rekor_bundle_json,
        })
        .collect())
}

async fn load_native_artifacts(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<Option<NativeArtifacts>> {
    let static_lib_rows = sqlx::query_as::<_, NativeStaticLibRow>(
        "SELECT lib_name, bytes_sha256 \
         FROM artifact_cache_native_static_libs \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let directive_rows = sqlx::query_as::<_, NativeDirectiveRow>(
        "SELECT directive \
         FROM artifact_cache_native_directives \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let dep_env_rows = sqlx::query_as::<_, NativeDepEnvVarRow>(
        "SELECT env_key, env_value \
         FROM artifact_cache_native_dep_env_vars \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY env_key",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;
    let out_dir_rows = sqlx::query_as::<_, NativeOutDirFileRow>(
        "SELECT relative_path, sha256 \
         FROM artifact_cache_native_out_dir_files \
         WHERE rustc_version = ? AND cache_key = ? \
         ORDER BY ordinal",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .fetch_all(connection)
    .await?;

    if static_lib_rows.is_empty()
        && directive_rows.is_empty()
        && dep_env_rows.is_empty()
        && out_dir_rows.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(NativeArtifacts {
        static_libs: static_lib_rows
            .into_iter()
            .map(|row| NativeLib {
                name: row.lib_name,
                bytes_sha256: row.bytes_sha256,
            })
            .collect(),
        cargo_directives: directive_rows
            .into_iter()
            .map(|row| row.directive)
            .collect(),
        dep_env_vars: dep_env_rows
            .into_iter()
            .map(|row| (row.env_key, row.env_value))
            .collect(),
        out_dir_files: out_dir_rows
            .into_iter()
            .map(|row| OutDirFile {
                relative_path: row.relative_path,
                sha256: row.sha256,
            })
            .collect(),
    }))
}

/// The full row payload `artifact_cache_entries` plus its child tables store
/// for one cached bundle — the same shape whether the bundle was fetched
/// from the edge or produced by a local rustc build.
struct CacheEntryMetadata<'a> {
    oci_reference: &'a str,
    oci_digest: &'a str,
    provenance: ArtifactProvenance,
    compile_key: &'a str,
    crate_name: &'a str,
    crate_version: String,
    c_metadata: &'a str,
    features_json: String,
    dependency_c_metadata_json: String,
    dependency_compile_keys_json: &'a str,
    /// Publisher-recorded compile time; `0` for locally produced entries.
    compile_millis: u64,
    target: &'a str,
    profile: &'a Profile,
    emit: &'a [String],
    kind: &'a ArtifactKind,
    crate_types: &'a [RustCrateType],
    outputs: &'a [ArtifactBundleFile],
    sigstore_signatures: &'a [SigstoreSignature],
    native: Option<&'a NativeArtifacts>,
}

impl<'a> CacheEntryMetadata<'a> {
    /// Row payload for a verified remote bundle.
    fn remote(bundle: &'a ArtifactBundle) -> Self {
        Self {
            oci_reference: &bundle.manifest.oci_reference,
            oci_digest: &bundle.manifest.oci_digest,
            provenance: ArtifactProvenance::Remote,
            compile_key: &bundle.manifest.config.compile_key,
            crate_name: bundle.manifest.config.crate_name.as_str(),
            crate_version: bundle.manifest.config.crate_version.to_string(),
            c_metadata: bundle.manifest.config.c_metadata.as_str(),
            features_json: bundle.manifest.config.features_json.raw(),
            dependency_c_metadata_json: bundle.manifest.config.dependency_c_metadata_json.raw(),
            dependency_compile_keys_json: &bundle.manifest.config.dependency_compile_keys_json,
            compile_millis: bundle.manifest.config.compile_millis,
            target: bundle.manifest.config.target.as_str(),
            profile: &bundle.manifest.config.profile,
            emit: &bundle.manifest.config.emit,
            kind: &bundle.manifest.config.kind,
            crate_types: &bundle.manifest.config.crate_types,
            outputs: &bundle.manifest.config.outputs,
            sigstore_signatures: &bundle.manifest.sigstore_signatures,
            native: bundle.manifest.config.native.as_ref(),
        }
    }
}

async fn replace_artifact_cache_metadata(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    relative_dir: &str,
    size_bytes: u64,
    last_accessed_ms: u64,
    metadata: &CacheEntryMetadata<'_>,
) -> stow_types::error::Result<()> {
    upsert_artifact_cache_entry(
        connection,
        rustc_version,
        cache_key,
        relative_dir,
        size_bytes,
        last_accessed_ms,
        metadata,
    )
    .await?;
    delete_artifact_cache_children(connection, rustc_version, cache_key).await?;
    insert_artifact_cache_outputs(connection, rustc_version, cache_key, metadata.outputs).await?;
    insert_artifact_cache_sigstore_signatures(
        connection,
        rustc_version,
        cache_key,
        metadata.sigstore_signatures,
    )
    .await?;
    if let Some(native) = metadata.native {
        insert_artifact_cache_native(connection, rustc_version, cache_key, native).await?;
    }
    Ok(())
}

/// Insert or refresh the `artifact_cache_entries` row. A rewrite clears the
/// verified-trust marker columns: the marker attests to the bytes that were
/// verified, and a replacement entry has not been verified yet.
async fn upsert_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    relative_dir: &str,
    size_bytes: u64,
    last_accessed_ms: u64,
    metadata: &CacheEntryMetadata<'_>,
) -> stow_types::error::Result<()> {
    sqlx::query(
        "INSERT INTO artifact_cache_entries \
         (rustc_version, cache_key, relative_dir, size_bytes, last_accessed_ms, oci_reference, oci_digest, compile_key, crate_name, crate_version, c_metadata, features_json, dependency_c_metadata_json, dependency_compile_keys_json, compile_millis, target, profile_json, emit_json, kind_json, crate_types_json, verified_marker_version, verified_marker_policy, provenance) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?) \
         ON CONFLICT(rustc_version, cache_key) DO UPDATE SET \
             relative_dir = excluded.relative_dir, \
             size_bytes = excluded.size_bytes, \
             last_accessed_ms = excluded.last_accessed_ms, \
             oci_reference = excluded.oci_reference, \
             oci_digest = excluded.oci_digest, \
             compile_key = excluded.compile_key, \
             crate_name = excluded.crate_name, \
             crate_version = excluded.crate_version, \
             c_metadata = excluded.c_metadata, \
             features_json = excluded.features_json, \
             dependency_c_metadata_json = excluded.dependency_c_metadata_json, \
             dependency_compile_keys_json = excluded.dependency_compile_keys_json, \
             compile_millis = excluded.compile_millis, \
             target = excluded.target, \
             profile_json = excluded.profile_json, \
             emit_json = excluded.emit_json, \
             kind_json = excluded.kind_json, \
             crate_types_json = excluded.crate_types_json, \
             verified_marker_version = NULL, \
             verified_marker_policy = NULL, \
             provenance = excluded.provenance",
    )
    .bind(rustc_version)
    .bind(cache_key)
    .bind(relative_dir)
    .bind(db_int::<_, i64>(size_bytes, "artifact cache entry size_bytes")?)
    .bind(db_int::<_, i64>(
        last_accessed_ms,
        "artifact cache entry last_accessed_ms",
    )?)
    .bind(metadata.oci_reference)
    .bind(metadata.oci_digest)
    .bind(metadata.compile_key)
    .bind(metadata.crate_name)
    .bind(&metadata.crate_version)
    .bind(metadata.c_metadata)
    .bind(&metadata.features_json)
    .bind(&metadata.dependency_c_metadata_json)
    .bind(metadata.dependency_compile_keys_json)
    .bind(db_int::<_, i64>(
        metadata.compile_millis,
        "artifact cache entry compile_millis",
    )?)
    .bind(metadata.target)
    .bind(serde_json::to_string(metadata.profile)?)
    .bind(serde_json::to_string(metadata.emit)?)
    .bind(serde_json::to_string(metadata.kind)?)
    .bind(serde_json::to_string(metadata.crate_types)?)
    .bind(metadata.provenance.as_column())
    .execute(connection)
    .await?;
    Ok(())
}

/// Persist the bundle's output file list, one row per file in bundle order.
async fn insert_artifact_cache_outputs(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    outputs: &[ArtifactBundleFile],
) -> stow_types::error::Result<()> {
    for (ordinal, file) in outputs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_outputs \
             (rustc_version, cache_key, ordinal, file_name, media_type, sha256) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(db_int::<_, i64>(ordinal, "artifact output ordinal")?)
        .bind(&file.file_name)
        .bind(&file.media_type)
        .bind(&file.sha256)
        .execute(connection)
        .await?;
    }
    Ok(())
}

/// Persist the bundle's sigstore signature material, one row per signature
/// in bundle order.
async fn insert_artifact_cache_sigstore_signatures(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    sigstore_signatures: &[SigstoreSignature],
) -> stow_types::error::Result<()> {
    for (ordinal, material) in sigstore_signatures.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_sigstore_signatures \
             (rustc_version, cache_key, ordinal, payload_path, signature, certificate_pem, rekor_bundle_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(db_int::<_, i64>(ordinal, "sigstore signature ordinal")?)
        .bind(&material.payload_path)
        .bind(&material.signature)
        .bind(&material.certificate_pem)
        .bind(material.rekor_bundle_json.as_deref())
        .execute(connection)
        .await?;
    }
    Ok(())
}

/// Persist a `links=` crate's captured build-script products: static libs,
/// cargo directives, dep env vars, and out-dir file digests.
async fn insert_artifact_cache_native(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    native: &NativeArtifacts,
) -> stow_types::error::Result<()> {
    for (ordinal, lib) in native.static_libs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_native_static_libs \
             (rustc_version, cache_key, ordinal, lib_name, bytes_sha256) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(db_int::<_, i64>(ordinal, "native static lib ordinal")?)
        .bind(&lib.name)
        .bind(&lib.bytes_sha256)
        .execute(connection)
        .await?;
    }
    for (ordinal, directive) in native.cargo_directives.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_native_directives \
             (rustc_version, cache_key, ordinal, directive) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(db_int::<_, i64>(ordinal, "native cargo directive ordinal")?)
        .bind(directive)
        .execute(connection)
        .await?;
    }
    for (env_key, env_value) in &native.dep_env_vars {
        sqlx::query(
            "INSERT INTO artifact_cache_native_dep_env_vars \
             (rustc_version, cache_key, env_key, env_value) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(env_key)
        .bind(env_value)
        .execute(connection)
        .await?;
    }
    for (ordinal, file) in native.out_dir_files.iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifact_cache_native_out_dir_files \
             (rustc_version, cache_key, ordinal, relative_path, sha256) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(rustc_version)
        .bind(cache_key)
        .bind(db_int::<_, i64>(ordinal, "native out-dir file ordinal")?)
        .bind(&file.relative_path)
        .bind(&file.sha256)
        .execute(connection)
        .await?;
    }
    Ok(())
}

async fn delete_artifact_cache_children(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    for table in [
        "artifact_cache_outputs",
        "artifact_cache_sigstore_signatures",
        "artifact_cache_native_static_libs",
        "artifact_cache_native_directives",
        "artifact_cache_native_dep_env_vars",
        "artifact_cache_native_out_dir_files",
    ] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE rustc_version = ? AND cache_key = ?"
        ))
        .bind(rustc_version)
        .bind(cache_key)
        .execute(connection)
        .await?;
    }
    Ok(())
}

async fn touch_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
    last_accessed_ms: u64,
) -> stow_types::error::Result<()> {
    let result = sqlx::query(
        "UPDATE artifact_cache_entries \
         SET last_accessed_ms = ? \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(db_int::<_, i64>(
        last_accessed_ms,
        "artifact cache entry last_accessed_ms",
    )?)
    .bind(rustc_version)
    .bind(cache_key)
    .execute(connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(stow_types::stow_error!(
            "artifact cache entry {cache_key} for rustc {rustc_version} is missing from the state database"
        ));
    }
    Ok(())
}

pub async fn persist_cached_bundle_trust_marker(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
    marker_version: u8,
    marker_policy: &str,
) -> stow_types::error::Result<()> {
    if bundle.provenance != ArtifactProvenance::Remote {
        return Err(stow_types::stow_error!(
            "refusing to persist a verified trust marker on a {} cache entry",
            bundle.provenance.as_column()
        ));
    }
    let connection = config.state_db_pool().await?;
    let result = sqlx::query(
        "UPDATE artifact_cache_entries \
         SET verified_marker_version = ?, verified_marker_policy = ? \
         WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(i64::from(marker_version))
    .bind(marker_policy)
    .bind(&bundle.rustc_version)
    .bind(&bundle.cache_key)
    .execute(&connection)
    .await?;
    if result.rows_affected() != 1 {
        return Err(stow_types::stow_error!(
            "artifact cache trust marker update did not match exactly one entry"
        ));
    }
    Ok(())
}

async fn delete_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    sqlx::query("DELETE FROM artifact_cache_entries WHERE rustc_version = ? AND cache_key = ?")
        .bind(rustc_version)
        .bind(cache_key)
        .execute(connection)
        .await?;
    Ok(())
}

/// Batched "which of these artifacts are already materialized locally?".
///
/// The prefetch pre-pass only needs a yes/no per artifact, but
/// [`load_cached_bundle`] pays a file lock, an LRU `UPDATE` and five `SELECT`s
/// per entry — and the pre-pass runs them serially. On a warm cache that alone
/// cost roughly 90 ms per artifact (over 10 s for a 115-crate graph, twice per
/// build) before a single rustc ran. One indexed query plus one batched LRU
/// update replaces all of it.
///
/// Returns the subset of `cache_keys` that has both a state-database row and a
/// materialized entry directory; anything else is reported as missing so the
/// caller re-fetches it through the normal path.
pub async fn filter_locally_cached_keys(
    config: &StowConfig,
    rustc_version: &str,
    cache_keys: &[String],
) -> stow_types::error::Result<std::collections::BTreeSet<String>> {
    // SQLite's default host-parameter limit is 999; stay well under it.
    const CHUNK: usize = 256;

    if cache_keys.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }
    let connection = config.state_db_pool().await?;
    let version_dir = config.artifact_cache_version_dir(rustc_version);
    let mut present = std::collections::BTreeSet::new();
    for chunk in cache_keys.chunks(CHUNK) {
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT cache_key, relative_dir FROM artifact_cache_entries \
             WHERE rustc_version = ? AND cache_key IN ({placeholders})"
        );
        let mut query = sqlx::query_as::<_, (String, String)>(&sql).bind(rustc_version);
        for cache_key in chunk {
            query = query.bind(cache_key);
        }
        for (cache_key, relative_dir) in query.fetch_all(&connection).await? {
            // A row whose bundle directory was pruned underneath us is a miss,
            // not an error: the caller simply re-fetches it.
            if version_dir.join(&relative_dir).exists() {
                present.insert(cache_key);
            }
        }
    }

    if !present.is_empty() {
        let now = now_millis();
        let last_accessed_ms = db_int::<_, i64>(now, "artifact cache entry last_accessed_ms")?;
        let keys = present.iter().cloned().collect::<Vec<_>>();
        for chunk in keys.chunks(CHUNK) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "UPDATE artifact_cache_entries SET last_accessed_ms = ? \
                 WHERE rustc_version = ? AND cache_key IN ({placeholders})"
            );
            let mut query = sqlx::query(&sql).bind(last_accessed_ms).bind(rustc_version);
            for cache_key in chunk {
                query = query.bind(cache_key);
            }
            query.execute(&connection).await?;
        }
    }

    Ok(present)
}

/// The state-database cache key for one artifact identity, so callers can
/// pre-filter with [`filter_locally_cached_keys`] before doing per-artifact work.
#[must_use]
pub fn artifact_cache_key(target: &str, c_metadata: &str) -> String {
    format!("{ARTIFACT_CACHE_LAYOUT_VERSION}/{target}/{c_metadata}")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sha2::Digest;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, SigstoreSignature,
    };
    use stow_types::public_cache::StableRegistryArtifactIdentity;
    use stow_types::rustc::ParsedExternCrate;

    use super::{
        cache_key, join_relative_path, list_artifact_cache_entries, load_semantic_cached_bundle,
        prepare_local_cache, prepare_local_cache_blocking, touch_artifact_cache_entry,
        write_downloaded_bundle_to_entry,
    };
    use crate::config::{StowConfig, VerifyMode};
    use crate::fetch::{ArtifactBundle, FetchRequest, SemanticFetchRequest, bundle_file_path};
    use crate::rustc_args::ParsedRustcArgs;
    use crate::state_db::connect;

    #[test]
    fn prepare_local_cache_only_purges_on_version_change() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        std::fs::create_dir_all(config.artifact_cache_root().join("1.90.0"))
            .expect("create stale dir");
        std::fs::write(
            config
                .artifact_cache_root()
                .join("1.90.0")
                .join("stale.txt"),
            b"stale",
        )
        .expect("write stale file");

        run_async(async {
            let lease = prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            drop(lease);
            assert!(config.artifact_cache_root().join("1.91.1").exists());
            assert!(!config.artifact_cache_root().join("1.90.0").exists());

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let active = sqlx::query_scalar::<_, String>(
                "SELECT value FROM metadata_values WHERE key = 'active_rustc_version'",
            )
            .fetch_optional(&pool)
            .await
            .expect("load active rustc version");
            assert_eq!(active.as_deref(), Some("1.91.1"));
        });
    }

    #[test]
    fn busy_old_rustc_version_is_not_purged() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let artifact_root = tempdir.path().join("cache");
        let purge_root = tempdir.path().join("purge");

        let first = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.90.0", false)
            .expect("prepare old rustc cache");
        std::fs::write(artifact_root.join("1.90.0").join("busy.txt"), b"busy")
            .expect("write busy marker");

        let switched = prepare_local_cache_blocking(&artifact_root, &purge_root, "1.91.1", false)
            .expect("prepare new rustc cache");
        assert_eq!(switched.stale_dirs, Vec::<PathBuf>::new());
        assert!(artifact_root.join("1.90.0").exists());
        assert!(artifact_root.join("1.91.1").exists());

        drop(first.version_lease);
    }

    #[test]
    fn store_and_load_cached_bundle_round_trip() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("round-trip");
        let bundle = sample_bundle("aabbccddeeff0011", "libdemo-aabbccddeeff0011.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            assert!(stored.entry_dir.exists());

            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("cached bundle");
            assert_eq!(loaded.oci_reference, bundle.manifest.oci_reference);
            assert_eq!(loaded.oci_digest, bundle.manifest.oci_digest);
            assert_eq!(loaded.outputs.len(), 1);
            assert_eq!(
                loaded.outputs[0].file_name,
                "libdemo-aabbccddeeff0011.rmeta"
            );
            assert_eq!(loaded.sigstore_signatures.len(), 1);
        });
    }

    #[test]
    fn load_semantic_cached_bundle_matches_compatible_version_with_different_metadata() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("11223344aabbccdd");
        let mut bundle = sample_bundle("11223344aabbccdd", "libdemo-11223344aabbccdd.rmeta");
        bundle.manifest.config.crate_name =
            stow_types::identity::CrateName::parse("ignore").unwrap();
        bundle.manifest.config.crate_version =
            stow_types::identity::CrateVersion::new(semver::Version::parse("0.4.24").unwrap());
        bundle.manifest.config.features_json =
            stow_types::identity::FeaturesJson::canonicalize(vec!["default".to_owned()]).unwrap();
        bundle.manifest.config.compile_key = "semantic-compile-key".to_owned();
        bundle.manifest.oci_reference = "ghcr.io/water-rs/stow-cache:ignore.test".to_owned();

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");

            let loaded = load_semantic_cached_bundle(
                &config,
                &SemanticFetchRequest {
                    crate_name: "ignore".to_owned(),
                    version: "0.4.22".to_owned(),
                    features_json: "[\"default\"]".to_owned(),
                    dependency_c_metadata_json: "[]".to_owned(),
                    target: "aarch64-apple-darwin".to_owned(),
                    rustc_version: "1.91.1".to_owned(),
                    profile: bundle.manifest.config.profile.clone(),
                    emit: bundle.manifest.config.emit.clone(),
                    kind: bundle.manifest.config.kind.clone(),
                    crate_types: bundle.manifest.config.crate_types.clone(),
                },
            )
            .await
            .expect("load semantic bundle")
            .expect("semantic cache hit");
            assert_eq!(loaded.crate_name, "ignore");
            assert_eq!(loaded.crate_version, "0.4.24");
            assert_eq!(loaded.c_metadata, "11223344aabbccdd");
        });
    }

    #[test]
    fn store_downloaded_bundle_evicts_least_recently_used_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let first_request = fetch_request("aaaa");
        let second_request = fetch_request("bbbb");
        let first_bundle = sample_bundle("aaaa", "libdemo-aaaa.rmeta");
        let second_bundle = sample_bundle("bbbb", "libdemo-bbbb.rmeta");
        let second_size = write_downloaded_bundle_to_entry(
            &tempdir.path().join("scratch-second"),
            &second_bundle,
        )
        .expect("measure second bundle size");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let first_cached =
                super::store_downloaded_bundle(&config, &first_request, &first_bundle)
                    .await
                    .expect("store first bundle");
            let first_entry_dir = first_cached.entry_dir.clone();
            let first_index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            let first_size = first_index
                .get(&cache_key(&first_request))
                .expect("first entry")
                .size_bytes;
            config.artifact_cache_max_bytes = first_size + second_size - 1;
            drop(first_cached);

            super::store_downloaded_bundle(&config, &second_request, &second_bundle)
                .await
                .expect("store second bundle");

            let index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            assert!(index.contains_key(&cache_key(&second_request)));
            assert!(!index.contains_key(&cache_key(&first_request)));
            assert!(!first_entry_dir.exists());
        });
    }

    #[test]
    fn load_cached_bundle_updates_lru_timestamp() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("touch-me");
        let bundle = sample_bundle("aa11bb22cc33dd44", "libdemo-aa11bb22cc33dd44.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let cached = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            drop(cached);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            touch_artifact_cache_entry(&pool, "1.91.1", &cache_key(&request), 1)
                .await
                .expect("set stale lru timestamp");

            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("cached bundle");
            drop(loaded);

            let updated = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .get(&cache_key(&request))
                .expect("cache entry")
                .last_accessed_ms;
            assert!(updated > 1);
        });
    }

    #[test]
    fn load_cached_bundle_rejects_unknown_provenance() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("provenance");
        let bundle = sample_bundle("55aa66bb77cc88dd", "libdemo-55aa66bb77cc88dd.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            assert_eq!(stored.provenance, super::ArtifactProvenance::Remote);
            drop(stored);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            sqlx::query(
                "UPDATE artifact_cache_entries SET provenance = 'bogus' \
                 WHERE rustc_version = '1.91.1' AND cache_key = ?",
            )
            .bind(cache_key(&request))
            .execute(&pool)
            .await
            .expect("corrupt provenance column");

            let error = super::load_cached_bundle(&config, &request)
                .await
                .expect_err("unknown provenance must fail fast");
            assert!(error.to_string().contains("unknown provenance"));
        });
    }

    #[test]
    fn trust_marker_is_refused_for_non_remote_entries() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let lease_path = tempdir.path().join("local.lock");
        let bundle = super::CachedArtifactBundle {
            provenance: super::ArtifactProvenance::Local,
            oci_reference: "local".to_owned(),
            oci_digest: "local".to_owned(),
            compile_key: "compile-key".to_owned(),
            crate_name: "demo".to_owned(),
            crate_version: "1.0.0".to_owned(),
            c_metadata: "deadbeef".to_owned(),
            features_json: "[]".to_owned(),
            dependency_c_metadata_json: "[]".to_owned(),
            dependency_compile_keys_json: "[]".to_owned(),
            compile_millis: 0,
            size_bytes: 0,
            profile: stow_types::platform::Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: stow_types::platform::PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec!["metadata".to_owned()],
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: Vec::new(),
            native: None,
            sigstore_signatures: Vec::new(),
            entry_dir: tempdir.path().join("entry"),
            rustc_version: "1.91.1".to_owned(),
            cache_key: "cache-key".to_owned(),
            verified_marker_version: None,
            verified_marker_policy: None,
            _lease_lock: std::fs::File::create(&lease_path).expect("lease lock"),
        };

        run_async(async {
            let error = super::persist_cached_bundle_trust_marker(&config, &bundle, 1, "policy")
                .await
                .expect_err("local entries must never receive trust markers");
            assert!(error.to_string().contains("local"));
        });
    }

    #[test]
    fn remove_cached_bundle_drops_entry_and_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("remove-me");
        let bundle = sample_bundle("ee44ff55aa66bb77", "libdemo-ee44ff55aa66bb77.rmeta");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let cached = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            let entry_dir = cached.entry_dir.clone();
            drop(cached);

            super::remove_cached_bundle(&config, &request)
                .await
                .expect("remove cached bundle");

            let index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            assert!(!index.contains_key(&cache_key(&request)));
            assert!(!entry_dir.exists());
        });
    }

    #[test]
    fn record_materialized_local_build_outputs_populates_dependency_metadata_lookup() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let dependency = parsed_rustc_args(
            "colorchoice",
            "abc123",
            out_dir,
            Vec::new(),
            vec!["lib".to_owned()],
        );

        run_async(async {
            super::record_materialized_local_build_outputs(
                &config,
                &dependency,
                &StableRegistryArtifactIdentity {
                    compile_key: "colorchoice-compile-key".to_owned(),
                    c_metadata: "stable-colorchoice".to_owned(),
                    extra_filename: "-stable-colorchoice".to_owned(),
                    crate_name: "colorchoice".to_owned(),
                    version: "1.0.0".to_owned(),
                },
            )
            .await
            .expect("record local build outputs");

            let consumer = consumer_parsed_args(
                tempdir.path(),
                dependency
                    .output_rmeta_path()
                    .expect("dependency rmeta path"),
            );

            let resolved = super::resolve_dependency_c_metadata_json(&config, &consumer)
                .await
                .expect("resolve dependency metadata")
                .expect("dependency metadata json");
            assert_eq!(
                resolved,
                r#"[{"crate_name":"colorchoice","c_metadata":"stable-colorchoice"}]"#
            );
        });
    }

    #[test]
    fn record_materialized_bundle_outputs_populates_dependency_metadata_lookup() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let stable_c_metadata = "0123456789abcdef";
        let dependency = parsed_rustc_args(
            "colorchoice",
            "compile-key",
            out_dir,
            Vec::new(),
            vec!["lib".to_owned()],
        );
        let mut artifact_bundle =
            sample_bundle(stable_c_metadata, "libcolorchoice-0123456789abcdef.rmeta");
        artifact_bundle.manifest.config.compile_key =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210".to_owned();
        let bundle = remote_cached_bundle(&artifact_bundle, tempdir.path());

        run_async(async {
            super::record_materialized_bundle_outputs(&config, &dependency, &bundle)
                .await
                .expect("record bundle outputs");

            let consumer = consumer_parsed_args(
                tempdir.path(),
                dependency
                    .output_rmeta_path()
                    .expect("dependency rmeta path"),
            );

            let resolved = super::resolve_dependency_c_metadata_json(&config, &consumer)
                .await
                .expect("resolve dependency metadata")
                .expect("dependency metadata json");
            assert_eq!(
                resolved,
                r#"[{"crate_name":"colorchoice","c_metadata":"0123456789abcdef"}]"#
            );
        });
    }

    #[test]
    fn store_local_build_outputs_stores_and_serves_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let stable_c_metadata = "0123456789abcdef";
        let parsed = local_build_parsed(
            "demo",
            "cargo-meta-1",
            out_dir,
            &["dep-info", "metadata", "link"],
        );
        let rlib_source = parsed.output_rlib_path().expect("rlib output path");
        let rmeta_source = parsed.output_rmeta_path().expect("rmeta output path");
        std::fs::write(&rlib_source, b"local-rlib-bytes").expect("write rlib");
        std::fs::write(&rmeta_source, b"local-rmeta-bytes").expect("write rmeta");
        let build = local_build_artifact(stable_c_metadata);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_local_build_outputs(&config, &parsed, &build)
                .await
                .expect("store local build");
            assert!(stored);

            let entry_dir = config
                .artifact_cache_version_dir("1.91.1")
                .join("bundles/v3/aarch64-apple-darwin")
                .join(stable_c_metadata);
            // Outputs land under the stable-name file names a remote bundle
            // would carry, with bytes identical to what rustc wrote.
            let staged_rlib = entry_dir.join("files/libdemo-0123456789abcdef.rlib");
            let staged_rmeta = entry_dir.join("files/libdemo-0123456789abcdef.rmeta");
            assert_eq!(
                std::fs::read(&staged_rlib).expect("read staged rlib"),
                b"local-rlib-bytes"
            );
            assert_eq!(
                std::fs::read(&staged_rmeta).expect("read staged rmeta"),
                b"local-rmeta-bytes"
            );
            // No temp stage dirs leak into the bundles dir.
            let leftovers = std::fs::read_dir(entry_dir.parent().expect("entry parent"))
                .expect("read bundles dir")
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy() != stable_c_metadata)
                .count();
            assert_eq!(leftovers, 0);

            let request = fetch_request(stable_c_metadata);
            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("local entry must load");
            assert_eq!(loaded.provenance, super::ArtifactProvenance::Local);
            assert!(loaded.sigstore_signatures.is_empty());
            assert_eq!(loaded.compile_key, "0123456789abcdef0123456789abcdef");
            let outputs = loaded
                .outputs
                .iter()
                .map(|output| (output.file_name.as_str(), output.sha256.as_str()))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                outputs.get("libdemo-0123456789abcdef.rlib").copied(),
                Some(hex::encode(sha2::Sha256::digest(b"local-rlib-bytes")).as_str())
            );
            assert_eq!(
                outputs.get("libdemo-0123456789abcdef.rmeta").copied(),
                Some(hex::encode(sha2::Sha256::digest(b"local-rmeta-bytes")).as_str())
            );

            // A local entry is trusted by construction: verification is a
            // no-op rather than a sigstore round-trip.
            crate::verify::verify_cached_bundle_signature(&config, &loaded)
                .await
                .expect("local entry verification is trusted by construction");
        });
    }

    #[test]
    fn store_local_build_outputs_captures_and_restores_native_out_dir() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");
        let native_out_dir = native_out_dir_fixture(tempdir.path());

        let stable_c_metadata = "cafebabefeedface";
        let parsed = local_build_parsed(
            "demo",
            "cargo-meta-native",
            out_dir,
            &["dep-info", "metadata", "link"],
        );
        std::fs::write(
            parsed.output_rlib_path().expect("rlib output path"),
            b"native-rlib-bytes",
        )
        .expect("write rlib");
        std::fs::write(
            parsed.output_rmeta_path().expect("rmeta output path"),
            b"native-rmeta-bytes",
        )
        .expect("write rmeta");
        let mut build = local_build_artifact(stable_c_metadata);
        build.build_script_out_dir = Some(native_out_dir.clone());

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build)
                    .await
                    .expect("store local build")
            );

            // OUT_DIR bytes land under the same `native/out/` layout a
            // downloaded bundle's native layer uses.
            let entry_dir = config
                .artifact_cache_version_dir("1.91.1")
                .join("bundles/v3/aarch64-apple-darwin")
                .join(stable_c_metadata);
            assert_eq!(
                std::fs::read(entry_dir.join("native/out/libdemo.a"))
                    .expect("read staged static lib"),
                b"archive-bytes"
            );
            assert_eq!(
                std::fs::read(entry_dir.join("native/out/gen/bindings.rs"))
                    .expect("read staged generated file"),
                b"pub fn demo() {}"
            );

            let request = fetch_request(stable_c_metadata);
            let bundle = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("local entry must load");
            let native = bundle.native.as_ref().expect("native metadata");
            // Rebuild hints and warnings are dropped; real directives kept.
            assert_eq!(
                native.cargo_directives,
                vec![
                    format!(
                        "cargo:rustc-link-search=native={}",
                        native_out_dir.display()
                    ),
                    "cargo:rustc-link-lib=static=demo".to_owned(),
                ]
            );
            assert_eq!(
                native
                    .static_libs
                    .iter()
                    .map(|lib| lib.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["libdemo.a"]
            );
            assert_eq!(
                native.static_libs[0].bytes_sha256,
                hex::encode(sha2::Sha256::digest(b"archive-bytes"))
            );
            assert_eq!(
                native
                    .out_dir_files
                    .iter()
                    .map(|file| file.relative_path.as_str())
                    .collect::<Vec<_>>(),
                vec!["gen/bindings.rs", "libdemo.a"]
            );

            // Restore into a fresh target dir: cargo passes the new OUT_DIR
            // to rustc via -L native=..., which is where the files land.
            let fresh_deps = tempdir.path().join("fresh/debug/deps");
            let fresh_native_out = tempdir.path().join("fresh/debug/build/demo-bbbb2222/out");
            let mut restore_parsed = local_build_parsed(
                "demo",
                "cargo-meta-restore",
                fresh_deps,
                &["dep-info", "metadata", "link"],
            );
            restore_parsed.native_search_paths = vec![fresh_native_out.clone()];
            crate::inject::write_artifacts(&restore_parsed, &bundle)
                .await
                .expect("restore local entry");
            assert_restored_native_out_dir(&fresh_native_out);
        });
    }

    /// A `links=` crate's build-script products under `root`: the `OUT_DIR`
    /// tree (one static lib, one generated file) plus the sibling `output`
    /// file of cargo directives. Returns the `OUT_DIR`.
    fn native_out_dir_fixture(root: &Path) -> PathBuf {
        let build_dir = root.join("build/demo-aaaa1111");
        let out_dir = build_dir.join("out");
        std::fs::create_dir_all(out_dir.join("gen")).expect("create OUT_DIR");
        std::fs::write(out_dir.join("libdemo.a"), b"archive-bytes").expect("write static lib");
        std::fs::write(out_dir.join("gen/bindings.rs"), b"pub fn demo() {}")
            .expect("write generated file");
        std::fs::write(
            build_dir.join("output"),
            format!(
                "cargo:rerun-if-env-changed=DEMO\n\
                 cargo:warning=ignored\n\
                 cargo:rustc-link-search=native={}\n\
                 cargo:rustc-link-lib=static=demo\n",
                out_dir.display()
            ),
        )
        .expect("write build script output");
        out_dir
    }

    fn assert_restored_native_out_dir(out_dir: &Path) {
        assert_eq!(
            std::fs::read(out_dir.join("libdemo.a")).expect("read restored lib"),
            b"archive-bytes"
        );
        assert_eq!(
            std::fs::read(out_dir.join("gen/bindings.rs")).expect("read restored generated file"),
            b"pub fn demo() {}"
        );
        let output =
            std::fs::read_to_string(out_dir.parent().expect("native build dir").join("output"))
                .expect("read restored build script output");
        // The link-search path is rewritten to the new OUT_DIR.
        assert!(
            output.contains(&format!(
                "cargo:rustc-link-search=native={}",
                out_dir.display()
            )),
            "rewritten directives: {output}"
        );
        assert!(output.contains("cargo:rustc-link-lib=static=demo"));
    }

    #[test]
    fn store_local_build_outputs_skips_missing_output() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let parsed = local_build_parsed("demo", "cargo-meta-2", out_dir, &["link"]);
        // A failed or partial build leaves outputs absent: rustc exited
        // non-zero, or wrote only some of them. Nothing may be stored.
        let build = local_build_artifact("aaaabbbbccccdddd");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_local_build_outputs(&config, &parsed, &build)
                .await
                .expect("store must not error on a dirty build");
            assert!(!stored);

            let version_dir = config.artifact_cache_version_dir("1.91.1");
            let leftovers = std::fs::read_dir(version_dir.join("bundles/v3/aarch64-apple-darwin"))
                .map_or(0, std::iter::Iterator::count);
            assert_eq!(leftovers, 0, "no staged dir or entry may remain");
            let index = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries");
            assert!(index.is_empty());
        });
    }

    #[test]
    fn store_local_build_outputs_is_idempotent() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let stable_c_metadata = "ffeeddccbbaa0099";
        let parsed = local_build_parsed("demo", "cargo-meta-3", out_dir, &["link"]);
        std::fs::write(
            parsed.output_rlib_path().expect("rlib output path"),
            b"first-build",
        )
        .expect("write rlib");
        let build = local_build_artifact(stable_c_metadata);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build)
                    .await
                    .expect("first store")
            );
            // A second worktree building the same identity must not
            // double-store or error.
            assert!(
                !super::store_local_build_outputs(&config, &parsed, &build)
                    .await
                    .expect("second store")
            );
        });
    }

    #[test]
    fn remote_download_does_not_displace_local_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let stable_c_metadata = "1122334455667788";
        let parsed = local_build_parsed("demo", "cargo-meta-4", out_dir, &["link"]);
        std::fs::write(
            parsed.output_rlib_path().expect("rlib output path"),
            b"locally-built",
        )
        .expect("write rlib");
        let build = local_build_artifact(stable_c_metadata);
        let request = fetch_request(stable_c_metadata);
        let bundle = sample_bundle(stable_c_metadata, "libdemo-1122334455667788.rlib");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build)
                    .await
                    .expect("store local build")
            );

            // The remote later gains the same identity: the download must not
            // displace the self-produced entry — it serves the local one.
            let served = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("download with local entry present");
            assert_eq!(served.provenance, super::ArtifactProvenance::Local);
            drop(served);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let (provenance, oci_reference): (String, String) = sqlx::query_as(
                "SELECT provenance, oci_reference FROM artifact_cache_entries \
                 WHERE rustc_version = '1.91.1' AND cache_key = ?",
            )
            .bind(cache_key(&request))
            .fetch_one(&pool)
            .await
            .expect("load provenance row");
            assert_eq!(provenance, "local");
            assert_eq!(oci_reference, "local");
        });
    }

    #[test]
    fn local_entry_is_evicted_by_shared_lru_budget() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let local_meta = "10ca1e7710ca1e77";
        let local_parsed = local_build_parsed("demo", "cargo-meta-ev1", out_dir, &["link"]);
        std::fs::write(
            local_parsed.output_rlib_path().expect("rlib output path"),
            b"evict-me",
        )
        .expect("write rlib");
        let local_build = local_build_artifact(local_meta);
        let local_key = super::artifact_cache_key("aarch64-apple-darwin", local_meta);
        let remote_request = fetch_request("bbbb");
        let remote_bundle = sample_bundle("bbbb", "libdemo-bbbb.rmeta");
        let third_request = fetch_request("cccc");
        let third_bundle = sample_bundle("cccc", "libdemo-cccc.rmeta");
        let third_size =
            write_downloaded_bundle_to_entry(&tempdir.path().join("scratch-third"), &third_bundle)
                .expect("measure third bundle size");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &local_parsed, &local_build)
                    .await
                    .expect("store local build")
            );
            super::store_downloaded_bundle(&config, &remote_request, &remote_bundle)
                .await
                .expect("store remote bundle");

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let resident: u64 = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .values()
                .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
            // One byte short of fitting all three: the next store must evict
            // the least recently touched entry — the local one.
            config.artifact_cache_max_bytes = resident + third_size - 1;
            touch_artifact_cache_entry(&pool, "1.91.1", &local_key, 1)
                .await
                .expect("stale local lru timestamp");
            let local_dir = config
                .artifact_cache_version_dir("1.91.1")
                .join("bundles/v3/aarch64-apple-darwin")
                .join(local_meta);
            assert!(local_dir.exists());

            super::store_downloaded_bundle(&config, &third_request, &third_bundle)
                .await
                .expect("store third bundle");

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(
                !index.contains_key(&local_key),
                "local entry must be evicted by the shared budget like a remote one"
            );
            assert!(index.contains_key(&cache_key(&remote_request)));
            assert!(index.contains_key(&cache_key(&third_request)));
            assert!(!local_dir.exists());
        });
    }

    #[test]
    fn remote_entry_evicts_before_newer_local_entry() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let remote_request = fetch_request("dddd");
        let remote_bundle = sample_bundle("dddd", "libdemo-dddd.rmeta");
        let remote_size = write_downloaded_bundle_to_entry(
            &tempdir.path().join("scratch-remote"),
            &remote_bundle,
        )
        .expect("measure remote bundle size");
        let third_request = fetch_request("eeee");
        let third_bundle = sample_bundle("eeee", "libdemo-eeee.rmeta");
        let third_size =
            write_downloaded_bundle_to_entry(&tempdir.path().join("scratch-third"), &third_bundle)
                .expect("measure third bundle size");

        let local_meta = "10ca1e7710ca1e78";
        let local_parsed = local_build_parsed("demo", "cargo-meta-ev2", out_dir, &["link"]);
        std::fs::write(
            local_parsed.output_rlib_path().expect("rlib output path"),
            b"newer-local",
        )
        .expect("write rlib");
        let local_build = local_build_artifact(local_meta);
        let local_key = super::artifact_cache_key("aarch64-apple-darwin", local_meta);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            super::store_downloaded_bundle(&config, &remote_request, &remote_bundle)
                .await
                .expect("store remote bundle");
            let pool = connect(&config.cache_dir).await.expect("connect state db");
            touch_artifact_cache_entry(&pool, "1.91.1", &cache_key(&remote_request), 1)
                .await
                .expect("stale remote lru timestamp");

            assert!(
                super::store_local_build_outputs(&config, &local_parsed, &local_build)
                    .await
                    .expect("store local build")
            );
            let local_size = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .get(&local_key)
                .expect("local entry")
                .size_bytes;
            config.artifact_cache_max_bytes = remote_size + local_size + third_size - 1;

            super::store_downloaded_bundle(&config, &third_request, &third_bundle)
                .await
                .expect("store third bundle");

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(
                !index.contains_key(&cache_key(&remote_request)),
                "the stale remote entry is evicted before the newer local one"
            );
            assert!(index.contains_key(&local_key));
            assert!(index.contains_key(&cache_key(&third_request)));
        });
    }

    #[test]
    fn local_entry_size_counts_native_out_dir_bytes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");
        let native_out_dir = native_out_dir_fixture(tempdir.path());

        let local_meta = "10ca1e7710ca1e79";
        let parsed = local_build_parsed(
            "demo",
            "cargo-meta-ev3",
            out_dir,
            &["dep-info", "metadata", "link"],
        );
        std::fs::write(
            parsed.output_rlib_path().expect("rlib output path"),
            b"native-rlib-bytes",
        )
        .expect("write rlib");
        std::fs::write(
            parsed.output_rmeta_path().expect("rmeta output path"),
            b"native-rmeta-bytes",
        )
        .expect("write rmeta");
        let mut build = local_build_artifact(local_meta);
        build.build_script_out_dir = Some(native_out_dir);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build)
                    .await
                    .expect("store local build")
            );

            let size_bytes = list_artifact_cache_entries(
                &connect(&config.cache_dir).await.expect("connect state db"),
                "1.91.1",
            )
            .await
            .expect("list entries")
            .get(&super::artifact_cache_key(
                "aarch64-apple-darwin",
                local_meta,
            ))
            .expect("local entry")
            .size_bytes;
            // The eviction budget charges native OUT_DIR bytes, not just the
            // rustc outputs.
            let expected = (b"native-rlib-bytes".len()
                + b"native-rmeta-bytes".len()
                + b"archive-bytes".len()
                + b"pub fn demo() {}".len()) as u64;
            assert_eq!(size_bytes, expected);
        });
    }

    #[test]
    fn join_relative_path_rejects_non_normal_components() {
        let root = Path::new("/cache-root");
        for path in ["", "..", "a/../b", "./a", "/a"] {
            assert!(
                join_relative_path(root, path).is_err(),
                "path {path:?} must be rejected"
            );
        }
        assert_eq!(
            join_relative_path(root, "files/x.rlib").expect("normal relative path"),
            root.join("files/x.rlib")
        );
    }

    #[cfg(windows)]
    #[test]
    fn join_relative_path_rejects_windows_roots() {
        let root = Path::new("C:/cache-root");
        for path in ["\\a", "C:a"] {
            assert!(
                join_relative_path(root, path).is_err(),
                "path {path:?} must be rejected"
            );
        }
    }

    fn test_config(root: &std::path::Path) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787/v2/water-rs/stow-cache".to_owned(),
            cache_dir: root.join(".stow"),
            request_timeout: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_secs(60),
            graph_cache_ttl: Duration::from_secs(60),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: u64::MAX,
            index_refresh_interval: Duration::from_secs(60),
            verify_mode: VerifyMode::GithubCi,
            admission_drain_timeout: crate::config::DEFAULT_ADMISSION_DRAIN_TIMEOUT,
            state_db_pool: StowConfig::default_state_db_pool(),
        }
    }

    fn fetch_request(c_metadata: &str) -> FetchRequest<'_> {
        FetchRequest {
            target: "aarch64-apple-darwin",
            rustc_version: "1.91.1",
            c_metadata,
            crate_name: "demo",
        }
    }

    fn sample_bundle(c_metadata: &str, file_name: &str) -> ArtifactBundle {
        let file_contents = b"demo-artifact".to_vec();
        let compression_level = *zstd::compression_level_range().end();
        let stored_contents = zstd::bulk::compress(&file_contents, compression_level)
            .expect("compress sample artifact bundle output");
        ArtifactBundle {
            manifest: ArtifactBundleManifest {
                oci_reference: "ghcr.io/water-rs/stow-cache:demo.test".to_owned(),
                oci_digest: "sha256:test".to_owned(),
                config: ArtifactBlobConfig {
                    compile_key: "compile-key".to_owned(),
                    crate_name: stow_types::identity::CrateName::parse("demo").unwrap(),
                    crate_version: stow_types::identity::CrateVersion::new(
                        semver::Version::parse("1.0.0").unwrap(),
                    ),
                    c_metadata: stow_types::identity::CMetadata::parse(c_metadata).unwrap(),
                    extra_filename: format!("-{c_metadata}"),
                    target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin")
                        .unwrap(),
                    rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
                    features_json: stow_types::identity::FeaturesJson::default(),
                    dependency_c_metadata_json:
                        stow_types::identity::DependencyCMetadataJson::default(),
                    dependency_compile_keys_json: "[]".to_owned(),
                    profile: stow_types::platform::Profile {
                        opt_level: "0".to_owned(),
                        debuginfo: 0,
                        debug_assertions: true,
                        overflow_checks: true,
                        panic: stow_types::platform::PanicStrategy::Unwind,
                        strip: stow_types::platform::StripLevel::None,
                    },
                    emit: vec!["metadata".to_owned()],
                    artifact_size: file_contents.len() as u64,
                    compile_millis: 0,
                    kind: ArtifactKind::Rlib,
                    crate_types: vec![RustCrateType::Lib],
                    outputs: vec![ArtifactBundleFile {
                        file_name: file_name.to_owned(),
                        media_type: stow_types::bundle::STOW_RMETA_MEDIA_TYPE.to_owned(),
                        sha256: hex::encode(sha2::Sha256::digest(&file_contents)),
                    }],
                    native: None,
                    native_archive: None,
                },
                sigstore_signatures: vec![SigstoreSignature {
                    payload_path: "sigstore/payload.json".to_owned(),
                    signature: "MEUCIQDUMMY".to_owned(),
                    certificate_pem: "mock-local".to_owned(),
                    rekor_bundle_json: None,
                }],
            },
            files: BTreeMap::from([
                (bundle_file_path(file_name), stored_contents),
                (
                    "sigstore/payload.json".to_owned(),
                    serde_json::to_vec(&serde_json::json!({
                        "critical": {
                            "identity": {
                                "docker-reference": "ghcr.io/water-rs/stow-cache:demo.test"
                            },
                            "image": {
                                "docker-manifest-digest": "sha256:test"
                            },
                            "type": "cosign container image signature"
                        },
                        "optional": null
                    }))
                    .expect("serialize sample sigstore payload"),
                ),
            ]),
        }
    }

    fn run_async(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(future);
    }

    fn parsed_rustc_args(
        crate_name: &str,
        c_metadata: &str,
        out_dir: PathBuf,
        extern_crates: Vec<ParsedExternCrate>,
        crate_types: Vec<String>,
    ) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: crate_name.to_owned(),
            crate_types,
            features: BTreeSet::default(),
            cfgs: BTreeSet::default(),
            emit: BTreeSet::default(),
            json: BTreeSet::default(),
            input_path: Some(out_dir.join(format!("{crate_name}.rs"))),
            target: Some("aarch64-apple-darwin".to_owned()),
            c_metadata: Some(c_metadata.to_owned()),
            out_dir: Some(out_dir),
            extra_filename: format!("-{c_metadata}"),
            opt_level: Some("0".to_owned()),
            debuginfo: Some("0".to_owned()),
            panic_strategy: None,
            debug_assertions: Some(true),
            overflow_checks: Some(true),
            strip: None,
            native_search_paths: Vec::new(),
            extern_crates,
            embed_metadata: None,
            embed_bitcode: false,
            has_custom_codegen: false,
        }
    }

    /// A parsed invocation as a successful passthrough left it: the stable
    /// identity lives in `build`, while `parsed` carries cargo's own
    /// `c_metadata`/`extra_filename` (different values on purpose — the entry
    /// must store outputs under the stable names, not the cargo ones).
    fn local_build_parsed(
        crate_name: &str,
        cargo_c_metadata: &str,
        out_dir: PathBuf,
        emit: &[&str],
    ) -> ParsedRustcArgs {
        let mut parsed = parsed_rustc_args(
            crate_name,
            cargo_c_metadata,
            out_dir,
            Vec::new(),
            vec!["rlib".to_owned()],
        );
        parsed.emit = emit.iter().map(|value| (*value).to_owned()).collect();
        parsed
    }

    fn local_build_artifact(stable_c_metadata: &str) -> super::LocalBuildArtifact {
        super::LocalBuildArtifact {
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            identity: StableRegistryArtifactIdentity {
                // Real compile keys are hex; the stable c_metadata is the
                // first 16 hex digits of the key.
                compile_key: format!("{stable_c_metadata}{stable_c_metadata}"),
                c_metadata: stable_c_metadata.to_owned(),
                extra_filename: format!("-{stable_c_metadata}"),
                crate_name: "demo".to_owned(),
                version: "1.0.0".to_owned(),
            },
            features_json: "[]".to_owned(),
            dependency_c_metadata_json: "[]".to_owned(),
            build_script_out_dir: None,
        }
    }

    /// A `demo` consumer unit that links `colorchoice` through
    /// `dependency_rmeta` — the shape `resolve_dependency_c_metadata_json`
    /// reads to answer "which `c_metadata` did this dependency compile with".
    fn consumer_parsed_args(temp_dir: &Path, dependency_rmeta: PathBuf) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: "demo".to_owned(),
            crate_types: vec!["lib".to_owned()],
            features: BTreeSet::default(),
            cfgs: BTreeSet::default(),
            emit: BTreeSet::default(),
            json: BTreeSet::default(),
            input_path: None,
            target: Some("aarch64-apple-darwin".to_owned()),
            c_metadata: Some("consumer".to_owned()),
            out_dir: Some(temp_dir.join("consumer")),
            extra_filename: "-consumer".to_owned(),
            opt_level: None,
            debuginfo: None,
            panic_strategy: None,
            debug_assertions: None,
            overflow_checks: None,
            strip: None,
            native_search_paths: Vec::new(),
            extern_crates: vec![ParsedExternCrate {
                crate_name: "colorchoice".to_owned(),
                path: dependency_rmeta,
            }],
            embed_metadata: None,
            embed_bitcode: false,
            has_custom_codegen: false,
        }
    }

    /// A `CachedArtifactBundle` in the remote-provenance row shape
    /// `record_materialized_bundle_outputs` persists, built from an
    /// `ArtifactBundle` fixture with its lease lock under `temp_dir`.
    fn remote_cached_bundle(
        artifact_bundle: &ArtifactBundle,
        temp_dir: &Path,
    ) -> super::CachedArtifactBundle {
        let lease_path = temp_dir.join("bundle.lock");
        super::CachedArtifactBundle {
            provenance: super::ArtifactProvenance::Remote,
            oci_reference: artifact_bundle.manifest.oci_reference.clone(),
            oci_digest: artifact_bundle.manifest.oci_digest.clone(),
            compile_key: artifact_bundle.manifest.config.compile_key.clone(),
            crate_name: artifact_bundle
                .manifest
                .config
                .crate_name
                .as_str()
                .to_owned(),
            crate_version: artifact_bundle.manifest.config.crate_version.to_string(),
            c_metadata: artifact_bundle
                .manifest
                .config
                .c_metadata
                .as_str()
                .to_owned(),
            features_json: artifact_bundle.manifest.config.features_json.raw(),
            dependency_c_metadata_json: artifact_bundle
                .manifest
                .config
                .dependency_c_metadata_json
                .raw(),
            dependency_compile_keys_json: artifact_bundle
                .manifest
                .config
                .dependency_compile_keys_json
                .clone(),
            compile_millis: artifact_bundle.manifest.config.compile_millis,
            size_bytes: 0,
            profile: artifact_bundle.manifest.config.profile.clone(),
            emit: artifact_bundle.manifest.config.emit.clone(),
            kind: artifact_bundle.manifest.config.kind.clone(),
            crate_types: artifact_bundle.manifest.config.crate_types.clone(),
            outputs: artifact_bundle.manifest.config.outputs.clone(),
            native: artifact_bundle.manifest.config.native.clone(),
            sigstore_signatures: artifact_bundle.manifest.sigstore_signatures.clone(),
            entry_dir: temp_dir.join("bundle-entry"),
            rustc_version: artifact_bundle
                .manifest
                .config
                .rustc_version
                .as_str()
                .to_owned(),
            cache_key: "cache-key".to_owned(),
            verified_marker_version: None,
            verified_marker_policy: None,
            _lease_lock: std::fs::File::create(&lease_path).expect("lease lock"),
        }
    }
}
