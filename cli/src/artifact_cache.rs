use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use semver::Version;
use sqlx::FromRow;
use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::bundle::{
    ArtifactBundleFile, STOW_BUNDLE_MANIFEST_PATH, STOW_DYLIB_MEDIA_TYPE,
    STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE, SigstoreSignature,
};
use stow_types::error::Context;
use stow_types::identity::{CrateName, DependencyCompileKeyIdentity};
use stow_types::platform::Profile;
use stow_types::public_cache::{
    StableUnitIdentity, normalized_cache_profile, stable_c_metadata_for_compile_key,
};
use stow_types::versioning::is_semver_compatible_upgrade;

use crate::config::StowConfig;
use crate::fetch::{
    ArtifactBundle, FetchRequest, SemanticFetchRequest, bundle_file_path,
    decode_bundle_output_bytes,
};
use crate::file_lock::FileLock;
use crate::inject::parsed_with_stable_identity;
use crate::rustc_args::ParsedRustcArgs;
use crate::state_db::{db_int, now_millis};

const BUNDLES_DIR: &str = "bundles";
const VERSION_LEASES_DIR: &str = "leases";
/// `<version_dir>/staging/` — beside `bundles/` and `locks/` on the same
/// filesystem, so a staged entry's rename into place stays atomic. One
/// subdirectory per storing process; `prepare_local_cache` sweeps the
/// ones a dead process left.
pub const STAGING_DIR: &str = "staging";
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
    _lock: FileLock,
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
    /// The stable unit identity (`compile_key` + 16-hex `c_metadata`).
    pub identity: StableUnitIdentity,
    /// How far this artifact's identity may travel — a local-only unit
    /// records rows its dependents fold to `LocalOnly` (stow#1006).
    pub reach: stow_types::public_cache::Reach,
    /// Canonical features JSON as fed into the compile key.
    pub features_json: String,
    /// The unit's `--extern` deps resolved against `materialized_outputs`,
    /// each carrying the instance digest it was compiled against.
    pub dependencies: ResolvedDependencies,
    /// The outputs the compile produced, each with the sha256 the
    /// post-compile resolution hashed once — the local store records them
    /// verbatim instead of re-hashing the staged copy.
    pub outputs: Vec<LocalBuildOutput>,
}

impl LocalBuildArtifact {
    /// The instance digest of this compile — the same
    /// [`outputs_instance_digest`] a cache entry's recorded outputs answer
    /// with, so a dependent's binding compares like for like.
    pub fn instance(&self) -> String {
        outputs_instance_digest(self.outputs.iter().map(|output| output.sha256.as_str()))
    }
}

/// One digest identifying exactly which bytes a unit instance is: blake3
/// under `stow.unit-instance.v1` over the unit's output files' sha256s —
/// the set `artifact_cache_outputs` records for an entry — sorted, so the
/// output ordering of a bundle manifest never perturbs it.
pub fn outputs_instance_digest<'a>(sha256s: impl IntoIterator<Item = &'a str>) -> String {
    let mut sha256s: Vec<&str> = sha256s.into_iter().collect();
    sha256s.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key("stow.unit-instance.v1");
    for sha256 in &sha256s {
        hasher.update(sha256.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// One locally-compiled registry unit as one build's rustc invocations
/// observed it: the identity the compile actually used — the argv
/// `--cfg` feature set, the real platform (the host triple for host
/// units — cargo passes them no `--target`), and the `--extern` deps
/// resolved to `(crate_name, c_metadata)` pairs. Misses mint only from
/// the observations of the build that just ran, so an observed unit's
/// edges name the dep's own identity (stow#317). Observations live in
/// the build supervisor's memory, or one line per unit in the build's
/// miss journal — they are never persisted to the state db.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObservedUnit {
    /// Crate name as known to crates.io.
    pub crate_name: String,
    /// Crate version.
    pub crate_version: String,
    /// The `--cfg feature="…"` scan of the compile's argv — evidence of
    /// the command line, not the unit's cargo feature set: it may also
    /// carry whatever the crate's build script printed as
    /// `cargo:rustc-cfg=feature="…"`. The resolved set lives on the build's
    /// unit graph node (stow#615).
    pub features: Vec<String>,
    /// The real platform the unit compiled for.
    pub target: String,
    /// The `--target` cargo passed for the unit — `None` marks a
    /// host-side compile, which cargo never passes one to (stow#317).
    pub explicit_target: Option<String>,
    /// The profile the unit compiled with — normalized from the argv
    /// codegen flags the way the unit graph states `unit.profile`, so
    /// the two compare like for like. A native build
    /// (`consumer_target == build_host`) gives host units and target
    /// units the same recorded platform, so the profile is part of the
    /// evidence that splits them (stow#596).
    pub profile: stow_types::platform::Profile,
    /// The invocation's `--extern` deps, resolved to their stable
    /// identities.
    pub externs: Vec<DependencyCMetadataIdentity>,
}

/// The recorded identity of a dependency artifact — enough of it to name
/// the dep node a miss's `depends_on` edge points at: name, version, the
/// feature set it was registered with, and which side of the host/target
/// split it compiles for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedDepIdentity {
    /// Crate name as known to crates.io.
    pub crate_name: String,
    /// Crate version.
    pub crate_version: String,
    /// The feature set the dep's artifact was recorded at.
    pub features: Vec<String>,
    /// The unit shape the published index records for the dep's
    /// `c_metadata` — the side the dep node serves. `None` when no
    /// published row names the dep's `c_metadata` — a locally compiled
    /// artifact the index does not cover — or when its rows disagree
    /// on a side.
    pub unit_shape: Option<stow_types::public_cache::UnitShape>,
    /// Whether the dep's recorded artifact is a proc-macro — the only
    /// host-side extern a target-side unit can carry.
    pub proc_macro: bool,
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
    /// `[{crate_name, compile_key, instance}]` — the dependency instances a
    /// local entry was compiled against; `'[]'` on remote entries, whose
    /// binding is the published instance by construction (stow#836).
    pub dependency_instances_json: String,
    /// How far this entry's identity may travel — recorded at store
    /// time, so a served local-only bundle keeps marking its outputs
    /// (and therefore its consumers) `LocalOnly` (stow#1006).
    pub reach: stow_types::public_cache::Reach,
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
    pub sigstore_signatures: Vec<SigstoreSignature>,
    pub(crate) entry_dir: PathBuf,
    pub(crate) rustc_version: String,
    pub(crate) cache_key: String,
    pub(crate) verified_marker_version: Option<u8>,
    pub(crate) verified_marker_policy: Option<String>,
    pub(crate) _lease_lock: FileLock,
}

impl CachedArtifactBundle {
    pub fn output_source_path(&self, file: &ArtifactBundleFile) -> PathBuf {
        self.entry_dir.join(bundle_file_path(&file.file_name))
    }

    /// The instance digest of this entry's recorded outputs — the value a
    /// dependent's `dependency_instances_json` binding and the externs'
    /// `materialized_outputs` rows compare against (stow#836).
    pub fn instance(&self) -> String {
        outputs_instance_digest(self.outputs.iter().map(|output| output.sha256.as_str()))
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
    let entry = load_artifact_cache_entry(&connection, &rustc_version, &cache_key)
        .await?
        .ok_or_else(|| {
            stow_types::stow_error!(
                "artifact cache entry {cache_key} for rustc {rustc_version} is missing from the state database"
            )
        })?;
    // Only write the LRU stamp when it is actually stale. This read runs
    // once per unit served *and* once per member of that unit's dependency
    // closure, so a build of a few dozen crates was making thousands of
    // UPDATEs — every one a write transaction, and SQLite serialises
    // those, which turned a parallel build's cache hits into a queue.
    // Eviction orders by the hour, not the millisecond; a stamp that can
    // be a minute stale costs it nothing.
    if now_millis().saturating_sub(recorded_millis(entry.last_accessed_ms)) > LRU_STAMP_INTERVAL_MS
    {
        touch_artifact_cache_entry(&connection, &rustc_version, &cache_key, now_millis()).await?;
    }
    let outputs = load_artifact_outputs(&connection, &rustc_version, &cache_key).await?;
    let sigstore_signatures =
        load_sigstore_signatures(&connection, &rustc_version, &cache_key).await?;
    let shape = EntryShape::parse(&entry, &rustc_version, &cache_key)?;
    Ok(Some(CachedArtifactBundle {
        provenance: ArtifactProvenance::from_column(&entry.provenance)?,
        reach: stow_types::public_cache::Reach::from_int(entry.reach).ok_or_else(|| {
            stow_types::stow_error!(
                "artifact cache entry {cache_key} for rustc {rustc_version} has unknown reach {}",
                entry.reach
            )
        })?,
        oci_reference: entry.oci_reference,
        oci_digest: entry.oci_digest,
        compile_key: entry.compile_key,
        crate_name: entry.crate_name,
        crate_version: entry.crate_version,
        c_metadata: entry.c_metadata,
        features_json: entry.features_json,
        dependency_c_metadata_json: entry.dependency_c_metadata_json,
        dependency_compile_keys_json: entry.dependency_compile_keys_json,
        dependency_instances_json: entry.dependency_instances_json,
        compile_millis: db_int(entry.compile_millis, "artifact cache entry compile_millis")?,
        size_bytes: db_int(entry.size_bytes, "artifact cache entry size_bytes")?,
        profile: shape.profile,
        emit: shape.emit,
        kind: shape.kind,
        crate_types: shape.crate_types,
        outputs,
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

/// The JSON-encoded unit shape columns of one artifact cache entry.
struct EntryShape {
    profile: Profile,
    emit: Vec<String>,
    kind: ArtifactKind,
    crate_types: Vec<RustCrateType>,
}

impl EntryShape {
    fn parse(
        entry: &ArtifactCacheEntryRow,
        rustc_version: &str,
        cache_key: &str,
    ) -> stow_types::error::Result<Self> {
        let profile = serde_json::from_str::<Profile>(&entry.profile_json).wrap_err_with(|| {
            format!(
                "parse artifact cache profile_json for rustc {rustc_version} cache key {cache_key}"
            )
        })?;
        let emit = serde_json::from_str::<Vec<String>>(&entry.emit_json).wrap_err_with(|| {
            format!(
                "parse artifact cache emit_json for rustc {rustc_version} cache key {cache_key}"
            )
        })?;
        let kind = serde_json::from_str::<ArtifactKind>(&entry.kind_json).wrap_err_with(|| {
            format!(
                "parse artifact cache kind_json for rustc {rustc_version} cache key {cache_key}"
            )
        })?;
        let crate_types = serde_json::from_str::<Vec<RustCrateType>>(&entry.crate_types_json)
            .wrap_err_with(|| {
                format!(
                    "parse artifact cache crate_types_json for rustc {rustc_version} cache key {cache_key}"
                )
            })?;
        Ok(Self {
            profile,
            emit,
            kind,
            crate_types,
        })
    }
}

#[derive(Debug, Clone, FromRow)]
struct CompileKeyLookupRow {
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
        "SELECT target, c_metadata \
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
        },
    )
    .await
}

/// Store a verified bundle's contents into `entry_dir` — the same layout a
/// local-cache entry has (`files/`, `oci/`, `manifest.json`).
///
/// The CI build's consumption path keeps each verified bundle in a
/// compile-key-addressed store the sandboxed phases mount read-only. The
/// host prefetch already digest-checked and cosign-verified every byte, so
/// the sqlite index and trust markers the CLI cache maintains do not exist
/// there — the read-only grant boundary is what keeps the entries
/// unforgeable. Returns the staged size like [`store_downloaded_bundle`].
pub fn store_bundle_entry_dir(
    entry_dir: &Path,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<u64> {
    if entry_dir.exists() {
        return Err(stow_types::stow_error!(
            "bundle entry dir {} already exists",
            entry_dir.display()
        ));
    }
    write_downloaded_bundle_to_entry(entry_dir, bundle)
}

/// Load a stored bundle entry back from its directory — the inverse of
/// [`store_bundle_entry_dir`], for the consumption path where the sqlite
/// index is unavailable. `lease_dir` must be writable and is where the
/// shared lease file lands; nothing evicts the CI store, so the lease is
/// plumbing, not eviction protection.
///
/// The entry's `manifest.json` is reparsed, so every identity field comes
/// from the bytes the prefetch verified — the same config the publisher
/// signed inside `oci/config.json`.
pub fn load_bundle_entry_dir(
    entry_dir: &Path,
    lease_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<Option<CachedArtifactBundle>> {
    let manifest_path = entry_dir.join(STOW_BUNDLE_MANIFEST_PATH);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let manifest_bytes = std::fs::read(&manifest_path)
        .wrap_err_with(|| format!("read bundle entry manifest {}", manifest_path.display()))?;
    let manifest: stow_types::bundle::ArtifactBundleManifest =
        serde_json::from_slice(&manifest_bytes)
            .wrap_err_with(|| format!("parse bundle entry manifest {}", manifest_path.display()))?;
    let lease_lock = acquire_entry_shared_lock(lease_dir, cache_key)?;
    Ok(Some(CachedArtifactBundle {
        provenance: ArtifactProvenance::Remote,
        reach: stow_types::public_cache::Reach::Public,
        oci_reference: manifest.oci_reference,
        oci_digest: manifest.oci_digest,
        compile_key: manifest.config.compile_key,
        crate_name: manifest.config.crate_name.as_str().to_owned(),
        crate_version: manifest.config.crate_version.to_string(),
        c_metadata: manifest.config.c_metadata.as_str().to_owned(),
        features_json: manifest.config.features_json.raw(),
        dependency_c_metadata_json: manifest.config.dependency_c_metadata_json.raw(),
        dependency_compile_keys_json: manifest.config.dependency_compile_keys_json,
        // A manifest carries no binding; a consume-store entry is
        // remote-provenance, so its binding is the published instance by
        // construction.
        dependency_instances_json: "[]".to_owned(),
        compile_millis: manifest.config.compile_millis,
        size_bytes: directory_size(entry_dir)?,
        profile: manifest.config.profile,
        emit: manifest.config.emit,
        kind: manifest.config.kind,
        crate_types: manifest.config.crate_types,
        outputs: manifest.config.outputs,
        sigstore_signatures: manifest.sigstore_signatures,
        entry_dir: entry_dir.to_path_buf(),
        rustc_version: manifest.config.rustc_version.as_str().to_owned(),
        cache_key: cache_key.to_owned(),
        // The prefetch's signature check happens once, on the host, before
        // the entry lands in the store — there is no trust marker column to
        // reload because there is no database to carry one.
        verified_marker_version: None,
        verified_marker_policy: None,
        _lease_lock: lease_lock,
    }))
}

/// Total byte size of every file under `root` — the same quantity a stored
/// bundle's `size_bytes` column records.
fn directory_size(root: &Path) -> stow_types::error::Result<u64> {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.wrap_err_with(|| format!("walk cache entry {}", root.display()))?;
        if entry.file_type().is_file() {
            total = total.saturating_add(
                entry
                    .metadata()
                    .wrap_err_with(|| format!("stat cache entry file {}", entry.path().display()))?
                    .len(),
            );
        }
    }
    Ok(total)
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
    let requested_features = serde_json::from_str::<Vec<String>>(&request.features_json)
        .wrap_err("parse semantic cache request features_json")?;
    // `features_json` and `dependency_c_metadata_json` stay out of the
    // WHERE clause (stow#881): a contained request is served from the
    // smallest published set containing it, whose dependency identity
    // is the serving set's own build context — the Rust-side filter
    // keeps containment while the chain check that gates a move ran
    // upstream at prefetch-staging time.
    let rows = sqlx::query_as::<_, SemanticCacheCandidateRow>(
        "SELECT c_metadata, crate_version, emit_json, features_json, crate_name, \
                compile_key, dependency_c_metadata_json \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND target = ? AND crate_name = ? \
           AND profile_json = ? AND kind_json = ? AND crate_types_json = ? \
           AND reach = ?",
    )
    .bind(&request.rustc_version)
    .bind(&request.target)
    .bind(&request.crate_name)
    .bind(profile_json)
    .bind(kind_json)
    .bind(crate_types_json)
    .bind(stow_types::public_cache::Reach::Public.to_int())
    .fetch_all(&connection)
    .await?;
    let mut candidates = rows
        .into_iter()
        .filter_map(|row| {
            match semantic_candidate_from_row(
                row,
                &requested_version,
                &request.emit,
                &requested_features,
            ) {
                Ok(Some(candidate)) => Some(Ok(candidate)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    candidates.sort_by(compare_semantic_candidates);
    // The first candidate in order that was also compiled with the
    // request's own cfgs, codegen and link options (stow#1047). One that
    // was not is a plain miss for this request, never an eviction: it is
    // a sound artifact for the requests it does match.
    for candidate in candidates {
        let loaded = load_cached_bundle(
            config,
            &FetchRequest {
                target: &request.target,
                rustc_version: &request.rustc_version,
                c_metadata: &candidate.c_metadata,
            },
        )
        .await?;
        let Some(loaded) = loaded else {
            continue;
        };
        if semantic_candidate_honours_consumer(request, &candidate, &loaded)? {
            return Ok(Some(loaded));
        }
        tracing::debug!(
            crate_name = %request.crate_name,
            candidate_version = %candidate.row.crate_version,
            candidate_compile_key = %candidate.row.compile_key,
            "local semantic candidate was compiled with different cfgs, codegen or link options"
        );
    }
    Ok(None)
}

/// Whether `loaded`, a semantic candidate of `request`, was compiled with
/// the request's own cfgs, extra codegen and link options.
///
/// A candidate of the request's version and feature set differs in its
/// emit set alone and ran the request's own build script. Any other was
/// built with its own build script's output, which a stored entry carries
/// only in the manifest a downloaded bundle keeps beside its files; a
/// locally compiled entry has none, so it is judged as having no
/// build-script inputs.
fn semantic_candidate_honours_consumer(
    request: &SemanticFetchRequest,
    candidate: &SemanticCacheCandidate,
    loaded: &CachedArtifactBundle,
) -> stow_types::error::Result<bool> {
    let build_script = match request
        .build_script_of_same_build(&candidate.row.crate_version, &candidate.row.features_json)
    {
        Some(own) => std::borrow::Cow::Borrowed(own),
        None => std::borrow::Cow::Owned(stow_types::upload_plan::BuildScriptInputs::of(
            read_entry_native(&loaded.entry_dir)?.as_ref(),
        )),
    };
    request.candidate_honours_consumer(
        &crate::fetch::SemanticCandidate {
            crate_name: &candidate.row.crate_name,
            crate_version: &candidate.row.crate_version,
            features_json: &candidate.row.features_json,
            dependency_c_metadata_json: &candidate.row.dependency_c_metadata_json,
            emit: &candidate.emit,
            compile_key: &candidate.row.compile_key,
        },
        &build_script,
    )
}

/// The captured build-script output of the bundle an entry was stored
/// from; `None` for an entry with no manifest (a local build).
fn read_entry_native(
    entry_dir: &Path,
) -> stow_types::error::Result<Option<stow_types::artifact::NativeArtifacts>> {
    let manifest_path = entry_dir.join(STOW_BUNDLE_MANIFEST_PATH);
    let bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).wrap_err_with(|| {
                format!("read bundle entry manifest {}", manifest_path.display())
            });
        }
    };
    let manifest = serde_json::from_slice::<stow_types::bundle::ArtifactBundleManifest>(&bytes)
        .wrap_err_with(|| format!("parse bundle entry manifest {}", manifest_path.display()))?;
    Ok(manifest.config.native)
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

    // Serialize writers on the entry lock: a concurrent local store or a
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

    let staging_dir = config
        .artifact_cache_staging_dir(&request.rustc_version)
        .await?;
    let size_bytes = tokio::task::spawn_blocking({
        let entry_dir = entry_dir.clone();
        let bundle = bundle.clone();
        let c_metadata = request.c_metadata.clone();
        move || write_bundle_entry_blocking(staging_dir.path(), &entry_dir, &bundle, &c_metadata)
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
        &config.cc_cache_dir(),
        config.artifact_cache_max_bytes,
        &ProtectedEntry::Rustc(&cache_key),
    )
    .await?;
    Ok(cached_bundle_for_entry(
        &bundle,
        entry_dir,
        request.rustc_version,
        cache_key,
        size_bytes,
        lease_lock,
    ))
}

/// The `CachedArtifactBundle` a just-stored remote bundle serves from —
/// every field lifted from the verified manifest the store just wrote.
fn cached_bundle_for_entry(
    bundle: &ArtifactBundle,
    entry_dir: PathBuf,
    rustc_version: String,
    cache_key: String,
    size_bytes: u64,
    lease_lock: FileLock,
) -> CachedArtifactBundle {
    CachedArtifactBundle {
        provenance: ArtifactProvenance::Remote,
        reach: stow_types::public_cache::Reach::Public,
        oci_reference: bundle.manifest.oci_reference.clone(),
        oci_digest: bundle.manifest.oci_digest.clone(),
        compile_key: bundle.manifest.config.compile_key.clone(),
        crate_name: bundle.manifest.config.crate_name.as_str().to_owned(),
        crate_version: bundle.manifest.config.crate_version.to_string(),
        c_metadata: bundle.manifest.config.c_metadata.as_str().to_owned(),
        features_json: bundle.manifest.config.features_json.raw(),
        dependency_c_metadata_json: bundle.manifest.config.dependency_c_metadata_json.raw(),
        dependency_compile_keys_json: bundle.manifest.config.dependency_compile_keys_json.clone(),
        // A remote entry's binding is the published instance by
        // construction; the column records '[]'.
        dependency_instances_json: "[]".to_owned(),
        compile_millis: bundle.manifest.config.compile_millis,
        size_bytes,
        profile: bundle.manifest.config.profile.clone(),
        emit: bundle.manifest.config.emit.clone(),
        kind: bundle.manifest.config.kind.clone(),
        crate_types: bundle.manifest.config.crate_types.clone(),
        outputs: bundle.manifest.config.outputs.clone(),
        sigstore_signatures: bundle.manifest.sigstore_signatures.clone(),
        entry_dir,
        rustc_version,
        cache_key,
        verified_marker_version: None,
        verified_marker_policy: None,
        _lease_lock: lease_lock,
    }
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
/// name inside the process's staging directory and renamed into place, so
/// readers never see a half-written entry; concurrent writers serialize on
/// the entry lock rather than double-storing.
#[tracing::instrument(name = "stow.cache.store_local_build", skip_all, fields(crate_name = %parsed.crate_name))]
pub async fn store_local_build_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    host: &str,
) -> stow_types::error::Result<bool> {
    if build.outputs.is_empty() {
        return Ok(false);
    }
    for output in &build.outputs {
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

    let Some(binding) =
        bind_dependency_instances(&connection, parsed, build, host, &version_dir).await?
    else {
        return Ok(false);
    };

    let staging_dir = config
        .artifact_cache_staging_dir(&build.rustc_version)
        .await?;
    let written = tokio::task::spawn_blocking({
        let staging_dir = staging_dir.clone();
        let entry_dir = entry_dir.clone();
        let outputs = build.outputs.clone();
        move || write_local_build_entry_blocking(staging_dir.path(), &entry_dir, &outputs)
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
        &binding,
    )
    .await?;
    drop(write_lease);

    // Same post-insert discipline as the download path: the new entry joins
    // the shared LRU budget immediately, protected from this eviction pass.
    evict_entries(
        &connection,
        &build.rustc_version,
        &version_dir,
        &config.cc_cache_dir(),
        config.artifact_cache_max_bytes,
        &ProtectedEntry::Rustc(&cache_key),
    )
    .await?;
    Ok(true)
}

/// The dependency binding a stored local entry records — the compile keys
/// and the instances of its direct dependencies' cache entries.
struct DependencyBinding {
    compile_keys_json: String,
    instances_json: String,
}

/// Bind a local build to the exact dependency instances it compiled
/// against, or `None` when the cache does not hold them: rustc binds a
/// dependent to its deps by SVH, so an artifact whose recorded instances the
/// cache does not hold could only ever be served into a broken pair
/// (E0460/E0463, stow#836). First-writer-wins per unit lets concurrent cold
/// builds split a dep set across different instances; the store refuses
/// the mismatched half rather than admit it.
async fn bind_dependency_instances(
    connection: &sqlx::SqlitePool,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    host: &str,
    version_dir: &Path,
) -> stow_types::error::Result<Option<DependencyBinding>> {
    let dep_entries = load_dependency_entry_instances(connection, build, host).await?;
    let mut dependency_compile_keys = Vec::with_capacity(build.dependencies.externs.len());
    let mut dependency_instances = Vec::with_capacity(build.dependencies.externs.len());
    for extern_dep in &build.dependencies.externs {
        match dep_entries.get(extern_dep.c_metadata.as_str()) {
            Some(dep_entry) if !version_dir.join(&dep_entry.relative_dir).exists() => {
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    dependency = %extern_dep.crate_name,
                    compiled_against = %extern_dep.instance,
                    "skipping local artifact cache store: dependency entry has a row but no files"
                );
                return Ok(None);
            }
            Some(dep_entry) if dep_entry.instance == extern_dep.instance => {
                dependency_compile_keys.push(DependencyCompileKeyIdentity {
                    crate_name: CrateName::parse(extern_dep.crate_name.as_str()).map_err(
                        |error| {
                            stow_types::stow_error!(
                                "extern crate name `{}` is not a registry crate name: {error}",
                                extern_dep.crate_name
                            )
                        },
                    )?,
                    compile_key: dep_entry.compile_key.clone(),
                });
                dependency_instances.push(DependencyInstanceIdentity {
                    crate_name: extern_dep.crate_name.clone(),
                    compile_key: dep_entry.compile_key.clone(),
                    instance: extern_dep.instance.clone(),
                });
            }
            Some(dep_entry) => {
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    dependency = %extern_dep.crate_name,
                    compiled_against = %extern_dep.instance,
                    entry_instance = %dep_entry.instance,
                    "skipping local artifact cache store: dependency instance differs from the cached one"
                );
                return Ok(None);
            }
            None => {
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    dependency = %extern_dep.crate_name,
                    compiled_against = %extern_dep.instance,
                    "skipping local artifact cache store: no cache entry for dependency"
                );
                return Ok(None);
            }
        }
    }
    let dependency_compile_keys_json = serde_json::to_string(
        &DependencyCompileKeyIdentity::canonicalize_list(dependency_compile_keys),
    )
    .wrap_err("serialize dependency compile keys")?;
    let dependency_instances_json = serde_json::to_string(
        &DependencyInstanceIdentity::canonicalize_list(dependency_instances),
    )
    .wrap_err("serialize dependency instances")?;
    Ok(Some(DependencyBinding {
        compile_keys_json: dependency_compile_keys_json,
        instances_json: dependency_instances_json,
    }))
}

/// Persist the `artifact_cache_entries` row for a freshly staged local entry:
/// local provenance, no signatures, no verified marker, and the dependency
/// binding — compile keys and instances — the refusal check just verified
/// against the entries that produced the deps.
async fn record_local_entry_metadata(
    connection: &sqlx::SqlitePool,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    cache_key: &str,
    entry_relative_dir: &Path,
    written: &LocalEntryWrite,
    binding: &DependencyBinding,
) -> stow_types::error::Result<()> {
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
            dependency_c_metadata_json: build.dependencies.c_metadata_json.clone(),
            dependency_compile_keys_json: &binding.compile_keys_json,
            dependency_instances_json: &binding.instances_json,
            reach: build.reach,
            compile_millis: 0,
            target: &build.target,
            profile: &profile,
            emit: &emit,
            kind: &kind,
            crate_types: &crate_types,
            outputs: &written.outputs,
            sigstore_signatures: &[],
        },
    )
    .await
}

pub async fn record_materialized_bundle_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    host: &str,
) -> stow_types::error::Result<()> {
    let out_dir = parsed.out_dir.as_ref().ok_or_else(|| {
        stow_types::stow_error!("materialized bundle outputs require rustc --out-dir")
    })?;
    let connection = config.state_db_pool().await?;
    let updated_at_ms: i64 = db_int(now_millis(), "materialized output timestamp")?;
    let stable_c_metadata = stable_c_metadata_for_compile_key(&bundle.compile_key)?;
    let dependency_identity = stable_c_metadata.as_str();
    let stable_extra_filename = format!("-{stable_c_metadata}");
    let instance =
        outputs_instance_digest(bundle.outputs.iter().map(|output| output.sha256.as_str()));
    // The entry's own reach: a served local-only bundle keeps marking
    // its materialized outputs local-only, so its consumers fold to
    // `LocalOnly` exactly as if it had compiled here (stow#1006).
    let reach = bundle.reach;
    let stable_parsed =
        parsed_with_stable_identity(parsed, &stable_c_metadata, &stable_extra_filename);

    for file in &bundle.outputs {
        let output_path = crate::inject::expected_output_path(parsed, out_dir, file, host)?;
        record_materialized_output(
            &connection,
            &output_path,
            dependency_identity,
            &instance,
            reach,
            updated_at_ms,
        )
        .await?;
        let original_path = crate::inject::original_output_path(out_dir, file)?;
        if original_path != output_path {
            record_materialized_output(
                &connection,
                &original_path,
                dependency_identity,
                &instance,
                reach,
                updated_at_ms,
            )
            .await?;
        }
        let stable_output_path =
            crate::inject::expected_output_path(&stable_parsed, out_dir, file, host)?;
        if stable_output_path != output_path && stable_output_path != original_path {
            record_materialized_output(
                &connection,
                &stable_output_path,
                dependency_identity,
                &instance,
                reach,
                updated_at_ms,
            )
            .await?;
        }
    }

    Ok(())
}

/// Record `materialized_outputs` rows for a closure dependency's
/// original-named outputs — the files
/// `inject::materialize_original_outputs` writes into the served unit's
/// out dir. The closure walk is the one materialization that used to
/// leave no rows behind; a later dependent resolving an `--extern` at one
/// of these paths needs the instance the bytes carry (stow#836).
pub async fn record_materialized_closure_outputs(
    config: &StowConfig,
    out_dir: &Path,
    bundle: &CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let updated_at_ms: i64 = db_int(now_millis(), "materialized output timestamp")?;
    let instance =
        outputs_instance_digest(bundle.outputs.iter().map(|output| output.sha256.as_str()));
    for file in &bundle.outputs {
        let original_path = crate::inject::original_output_path(out_dir, file)?;
        record_materialized_output(
            &connection,
            &original_path,
            bundle.c_metadata.as_str(),
            &instance,
            bundle.reach,
            updated_at_ms,
        )
        .await?;
    }
    Ok(())
}

/// The output paths a locally-compiled unit records in
/// `materialized_outputs` — the paths a dependent's `--extern` arguments
/// name — derived by the parsed invocation's own `output_*_path`
/// methods, never by naming files by hand (stow#618). Empty for a unit
/// that records nothing: no `-C metadata`, or no restorable artifact
/// shape at all.
pub fn materialized_output_paths(
    parsed: &ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<Vec<PathBuf>> {
    if parsed.c_metadata.is_none() || !parsed.is_restorable_artifact() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    if let Some(path) = parsed.output_rlib_path() {
        paths.push(path);
    }
    if let Some(path) = parsed.output_rmeta_path() {
        paths.push(path);
    }
    if let Some(path) = parsed
        .output_dynamic_library_path(host)
        .map_err(stow_types::error::Error::msg)?
    {
        paths.push(path);
    }
    Ok(paths)
}

pub async fn record_materialized_local_build_outputs(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    host: &str,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let updated_at_ms: i64 = db_int(now_millis(), "materialized output timestamp")?;
    let dependency_identity = build.identity.c_metadata.as_str();
    let instance = build.instance();
    let stable_parsed = parsed_with_stable_identity(
        parsed,
        &build.identity.c_metadata,
        &build.identity.extra_filename,
    );

    // The stable-named invocation is the same unit under another file
    // name, so it names the same outputs: a shape present under one name
    // and absent under the other is a broken rewrite, not a unit with
    // fewer rows.
    let cargo_named = materialized_output_paths(parsed, host)?;
    let stable_named = materialized_output_paths(&stable_parsed, host)?;
    if cargo_named.len() != stable_named.len() {
        return Err(stow_types::stow_error!(
            "stable parsed rustc args name {} outputs for crate {}, the invocation names {}",
            stable_named.len(),
            stable_parsed.crate_name,
            cargo_named.len()
        ));
    }
    for path in cargo_named.iter().chain(&stable_named) {
        record_materialized_output(
            &connection,
            path,
            dependency_identity,
            &instance,
            build.reach,
            updated_at_ms,
        )
        .await?;
    }

    Ok(())
}

/// Resolve a set of `c_metadata` values to the artifact identities this
/// toolchain recorded — one batched read off the compile path, used at
/// build end to name each observed unit's `--extern` deps at the dep's
/// own identity.
pub async fn load_artifact_dep_identities(
    config: &StowConfig,
    rustc_version: &str,
    c_metadatas: &BTreeSet<String>,
) -> stow_types::error::Result<BTreeMap<String, ObservedDepIdentity>> {
    if c_metadatas.is_empty() {
        return Ok(BTreeMap::new());
    }
    let connection = config.state_db_pool().await?;
    let placeholders = c_metadatas
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT c_metadata, crate_name, crate_version, features_json, kind_json \
         FROM artifact_cache_entries \
         WHERE rustc_version = ? AND c_metadata IN ({placeholders})"
    );
    let mut rows =
        sqlx::query_as::<_, ObservedDepIdentityRow>(sqlx::AssertSqlSafe(sql)).bind(rustc_version);
    for c_metadata in c_metadatas {
        rows = rows.bind(c_metadata);
    }
    let rows = rows.fetch_all(&connection).await?;
    let mut identities = BTreeMap::new();
    for row in rows {
        let Ok(features) = serde_json::from_str::<Vec<String>>(&row.features_json) else {
            continue;
        };
        let proc_macro = serde_json::from_str::<ArtifactKind>(&row.kind_json)
            .is_ok_and(|kind| kind == ArtifactKind::ProcMacro);
        identities.insert(
            row.c_metadata,
            ObservedDepIdentity {
                crate_name: row.crate_name,
                crate_version: row.crate_version,
                features,
                unit_shape: None,
                proc_macro,
            },
        );
    }
    Ok(identities)
}

#[derive(sqlx::FromRow)]
struct ObservedDepIdentityRow {
    c_metadata: String,
    crate_name: String,
    crate_version: String,
    features_json: String,
    kind_json: String,
}

/// Every `(crate_name, crate_version, target)` the local artifact cache
/// holds for this rustc — one query per build so the serve map can name
/// the pairs a local lookup could answer (stow#347).
pub async fn locally_covered_units(
    config: &StowConfig,
    rustc_version: &str,
) -> stow_types::error::Result<Vec<(String, String, String)>> {
    let connection = config.state_db_pool().await?;
    sqlx::query_as::<_, (String, String, String)>(sqlx::AssertSqlSafe(
        "SELECT crate_name, crate_version, target \
         FROM artifact_cache_entries \
         WHERE rustc_version = ?",
    ))
    .bind(rustc_version)
    .fetch_all(&connection)
    .await
    .wrap_err("read locally covered crate units")
}

/// The `(crate_name, output_path)` pairs a unit's `--extern` arguments
/// name, in the order the dependency-identity JSON serializes them —
/// sorted by crate name then path. The `output_path`s are the
/// `materialized_outputs` rows' keys: the same normalization the records
/// use on the write side (stow#618).
pub fn extern_output_paths(
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Vec<(String, String)>> {
    let mut identities = parsed
        .extern_crates
        .iter()
        .map(|extern_crate| {
            let path = path_to_string(&extern_crate.path)?;
            Ok((extern_crate.crate_name.clone(), path))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    identities.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(identities)
}

/// What resolving a unit's `--extern` set against `materialized_outputs`
/// found (stow#618).
pub enum DependencyCMetadataResolution {
    /// Every extern resolved; the serialized dependency-identity JSON the
    /// compile key and the miss journal consume, plus each extern's
    /// recorded instance digest.
    Resolved(ResolvedDependencies),
    /// The first extern path — in `extern_output_paths` order — with no
    /// recorded row. The dependency's bookkeeping genuinely never landed:
    /// a path or git dependency, or a dependency whose own store was
    /// skipped.
    Unrecorded(String),
}

/// A unit's `--extern` set resolved against `materialized_outputs` — the
/// identity JSON the compile key consumes and, alongside it, the exact
/// dependency instances the compile ran against (stow#836).
#[derive(Debug)]
pub struct ResolvedDependencies {
    /// `[{crate_name, c_metadata}]` in canonical order — the
    /// `dependency_c_metadata_json` the compile key and the miss journal
    /// consume.
    pub c_metadata_json: String,
    /// Each extern's crate, stable identity and recorded instance digest,
    /// in `c_metadata_json` order.
    pub externs: Vec<MaterializedDependency>,
    /// The tightest reach any extern's row recorded — `LocalOnly` when a
    /// dependency is git-sourced or codegen-keyed (stow#1006).
    pub reach: stow_types::public_cache::Reach,
}

/// One resolved `--extern`: which stable identity the extern path belongs
/// to, and which exact instance of it the compile ran against.
#[derive(Debug, Clone)]
pub struct MaterializedDependency {
    /// The crate name as the `--extern` spelled it.
    pub crate_name: String,
    /// The dependency's stable `c_metadata`.
    pub c_metadata: String,
    /// [`outputs_instance_digest`] of the bytes the extern path carried.
    pub instance: String,
}

pub async fn resolve_dependency_c_metadata_json(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<DependencyCMetadataResolution> {
    let connection = config.state_db_pool().await?;
    let identities = extern_output_paths(parsed)?;
    if identities.is_empty() {
        return Ok(DependencyCMetadataResolution::Resolved(
            ResolvedDependencies {
                c_metadata_json: "[]".to_owned(),
                externs: Vec::new(),
                reach: stow_types::public_cache::Reach::Public,
            },
        ));
    }

    // One round trip for the whole extern set — this runs inside every
    // rustc invocation, so per-extern queries are not an option.
    let placeholders = identities
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT output_path, c_metadata, instance, reach FROM materialized_outputs \
         WHERE output_path IN ({placeholders})"
    );
    let mut rows = sqlx::query_as::<_, (String, String, String, i64)>(sqlx::AssertSqlSafe(sql));
    for output_path in identities.iter().map(|(_, output_path)| output_path) {
        rows = rows.bind(output_path);
    }
    let rows = rows.fetch_all(&connection).await?;
    let mut reach = stow_types::public_cache::Reach::Public;
    let mut metadata_by_path = BTreeMap::new();
    for (path, c_metadata, instance, row_reach) in rows {
        // A reach value the table cannot decode is an inconsistent
        // schema — fail fast rather than misclassify a local-only dep
        // as public.
        let row_reach = stow_types::public_cache::Reach::from_int(row_reach).ok_or_else(|| {
            stow_types::stow_error!("materialized_outputs.reach has unknown value {row_reach}")
        })?;
        reach = reach.fold(row_reach);
        metadata_by_path.insert(path, (c_metadata, instance));
    }
    let mut resolved = Vec::with_capacity(identities.len());
    let mut externs = Vec::with_capacity(identities.len());
    for (crate_name, output_path) in identities {
        let Some((c_metadata, instance)) = metadata_by_path.get(&output_path) else {
            return Ok(DependencyCMetadataResolution::Unrecorded(output_path));
        };
        resolved.push(DependencyCMetadataIdentity {
            crate_name: crate_name.clone(),
            c_metadata: c_metadata.clone(),
        });
        externs.push(MaterializedDependency {
            crate_name,
            c_metadata: c_metadata.clone(),
            instance: instance.clone(),
        });
    }

    Ok(DependencyCMetadataResolution::Resolved(
        ResolvedDependencies {
            c_metadata_json: serde_json::to_string(&resolved)?,
            externs,
            reach,
        },
    ))
}

async fn record_materialized_output(
    connection: &sqlx::SqlitePool,
    path: &Path,
    c_metadata: &str,
    instance: &str,
    reach: stow_types::public_cache::Reach,
    updated_at_ms: i64,
) -> stow_types::error::Result<()> {
    sqlx::query(
        "INSERT INTO materialized_outputs (output_path, c_metadata, instance, reach, updated_at_ms) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(output_path) DO UPDATE SET \
             c_metadata = excluded.c_metadata, \
             instance = excluded.instance, \
             reach = excluded.reach, \
             updated_at_ms = excluded.updated_at_ms",
    )
    .bind(path_to_string(path)?)
    .bind(c_metadata)
    .bind(instance)
    .bind(reach.to_int())
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

/// Remove the entry a loaded bundle was read from — the same removal path
/// as [`remove_cached_bundle`], addressed by the bundle's own `cache_key`
/// for a serve path that holds the bundle rather than the request that
/// found it (stow#836). The bundle is consumed: its shared lease goes
/// before the removal takes the entry's exclusive lock.
pub async fn remove_loaded_bundle_entry(
    config: &StowConfig,
    bundle: CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let rustc_version = bundle.rustc_version.clone();
    let cache_key = bundle.cache_key.clone();
    drop(bundle);
    let version_dir = config.artifact_cache_version_dir(&rustc_version);
    let connection = config.state_db_pool().await?;
    remove_cached_bundle_locked(&connection, &version_dir, &rustc_version, &cache_key).await
}

/// One process's staging directory inside a cache version's staging root:
/// `<name>/` holds every entry the process is mid-store on, and the
/// sibling `<name>.lock` carries the exclusive lock that marks the
/// owner alive. `<name>` is the process id plus tempfile's random suffix.
///
/// The lock file is created under a temporary name, locked, then renamed
/// to `<name>.lock`, so a `<name>.lock` a sweeper sees is always either
/// held by its live owner or left by a dead one — never mid-acquisition.
/// Dropping removes the directory and the lock file. Every command
/// returns to the entry point rather than exiting on the spot
/// (stow#682), so the drop is the ordinary end; a process killed before
/// it gets there runs no destructor, which is what
/// [`sweep_staging_locks`] covers.
#[derive(Debug)]
pub struct StagingDir {
    rustc_version: String,
    dir: PathBuf,
    lock_path: PathBuf,
    _lock: FileLock,
}

impl StagingDir {
    /// Create this process's staging directory under `staging_root`,
    /// holding `<name>.lock` until the returned value drops.
    pub fn acquire(staging_root: &Path, rustc_version: &str) -> stow_types::error::Result<Self> {
        std::fs::create_dir_all(staging_root).wrap_err_with(|| {
            format!(
                "create artifact cache staging root {}",
                staging_root.display()
            )
        })?;
        let (file, temp_path) = tempfile::Builder::new()
            .prefix(&format!("{}-", std::process::id()))
            .tempfile_in(staging_root)
            .wrap_err_with(|| format!("create staging lock in {}", staging_root.display()))?
            .into_parts();
        let lock = FileLock::exclusive(file)
            .wrap_err_with(|| format!("lock staging lock {}", temp_path.display()))?;
        let name = temp_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                stow_types::stow_error!("staging lock {} has no UTF-8 name", temp_path.display())
            })?
            .to_owned();
        let lock_path = staging_root.join(format!("{name}.lock"));
        temp_path.persist_noclobber(&lock_path).map_err(|error| {
            stow_types::stow_error!("persist staging lock {}: {error}", lock_path.display())
        })?;
        let dir = staging_root.join(&name);
        std::fs::create_dir(&dir)
            .wrap_err_with(|| format!("create staging dir {}", dir.display()))?;
        Ok(Self {
            rustc_version: rustc_version.to_owned(),
            dir,
            lock_path,
            _lock: lock,
        })
    }

    /// The `<name>/` directory stores stage their entries into.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// The cache version this staging directory belongs to.
    pub fn rustc_version(&self) -> &str {
        &self.rustc_version
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_file(&self.lock_path);
    }
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
    std::fs::create_dir_all(version_dir.join(STAGING_DIR)).wrap_err_with(|| {
        format!(
            "create rustc artifact cache staging directory {}",
            version_dir.display()
        )
    })?;
    let version_lease = RustcVersionLease {
        _lock: acquire_version_shared_lock(&leases_root, rustc_version)?,
    };
    // Under the version lease, so a concurrent stale-version purge cannot
    // move this directory while its staging is being swept.
    sweep_staging_locks(&version_dir.join(STAGING_DIR))?;

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
    staging_dir: &Path,
    entry_dir: &Path,
    bundle: &ArtifactBundle,
    c_metadata: &str,
) -> stow_types::error::Result<u64> {
    let tempdir = tempfile::Builder::new()
        .prefix(&format!("{c_metadata}-"))
        .tempdir_in(staging_dir)
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
#[derive(Debug, Clone)]
pub struct LocalBuildOutput {
    /// Where the passthrough build wrote the artifact.
    source: PathBuf,
    /// The file name inside the entry's `files/` dir — the stable-name form
    /// a remote bundle would have carried.
    file_name: String,
    media_type: &'static str,
    /// SHA-256 of the source's bytes, hashed once at compile finish.
    sha256: String,
}

/// The files a local store captured into the staged entry, plus its size.
struct LocalEntryWrite {
    outputs: Vec<ArtifactBundleFile>,
    size_bytes: u64,
}

/// The artifacts a successful rustc invocation produced, paired with the
/// stable-name file names they carry inside the cache entry. The dep-info
/// file is not an output: like remote bundles it is synthesized on restore.
pub fn local_build_output_specs(
    parsed: &ParsedRustcArgs,
    stable_parsed: &ParsedRustcArgs,
    host: &str,
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
            sha256: String::new(),
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
            sha256: String::new(),
        });
    }
    if parsed.emit.contains("link") && parsed.produces_dynamic_library() {
        let source = parsed
            .output_dynamic_library_path(host)
            .map_err(stow_types::error::Error::msg)?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "dynamic library output path unavailable for crate {}",
                    parsed.crate_name
                )
            })?;
        let file_name = output_file_name(
            &stable_parsed
                .output_dynamic_library_path(host)
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
            sha256: String::new(),
        });
    }
    Ok(outputs)
}

/// Hash each output's source bytes — once per compile, so the local store
/// records per-file digests without reading the staged copy again.
pub async fn hash_local_build_outputs(
    mut outputs: Vec<LocalBuildOutput>,
) -> stow_types::error::Result<Vec<LocalBuildOutput>> {
    tokio::task::spawn_blocking(move || {
        hash_local_build_outputs_sync(&mut outputs)?;
        Ok(outputs)
    })
    .await
    .wrap_err("join local build output hashing task")?
}

/// The blocking half of [`hash_local_build_outputs`] — tests call it
/// directly off the runtime.
pub fn hash_local_build_outputs_sync(
    outputs: &mut [LocalBuildOutput],
) -> stow_types::error::Result<()> {
    for output in outputs {
        output.sha256 = sha256_file_bytes(&output.source)?.0;
    }
    Ok(())
}

/// Stage a locally-built entry under a temp name in the process's staging
/// directory and rename it into place. Runs under the exclusive entry
/// lock, so a partial stage never lands: a failed stage drops the
/// `TempDir`, and a crash between rename and row insert leaves an orphan
/// `entry_dir` the next store removes. A process killed mid-stage leaves
/// the temp dir under `<version>/staging/<name>/`, which the
/// `prepare_local_cache` sweep reclaims.
fn write_local_build_entry_blocking(
    staging_dir: &Path,
    entry_dir: &Path,
    outputs: &[LocalBuildOutput],
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
        .tempdir_in(staging_dir)
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
        reflink_copy::reflink_or_copy(&output.source, &dest).wrap_err_with(|| {
            format!(
                "materialize {} into local cache entry",
                output.source.display()
            )
        })?;
        // The compile hashed the source bytes once; the staged copy is a
        // clone of exactly those bytes, so the digest it recorded is what
        // the entry holds.
        let len = std::fs::metadata(&dest)
            .wrap_err_with(|| format!("stat staged cache file {}", dest.display()))?
            .len();
        size_bytes = size_bytes.saturating_add(len);
        written_outputs.push(ArtifactBundleFile {
            file_name: output.file_name.clone(),
            media_type: output.media_type.to_owned(),
            sha256: output.sha256.clone(),
        });
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
        size_bytes,
    })
}

/// One entry in `dependency_instances_json`: which instance of a direct
/// dependency a stored artifact was compiled against — the
/// [`outputs_instance_digest`] of the dep entry's recorded outputs at
/// store time. A served hit is sound only while the dep's current entry
/// still carries that instance (stow#836).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DependencyInstanceIdentity {
    /// Crate name as known to crates.io.
    pub crate_name: String,
    /// Blake3 compile key of the dependency's cache entry.
    pub compile_key: String,
    /// Instance digest of the dependency's cache entry when the store
    /// verified the binding.
    pub instance: String,
}

impl DependencyInstanceIdentity {
    /// Sort and deduplicate a list of identities into canonical order —
    /// the same order [`DependencyCompileKeyIdentity::canonicalize_list`]
    /// gives the parallel column.
    pub fn canonicalize_list(mut identities: Vec<Self>) -> Vec<Self> {
        identities.sort();
        identities.dedup();
        identities
    }
}

/// A dependency's current cache entry reduced to what the store's instance
/// check reads.
struct DependencyEntryInstance {
    compile_key: String,
    relative_dir: String,
    instance: String,
}

/// The current cache entries for a local build's direct dependencies in one
/// batched primary-key query — the `c_metadata → (compile_key, entry dir,
/// instance)` map the store's refusal check reads. A dep's entry sits under
/// the dependent's own target or, for a host-side dep such as a proc-macro
/// of a `--target` build, under the host triple; the stable `c_metadata`
/// already carries the target, so one dep naming entries under both is a
/// corrupt cache and fails.
async fn load_dependency_entry_instances(
    connection: &sqlx::SqlitePool,
    build: &LocalBuildArtifact,
    host: &str,
) -> stow_types::error::Result<BTreeMap<String, DependencyEntryInstance>> {
    if build.dependencies.externs.is_empty() {
        return Ok(BTreeMap::new());
    }
    let targets: BTreeSet<&str> = [build.target.as_str(), host].into_iter().collect();
    let cache_keys: Vec<String> = build
        .dependencies
        .externs
        .iter()
        .flat_map(|extern_dep| {
            targets
                .iter()
                .map(|target| artifact_cache_key(target, extern_dep.c_metadata.as_str()))
        })
        .collect();
    let placeholders = cache_keys
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT e.c_metadata, e.cache_key, e.compile_key, e.relative_dir, o.sha256 \
         FROM artifact_cache_entries e \
         LEFT JOIN artifact_cache_outputs o \
             ON o.rustc_version = e.rustc_version AND o.cache_key = e.cache_key \
         WHERE e.rustc_version = ? AND e.cache_key IN ({placeholders}) \
         ORDER BY e.cache_key, o.ordinal"
    );
    let mut query = sqlx::query_as::<_, (String, String, String, String, Option<String>)>(
        sqlx::AssertSqlSafe(sql),
    )
    .bind(&build.rustc_version);
    for cache_key in &cache_keys {
        query = query.bind(cache_key);
    }
    let rows = query.fetch_all(connection).await?;
    let mut entries: BTreeMap<String, (String, String, String, Vec<String>)> = BTreeMap::new();
    for (c_metadata, cache_key, compile_key, relative_dir, sha256) in rows {
        let entry = entries
            .entry(c_metadata.clone())
            .or_insert_with(|| (cache_key.clone(), compile_key, relative_dir, Vec::new()));
        if entry.0 != cache_key {
            return Err(stow_types::stow_error!(
                "dependency c_metadata {c_metadata} has cache entries under both {} and {cache_key}",
                entry.0
            ));
        }
        if let Some(sha256) = sha256 {
            entry.3.push(sha256);
        }
    }
    Ok(entries
        .into_iter()
        .map(|(c_metadata, (_, compile_key, relative_dir, sha256s))| {
            let instance = outputs_instance_digest(sha256s.iter().map(String::as_str));
            (
                c_metadata,
                DependencyEntryInstance {
                    compile_key,
                    relative_dir,
                    instance,
                },
            )
        })
        .collect())
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

/// The entry the store that just ran shields from its own eviction
/// pass: it already joined the shared budget, and being its own pass's
/// first victim serves no one. `Rustc` names an `artifact_cache_entries`
/// row under `version_dir`; `Cc` names a `cc_cache_entries` object under
/// `cc_dir`.
enum ProtectedEntry<'a> {
    Rustc(&'a str),
    Cc(&'a str),
}

impl ProtectedEntry<'_> {
    fn matches(&self, candidate: &EvictionCandidate) -> bool {
        let key = match self {
            Self::Rustc(key) | Self::Cc(key) => *key,
        };
        let same_kind = matches!(
            (self, &candidate.location),
            (Self::Rustc(_), EvictionLocation::Rustc) | (Self::Cc(_), EvictionLocation::Cc)
        );
        same_kind && key == candidate.cache_key
    }
}

/// Where an eviction candidate's bytes live.
enum EvictionLocation {
    /// An `artifact_cache_entries` row; its `relative_dir` in the pass's
    /// listing names the entry dir under `version_dir`.
    Rustc,
    /// A `cc_cache_entries` row; the object file is `cc_dir/<key>.o`.
    Cc,
}

impl EvictionLocation {
    /// Deterministic order between candidates tied on stamp and key.
    const fn rank(&self) -> u8 {
        match self {
            Self::Rustc => 0,
            Self::Cc => 1,
        }
    }
}

/// One entry in the shared `artifact_cache_max_bytes` LRU — a rustc
/// bundle entry under `version_dir` or a C/C++ object under `cc_dir`
/// (stow#980), ordered by `last_accessed_ms`.
struct EvictionCandidate {
    cache_key: String,
    size_bytes: u64,
    last_accessed_ms: u64,
    location: EvictionLocation,
}

/// Post-store eviction for a C/C++ object store: the object joined the
/// shared budget already, and its own pass protects it the way a rustc
/// store protects its entry. The rustc half of the pass is the active
/// version's entries — the same set every rustc-triggered pass sees.
pub async fn evict_after_cc_store(
    config: &StowConfig,
    connection: &sqlx::SqlitePool,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    let rustc_version: Option<String> =
        sqlx::query_scalar("SELECT value FROM metadata_values WHERE key = 'active_rustc_version'")
            .fetch_optional(connection)
            .await?;
    // No active version means no rustc build has prepared the cache yet, so
    // no `artifact_cache_entries` row exists and the pass is the `cc/` half
    // alone; no row carries the empty version.
    let rustc_version = rustc_version.unwrap_or_default();
    evict_entries(
        connection,
        &rustc_version,
        &config.artifact_cache_version_dir(&rustc_version),
        &config.cc_cache_dir(),
        config.artifact_cache_max_bytes,
        &ProtectedEntry::Cc(cache_key),
    )
    .await
}

/// The dependency-closure view of one pass's `artifact_cache_entries`
/// listing (stow#1005): `providers` maps a compile key to the cache keys
/// of the entries carrying it, and `dependents_of` maps it to the cache
/// keys of the entries whose `dependency_compile_keys_json` names it, so a
/// victim carries out every entry its removal would leave without a
/// dependency entry. Remote and local rows both record the column, so the
/// rule is provenance-agnostic.
struct ClosureGraph {
    /// Compile key → cache keys of the listed entries carrying it.
    providers: BTreeMap<String, BTreeSet<String>>,
    /// Compile key → cache keys of the listed entries depending on it.
    dependents_of: BTreeMap<String, BTreeSet<String>>,
    /// Cache key → the entry's own compile key.
    compile_key_of: BTreeMap<String, String>,
    /// Cache key → the compile keys the entry depends on.
    dep_keys_of: BTreeMap<String, Vec<String>>,
}

impl ClosureGraph {
    /// Build the closure view over a listing's rows; a row whose
    /// `dependency_compile_keys_json` does not parse is a corrupt store
    /// and fails the pass.
    fn build(
        entries: &BTreeMap<String, ArtifactCacheIndexEntry>,
    ) -> stow_types::error::Result<Self> {
        let mut graph = Self {
            providers: BTreeMap::new(),
            dependents_of: BTreeMap::new(),
            compile_key_of: BTreeMap::new(),
            dep_keys_of: BTreeMap::new(),
        };
        for (cache_key, entry) in entries {
            graph
                .providers
                .entry(entry.compile_key.clone())
                .or_default()
                .insert(cache_key.clone());
            let dep_keys = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
                &entry.dependency_compile_keys_json,
            )
            .wrap_err_with(|| {
                format!(
                    "parse artifact cache dependency_compile_keys_json for cache key {cache_key}"
                )
            })?;
            for dep in &dep_keys {
                graph
                    .dependents_of
                    .entry(dep.compile_key.clone())
                    .or_default()
                    .insert(cache_key.clone());
            }
            graph
                .compile_key_of
                .insert(cache_key.clone(), entry.compile_key.clone());
            graph.dep_keys_of.insert(
                cache_key.clone(),
                dep_keys.into_iter().map(|dep| dep.compile_key).collect(),
            );
        }
        Ok(graph)
    }

    /// The cache keys no victim group may touch: the protected entry and
    /// every entry it transitively depends on — evicting inside that
    /// closure would orphan the just-stored entry on the spot.
    fn untouchable_closure(&self, protected_key: &str) -> BTreeSet<String> {
        let mut closure = BTreeSet::from([protected_key.to_owned()]);
        let mut frontier = vec![protected_key.to_owned()];
        while let Some(cache_key) = frontier.pop() {
            let Some(dep_keys) = self.dep_keys_of.get(&cache_key) else {
                continue;
            };
            for dep_key in dep_keys {
                let Some(providers) = self.providers.get(dep_key) else {
                    continue;
                };
                for provider in providers {
                    if closure.insert(provider.clone()) {
                        frontier.push(provider.clone());
                    }
                }
            }
        }
        closure
    }

    /// The victim's eviction group: the victim plus every entry that
    /// depends on it, transitively — an entry joins the group when the
    /// group and the already-evicted set together hold every remaining
    /// provider of a compile key it needs. `None` when a member would be
    /// in the protected entry's closure, which is never a victim: the
    /// group cannot complete, so the victim keeps its place.
    fn victim_group(
        &self,
        victim: &str,
        evicted: &BTreeSet<String>,
        untouchable: &BTreeSet<String>,
    ) -> Option<BTreeSet<String>> {
        let mut group = BTreeSet::from([victim.to_owned()]);
        let mut frontier = vec![victim.to_owned()];
        while let Some(member) = frontier.pop() {
            // `member` is a listed rustc entry, so it has a compile key.
            let compile_key = &self.compile_key_of[&member];
            let last_provider = self
                .providers
                .get(compile_key)
                .into_iter()
                .flatten()
                .all(|provider| group.contains(provider) || evicted.contains(provider));
            if !last_provider {
                continue;
            }
            for dependent in self.dependents_of.get(compile_key).into_iter().flatten() {
                if group.contains(dependent) || evicted.contains(dependent) {
                    continue;
                }
                if untouchable.contains(dependent) {
                    return None;
                }
                group.insert(dependent.clone());
                frontier.push(dependent.clone());
            }
        }
        Some(group)
    }
}

/// `(cache_key, relative_dir)` for each member of a victim group, in
/// cache-key order — the order `try_lock_entry_group` takes the locks in.
fn entry_group_members(
    entries: &BTreeMap<String, ArtifactCacheIndexEntry>,
    group: &BTreeSet<String>,
) -> Vec<(String, String)> {
    group
        .iter()
        .map(|cache_key| (cache_key.clone(), entries[cache_key].relative_dir.clone()))
        .collect()
}

async fn evict_entries(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    version_dir: &Path,
    cc_dir: &Path,
    max_bytes: u64,
    protected: &ProtectedEntry<'_>,
) -> stow_types::error::Result<()> {
    let entries = list_artifact_cache_entries(connection, rustc_version).await?;
    let mut candidates: Vec<EvictionCandidate> = entries
        .iter()
        .map(|(cache_key, entry)| EvictionCandidate {
            cache_key: cache_key.clone(),
            size_bytes: entry.size_bytes,
            last_accessed_ms: entry.last_accessed_ms,
            location: EvictionLocation::Rustc,
        })
        .chain(
            crate::cc::list_cc_cache_entries(connection)
                .await?
                .into_iter()
                .map(|(cache_key, entry)| EvictionCandidate {
                    cache_key,
                    size_bytes: entry.size_bytes,
                    last_accessed_ms: entry.last_accessed_ms,
                    location: EvictionLocation::Cc,
                }),
        )
        .collect();
    let mut total_bytes = candidates.iter().fold(0u64, |sum, candidate| {
        sum.saturating_add(candidate.size_bytes)
    });
    if total_bytes <= max_bytes {
        return Ok(());
    }

    // stow#1005: eviction is closure-aware — a victim carries out every
    // entry that depends on it, transitively, in the same pass, and
    // nothing in the protected entry's own dependency closure is ever a
    // victim. Victim order stays `last_accessed_ms`.
    let mut pass = EvictionPass {
        connection,
        rustc_version,
        version_dir,
        graph: ClosureGraph::build(&entries)?,
        entries,
        evicted: BTreeSet::new(),
    };
    candidates.sort_by(|left, right| {
        left.last_accessed_ms
            .cmp(&right.last_accessed_ms)
            .then_with(|| left.cache_key.cmp(&right.cache_key))
            .then_with(|| left.location.rank().cmp(&right.location.rank()))
    });
    let protected_index = candidates
        .iter()
        .position(|candidate| protected.matches(candidate));
    let untouchable: BTreeSet<String> = match protected {
        ProtectedEntry::Rustc(cache_key) => pass.graph.untouchable_closure(cache_key),
        ProtectedEntry::Cc(_) => BTreeSet::new(),
    };
    for (index, candidate) in candidates.iter().enumerate() {
        if Some(index) == protected_index
            || untouchable.contains(&candidate.cache_key)
            || pass.evicted.contains(&candidate.cache_key)
        {
            continue;
        }
        let evicted_bytes = match &candidate.location {
            EvictionLocation::Rustc => {
                let Some(bytes) = pass
                    .try_evict_lru_victim(&candidate.cache_key, &untouchable)
                    .await?
                else {
                    continue;
                };
                bytes
            }
            EvictionLocation::Cc => {
                evict_cc_object(connection, cc_dir, &candidate.cache_key).await?;
                candidate.size_bytes
            }
        };
        total_bytes = total_bytes.saturating_sub(evicted_bytes);
        if total_bytes <= max_bytes {
            return Ok(());
        }
    }

    if total_bytes > max_bytes
        && let Some(protected_index) = protected_index
    {
        let candidate = &candidates[protected_index];
        pass.evict_protected_entry(cc_dir, candidate).await?;
        return Err(stow_types::stow_error!(
            "artifact cache entry {} exceeds max local cache size {} bytes",
            candidate.cache_key,
            max_bytes
        ));
    }

    Err(stow_types::stow_error!(
        "artifact cache is full but all eviction candidates are currently in use by other stow processes"
    ))
}

/// One eviction pass's working state (stow#1005): the listing it runs
/// over, the closure graph built from it, and the cache keys already
/// removed — group computation treats them as gone.
struct EvictionPass<'a> {
    connection: &'a sqlx::SqlitePool,
    rustc_version: &'a str,
    version_dir: &'a Path,
    graph: ClosureGraph,
    entries: BTreeMap<String, ArtifactCacheIndexEntry>,
    evicted: BTreeSet<String>,
}

impl EvictionPass<'_> {
    /// One victim's group eviction — the victim plus every entry its
    /// removal would orphan, returned as the group's byte total. `None`
    /// when the group cannot go — it would touch the protected closure,
    /// or another process holds a member's lock — in which case no
    /// member is removed, so no pass leaves a dependent without its
    /// dependency.
    async fn try_evict_lru_victim(
        &mut self,
        victim: &str,
        untouchable: &BTreeSet<String>,
    ) -> stow_types::error::Result<Option<u64>> {
        let Some(group) = self.graph.victim_group(victim, &self.evicted, untouchable) else {
            return Ok(None);
        };
        if !try_evict_rustc_entry_group(
            self.connection,
            self.rustc_version,
            self.version_dir,
            &entry_group_members(&self.entries, &group),
        )
        .await?
        {
            return Ok(None);
        }
        self.evicted.extend(group.iter().cloned());
        Ok(Some(group.iter().fold(0u64, |sum, cache_key| {
            sum.saturating_add(self.entries[cache_key].size_bytes)
        })))
    }

    /// Evict the store's own entry — the last resort when every other
    /// candidate left the cache over budget. A rustc entry goes out with
    /// its whole victim group, like any other group; a member another
    /// process has locked fails here rather than being skipped.
    async fn evict_protected_entry(
        &self,
        cc_dir: &Path,
        candidate: &EvictionCandidate,
    ) -> stow_types::error::Result<()> {
        match &candidate.location {
            EvictionLocation::Rustc => {
                let group = self
                    .graph
                    .victim_group(&candidate.cache_key, &self.evicted, &BTreeSet::new())
                    .expect("the protected entry's group has no untouchable member");
                let members = entry_group_members(&self.entries, &group);
                let Some(eviction_locks) = tokio::task::spawn_blocking({
                    let version_dir = self.version_dir.to_path_buf();
                    let members = members.clone();
                    move || try_lock_entry_group(&version_dir, &members)
                })
                .await
                .wrap_err("join evict_entries protected lock task")??
                else {
                    return Err(stow_types::stow_error!(
                        "artifact cache is full and the protected entry {} or one of its dependents is in use by another stow process",
                        candidate.cache_key
                    ));
                };
                remove_entry_group(
                    self.connection,
                    self.rustc_version,
                    self.version_dir,
                    &members,
                )
                .await?;
                drop(eviction_locks);
            }
            EvictionLocation::Cc => {
                evict_cc_object(self.connection, cc_dir, &candidate.cache_key).await?;
            }
        }
        Ok(())
    }
}

/// Exclusive entry locks on every group member, taken in the members'
/// cache-key order; `None` when another process holds one — the locks
/// already taken release with the `Vec`, so a skipped group loses no
/// member.
fn try_lock_entry_group(
    version_dir: &Path,
    members: &[(String, String)],
) -> stow_types::error::Result<Option<Vec<FileLock>>> {
    let mut locks = Vec::with_capacity(members.len());
    for (cache_key, _) in members {
        match try_acquire_entry_exclusive_lock(version_dir, cache_key)? {
            Some(lock) => locks.push(lock),
            None => return Ok(None),
        }
    }
    Ok(Some(locks))
}

/// Delete each member's state-db row, then its entry dir — called under
/// the group's held locks.
async fn remove_entry_group(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    version_dir: &Path,
    members: &[(String, String)],
) -> stow_types::error::Result<()> {
    for (cache_key, relative_dir) in members {
        delete_artifact_cache_entry(connection, rustc_version, cache_key).await?;
        let entry_dir = version_dir.join(relative_dir);
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
    }
    Ok(())
}

/// Try to evict a victim group under one lock hold for the whole group:
/// `false` when another process uses any member, in which case no member
/// is removed.
async fn try_evict_rustc_entry_group(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    version_dir: &Path,
    members: &[(String, String)],
) -> stow_types::error::Result<bool> {
    let Some(eviction_locks) = tokio::task::spawn_blocking({
        let version_dir = version_dir.to_path_buf();
        let members = members.to_vec();
        move || try_lock_entry_group(&version_dir, &members)
    })
    .await
    .wrap_err("join evict_entries lock task")??
    else {
        return Ok(false);
    };
    remove_entry_group(connection, rustc_version, version_dir, members).await?;
    drop(eviction_locks);
    Ok(true)
}

/// Evict one C/C++ object: the row goes, then the file. A lookup racing
/// the delete misses or fails its clone and compiles — the shim's hit
/// path carries no lease machinery.
async fn evict_cc_object(
    connection: &sqlx::SqlitePool,
    cc_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    crate::cc::delete_cc_cache_entry(connection, cache_key).await?;
    let object_path = crate::cc::cc_object_path(cc_dir, cache_key);
    if object_path.exists() {
        tokio::task::spawn_blocking(move || {
            std::fs::remove_file(&object_path)
                .wrap_err_with(|| format!("evict C/C++ object {}", object_path.display()))
        })
        .await
        .wrap_err("join evict_entries remove_file task")??;
    }
    Ok(())
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
    // `manifest.json` is what makes an entry loadable, so it is written
    // last. Anything that stops this function part-way — the disk filling
    // up mid-write, the process dying — then leaves an
    // entry a reader skips rather than a torn one it loads and then fails
    // on a file that never arrived. A miss compiles the unit; a
    // half-written hit would kill the build.
    let write_entry_file = |relative_path: &String, contents: &Vec<u8>| {
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
        stow_types::error::Result::Ok(decoded.len() as u64)
    };
    // The native archive is signature-covered bytes the fetch verified
    // and nothing reads from an entry: it is not stored (stow#640).
    let native_archive_path = bundle
        .manifest
        .config
        .native_archive
        .as_ref()
        .map(|file| bundle_file_path(&file.file_name));
    for (relative_path, contents) in &bundle.files {
        if relative_path == stow_types::bundle::STOW_BUNDLE_MANIFEST_PATH
            || Some(relative_path) == native_archive_path.as_ref()
        {
            continue;
        }
        total_bytes = total_bytes.saturating_add(write_entry_file(relative_path, contents)?);
    }

    // `parse_bundle` lifts `manifest.json` into `bundle.manifest`, so it is
    // never among `files` — the entry's manifest comes from the parsed and
    // verified value, written last so a torn write stays unloadable.
    let manifest_path = stow_types::bundle::STOW_BUNDLE_MANIFEST_PATH.to_owned();
    let manifest_json = serde_json::to_vec(&bundle.manifest)
        .wrap_err("serialize bundle manifest for the cache entry")?;
    total_bytes = total_bytes.saturating_add(write_entry_file(&manifest_path, &manifest_json)?);

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

pub fn path_to_string(path: &Path) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("path {} is not UTF-8", path.display()))
}

fn acquire_version_shared_lock(
    leases_root: &Path,
    rustc_version: &str,
) -> stow_types::error::Result<FileLock> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open version lease {}", lock_path.display()))?;
    FileLock::shared(file).wrap_err_with(|| format!("lock version lease {}", lock_path.display()))
}

/// Whether opening or removing a staging lock failed because another
/// sweeper has removed it. On unix the file is simply gone. On Windows a file
/// removed while a handle to it is still open — the sweeper holds its
/// lock through the removal — stays listed in delete-pending state and
/// refuses every open with access denied until that handle closes.
fn is_being_reclaimed(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || (cfg!(windows) && error.kind() == std::io::ErrorKind::PermissionDenied)
}

/// Reclaim staging directories their owning process abandoned. A live
/// store holds `<name>.lock` exclusively for the process's whole life, so
/// an exclusive try-lock that succeeds names a dead process: its sibling
/// `<name>/` and the lock file are removed. A contended lock is a live
/// writer and is left alone. The cost is one listing of the staging root,
/// whose size is the number of live and dead stow processes — never the
/// number of cache entries.
///
/// Every stow process of a build sweeps, so several reach the same dead
/// lock at once. The lock serializes them: the first removes the
/// directory and the lock file, and a later one either cannot open the
/// file any more or locks the unlinked file and has nothing left to
/// remove.
fn sweep_staging_locks(staging_root: &Path) -> stow_types::error::Result<()> {
    for entry in std::fs::read_dir(staging_root)
        .wrap_err_with(|| format!("read staging root {}", staging_root.display()))?
    {
        let lock_path = entry?.path();
        if lock_path.extension() != Some(std::ffi::OsStr::new("lock")) {
            continue;
        }
        let file = match OpenOptions::new().read(true).write(true).open(&lock_path) {
            Ok(file) => file,
            Err(error) if is_being_reclaimed(&error) => continue,
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "open staging lock {}: {error}",
                    lock_path.display()
                ));
            }
        };
        let _reclaim = match FileLock::try_exclusive(file) {
            Ok(Some(lock)) => lock,
            Ok(None) => continue,
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "lock staging lease {}: {error}",
                    lock_path.display()
                ));
            }
        };
        let staged_dir = lock_path.with_extension("");
        if staged_dir.exists() {
            std::fs::remove_dir_all(&staged_dir).wrap_err_with(|| {
                format!("remove abandoned staging dir {}", staged_dir.display())
            })?;
        }
        match std::fs::remove_file(&lock_path) {
            Ok(()) => {}
            Err(error) if is_being_reclaimed(&error) => {}
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "remove staging lock {}: {error}",
                    lock_path.display()
                ));
            }
        }
    }
    Ok(())
}

fn try_acquire_version_exclusive_lock(
    leases_root: &Path,
    rustc_version: &str,
) -> stow_types::error::Result<Option<FileLock>> {
    let lock_path = version_lease_path(leases_root, rustc_version);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .wrap_err_with(|| format!("open stale version lease {}", lock_path.display()))?;
    FileLock::try_exclusive(file).map_err(|error| {
        stow_types::stow_error!("lock stale version lease {}: {error}", lock_path.display())
    })
}

fn version_lease_path(leases_root: &Path, rustc_version: &str) -> PathBuf {
    leases_root.join(format!("{rustc_version}.lock"))
}

fn acquire_entry_shared_lock(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<FileLock> {
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
    FileLock::shared(file).wrap_err_with(|| format!("lock cache lease {}", lock_path.display()))
}

fn acquire_entry_exclusive_lock(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<FileLock> {
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
    FileLock::exclusive(file)
        .wrap_err_with(|| format!("lock cache entry writer {}", lock_path.display()))
}

async fn acquire_entry_exclusive_lock_async(
    version_dir: &Path,
    cache_key: &str,
) -> stow_types::error::Result<FileLock> {
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
    if load_artifact_cache_entry(
        connection,
        &request.rustc_version,
        &cache_key_owned(request),
    )
    .await?
    .is_none()
    {
        return Ok(None);
    }
    load_cached_bundle(
        config,
        &FetchRequest {
            target: &request.target,
            rustc_version: &request.rustc_version,
            c_metadata: &request.c_metadata,
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
) -> stow_types::error::Result<Option<FileLock>> {
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
    FileLock::try_exclusive(file).map_err(|error| {
        stow_types::stow_error!("lock cache eviction {}: {error}", lock_path.display())
    })
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
    /// The compile key this entry provides — what a dependent's
    /// `dependency_compile_keys_json` names (stow#1005).
    compile_key: String,
    /// `[{crate_name, compile_key}]` — the direct dependencies the entry
    /// was compiled against, as stored.
    dependency_compile_keys_json: String,
}

#[derive(Debug)]
struct PreparedLocalCache {
    stale_dirs: Vec<PathBuf>,
    version_lease: RustcVersionLease,
}

#[derive(Debug, Clone, FromRow)]
struct ArtifactCacheEntryRow {
    relative_dir: String,
    last_accessed_ms: i64,
    oci_reference: String,
    oci_digest: String,
    compile_key: String,
    crate_name: String,
    crate_version: String,
    c_metadata: String,
    features_json: String,
    dependency_c_metadata_json: String,
    dependency_compile_keys_json: String,
    dependency_instances_json: String,
    compile_millis: i64,
    size_bytes: i64,
    profile_json: String,
    emit_json: String,
    kind_json: String,
    crate_types_json: String,
    verified_marker_version: Option<i64>,
    verified_marker_policy: Option<String>,
    provenance: String,
    reach: i64,
}

#[derive(Debug, Clone, FromRow)]
struct SemanticCacheCandidateRow {
    c_metadata: String,
    crate_version: String,
    emit_json: String,
    features_json: String,
    crate_name: String,
    compile_key: String,
    dependency_c_metadata_json: String,
}

#[derive(Debug, Clone)]
struct SemanticCacheCandidate {
    version: Version,
    c_metadata: String,
    emit_len: usize,
    /// The bundle's recorded feature set — a request is served from the
    /// smallest staged set containing it (stow#881), so the order keys
    /// on this.
    features: Vec<String>,
    emit: Vec<String>,
    row: SemanticCacheCandidateRow,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependencyCMetadataIdentity {
    pub crate_name: String,
    pub c_metadata: String,
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

async fn load_artifact_cache_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<Option<ArtifactCacheEntryRow>> {
    sqlx::query_as::<_, ArtifactCacheEntryRow>(
        "SELECT relative_dir, last_accessed_ms, oci_reference, oci_digest, \
                compile_key, crate_name, crate_version, c_metadata, features_json, dependency_c_metadata_json, dependency_compile_keys_json, dependency_instances_json, \
                compile_millis, size_bytes, \
                profile_json, emit_json, kind_json, crate_types_json, \
                verified_marker_version, verified_marker_policy, provenance, reach \
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
    let rows = sqlx::query_as::<_, (String, String, i64, i64, String, String)>(
        "SELECT cache_key, relative_dir, size_bytes, last_accessed_ms, compile_key, \
                dependency_compile_keys_json \
         FROM artifact_cache_entries \
         WHERE rustc_version = ?",
    )
    .bind(rustc_version)
    .fetch_all(connection)
    .await?;
    let mut entries = BTreeMap::new();
    for (cache_key, relative_dir, size_bytes, last_accessed_ms, compile_key, dep_keys_json) in rows
    {
        entries.insert(
            cache_key,
            ArtifactCacheIndexEntry {
                relative_dir,
                size_bytes: db_int(size_bytes, "artifact cache entry size_bytes")?,
                last_accessed_ms: db_int(
                    last_accessed_ms,
                    "artifact cache entry last_accessed_ms",
                )?,
                compile_key,
                dependency_compile_keys_json: dep_keys_json,
            },
        );
    }
    Ok(entries)
}

fn semantic_candidate_from_row(
    row: SemanticCacheCandidateRow,
    requested_version: &Version,
    requested_emit: &[String],
    requested_features: &[String],
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
    // A bundle serves the request when its recorded feature set contains
    // the requested one — superset serving, never unioned (stow#881).
    let candidate_features = serde_json::from_str::<Vec<String>>(&row.features_json)
        .wrap_err("parse cached features_json")?;
    if !stow_types::feature_sets::contains_all(&candidate_features, requested_features) {
        return Ok(None);
    }
    Ok(Some(SemanticCacheCandidate {
        version: candidate_version,
        c_metadata: row.c_metadata.clone(),
        emit_len: candidate_emit.len(),
        features: candidate_features,
        emit: candidate_emit,
        row,
    }))
}

/// The deterministic order a staged semantic candidate is tried in: the
/// smallest containing feature set first (the stow#881 serving set —
/// an exactly-matching bundle always precedes a superset), then the
/// previous order of version descending, shortest emit list and
/// `c_metadata`.
fn compare_semantic_candidates(
    left: &SemanticCacheCandidate,
    right: &SemanticCacheCandidate,
) -> std::cmp::Ordering {
    left.features
        .len()
        .cmp(&right.features.len())
        .then(left.features.cmp(&right.features))
        .then(right.version.cmp(&left.version))
        .then(left.emit_len.cmp(&right.emit_len))
        .then(left.c_metadata.cmp(&right.c_metadata))
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
    dependency_instances_json: &'a str,
    /// `Public` for remote bundles; the local build's folded reach for
    /// self-produced entries.
    reach: stow_types::public_cache::Reach,
    /// Publisher-recorded compile time; `0` for locally produced entries.
    compile_millis: u64,
    target: &'a str,
    profile: &'a Profile,
    emit: &'a [String],
    kind: &'a ArtifactKind,
    crate_types: &'a [RustCrateType],
    outputs: &'a [ArtifactBundleFile],
    sigstore_signatures: &'a [SigstoreSignature],
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
            dependency_instances_json: "[]",
            reach: stow_types::public_cache::Reach::Public,
            compile_millis: bundle.manifest.config.compile_millis,
            target: bundle.manifest.config.target.as_str(),
            profile: &bundle.manifest.config.profile,
            emit: &bundle.manifest.config.emit,
            kind: &bundle.manifest.config.kind,
            crate_types: &bundle.manifest.config.crate_types,
            outputs: &bundle.manifest.config.outputs,
            sigstore_signatures: &bundle.manifest.sigstore_signatures,
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
    // One entry owns its child rows. Replacing the parent cascades the old
    // children away; a new entry has none to delete. Keep the replacement
    // and all its children on one connection in one atomic commit.
    let mut transaction = connection.begin().await?;
    insert_artifact_cache_entry(
        &mut transaction,
        rustc_version,
        cache_key,
        relative_dir,
        size_bytes,
        last_accessed_ms,
        metadata,
    )
    .await?;
    insert_artifact_cache_outputs(&mut transaction, rustc_version, cache_key, metadata.outputs)
        .await?;
    insert_artifact_cache_sigstore_signatures(
        &mut transaction,
        rustc_version,
        cache_key,
        metadata.sigstore_signatures,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Insert or refresh the `artifact_cache_entries` row. A rewrite clears the
/// verified-trust marker columns: the marker attests to the bytes that were
/// verified, and a replacement entry has not been verified yet.
async fn insert_artifact_cache_entry(
    connection: &mut sqlx::SqliteConnection,
    rustc_version: &str,
    cache_key: &str,
    relative_dir: &str,
    size_bytes: u64,
    last_accessed_ms: u64,
    metadata: &CacheEntryMetadata<'_>,
) -> stow_types::error::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO artifact_cache_entries \
         (rustc_version, cache_key, relative_dir, size_bytes, last_accessed_ms, oci_reference, oci_digest, compile_key, crate_name, crate_version, c_metadata, features_json, dependency_c_metadata_json, dependency_compile_keys_json, dependency_instances_json, compile_millis, target, profile_json, emit_json, kind_json, crate_types_json, verified_marker_version, verified_marker_policy, provenance, reach) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
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
    .bind(metadata.dependency_instances_json)
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
    .bind(metadata.reach.to_int())
    .execute(connection)
    .await?;
    Ok(())
}

/// Persist the bundle's output file list, one row per file in bundle order.
async fn insert_artifact_cache_outputs(
    connection: &mut sqlx::SqliteConnection,
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
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

/// Persist the bundle's sigstore signature material, one row per signature
/// in bundle order.
async fn insert_artifact_cache_sigstore_signatures(
    connection: &mut sqlx::SqliteConnection,
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
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

/// How stale an entry's LRU stamp may be before a read rewrites it.
pub const LRU_STAMP_INTERVAL_MS: u64 = 60_000;

/// A stamp read back from the database, clamped: a negative value is a row
/// written by something that did not go through `db_int`, and "very old" is
/// the reading that keeps eviction honest.
pub const fn recorded_millis(stamp: i64) -> u64 {
    if stamp < 0 { 0 } else { stamp.cast_unsigned() }
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
/// [`load_cached_bundle`] pays a file lock, an LRU `UPDATE` and three `SELECT`s
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
        let mut query =
            sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(sql)).bind(rustc_version);
        for cache_key in chunk {
            query = query.bind(cache_key);
        }
        let rows = query.fetch_all(&connection).await?;
        // A row whose bundle directory was pruned underneath us is a miss,
        // not an error: the caller simply re-fetches it. One stat per row
        // of the build's graph, so the chunk's stats run on a blocking
        // thread (stow#624).
        let version_dir = version_dir.clone();
        present.extend(
            smol::unblock(move || {
                rows.into_iter()
                    .filter(|(_, relative_dir)| version_dir.join(relative_dir).exists())
                    .map(|(cache_key, _)| cache_key)
                    .collect::<Vec<_>>()
            })
            .await,
        );
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
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(last_accessed_ms)
                .bind(rustc_version);
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
pub mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sha2::Digest;
    use stow_types::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, SigstoreSignature,
    };
    use stow_types::public_cache::StableUnitIdentity;

    use stow_types::rustc::ParsedExternCrate;

    use super::{
        STAGING_DIR, cache_key, join_relative_path, list_artifact_cache_entries,
        load_bundle_entry_dir, load_semantic_cached_bundle, prepare_local_cache,
        prepare_local_cache_blocking, store_bundle_entry_dir, touch_artifact_cache_entry,
        write_downloaded_bundle_to_entry,
    };
    use crate::config::{StowConfig, VerifyMode};
    use crate::fetch::{ArtifactBundle, FetchRequest, SemanticFetchRequest, bundle_file_path};
    use crate::rustc_args::ParsedRustcArgs;
    use crate::state_db::connect;

    /// The consume-store layout the build prefetch and the serve path
    /// share — an entry under `store_dir/<slice target>/<compile key>`:
    /// a unit asking for a key under a different target misses, because
    /// only the slice for its own effective target can vouch for a row.
    /// A catalog row whose compile key points at a target its slice does
    /// not carry sits in a directory no unit is ever served from.
    #[test]
    fn load_bundle_entry_dir_scopes_hits_to_the_slice_target_dir() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = tempdir.path().join("store");
        let lease = tempdir.path().join("lease");
        let entry = store.join("aarch64-unknown-linux-gnu").join("key-1");
        store_bundle_entry_dir(
            &entry,
            &sample_bundle("aabbccddeeff0011", "libdemo-aabbccddeeff0011.rmeta"),
        )
        .expect("stage bundle");
        assert!(
            load_bundle_entry_dir(
                &store.join("x86_64-unknown-linux-gnu").join("key-1"),
                &lease,
                "key-1"
            )
            .expect("load other-target dir")
            .is_none()
        );
        assert!(
            load_bundle_entry_dir(&entry, &lease, "key-1")
                .expect("load slice-target dir")
                .is_some()
        );
    }

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

    const STAGING_HELPER_ENV: &str = "STOW_TEST_STAGING_HELPER";
    const STAGING_HELPER_ROOT_ENV: &str = "STOW_TEST_STAGING_ROOT";
    const STAGING_HELPER_MARKER_ENV: &str = "STOW_TEST_STAGING_MARKER";
    const STAGING_HELPER_TEST: &str = "artifact_cache::tests::staging_helper_process";

    /// The child half of the staging-sweep tests: the parent re-executes
    /// this test binary as `--exact <this test> --nocapture` with the
    /// helper env vars set. In a normal `cargo test` run the gate is
    /// unset and it is a no-op; armed, it acquires the process staging
    /// directory through the production accessor, leaves a half-written
    /// staged entry inside it, writes the readiness marker the parent
    /// polls for, then blocks until killed.
    #[test]
    fn staging_helper_process() {
        if std::env::var_os(STAGING_HELPER_ENV).is_none() {
            return;
        }
        let root = PathBuf::from(
            std::env::var_os(STAGING_HELPER_ROOT_ENV).expect("staging helper root env"),
        );
        let marker = PathBuf::from(
            std::env::var_os(STAGING_HELPER_MARKER_ENV).expect("staging helper marker env"),
        );
        let config = test_config(&root);
        run_async(async move {
            let staging = config
                .artifact_cache_staging_dir("1.91.1")
                .await
                .expect("acquire staging dir");
            let staged = tempfile::Builder::new()
                .prefix("entry-")
                .tempdir_in(staging.path())
                .expect("stage entry");
            std::fs::write(staged.path().join("partial.txt"), b"partial")
                .expect("write staged file");
            let staged = staged.keep();
            assert!(staged.join("partial.txt").exists());
            std::fs::write(&marker, b"ready").expect("write readiness marker");
            loop {
                std::thread::park();
            }
        });
    }

    fn spawn_staging_helper(root: &Path, marker: &Path) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(STAGING_HELPER_TEST)
            .arg("--nocapture")
            .env(STAGING_HELPER_ENV, "1")
            .env(STAGING_HELPER_ROOT_ENV, root)
            .env(STAGING_HELPER_MARKER_ENV, marker)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn staging helper process")
    }

    fn wait_for_staging_marker(marker: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "staging helper never wrote its readiness marker"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kills the helper on drop so a failed assertion cannot leak a
    /// parked child.
    struct KillOnDrop(std::process::Child);

    impl KillOnDrop {
        fn kill(&mut self) {
            self.0.kill().expect("kill staging helper");
            self.0.wait().expect("reap staging helper");
        }
    }

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A process killed mid-store leaves its staging dir and lock file;
    /// the next `prepare_local_cache` sweep reclaims both.
    #[test]
    fn prepare_sweeps_dead_process_staging() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let marker = tempdir.path().join("helper-ready");
        let mut child = KillOnDrop(spawn_staging_helper(tempdir.path(), &marker));
        wait_for_staging_marker(&marker);
        child.kill();

        let config = test_config(tempdir.path());
        let prepared = prepare_local_cache_blocking(
            &config.artifact_cache_root(),
            &config.artifact_cache_purge_root(),
            "1.91.1",
            true,
        )
        .expect("prepare cache");
        let staging_root = config
            .artifact_cache_version_dir("1.91.1")
            .join(STAGING_DIR);
        let leftovers = std::fs::read_dir(&staging_root)
            .expect("read staging root")
            .count();
        assert_eq!(
            leftovers, 0,
            "the dead process's staging dir and lock must be swept"
        );
        drop(prepared.version_lease);
    }

    /// Every stow process of a build sweeps, so the same dead locks are
    /// reached by several sweepers at once; none of them may fail on a
    /// lock another one reclaimed first.
    #[test]
    fn concurrent_sweeps_reclaim_the_same_dead_staging() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let staging_root = tempdir.path().join(STAGING_DIR);
        std::fs::create_dir_all(&staging_root).expect("create staging root");
        for index in 0..64 {
            let name = format!("{index}-dead");
            std::fs::write(staging_root.join(format!("{name}.lock")), b"").expect("write lock");
            std::fs::create_dir(staging_root.join(&name)).expect("create staging dir");
            std::fs::write(staging_root.join(&name).join("partial.txt"), b"partial")
                .expect("write staged file");
        }

        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let sweepers = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        super::sweep_staging_locks(&staging_root)
                    })
                })
                .collect::<Vec<_>>();
            for sweeper in sweepers {
                sweeper
                    .join()
                    .expect("join sweeper")
                    .expect("a sweep must not fail on a lock another sweep reclaimed");
            }
        });
        assert_eq!(
            std::fs::read_dir(&staging_root)
                .expect("read staging root")
                .count(),
            0
        );
    }

    /// A live process's staging dir survives the sweep: its `<name>.lock`
    /// is held, so `prepare_local_cache` leaves it and its staged files.
    #[test]
    fn prepare_leaves_live_process_staging() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let marker = tempdir.path().join("helper-ready");
        let mut child = KillOnDrop(spawn_staging_helper(tempdir.path(), &marker));
        wait_for_staging_marker(&marker);

        let config = test_config(tempdir.path());
        let prepared = prepare_local_cache_blocking(
            &config.artifact_cache_root(),
            &config.artifact_cache_purge_root(),
            "1.91.1",
            true,
        )
        .expect("prepare cache");
        let staging_root = config
            .artifact_cache_version_dir("1.91.1")
            .join(STAGING_DIR);
        let entries = std::fs::read_dir(&staging_root)
            .expect("read staging root")
            .map(|entry| entry.expect("staging root entry"))
            .collect::<Vec<_>>();
        assert_eq!(
            entries.len(),
            2,
            "a live process's lock file and staging dir must survive the sweep"
        );
        let process_dir = entries
            .iter()
            .map(std::fs::DirEntry::path)
            .find(|path| path.is_dir())
            .expect("process staging dir");
        let staged = std::fs::read_dir(&process_dir)
            .expect("read process staging dir")
            .map(|entry| entry.expect("staged entry").path())
            .collect::<Vec<_>>();
        assert_eq!(staged.len(), 1);
        assert!(staged[0].join("partial.txt").exists());
        child.kill();
        drop(prepared.version_lease);
    }

    /// A completed store renames its staged entry out of the process's
    /// staging dir: `<name>/` is left empty and the entry is in place.
    #[test]
    fn store_leaves_process_staging_dir_empty() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let stable_c_metadata = "0123456789abcdef";
        let parsed = local_build_parsed(
            "demo",
            "cargo-meta-staging",
            out_dir,
            &["dep-info", "metadata", "link"],
        );
        std::fs::write(
            parsed.output_rlib_path().expect("rlib output path"),
            b"staged-rlib-bytes",
        )
        .expect("write rlib");
        std::fs::write(
            parsed.output_rmeta_path().expect("rmeta output path"),
            b"staged-rmeta-bytes",
        )
        .expect("write rmeta");
        let build = local_build_artifact(&parsed, stable_c_metadata);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
                    .await
                    .expect("store local build")
            );

            let staging = config
                .artifact_cache_staging_dir("1.91.1")
                .await
                .expect("staging dir");
            assert_eq!(
                std::fs::read_dir(staging.path())
                    .expect("read process staging dir")
                    .count(),
                0,
                "the rename moves the staged entry out of <name>/"
            );
            let entry_dir = config
                .artifact_cache_version_dir("1.91.1")
                .join("bundles/v3/aarch64-apple-darwin")
                .join(stable_c_metadata);
            assert!(
                entry_dir
                    .join("files/libdemo-0123456789abcdef.rlib")
                    .exists()
            );
        });
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
    fn metadata_replacement_rolls_back_children_and_verification_on_failure() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let bundle = sample_bundle("aabbccddeeff0011", "libdemo-aabbccddeeff0011.rmeta");
        run_async(async {
            let pool = config.state_db_pool().await.expect("state db");
            let original = super::CacheEntryMetadata::remote(&bundle);
            super::replace_artifact_cache_metadata(
                &pool, "1.91.1", "entry", "original", 100, 1, &original,
            )
            .await
            .expect("original metadata");
            sqlx::query(
                "UPDATE artifact_cache_entries SET verified_marker_version = 2, verified_marker_policy = 'verified'",
            )
            .execute(&pool)
            .await
            .expect("verified original");
            sqlx::raw_sql(include_str!("../tests/fixtures/reject-cache-output.sql"))
                .execute(&pool)
                .await
                .expect("inject output write failure");
            let mut replacement = super::CacheEntryMetadata::remote(&bundle);
            replacement.sigstore_signatures = &[];
            let error = super::replace_artifact_cache_metadata(
                &pool,
                "1.91.1",
                "entry",
                "replacement",
                200,
                2,
                &replacement,
            )
            .await
            .expect_err("child insertion fails after parent replacement");
            assert!(error.to_string().contains("injected output write failure"));
            let row = super::load_artifact_cache_entry(&pool, "1.91.1", "entry")
                .await
                .expect("load original")
                .expect("original survives");
            assert_eq!(row.relative_dir, "original");
            assert_eq!(row.size_bytes, 100);
            assert_eq!(row.verified_marker_version, Some(2));
            assert_eq!(row.verified_marker_policy.as_deref(), Some("verified"));
            assert_metadata_children(&pool, &original).await;

            sqlx::query("DROP TRIGGER reject_cache_output")
                .execute(&pool)
                .await
                .expect("remove injected failure");
            super::replace_artifact_cache_metadata(
                &pool,
                "1.91.1",
                "entry",
                "replacement",
                200,
                2,
                &replacement,
            )
            .await
            .expect("replace metadata");
            let row = super::load_artifact_cache_entry(&pool, "1.91.1", "entry")
                .await
                .expect("load replacement")
                .expect("replacement exists");
            assert_eq!(row.relative_dir, "replacement");
            assert_eq!(row.size_bytes, 200);
            assert_eq!(row.verified_marker_version, None);
            assert_eq!(row.verified_marker_policy, None);
            assert_metadata_children(&pool, &replacement).await;
        });
    }

    async fn assert_metadata_children(
        pool: &sqlx::SqlitePool,
        expected: &super::CacheEntryMetadata<'_>,
    ) {
        assert_eq!(
            super::load_artifact_outputs(pool, "1.91.1", "entry")
                .await
                .expect("outputs"),
            expected.outputs
        );
        assert_eq!(
            super::load_sigstore_signatures(pool, "1.91.1", "entry")
                .await
                .expect("signatures")
                .len(),
            expected.sigstore_signatures.len()
        );
    }

    /// A stored `ignore` 0.4.24 bundle whose compile key is the one it
    /// would carry under `build_script`, and the request for 0.4.22 the
    /// semantic lookup answers.
    fn semantic_fixture(
        features: &[&str],
        build_script: &stow_types::upload_plan::BuildScriptInputs,
    ) -> (ArtifactBundle, SemanticFetchRequest) {
        let mut bundle = sample_bundle("11223344aabbccdd", "libdemo-11223344aabbccdd.rmeta");
        let config = &mut bundle.manifest.config;
        config.crate_name = stow_types::identity::CrateName::parse("ignore").unwrap();
        config.crate_version =
            stow_types::identity::CrateVersion::new(semver::Version::parse("0.4.24").unwrap());
        config.features_json = stow_types::identity::FeaturesJson::canonicalize(
            features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        )
        .unwrap();
        config.compile_key = stow_types::upload_plan::candidate_compile_key(
            &stow_types::upload_plan::CandidateIdentity {
                crate_name: "ignore",
                crate_version: "0.4.24",
                target: "aarch64-apple-darwin",
                rustc_version: "1.91.1",
                features_json: &config.features_json.raw(),
                dependency_c_metadata_json: &config.dependency_c_metadata_json.raw(),
                kind: &config.kind,
                profile: &config.profile,
                crate_types: &config.crate_types,
                emit: &config.emit,
            },
            &stow_types::upload_plan::ConsumerInputs::stock(),
            build_script,
        )
        .expect("compile key");
        bundle.manifest.oci_reference = "ghcr.io/water-rs/stow-cache-1.91.1:ignore.test".to_owned();
        let config = &bundle.manifest.config;
        let request = SemanticFetchRequest {
            crate_name: "ignore".to_owned(),
            version: "0.4.22".to_owned(),
            features_json: "[\"default\"]".to_owned(),
            dependency_c_metadata_json: "[]".to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            profile: config.profile.clone(),
            emit: config.emit.clone(),
            kind: config.kind.clone(),
            crate_types: config.crate_types.clone(),
            consumer: stow_types::upload_plan::ConsumerInputs::stock(),
            build_script: stow_types::upload_plan::BuildScriptInputs::default(),
        };
        (bundle, request)
    }

    async fn store_and_load_semantic(
        config: &StowConfig,
        bundle: &ArtifactBundle,
        request: &SemanticFetchRequest,
    ) -> Option<super::CachedArtifactBundle> {
        prepare_local_cache(config, "1.91.1")
            .await
            .expect("prepare cache");
        super::store_downloaded_bundle(config, &fetch_request("11223344aabbccdd"), bundle)
            .await
            .expect("store bundle");
        load_semantic_cached_bundle(config, request)
            .await
            .expect("load semantic bundle")
    }

    #[test]
    fn load_semantic_cached_bundle_matches_compatible_version_with_different_metadata() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let (bundle, request) = semantic_fixture(
            &["default"],
            &stow_types::upload_plan::BuildScriptInputs::default(),
        );

        run_async(async {
            let loaded = store_and_load_semantic(&config, &bundle, &request)
                .await
                .expect("semantic cache hit");
            assert_eq!(loaded.crate_name, "ignore");
            assert_eq!(loaded.crate_version, "0.4.24");
            assert_eq!(loaded.c_metadata, "11223344aabbccdd");
        });
    }

    /// stow#1047: an entry compiled without the request's own `--cfg`
    /// answers the requests that carry none, never one that does.
    #[test]
    fn a_semantic_entry_compiled_without_the_requests_cfg_is_a_miss() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let (bundle, mut request) = semantic_fixture(
            &["default"],
            &stow_types::upload_plan::BuildScriptInputs::default(),
        );
        request.consumer.cfgs = vec!["custom".to_owned()];

        run_async(async {
            assert!(
                store_and_load_semantic(&config, &bundle, &request)
                    .await
                    .is_none()
            );
        });
    }

    /// Superset serving stays intact when the serving set's own build
    /// script set a cfg the request's set never saw (stow#881): the cfg
    /// is read from the candidate's captured build-script output.
    #[test]
    fn a_superset_entry_keeps_serving_with_its_own_build_script_cfg() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let own = stow_types::upload_plan::BuildScriptInputs::from_directives(&[
            "cargo:rustc-cfg=has_extra".to_owned(),
        ]);
        let (mut bundle, request) = semantic_fixture(&["default", "extra"], &own);
        bundle.manifest.config.native = Some(stow_types::artifact::NativeArtifacts {
            static_libs: Vec::new(),
            cargo_directives: vec!["cargo:rustc-cfg=has_extra".to_owned()],
            dep_env_vars: BTreeMap::new(),
            out_dir_files: Vec::new(),
            original_out_dir: PathBuf::from("/out"),
        });

        run_async(async {
            let loaded = store_and_load_semantic(&config, &bundle, &request)
                .await
                .expect("the superset serves the request");
            assert_eq!(loaded.features_json, "[\"default\",\"extra\"]");
        });
    }

    /// stow#1047: a local entry keyed before the check defaults were
    /// corrected, labeled `opt-level=3` with checks on, is never served to
    /// a request that spells those checks out.
    #[test]
    fn a_stale_optimized_entry_is_not_served_for_explicit_checks() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let (mut bundle, mut request) = semantic_fixture(
            &["default"],
            &stow_types::upload_plan::BuildScriptInputs::default(),
        );
        let stale_profile = stow_types::platform::Profile {
            opt_level: "3".to_owned(),
            debug_assertions: true,
            overflow_checks: true,
            ..bundle.manifest.config.profile.clone()
        };
        // The key the entry for a plain `-C opt-level=3` was stored under
        // before the correction: the same hash without the check-defaults
        // tag, as computed by the code of that day.
        bundle.manifest.config.profile = stale_profile.clone();
        bundle.manifest.config.compile_key =
            "3bdb535cb0261859019abc13bebfbdf50ff3f48647bd89270f7e4e0318c48645".to_owned();
        request.profile = stale_profile;

        run_async(async {
            assert!(
                store_and_load_semantic(&config, &bundle, &request)
                    .await
                    .is_none()
            );
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

    /// A bundle whose signed config declares a `native` block and a
    /// `native_archive` member still stores, and the entry holds its
    /// outputs alone: the archive is neither unpacked nor kept.
    #[test]
    fn a_bundle_with_a_native_archive_stores_only_its_outputs() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let request = fetch_request("deadbeefcafe0001");
        let mut bundle = sample_bundle("deadbeefcafe0001", "libdemo-deadbeefcafe0001.rmeta");
        let archive_bytes = b"native-archive-bytes".to_vec();
        bundle.manifest.config.native = Some(NativeArtifacts {
            static_libs: vec![stow_types::artifact::NativeLib {
                name: "demo".to_owned(),
                bytes_sha256: "native-digest".to_owned(),
            }],
            cargo_directives: vec!["cargo:rustc-link-lib=static=demo".to_owned()],
            dep_env_vars: BTreeMap::from([("DEP_DEMO_ROOT".to_owned(), "/build/out".to_owned())]),
            out_dir_files: vec![stow_types::artifact::OutDirFile {
                relative_path: "libdemo.a".to_owned(),
                sha256: "native-digest".to_owned(),
            }],
            original_out_dir: PathBuf::from("/build/out"),
        });
        bundle.manifest.config.native_archive = Some(ArtifactBundleFile {
            file_name: "native.tar.zst".to_owned(),
            media_type: "application/vnd.stow.native+tar".to_owned(),
            sha256: hex::encode(sha2::Sha256::digest(&archive_bytes)),
        });
        bundle
            .files
            .insert(bundle_file_path("native.tar.zst"), archive_bytes);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored = super::store_downloaded_bundle(&config, &request, &bundle)
                .await
                .expect("store bundle");
            let entry_dir = stored.entry_dir.clone();
            assert!(entry_dir.exists());
            assert!(
                !entry_dir.join("native").exists(),
                "the native archive is verified bytes, never unpacked into the entry"
            );
            assert!(
                !entry_dir.join(bundle_file_path("native.tar.zst")).exists(),
                "the native archive itself is not stored either"
            );
            drop(stored);

            let loaded = super::load_cached_bundle(&config, &request)
                .await
                .expect("load bundle")
                .expect("cached bundle");
            assert_eq!(loaded.outputs.len(), 1);
            assert_eq!(
                loaded.outputs[0].file_name,
                "libdemo-deadbeefcafe0001.rmeta"
            );
            assert!(loaded.output_source_path(&loaded.outputs[0]).exists());
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
            reach: stow_types::public_cache::Reach::Public,
            oci_reference: "local".to_owned(),
            oci_digest: "local".to_owned(),
            compile_key: "compile-key".to_owned(),
            crate_name: "demo".to_owned(),
            crate_version: "1.0.0".to_owned(),
            c_metadata: "deadbeef".to_owned(),
            features_json: "[]".to_owned(),
            dependency_c_metadata_json: "[]".to_owned(),
            dependency_compile_keys_json: "[]".to_owned(),
            dependency_instances_json: "[]".to_owned(),
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
            sigstore_signatures: Vec::new(),
            entry_dir: tempdir.path().join("entry"),
            rustc_version: "1.91.1".to_owned(),
            cache_key: "cache-key".to_owned(),
            verified_marker_version: None,
            verified_marker_policy: None,
            _lease_lock: super::FileLock::shared(
                std::fs::File::create(&lease_path).expect("lease file"),
            )
            .expect("lease lock"),
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
                &local_build_artifact(&dependency, "stable-colorchoice"),
                "aarch64-apple-darwin",
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
                .expect("resolve dependency metadata");
            let super::DependencyCMetadataResolution::Resolved(resolved) = resolved else {
                panic!("the dependency's bookkeeping resolved");
            };
            assert_eq!(
                resolved.c_metadata_json,
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
            super::record_materialized_bundle_outputs(
                &config,
                &dependency,
                &bundle,
                "aarch64-apple-darwin",
            )
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
                .expect("resolve dependency metadata");
            let super::DependencyCMetadataResolution::Resolved(resolved) = resolved else {
                panic!("the dependency's bookkeeping resolved");
            };
            assert_eq!(
                resolved.c_metadata_json,
                r#"[{"crate_name":"colorchoice","c_metadata":"0123456789abcdef"}]"#
            );
        });
    }

    #[test]
    fn dependency_reach_folds_local_only_rows_whatever_recorded_them() {
        use stow_types::public_cache::Reach;

        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        // A local build recorded local-only, and a served bundle whose
        // entry was stored local-only, both mark their outputs so.
        let built = parsed_rustc_args(
            "colorchoice",
            "abc123",
            out_dir.clone(),
            Vec::new(),
            vec!["lib".to_owned()],
        );
        let mut local_build = local_build_artifact(&built, "stable-colorchoice");
        local_build.reach = Reach::LocalOnly;
        let served = parsed_rustc_args(
            "anstyle",
            "compile-key",
            out_dir,
            Vec::new(),
            vec!["lib".to_owned()],
        );
        let mut artifact_bundle =
            sample_bundle("0123456789abcdef", "libanstyle-0123456789abcdef.rmeta");
        artifact_bundle.manifest.config.compile_key =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210".to_owned();
        let mut bundle = remote_cached_bundle(&artifact_bundle, tempdir.path());
        bundle.reach = Reach::LocalOnly;

        run_async(async {
            super::record_materialized_local_build_outputs(
                &config,
                &built,
                &local_build,
                "aarch64-apple-darwin",
            )
            .await
            .expect("record local build outputs");
            super::record_materialized_bundle_outputs(
                &config,
                &served,
                &bundle,
                "aarch64-apple-darwin",
            )
            .await
            .expect("record bundle outputs");

            for dependency in [&built, &served] {
                let consumer = consumer_parsed_args(
                    tempdir.path(),
                    dependency
                        .output_rmeta_path()
                        .expect("dependency rmeta path"),
                );
                let super::DependencyCMetadataResolution::Resolved(resolved) =
                    super::resolve_dependency_c_metadata_json(&config, &consumer)
                        .await
                        .expect("resolve dependency metadata")
                else {
                    panic!("the dependency's bookkeeping resolved");
                };
                assert_eq!(
                    resolved.reach,
                    Reach::LocalOnly,
                    "a consumer of {} did not fold local-only",
                    dependency.crate_name
                );
            }
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
        let build = local_build_artifact(&parsed, stable_c_metadata);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored =
                super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
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
    fn store_local_build_outputs_skips_missing_output() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create dep out dir");

        let parsed = local_build_parsed("demo", "cargo-meta-2", out_dir, &["link"]);
        // A failed or partial build leaves outputs absent: rustc exited
        // non-zero, or wrote only some of them. Nothing may be stored.
        let build = local_build_artifact(&parsed, "aaaabbbbccccdddd");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            let stored =
                super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
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
        let build = local_build_artifact(&parsed, stable_c_metadata);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
                    .await
                    .expect("first store")
            );
            // A second worktree building the same identity must not
            // double-store or error.
            assert!(
                !super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
                    .await
                    .expect("second store")
            );
        });
    }

    /// Staging is a clone-or-copy of the build's outputs, never a view
    /// of them: bytes staged into the entry must not move when the
    /// worktree's outputs are rewritten afterwards — a hardlink would
    /// carry the rewrite straight through.
    #[test]
    fn staged_entry_keeps_its_bytes_when_the_build_output_changes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let staging_dir = tempdir.path().join("staging");
        let entry_dir = tempdir.path().join("bundles").join("key-1");
        std::fs::create_dir_all(&staging_dir).expect("create staging dir");
        std::fs::create_dir_all(entry_dir.parent().unwrap()).expect("create bundles dir");
        let source = tempdir.path().join("libdemo-abc.rlib");
        std::fs::write(&source, b"local-rlib-bytes").expect("write build output");

        let outputs = vec![super::LocalBuildOutput {
            source: source.clone(),
            file_name: "libdemo-def.rlib".to_owned(),
            media_type: super::STOW_RLIB_MEDIA_TYPE,
            sha256: hex::encode(sha2::Sha256::digest(b"local-rlib-bytes")),
        }];
        let write = super::write_local_build_entry_blocking(&staging_dir, &entry_dir, &outputs)
            .expect("stage local build entry");
        assert_eq!(write.size_bytes, b"local-rlib-bytes".len() as u64);

        std::fs::write(&source, b"rewritten").expect("rewrite build output");
        assert_eq!(
            std::fs::read(entry_dir.join("files/libdemo-def.rlib")).expect("read staged file"),
            b"local-rlib-bytes",
            "a rewrite of the build output reached the staged file"
        );
    }

    /// Record a dependency's materialized outputs the way the wrapper does
    /// after its compile, then offer it to the store.
    async fn store_dependency(
        config: &StowConfig,
        parsed: &ParsedRustcArgs,
        build: &super::LocalBuildArtifact,
    ) -> bool {
        super::record_materialized_local_build_outputs(
            config,
            parsed,
            build,
            "aarch64-apple-darwin",
        )
        .await
        .expect("record dependency outputs");
        super::store_local_build_outputs(config, parsed, build, "aarch64-apple-darwin")
            .await
            .expect("store dependency")
    }

    /// Resolve a dependent's externs through the materialized outputs, as
    /// the wrapper's finish path does, and offer it to the store under
    /// `target` with the host the tests run on.
    async fn store_dependent(
        config: &StowConfig,
        parsed: &ParsedRustcArgs,
        stable_c_metadata: &str,
        target: &str,
    ) -> (bool, super::LocalBuildArtifact) {
        let super::DependencyCMetadataResolution::Resolved(dependencies) =
            super::resolve_dependency_c_metadata_json(config, parsed)
                .await
                .expect("resolve dependent externs")
        else {
            panic!("the dependent's externs resolve")
        };
        let mut build = local_build_artifact(parsed, stable_c_metadata);
        build.target = target.to_owned();
        build.dependencies = dependencies;
        let stored =
            super::store_local_build_outputs(config, parsed, &build, "aarch64-apple-darwin")
                .await
                .expect("store dependent");
        (stored, build)
    }

    /// A `toml` unit in `out_dir` linking `serde_core` through `dep_rmeta`,
    /// with its rlib and rmeta written.
    fn toml_dependent(out_dir: &Path, dep_rmeta: PathBuf) -> ParsedRustcArgs {
        let mut parsed = parsed_rustc_args(
            "toml",
            "cargo-meta-toml",
            out_dir.to_path_buf(),
            vec![ParsedExternCrate {
                crate_name: "serde_core".to_owned(),
                path: dep_rmeta,
            }],
            vec!["lib".to_owned()],
        );
        parsed.emit = ["metadata", "link"]
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        std::fs::write(parsed.output_rlib_path().expect("toml rlib"), b"toml-rlib")
            .expect("write toml rlib");
        std::fs::write(
            parsed.output_rmeta_path().expect("toml rmeta"),
            b"toml-rmeta",
        )
        .expect("write toml rmeta");
        parsed
    }

    /// stow#836: two concurrent cold builds compile the same unit to
    /// different bytes (different target dirs, different `OUT_DIR` in the
    /// SVH). First-writer-wins keeps the dep's entry to build A; build B's
    /// dependent, compiled against the other instance, must be refused —
    /// storing it would bind a dependent to bytes the cache does not
    /// hold, and every later build served the pair fails E0460/E0463.
    /// Build A's dependent, compiled against the stored instance, stores
    /// and records that instance.
    #[test]
    fn a_dependent_compiled_against_another_builds_dependency_is_not_stored() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let first_dir = tempdir.path().join("a/deps");
        let second_dir = tempdir.path().join("b/deps");
        let dependents_dir = tempdir.path().join("consumer/deps");
        for dir in [&first_dir, &second_dir, &dependents_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        // One stable identity, two instances: the dep's bytes differ
        // between target dirs while its identity does not.
        let dep_stable = "5edec0de5edec0de";
        let stored_dep =
            local_build_parsed("serde_core", "cargo-meta-dep", first_dir, &["metadata"]);
        std::fs::write(stored_dep.output_rmeta_path().expect("rmeta"), b"svh-a").expect("write");
        let losing_dep =
            local_build_parsed("serde_core", "cargo-meta-dep", second_dir, &["metadata"]);
        std::fs::write(losing_dep.output_rmeta_path().expect("rmeta"), b"svh-b").expect("write");
        let stored_dep_build = local_build_artifact(&stored_dep, dep_stable);
        let losing_dep_build = local_build_artifact(&losing_dep, dep_stable);
        assert_ne!(
            stored_dep_build.instance(),
            losing_dep_build.instance(),
            "different bytes must produce different instances"
        );

        let toml_stable = "70a170a170a170a1";
        let refused = toml_dependent(
            &dependents_dir,
            losing_dep.output_rmeta_path().expect("rmeta"),
        );
        let admitted = toml_dependent(
            &dependents_dir,
            stored_dep.output_rmeta_path().expect("rmeta"),
        );

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                store_dependency(&config, &stored_dep, &stored_dep_build).await,
                "build a's dep stores first"
            );
            assert!(
                !store_dependency(&config, &losing_dep, &losing_dep_build).await,
                "first-writer-wins keeps build a's dep"
            );

            let (stored, _) =
                store_dependent(&config, &refused, toml_stable, "aarch64-apple-darwin").await;
            assert!(
                !stored,
                "a dependent bound to an instance the cache does not hold must not store"
            );
            assert!(
                super::load_cached_bundle(&config, &fetch_request(toml_stable))
                    .await
                    .expect("load toml bundle")
                    .is_none(),
                "no entry may exist for the refused dependent"
            );

            let (stored, _) =
                store_dependent(&config, &admitted, toml_stable, "aarch64-apple-darwin").await;
            assert!(stored, "a dependent bound to the stored instance stores");
            let instances = stored_dependency_instances(
                &config,
                &super::artifact_cache_key("aarch64-apple-darwin", toml_stable),
            )
            .await;
            assert_eq!(instances.len(), 1);
            assert_eq!(instances[0].crate_name, "serde_core");
            assert_eq!(
                instances[0].compile_key, stored_dep_build.identity.compile_key,
                "the row binds to build a's dep entry"
            );
            assert_eq!(
                instances[0].instance,
                stored_dep_build.instance(),
                "the row records the instance the dependent compiled against"
            );
        });
    }

    /// A `--target` build's dependent links host-side deps (proc-macros)
    /// whose entries sit under the host triple, not the dependent's
    /// target; the binding finds them there and the dependent stores.
    #[test]
    fn a_cross_target_dependent_binds_a_host_side_dependency() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let host_dir = tempdir.path().join("host/deps");
        let target_dir = tempdir.path().join("x86_64-unknown-linux-gnu/deps");
        for dir in [&host_dir, &target_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", host_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"host-side").expect("write");
        let dep_build = local_build_artifact(&dep, "5edec0de5edec0de");
        let mut dependent = toml_dependent(&target_dir, dep.output_rmeta_path().expect("rmeta"));
        dependent.target = Some("x86_64-unknown-linux-gnu".to_owned());

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            let (stored, _) = store_dependent(
                &config,
                &dependent,
                "70a170a170a170a1",
                "x86_64-unknown-linux-gnu",
            )
            .await;
            assert!(
                stored,
                "the host-side dep's entry binds the cross dependent"
            );
            let instances = stored_dependency_instances(
                &config,
                &super::artifact_cache_key("x86_64-unknown-linux-gnu", "70a170a170a170a1"),
            )
            .await;
            assert_eq!(instances.len(), 1);
            assert_eq!(instances[0].instance, dep_build.instance());
        });
    }

    async fn stored_dependency_instances(
        config: &StowConfig,
        cache_key: &str,
    ) -> Vec<super::DependencyInstanceIdentity> {
        let pool = connect(&config.cache_dir).await.expect("connect state db");
        let instances_json: String = sqlx::query_scalar(
            "SELECT dependency_instances_json FROM artifact_cache_entries \
             WHERE rustc_version = '1.91.1' AND cache_key = ?",
        )
        .bind(cache_key)
        .fetch_one(&pool)
        .await
        .expect("read dependency instances");
        serde_json::from_str(&instances_json).expect("parse dependency instances")
    }

    /// Serve the cached entry under `stable_c_metadata` into `parsed`'s
    /// out dir the way the serve path does: write its files, then record
    /// their `materialized_outputs` rows with the entry's instance.
    async fn materialize_served(
        config: &StowConfig,
        parsed: &ParsedRustcArgs,
        stable_c_metadata: &str,
    ) {
        let bundle = super::load_cached_bundle(config, &fetch_request(stable_c_metadata))
            .await
            .expect("load served bundle")
            .expect("served entry present");
        crate::inject::write_artifacts(
            parsed,
            &bundle,
            "aarch64-apple-darwin",
            crate::inject::OutputDirWriters::StowOnly,
        )
        .await
        .expect("materialize served bundle");
        super::record_materialized_bundle_outputs(config, parsed, &bundle, "aarch64-apple-darwin")
            .await
            .expect("record served outputs");
    }

    /// stow#836: dep-A's entry is evicted and dep-B re-stored under the
    /// same identity — same compile key, different instance. The dependent
    /// bound to dep-A's instance is stale: serving it misses, and its
    /// entry is evicted so a later local compile can store a consistent
    /// replacement.
    #[test]
    fn a_closure_entry_bound_to_an_evicted_dependency_is_not_served() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let first_dir = tempdir.path().join("a/deps");
        let second_dir = tempdir.path().join("b/deps");
        let third_dir = tempdir.path().join("c/deps");
        let dependent_dir = tempdir.path().join("a-dependent/deps");
        for dir in [&first_dir, &second_dir, &third_dir, &dependent_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let evicted_dep =
            local_build_parsed("serde_core", "cargo-meta-dep", first_dir, &["metadata"]);
        std::fs::write(evicted_dep.output_rmeta_path().expect("rmeta"), b"svh-a").expect("write");
        let refilled_dep =
            local_build_parsed("serde_core", "cargo-meta-dep", second_dir, &["metadata"]);
        std::fs::write(refilled_dep.output_rmeta_path().expect("rmeta"), b"svh-b").expect("write");
        let evicted_dep_build = local_build_artifact(&evicted_dep, dep_stable);
        let refilled_dep_build = local_build_artifact(&refilled_dep, dep_stable);
        assert_ne!(
            evicted_dep_build.instance(),
            refilled_dep_build.instance(),
            "different bytes must produce different instances"
        );

        let toml_stable = "70a170a170a170a1";
        let dependent = toml_dependent(
            &dependent_dir,
            evicted_dep.output_rmeta_path().expect("rmeta"),
        );

        // The serving build is served dep-B: its files land in the third
        // out dir the way the serve path writes them, and the rows it
        // records carry dep-B's instance.
        let refilled_dep_served = local_build_parsed(
            "serde_core",
            "cargo-meta-dep",
            third_dir.clone(),
            &["metadata"],
        );

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &evicted_dep, &evicted_dep_build).await);
            let (stored, _) =
                store_dependent(&config, &dependent, toml_stable, "aarch64-apple-darwin").await;
            assert!(stored, "the dependent binds to dep-a's instance");

            // Dep-A's entry is evicted; another build's dep-B fills the key.
            super::remove_cached_bundle(&config, &fetch_request(dep_stable))
                .await
                .expect("evict dep-a entry");
            assert!(store_dependency(&config, &refilled_dep, &refilled_dep_build).await);

            materialize_served(&config, &refilled_dep_served, dep_stable).await;

            let dependent_third = toml_dependent(
                &third_dir,
                refilled_dep_served.output_rmeta_path().expect("rmeta"),
            );
            let request = fetch_request(toml_stable);
            let bundle = super::load_cached_bundle(&config, &request)
                .await
                .expect("load dependent bundle")
                .expect("dependent entry present");
            let served = crate::prune_materialized_aliases_for_cached_closure(
                &config,
                &dependent_third,
                &request,
                bundle,
            )
            .await
            .expect("closure binding check");
            assert!(
                served.is_none(),
                "a dependent bound to an evicted instance must miss"
            );
            assert!(
                super::load_cached_bundle(&config, &request)
                    .await
                    .expect("reload dependent")
                    .is_none(),
                "the stale dependent entry is evicted"
            );
        });
    }

    /// `toml_edit` in `out_dir`, compiled against the `toml` rmeta at
    /// `toml_rmeta` — a dependent one level above `toml_dependent`.
    fn toml_edit_dependent(out_dir: &Path, toml_rmeta: PathBuf) -> ParsedRustcArgs {
        let mut parsed = parsed_rustc_args(
            "toml_edit",
            "cargo-meta-top",
            out_dir.to_path_buf(),
            vec![ParsedExternCrate {
                crate_name: "toml".to_owned(),
                path: toml_rmeta,
            }],
            vec!["lib".to_owned()],
        );
        parsed.emit = ["metadata", "link"]
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        parsed
    }

    /// stow#836: the stale entry need not be the one served. `toml` binds
    /// to dep-A, `toml_edit` binds to `toml`; dep-A is evicted and dep-B
    /// fills its key. Serving `toml_edit` — whose own binding to `toml`
    /// still holds — misses, and the stale `toml` deeper in the closure is
    /// the entry evicted.
    #[test]
    fn a_stale_entry_deeper_in_the_closure_is_evicted() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let first_dir = tempdir.path().join("a/deps");
        let second_dir = tempdir.path().join("b/deps");
        let serving_dir = tempdir.path().join("c/deps");
        for dir in [&first_dir, &second_dir, &serving_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let evicted_dep = local_build_parsed(
            "serde_core",
            "cargo-meta-dep",
            first_dir.clone(),
            &["metadata"],
        );
        std::fs::write(evicted_dep.output_rmeta_path().expect("rmeta"), b"svh-a").expect("write");
        let refilled_dep =
            local_build_parsed("serde_core", "cargo-meta-dep", second_dir, &["metadata"]);
        std::fs::write(refilled_dep.output_rmeta_path().expect("rmeta"), b"svh-b").expect("write");
        let evicted_dep_build = local_build_artifact(&evicted_dep, dep_stable);
        let refilled_dep_build = local_build_artifact(&refilled_dep, dep_stable);

        let toml_stable = "70a170a170a170a1";
        let toml = toml_dependent(&first_dir, evicted_dep.output_rmeta_path().expect("rmeta"));
        let top_stable = "70e170e170e170e1";
        let top_first = toml_edit_dependent(&first_dir, toml.output_rmeta_path().expect("rmeta"));
        std::fs::write(top_first.output_rlib_path().expect("rlib"), b"top-rlib").expect("write");
        std::fs::write(top_first.output_rmeta_path().expect("rmeta"), b"top-rmeta").expect("write");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &evicted_dep, &evicted_dep_build).await);
            let (stored, toml_build) =
                store_dependent(&config, &toml, toml_stable, "aarch64-apple-darwin").await;
            assert!(stored, "toml binds to dep-a");
            super::record_materialized_local_build_outputs(
                &config,
                &toml,
                &toml_build,
                "aarch64-apple-darwin",
            )
            .await
            .expect("record toml outputs");
            let (stored, _) =
                store_dependent(&config, &top_first, top_stable, "aarch64-apple-darwin").await;
            assert!(stored, "toml_edit binds to toml");

            super::remove_cached_bundle(&config, &fetch_request(dep_stable))
                .await
                .expect("evict dep-a entry");
            assert!(store_dependency(&config, &refilled_dep, &refilled_dep_build).await);

            // The serving build is served `toml` itself, unchanged — the
            // extern `toml_edit` checks against still carries the bound
            // instance; only `toml`'s own binding is stale.
            let toml_served = toml_dependent(
                &serving_dir,
                refilled_dep.output_rmeta_path().expect("rmeta"),
            );
            materialize_served(&config, &toml_served, toml_stable).await;

            let top_serving = toml_edit_dependent(
                &serving_dir,
                toml_served.output_rmeta_path().expect("rmeta"),
            );
            let request = fetch_request(top_stable);
            let bundle = super::load_cached_bundle(&config, &request)
                .await
                .expect("load toml_edit bundle")
                .expect("toml_edit entry present");
            let served = crate::prune_materialized_aliases_for_cached_closure(
                &config,
                &top_serving,
                &request,
                bundle,
            )
            .await
            .expect("closure binding check");
            assert!(
                served.is_none(),
                "a closure holding a stale entry must miss"
            );
            assert!(
                super::load_cached_bundle(&config, &fetch_request(toml_stable))
                    .await
                    .expect("reload toml")
                    .is_none(),
                "the stale toml entry deeper in the closure is evicted"
            );
            assert!(
                super::load_cached_bundle(&config, &request)
                    .await
                    .expect("reload toml_edit")
                    .is_some(),
                "toml_edit's own binding still holds; it stays cached"
            );
        });
    }

    /// stow#836: a remote dependent was compiled against the published dep
    /// instance; a dep whose cache entry is local-provenance can never
    /// satisfy it. The serve misses and the local dep entry is evicted, so
    /// the next build downloads the published dep and the remote pair
    /// serves; the remote dependent stays cached.
    #[test]
    fn a_remote_dependent_over_a_local_dependency_evicts_the_local_dependency() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dep_dir = tempdir.path().join("dep/deps");
        let out_dir = tempdir.path().join("served/deps");
        for dir in [&dep_dir, &out_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", dep_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"local-dep").expect("write");
        let dep_build = local_build_artifact(&dep, dep_stable);

        // A remote dependent bound to the dep's compile key — the binding
        // a published artifact carries.
        let remote_meta = "70a170a170a170a1";
        let mut remote = sample_bundle(remote_meta, "libtoml-70a170a170a170a1.rmeta");
        remote.manifest.config.dependency_compile_keys_json =
            serde_json::to_string(&[stow_types::identity::DependencyCompileKeyIdentity {
                crate_name: stow_types::identity::CrateName::parse("serde_core")
                    .expect("crate name"),
                compile_key: dep_build.identity.compile_key.clone(),
            }])
            .expect("serialize dependency compile keys");

        // The build serving the remote dependent compiled the dep locally:
        // its extern carries the local instance.
        let local_dep_in_out = local_build_parsed(
            "serde_core",
            "cargo-meta-dep",
            out_dir.clone(),
            &["metadata"],
        );
        std::fs::write(
            local_dep_in_out.output_rmeta_path().expect("rmeta"),
            b"local-dep",
        )
        .expect("write local dep rmeta");
        let dependent = toml_dependent(
            &out_dir,
            local_dep_in_out.output_rmeta_path().expect("rmeta"),
        );

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            let stored =
                super::store_downloaded_bundle(&config, &fetch_request(remote_meta), &remote)
                    .await
                    .expect("store remote dependent");
            assert_eq!(stored.provenance, super::ArtifactProvenance::Remote);

            super::record_materialized_local_build_outputs(
                &config,
                &local_dep_in_out,
                &dep_build,
                "aarch64-apple-darwin",
            )
            .await
            .expect("record local dep outputs");

            let request = fetch_request(remote_meta);
            let served = crate::prune_materialized_aliases_for_cached_closure(
                &config, &dependent, &request, stored,
            )
            .await
            .expect("closure binding check");
            assert!(
                served.is_none(),
                "a remote dependent over a local dependency must miss"
            );
            assert!(
                super::load_cached_bundle(&config, &request)
                    .await
                    .expect("reload remote dependent")
                    .is_some(),
                "the remote dependent stays cached"
            );
            assert!(
                super::load_cached_bundle(&config, &fetch_request(dep_stable))
                    .await
                    .expect("reload dep")
                    .is_none(),
                "the local dep entry the remote dependent sits on is evicted"
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
        let build = local_build_artifact(&parsed, stable_c_metadata);
        let request = fetch_request(stable_c_metadata);
        let bundle = sample_bundle(stable_c_metadata, "libdemo-1122334455667788.rlib");

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(
                super::store_local_build_outputs(&config, &parsed, &build, "aarch64-apple-darwin")
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
        let local_build = local_build_artifact(&local_parsed, local_meta);
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
                super::store_local_build_outputs(
                    &config,
                    &local_parsed,
                    &local_build,
                    "aarch64-apple-darwin",
                )
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
        let local_build = local_build_artifact(&local_parsed, local_meta);
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
                super::store_local_build_outputs(
                    &config,
                    &local_parsed,
                    &local_build,
                    "aarch64-apple-darwin",
                )
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

    /// A `derive_demo` proc-macro unit in `out_dir`, compiled against the
    /// `serde_core` rmeta at `dep_rmeta`, with its dylib written — the
    /// host-side dependent shape stow#1005 names.
    fn proc_macro_dependent(out_dir: &Path, dep_rmeta: PathBuf) -> ParsedRustcArgs {
        let mut parsed = parsed_rustc_args(
            "derive_demo",
            "cargo-meta-derive",
            out_dir.to_path_buf(),
            vec![ParsedExternCrate {
                crate_name: "serde_core".to_owned(),
                path: dep_rmeta,
            }],
            vec!["proc-macro".to_owned()],
        );
        parsed.emit = BTreeSet::from(["link".to_owned()]);
        std::fs::write(
            parsed
                .output_dynamic_library_path("aarch64-apple-darwin")
                .expect("proc-macro dylib path")
                .expect("proc-macro produces a dylib"),
            b"derive-dylib",
        )
        .expect("write proc-macro dylib");
        parsed
    }

    /// The invariant a closure-aware pass leaves (stow#1005): every
    /// dependency compile key a stored entry names is still carried by a
    /// stored entry.
    fn assert_closure_complete(index: &BTreeMap<String, super::ArtifactCacheIndexEntry>) {
        let provided: BTreeSet<&str> = index
            .values()
            .map(|entry| entry.compile_key.as_str())
            .collect();
        for (cache_key, entry) in index {
            let deps: Vec<stow_types::identity::DependencyCompileKeyIdentity> =
                serde_json::from_str(&entry.dependency_compile_keys_json)
                    .expect("parse dependency compile keys");
            for dep in deps {
                assert!(
                    provided.contains(dep.compile_key.as_str()),
                    "entry {cache_key} lost the entry for dependency compile key {}",
                    dep.compile_key
                );
            }
        }
    }

    /// stow#1005: evicting a dependency's entry carries out every entry
    /// that depends on it — a proc macro over evicted deps is dead
    /// weight, so it goes out in the same pass.
    #[test]
    fn evicting_a_dependency_evicts_its_proc_macro_dependent() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let dep_dir = tempdir.path().join("dep/deps");
        let derive_dir = tempdir.path().join("derive/deps");
        let leaf_dir = tempdir.path().join("leaf/deps");
        for dir in [&dep_dir, &derive_dir, &leaf_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", dep_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"dep-rmeta").expect("write");
        let dep_build = local_build_artifact(&dep, dep_stable);

        let derive_stable = "de31c0dede31c0de";
        let derive = proc_macro_dependent(&derive_dir, dep.output_rmeta_path().expect("rmeta"));

        let leaf_stable = "1eaf1eaf1eaf1eaf";
        let leaf = local_build_parsed("leaf", "cargo-meta-leaf", leaf_dir, &["metadata"]);
        let leaf_rmeta = leaf.output_rmeta_path().expect("rmeta");
        std::fs::write(&leaf_rmeta, b"leaf-rmeta").expect("write");
        let leaf_build = local_build_artifact(&leaf, leaf_stable);
        let leaf_size = std::fs::metadata(&leaf_rmeta)
            .expect("leaf rmeta metadata")
            .len();

        let dep_key = super::artifact_cache_key("aarch64-apple-darwin", dep_stable);
        let derive_key = super::artifact_cache_key("aarch64-apple-darwin", derive_stable);
        let leaf_key = super::artifact_cache_key("aarch64-apple-darwin", leaf_stable);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            let (stored, _) =
                store_dependent(&config, &derive, derive_stable, "aarch64-apple-darwin").await;
            assert!(stored, "the proc-macro dependent binds to the dep");

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let resident: u64 = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .values()
                .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
            config.artifact_cache_max_bytes = resident + leaf_size - 1;
            touch_artifact_cache_entry(&pool, "1.91.1", &dep_key, 1)
                .await
                .expect("stale dep lru timestamp");

            assert!(
                store_dependency(&config, &leaf, &leaf_build).await,
                "the leaf store triggers the pass"
            );

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(!index.contains_key(&dep_key), "the dep is evicted");
            assert!(
                !index.contains_key(&derive_key),
                "its proc-macro dependent goes out in the same pass"
            );
            assert!(index.contains_key(&leaf_key));
            let entries_dir = config
                .artifact_cache_version_dir("1.91.1")
                .join("bundles/v3/aarch64-apple-darwin");
            assert!(!entries_dir.join(dep_stable).exists());
            assert!(!entries_dir.join(derive_stable).exists());
            assert_closure_complete(&index);
        });
    }

    /// stow#1005: nothing in the protected entry's dependency closure is
    /// ever a victim — the oldest entry stays when the just-stored entry
    /// depends on it, provenance-agnostic: a remote dependent over a
    /// local dep keeps the dep.
    #[test]
    fn the_protected_entrys_dependency_closure_is_never_evicted() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let dep_dir = tempdir.path().join("dep/deps");
        let leaf_dir = tempdir.path().join("leaf/deps");
        for dir in [&dep_dir, &leaf_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", dep_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"dep-rmeta").expect("write");
        let dep_build = local_build_artifact(&dep, dep_stable);

        let leaf_stable = "1eaf1eaf1eaf1eaf";
        let leaf = local_build_parsed("leaf", "cargo-meta-leaf", leaf_dir, &["metadata"]);
        std::fs::write(leaf.output_rmeta_path().expect("rmeta"), b"leaf-rmeta").expect("write");
        let leaf_build = local_build_artifact(&leaf, leaf_stable);

        // A remote dependent bound to the dep's compile key — the binding
        // a published artifact carries.
        let remote_meta = "70a170a170a170a1";
        let mut remote = sample_bundle(remote_meta, "libtoml-70a170a170a170a1.rmeta");
        remote.manifest.config.dependency_compile_keys_json =
            serde_json::to_string(&[stow_types::identity::DependencyCompileKeyIdentity {
                crate_name: stow_types::identity::CrateName::parse("serde_core")
                    .expect("crate name"),
                compile_key: dep_build.identity.compile_key.clone(),
            }])
            .expect("serialize dependency compile keys");
        let remote_size =
            write_downloaded_bundle_to_entry(&tempdir.path().join("scratch"), &remote)
                .expect("measure remote bundle size");
        let remote_key = cache_key(&fetch_request(remote_meta));

        let dep_key = super::artifact_cache_key("aarch64-apple-darwin", dep_stable);
        let leaf_key = super::artifact_cache_key("aarch64-apple-darwin", leaf_stable);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            assert!(store_dependency(&config, &leaf, &leaf_build).await);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let dep_size = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .get(&dep_key)
                .expect("dep entry")
                .size_bytes;
            // Evicting the dep's group would leave the remote dependent
            // without its dependency, but the remote store's own pass
            // protects its closure: the leaf goes instead.
            config.artifact_cache_max_bytes = dep_size + remote_size;
            touch_artifact_cache_entry(&pool, "1.91.1", &dep_key, 1)
                .await
                .expect("stale dep lru timestamp");

            super::store_downloaded_bundle(&config, &fetch_request(remote_meta), &remote)
                .await
                .expect("store remote dependent");

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(
                index.contains_key(&dep_key),
                "the protected entry's dependency is never a victim"
            );
            assert!(index.contains_key(&remote_key));
            assert!(
                !index.contains_key(&leaf_key),
                "the unprotected leaf takes the eviction"
            );
            assert_closure_complete(&index);
        });
    }

    /// stow#1005: a victim group is evicted whole or not at all — a
    /// member another process holds a lock on skips the whole group, so
    /// no pass can leave a dependent without its dependency.
    #[test]
    fn a_victim_group_with_a_locked_member_is_skipped_whole() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let dep_dir = tempdir.path().join("dep/deps");
        let dependent_dir = tempdir.path().join("dependent/deps");
        let leaf_dir = tempdir.path().join("leaf/deps");
        let trigger_dir = tempdir.path().join("trigger/deps");
        for dir in [&dep_dir, &dependent_dir, &leaf_dir, &trigger_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", dep_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"dep-rmeta").expect("write");
        let dep_build = local_build_artifact(&dep, dep_stable);

        let toml_stable = "70a170a170a170a1";
        let toml = toml_dependent(&dependent_dir, dep.output_rmeta_path().expect("rmeta"));

        let leaf_stable = "1eaf1eaf1eaf1eaf";
        let leaf = local_build_parsed("leaf", "cargo-meta-leaf", leaf_dir, &["metadata"]);
        std::fs::write(leaf.output_rmeta_path().expect("rmeta"), b"leaf-rmeta").expect("write");
        let leaf_build = local_build_artifact(&leaf, leaf_stable);

        let trigger_stable = "71a971a971a971a9";
        let trigger =
            local_build_parsed("trigger", "cargo-meta-trigger", trigger_dir, &["metadata"]);
        let trigger_rmeta = trigger.output_rmeta_path().expect("rmeta");
        std::fs::write(&trigger_rmeta, b"trigger").expect("write");
        let trigger_build = local_build_artifact(&trigger, trigger_stable);
        let trigger_size = std::fs::metadata(&trigger_rmeta)
            .expect("trigger rmeta metadata")
            .len();

        let dep_key = super::artifact_cache_key("aarch64-apple-darwin", dep_stable);
        let toml_key = super::artifact_cache_key("aarch64-apple-darwin", toml_stable);
        let leaf_key = super::artifact_cache_key("aarch64-apple-darwin", leaf_stable);
        let trigger_key = super::artifact_cache_key("aarch64-apple-darwin", trigger_stable);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            let (stored, _) =
                store_dependent(&config, &toml, toml_stable, "aarch64-apple-darwin").await;
            assert!(stored, "the dependent binds to the dep");
            assert!(store_dependency(&config, &leaf, &leaf_build).await);

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries");
            let leaf_size = index.get(&leaf_key).expect("leaf entry").size_bytes;
            let resident: u64 = index
                .values()
                .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
            // The dep's group holds `toml`; with `toml` locked the whole
            // group is skipped and the budget comes out of the leaf alone.
            config.artifact_cache_max_bytes = resident - leaf_size + trigger_size;
            touch_artifact_cache_entry(&pool, "1.91.1", &dep_key, 1)
                .await
                .expect("stale dep lru timestamp");
            touch_artifact_cache_entry(&pool, "1.91.1", &toml_key, 2)
                .await
                .expect("stale dependent lru timestamp");
            touch_artifact_cache_entry(&pool, "1.91.1", &leaf_key, 3)
                .await
                .expect("stale leaf lru timestamp");

            // Another process holds the dependent's lease.
            let _dependent_lease = super::acquire_entry_shared_lock(
                &config.artifact_cache_version_dir("1.91.1"),
                &toml_key,
            )
            .expect("lease the dependent entry");

            assert!(
                store_dependency(&config, &trigger, &trigger_build).await,
                "the trigger store runs the pass"
            );

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(
                index.contains_key(&dep_key),
                "a locked member skips the whole group — the dep stays"
            );
            assert!(index.contains_key(&toml_key));
            assert!(index.contains_key(&trigger_key));
            assert!(!index.contains_key(&leaf_key));
            assert_closure_complete(&index);
        });
    }

    /// stow#1005, the done-when: after a pass no stored entry lacks a
    /// dependency entry. `serde_core` ← `toml` ← `toml_edit`; evicting the
    /// dep carries the whole chain out, transitively.
    #[test]
    fn an_eviction_pass_leaves_no_dependent_without_its_dependency() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path());
        let dep_dir = tempdir.path().join("dep/deps");
        let toml_dir = tempdir.path().join("toml/deps");
        let top_dir = tempdir.path().join("top/deps");
        let leaf_dir = tempdir.path().join("leaf/deps");
        for dir in [&dep_dir, &toml_dir, &top_dir, &leaf_dir] {
            std::fs::create_dir_all(dir).expect("create out dir");
        }

        let dep_stable = "5edec0de5edec0de";
        let dep = local_build_parsed("serde_core", "cargo-meta-dep", dep_dir, &["metadata"]);
        std::fs::write(dep.output_rmeta_path().expect("rmeta"), b"dep-rmeta").expect("write");
        let dep_build = local_build_artifact(&dep, dep_stable);

        let toml_stable = "70a170a170a170a1";
        let toml = toml_dependent(&toml_dir, dep.output_rmeta_path().expect("rmeta"));
        let top_stable = "70e170e170e170e1";
        let top = toml_edit_dependent(&top_dir, toml.output_rmeta_path().expect("rmeta"));
        std::fs::write(top.output_rlib_path().expect("rlib"), b"top-rlib").expect("write");
        std::fs::write(top.output_rmeta_path().expect("rmeta"), b"top-rmeta").expect("write");

        let leaf_stable = "1eaf1eaf1eaf1eaf";
        let leaf = local_build_parsed("leaf", "cargo-meta-leaf", leaf_dir, &["metadata"]);
        let leaf_rmeta = leaf.output_rmeta_path().expect("rmeta");
        std::fs::write(&leaf_rmeta, b"leaf-rmeta").expect("write");
        let leaf_build = local_build_artifact(&leaf, leaf_stable);
        let leaf_size = std::fs::metadata(&leaf_rmeta)
            .expect("leaf rmeta metadata")
            .len();

        let dep_key = super::artifact_cache_key("aarch64-apple-darwin", dep_stable);
        let toml_key = super::artifact_cache_key("aarch64-apple-darwin", toml_stable);
        let top_key = super::artifact_cache_key("aarch64-apple-darwin", top_stable);
        let leaf_key = super::artifact_cache_key("aarch64-apple-darwin", leaf_stable);

        run_async(async {
            prepare_local_cache(&config, "1.91.1")
                .await
                .expect("prepare cache");
            assert!(store_dependency(&config, &dep, &dep_build).await);
            let (stored, toml_build) =
                store_dependent(&config, &toml, toml_stable, "aarch64-apple-darwin").await;
            assert!(stored, "toml binds to the dep");
            super::record_materialized_local_build_outputs(
                &config,
                &toml,
                &toml_build,
                "aarch64-apple-darwin",
            )
            .await
            .expect("record toml outputs");
            let (stored, _) =
                store_dependent(&config, &top, top_stable, "aarch64-apple-darwin").await;
            assert!(stored, "toml_edit binds to toml");

            let pool = connect(&config.cache_dir).await.expect("connect state db");
            let resident: u64 = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries")
                .values()
                .fold(0u64, |sum, entry| sum.saturating_add(entry.size_bytes));
            config.artifact_cache_max_bytes = resident + leaf_size - 1;
            touch_artifact_cache_entry(&pool, "1.91.1", &dep_key, 1)
                .await
                .expect("stale dep lru timestamp");

            assert!(
                store_dependency(&config, &leaf, &leaf_build).await,
                "the leaf store triggers the pass"
            );

            let index = list_artifact_cache_entries(&pool, "1.91.1")
                .await
                .expect("list entries after eviction");
            assert!(!index.contains_key(&dep_key), "the dep is evicted");
            assert!(
                !index.contains_key(&toml_key),
                "the direct dependent goes with it"
            );
            assert!(
                !index.contains_key(&top_key),
                "the transitive dependent goes with it"
            );
            assert!(index.contains_key(&leaf_key));
            assert_closure_complete(&index);
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
            registry_base_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: root.join(".stow"),
            request_timeout: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_mins(1),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: u64::MAX,
            index_refresh_interval: Duration::from_mins(1),
            verify_mode: VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
            experimental: crate::config::ExperimentalConfig::default(),
        }
    }

    fn fetch_request(c_metadata: &str) -> FetchRequest<'_> {
        FetchRequest {
            target: "aarch64-apple-darwin",
            rustc_version: "1.91.1",
            c_metadata,
        }
    }

    pub fn sample_bundle(c_metadata: &str, file_name: &str) -> ArtifactBundle {
        let file_contents = b"demo-artifact".to_vec();
        let compression_level = *zstd::compression_level_range().end();
        let stored_contents = zstd::bulk::compress(&file_contents, compression_level)
            .expect("compress sample artifact bundle output");
        ArtifactBundle {
            manifest: ArtifactBundleManifest {
                oci_reference: "ghcr.io/water-rs/stow-cache-1.91.1:demo.test".to_owned(),
                oci_digest: "sha256:test".to_owned(),
                config: ArtifactBlobConfig {
                    dependency_identity: stow_types::identity::DependencyIdentity::leaf()
                        .expect("leaf identity"),
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
                                "docker-reference": "ghcr.io/water-rs/stow-cache-1.91.1:demo.test"
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
            cfg_args: Vec::new(),
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
            build_script_out_dir: None,
            extern_crates,
            embed_metadata: None,
            embed_bitcode: false,
            extra_codegen: Vec::new(),
            link_options: Vec::new(),
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

    fn local_build_artifact(
        parsed: &ParsedRustcArgs,
        stable_c_metadata: &str,
    ) -> super::LocalBuildArtifact {
        let identity = StableUnitIdentity {
            // Real compile keys are hex; the stable c_metadata is the
            // first 16 hex digits of the key.
            compile_key: format!("{stable_c_metadata}{stable_c_metadata}"),
            c_metadata: stable_c_metadata.to_owned(),
            extra_filename: format!("-{stable_c_metadata}"),
            crate_name: parsed.crate_name.clone(),
            version: "1.0.0".to_owned(),
            source: stow_types::public_cache::UnitSource::CratesIo {
                package: parsed.crate_name.clone(),
                version: "1.0.0".to_owned(),
            },
            reach: stow_types::public_cache::Reach::Public,
        };
        // The fixture mirrors the resolve path's hashing, except it
        // tolerates a missing source — the skips-missing-output test
        // needs an artifact whose outputs rustc never wrote, which the
        // real resolve path can never produce.
        let stable_parsed = crate::inject::parsed_with_stable_identity(
            parsed,
            &identity.c_metadata,
            &identity.extra_filename,
        );
        let mut outputs =
            super::local_build_output_specs(parsed, &stable_parsed, "aarch64-apple-darwin")
                .expect("local build output specs");
        for output in &mut outputs {
            if output.source.exists() {
                output.sha256 = super::sha256_file_bytes(&output.source)
                    .expect("hash fixture output")
                    .0;
            }
        }
        super::LocalBuildArtifact {
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            identity,
            reach: stow_types::public_cache::Reach::Public,
            features_json: "[]".to_owned(),
            dependencies: super::ResolvedDependencies {
                c_metadata_json: "[]".to_owned(),
                externs: Vec::new(),
                reach: stow_types::public_cache::Reach::Public,
            },
            outputs,
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
            cfg_args: Vec::new(),
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
            build_script_out_dir: None,
            extern_crates: vec![ParsedExternCrate {
                crate_name: "colorchoice".to_owned(),
                path: dependency_rmeta,
            }],
            embed_metadata: None,
            embed_bitcode: false,
            extra_codegen: Vec::new(),
            link_options: Vec::new(),
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
            reach: stow_types::public_cache::Reach::Public,
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
            dependency_instances_json: "[]".to_owned(),
            compile_millis: artifact_bundle.manifest.config.compile_millis,
            size_bytes: 0,
            profile: artifact_bundle.manifest.config.profile.clone(),
            emit: artifact_bundle.manifest.config.emit.clone(),
            kind: artifact_bundle.manifest.config.kind.clone(),
            crate_types: artifact_bundle.manifest.config.crate_types.clone(),
            outputs: artifact_bundle.manifest.config.outputs.clone(),
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
            _lease_lock: super::FileLock::shared(
                std::fs::File::create(&lease_path).expect("lease file"),
            )
            .expect("lease lock"),
        }
    }

    /// The dir-only entry the CI consume-store writes and the sandboxed
    /// capture wrapper reads must round-trip: the entry's `manifest.json`
    /// is what marks it loadable, and `parse_bundle` never carries it in
    /// `files` — it has to be written from the parsed manifest.
    #[test]
    fn stored_bundle_entry_dir_loads_back() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let lease_dir = tempfile::tempdir().expect("lease dir");
        let bundle = sample_bundle("aabbccddeeff0011", "libdemo-aabbccddeeff0011.rmeta");
        let entry_dir = tempdir.path().join("compile-key");

        store_bundle_entry_dir(&entry_dir, &bundle).expect("store bundle entry");
        assert!(entry_dir.join("manifest.json").exists());

        let loaded = load_bundle_entry_dir(&entry_dir, lease_dir.path(), "compile-key")
            .expect("load bundle entry")
            .expect("bundle entry present");
        assert_eq!(loaded.compile_key, bundle.manifest.config.compile_key);
        assert_eq!(loaded.crate_name, "demo");
        assert_eq!(loaded.outputs.len(), 1);
    }
}
