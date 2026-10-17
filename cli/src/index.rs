//! The locally cached, signature-verified artifact index (stow#194).
//!
//! Each `(target, rustc_version)` slice is published to the OCI registry as
//! `index.<target>.<rustc>` by `.github/workflows/index-publish.yml`. The
//! wrapper pulls the slice's manifest and single zstd layer, verifies the
//! cosign signature against the index-publish workflow identity, and caches
//! the verified blob under `cache_dir/index/<target>/<rustc_version>/`: the
//! blob named by manifest digest plus a `current.json` pointer carrying
//! `{manifest_digest, fetched_at, row_count}`.
//!
//! Refresh policy: a pointer younger than `index_refresh_interval`
//! short-circuits the network entirely; past it, one manifest request
//! re-validates the digest and only a moved digest costs a download and
//! re-verification. Network failure with a cached slice logs at `info` and
//! serves it; no cached slice and no reachable registry is a hard error
//! naming the tag — resolution then proceeds only from signed bytes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use futures_lite::StreamExt as _;
use serde::{Deserialize, Serialize};
use stow_types::error::Context;
use stow_types::identity::WireRustcVersion;
use stow_types::index::{ArtifactIndex, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::registry::{CacheRepository, cache_repository};

use crate::config::StowConfig;
use crate::verify;

/// The pointer file inside each slice directory.
const POINTER_FILE: &str = "current.json";

/// The cached-slice pointer: which verified blob `current` selects, when
/// the registry last confirmed it, and the row count it decoded to so
/// `stow index status` never pays a decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlicePointer {
    manifest_digest: String,
    fetched_at: u64,
    row_count: u64,
}

/// A verified index slice: the decoded rows plus the manifest digest that
/// carried them, so callers can report what they resolved against.
#[derive(Debug, Clone)]
pub struct IndexSlice {
    /// `sha256:…` of the OCI manifest the blob came from.
    pub manifest_digest: String,
    /// The decoded index — header identity already checked against the
    /// requested `(target, rustc_version)`.
    pub index: ArtifactIndex,
}

/// One cached slice's status, surfaced by `stow index status`.
#[derive(Debug, Clone)]
pub struct CachedSliceStatus {
    /// Compilation target triple of the slice.
    pub target: String,
    /// Stable rustc version of the slice.
    pub rustc_version: String,
    /// `sha256:…` of the manifest the cached blob came from.
    pub manifest_digest: String,
    /// Unix seconds at which the registry last confirmed the digest.
    pub fetched_at: u64,
    /// Number of rows the slice carries.
    pub row_count: u64,
}

/// The slice every resolution path consumes: serve the verified cache while
/// it is fresh, re-validate against the registry past the refresh interval,
/// and fall back to the cache when the registry is unreachable. With no
/// cached slice, a registry failure is the error the caller surfaces — the
/// resolver never runs against unsigned or absent data.
///
/// The fetch itself runs once per process — a build holds one index, and
/// every caller after the first consumes the memoized rows rather than
/// paying the pull and the signature verification again (stow#347). A
/// failure is not memoized: the next caller retries the fetch.
///
/// # Errors
///
/// Returns an error when no usable slice can be produced.
pub async fn ensure_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<IndexSlice> {
    static SLICES: tokio::sync::OnceCell<
        tokio::sync::Mutex<std::collections::BTreeMap<(String, String), IndexSlice>>,
    > = tokio::sync::OnceCell::const_new();
    let key = (target.to_owned(), rustc_version.to_owned());
    let slices = SLICES
        .get_or_init(|| async { tokio::sync::Mutex::new(BTreeMap::new()) })
        .await;
    let mut slices = slices.lock().await;
    if let Some(slice) = slices.get(&key) {
        return Ok(slice.clone());
    }
    let slice = fetch_slice(config, target, rustc_version, false).await?;
    slices.insert(key, slice.clone());
    drop(slices);
    Ok(slice)
}

/// The wrapper's slice source: the verified cache only, never the network.
/// Freshness is the driver's job — `cargo`-side analysis calls
/// [`ensure_slice`] once per build — so a per-invocation wrapper that paid
/// a manifest revalidation would put a registry round trip on every rustc
/// call. `None` means "no verified slice is cached": the caller treats it
/// as a cache miss, not an error.
///
/// # Errors
///
/// Returns an error when the cached bytes or pointer cannot be decoded —
/// corruption is surfaced, absence and foreign formats are not errors.
pub async fn cached_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<IndexSlice>> {
    let dir = slice_dir(config, target, rustc_version);
    let Some(pointer) = read_pointer(&dir).await else {
        return Ok(None);
    };
    load_cached(&dir, &pointer).await
}

/// `stow index refresh` — hit the registry even when the pointer is fresh.
///
/// # Errors
///
/// Returns an error when the registry is unreachable and no cached slice
/// exists, when the fetched artifact fails signature or digest
/// verification, or when the cached bytes cannot be decoded.
pub async fn refresh_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<IndexSlice> {
    fetch_slice(config, target, rustc_version, true).await
}

/// Every cached slice under `cache_dir/index/`, for `stow index status`.
///
/// # Errors
///
/// Returns an error when the index directory cannot be traversed.
pub async fn cached_slices(
    config: &StowConfig,
) -> stow_types::error::Result<Vec<CachedSliceStatus>> {
    let root = config.cache_dir.join("index");
    let mut slices = Vec::new();
    let Ok(mut targets) = async_fs::read_dir(&root).await else {
        return Ok(slices);
    };
    while let Some(target_entry) = targets
        .next()
        .await
        .transpose()
        .wrap_err_with(|| format!("traverse index cache {}", root.display()))?
    {
        if !target_entry
            .file_type()
            .await
            .is_ok_and(|kind| kind.is_dir())
        {
            continue;
        }
        let target = target_entry.file_name().to_string_lossy().into_owned();
        let mut versions = async_fs::read_dir(target_entry.path())
            .await
            .wrap_err_with(|| format!("read index dir {}", target_entry.path().display()))?;
        while let Some(version_entry) = versions
            .next()
            .await
            .transpose()
            .wrap_err_with(|| format!("traverse index dir {}", target_entry.path().display()))?
        {
            let dir = version_entry.path();
            let Some(pointer) = read_pointer(&dir).await else {
                continue;
            };
            slices.push(CachedSliceStatus {
                target: target.clone(),
                rustc_version: version_entry.file_name().to_string_lossy().into_owned(),
                manifest_digest: pointer.manifest_digest,
                fetched_at: pointer.fetched_at,
                row_count: pointer.row_count,
            });
        }
    }
    slices.sort_by(|a, b| {
        a.target
            .cmp(&b.target)
            .then_with(|| a.rustc_version.cmp(&b.rustc_version))
    });
    Ok(slices)
}

async fn fetch_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    force: bool,
) -> stow_types::error::Result<IndexSlice> {
    let dir = slice_dir(config, target, rustc_version);
    let pointer = read_pointer(&dir).await;
    if !force
        && let Some(pointer) = &pointer
        && pointer_is_fresh(pointer, config.index_refresh_interval)
        && let Some(slice) = load_cached(&dir, pointer).await?
    {
        return Ok(slice);
    }
    // A cached blob of another index format is exactly a stale slice: a
    // format bump republishes every slice, so the tag's manifest digest
    // has moved and the revalidation below picks the new one.

    let tag = index_tag(target, rustc_version);
    let base = stow_oci::RegistryBase::parse(&config.registry_base_url)?;
    let http = config.registry_http().await?;
    let repository = cache_repository(
        &WireRustcVersion::parse(rustc_version)
            .map_err(|error| stow_types::stow_error!("rustc version {rustc_version}: {error}"))?,
    );
    let session = base.session(&repository, &http);
    let reference = session.reference(&tag)?;

    // With a cached pointer the freshness check is one `HEAD`; without one
    // there is nothing to compare, so the manifest pull itself answers the
    // digest — the `HEAD` would be a wasted round trip before every cold
    // fetch (stow#347).
    if let Some(pointer) = &pointer {
        match session.fetch_manifest_digest(&reference).await {
            Ok(remote_digest) => {
                if pointer.manifest_digest == remote_digest {
                    let pointer = SlicePointer {
                        row_count: pointer.row_count,
                        manifest_digest: remote_digest,
                        fetched_at: now_secs(),
                    };
                    write_pointer(&dir, &pointer).await?;
                    if let Some(slice) = load_cached(&dir, &pointer).await? {
                        return Ok(slice);
                    }
                    // The tag still names the foreign-format manifest —
                    // it is the *published* slice that cannot be read:
                    // the pull below surfaces that `Format` error.
                }
            }
            Err(error) => {
                tracing::info!(
                    error = %error,
                    tag = %tag,
                    "index refresh failed; serving cached slice"
                );
                if let Some(slice) = load_cached(&dir, pointer).await? {
                    return Ok(slice);
                }
            }
        }
    }

    let (blob, manifest_digest, index) = download_verified_slice(
        config,
        &session,
        &repository,
        &reference,
        &tag,
        target,
        rustc_version,
    )
    .await?;
    store_slice(&dir, &manifest_digest, &blob).await?;
    let pointer = SlicePointer {
        row_count: index.rows.len() as u64,
        manifest_digest: manifest_digest.clone(),
        fetched_at: now_secs(),
    };
    write_pointer(&dir, &pointer).await?;
    Ok(IndexSlice {
        manifest_digest,
        index,
    })
}

/// Pull, verify, and decode the index artifact `tag` resolves to. Any
/// failure — manifest shape, blob digest, signature, slice identity —
/// aborts before a byte is cached.
///
/// The three network legs that do not depend on each other run
/// concurrently: the trust root (its own TUF repository download on a
/// cold sigstore cache) starts before the manifest pull, and the blob and
/// the signature materials fetch together once the manifest names them
/// (stow#347).
async fn download_verified_slice(
    config: &StowConfig,
    session: &stow_oci::RegistrySession,
    repository: &CacheRepository,
    reference: &oci_client::Reference,
    tag: &str,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<(Vec<u8>, String, ArtifactIndex)> {
    let trust = verify::spawn_trust(config);
    let (manifest_digest, manifest) = stow_oci::pull_tagged_manifest(session, reference).await?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "index manifest {reference} carries {} layers, expected exactly one",
            manifest.layers.len()
        ));
    };
    if layer.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "index manifest {reference} layer is {}, expected {STOW_INDEX_MEDIA_TYPE}",
            layer.media_type
        ));
    }
    let (blob, materials) = tokio::try_join!(
        stow_oci::pull_blob_verified(session, layer),
        stow_oci::pull_signature_materials(session, reference, &manifest_digest),
    )?;
    // The signer binds the canonical GHCR reference, not whichever
    // transport base the pull came through.
    let identity_reference = repository.reference(tag);
    let trust = trust
        .await
        .map_err(|error| stow_types::stow_error!("join sigstore trust task: {error}"))??;
    verify::verify_index_signature_with_trust(
        trust,
        &identity_reference,
        &manifest_digest,
        &materials,
    )
    .await?;
    // A slice decodes every row the index publishes for the target, so
    // the decode runs on a blocking thread (stow#624).
    let (index, blob) = smol::unblock(move || {
        ArtifactIndex::decode(&blob)
            .wrap_err("decode index slice")
            .map(|index| (index, blob))
    })
    .await?;
    if index.header.target.as_str() != target
        || index.header.rustc_version.as_str() != rustc_version
    {
        return Err(stow_types::stow_error!(
            "index slice {tag} was published for {}@{}",
            index.header.target.as_str(),
            index.header.rustc_version.as_str()
        ));
    }
    Ok((blob, manifest_digest, index))
}

/// Atomically swap the verified blob into `dir`: temp-write, rename over
/// the digest-named slot, then drop every other blob so one slice dir never
/// holds two generations.
async fn store_slice(
    dir: &Path,
    manifest_digest: &str,
    blob: &[u8],
) -> stow_types::error::Result<()> {
    async_fs::create_dir_all(dir)
        .await
        .wrap_err_with(|| format!("create index dir {}", dir.display()))?;
    let keep = blob_name(manifest_digest);
    let tmp = dir.join(format!(".tmp-{}", std::process::id()));
    async_fs::write(&tmp, blob)
        .await
        .wrap_err_with(|| format!("write index blob {}", tmp.display()))?;
    async_fs::rename(&tmp, dir.join(&keep))
        .await
        .wrap_err_with(|| format!("commit index blob into {}", dir.display()))?;
    let mut entries = async_fs::read_dir(dir)
        .await
        .wrap_err_with(|| format!("read index dir {}", dir.display()))?;
    while let Some(entry) = entries
        .next()
        .await
        .transpose()
        .wrap_err_with(|| format!("traverse index dir {}", dir.display()))?
    {
        let name = entry.file_name();
        if name != POINTER_FILE && name != keep.as_str() {
            async_fs::remove_file(entry.path())
                .await
                .wrap_err_with(|| format!("evict stale index blob {}", entry.path().display()))?;
        }
    }
    Ok(())
}

async fn write_pointer(dir: &Path, pointer: &SlicePointer) -> stow_types::error::Result<()> {
    async_fs::create_dir_all(dir)
        .await
        .wrap_err_with(|| format!("create index dir {}", dir.display()))?;
    let tmp = dir.join(format!(".{POINTER_FILE}.tmp-{}", std::process::id()));
    async_fs::write(&tmp, serde_json::to_vec(pointer)?)
        .await
        .wrap_err_with(|| format!("write index pointer {}", tmp.display()))?;
    async_fs::rename(&tmp, dir.join(POINTER_FILE))
        .await
        .wrap_err_with(|| format!("commit index pointer in {}", dir.display()))?;
    Ok(())
}

async fn read_pointer(dir: &Path) -> Option<SlicePointer> {
    let bytes = async_fs::read(dir.join(POINTER_FILE)).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Decode the cached blob `pointer` selects. `None` when the blob carries
/// a foreign `format_version` — not corruption, a publish format this
/// build does not read; the caller re-pulls (or, on the read-only path,
/// counts the slice as absent). Any other decode failure is corrupt
/// cache and is surfaced.
async fn load_cached(
    dir: &Path,
    pointer: &SlicePointer,
) -> stow_types::error::Result<Option<IndexSlice>> {
    let path = dir.join(blob_name(&pointer.manifest_digest));
    let bytes = async_fs::read(&path)
        .await
        .wrap_err_with(|| format!("read cached index {}", path.display()))?;
    let index = match smol::unblock(move || ArtifactIndex::decode(&bytes)).await {
        Ok(index) => index,
        Err(stow_types::index::IndexDecodeError::Format { .. }) => return Ok(None),
        Err(error) => return Err(error).wrap_err("decode cached index slice"),
    };
    Ok(Some(IndexSlice {
        manifest_digest: pointer.manifest_digest.clone(),
        index,
    }))
}

/// `sha256:<hex>` → `sha256_<hex>` — the on-disk blob name for a manifest
/// digest (a `:` cannot appear in a file name on every platform).
fn blob_name(manifest_digest: &str) -> String {
    manifest_digest.replace(':', "_")
}

fn slice_dir(config: &StowConfig, target: &str, rustc_version: &str) -> PathBuf {
    config
        .cache_dir
        .join("index")
        .join(target)
        .join(rustc_version)
}

/// The one freshness rule for a cached slice pointer: inside
/// `index_refresh_interval` it serves as-is (an interval of 0
/// revalidates every call); absent or past it, `fetch_slice` will
/// consult the registry. Readers that must know whether the in-build
/// fetch can still change their answer share this rule (stow#788).
fn pointer_is_fresh(pointer: &SlicePointer, interval: std::time::Duration) -> bool {
    now_secs().saturating_sub(pointer.fetched_at) < interval.as_secs()
}

/// Whether the next `fetch_slice` for this `(target, rustc)` will
/// consult the registry — no usable pointer, or one that aged out.
/// `cached_slice`'s "absent" is not the same question: a readable stale
/// slice still exists, but the fetch it precedes can change every
/// answer derived from it.
pub async fn slice_fetch_pending(config: &StowConfig, target: &str, rustc_version: &str) -> bool {
    read_pointer(&slice_dir(config, target, rustc_version))
        .await
        .is_none_or(|pointer| !pointer_is_fresh(&pointer, config.index_refresh_interval))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Write `index` as the cached slice for `(target, rustc_version)` in the
/// same shape `fetch_slice` leaves it — blob plus `current.json` pointer —
/// so a test lands a slice without a registry (stow#735). Returns the
/// manifest digest the pointer names.
#[cfg(test)]
pub async fn write_cached_test_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    index: &ArtifactIndex,
) -> stow_types::error::Result<String> {
    let dir = slice_dir(config, target, rustc_version);
    let blob = stow_types::index::encode(index)
        .map_err(|error| stow_types::stow_error!("encode test index slice: {error}"))?;
    let digest = "sha256:test-slice-manifest".to_owned();
    store_slice(&dir, &digest, &blob).await?;
    write_pointer(
        &dir,
        &SlicePointer {
            manifest_digest: digest.clone(),
            fetched_at: now_secs(),
            row_count: index.rows.len() as u64,
        },
    )
    .await?;
    Ok(digest)
}

/// A syntactically valid index row keyed by `c_metadata` — the
/// slice-memo tests need a row whose key a lookup can name (stow#797).
#[cfg(test)]
pub fn index_test_row(c_metadata: &str) -> stow_types::index::ArtifactIndexRow {
    use semver::Version;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, DependencyIdentity,
        FeaturesJson,
    };
    use stow_types::index::ArtifactIndexRow;
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

    ArtifactIndexRow {
        dependency_identity: DependencyIdentity::leaf().expect("leaf identity"),
        crate_name: CrateName::parse("serde").expect("crate name"),
        version: CrateVersion::new(Version::new(1, 0, 219)),
        features_json: FeaturesJson::canonicalize(vec!["default".to_owned()]).expect("features"),
        dependency_c_metadata_json: DependencyCMetadataJson::default(),
        c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
        compile_key: format!("{c_metadata}{c_metadata}"),
        bundle_digest: format!("sha256:{c_metadata:0>64}"),
        bundle_size: 1234,
        artifact_kind: ArtifactKind::Rlib,
        crate_types: vec![RustCrateType::Rlib],
        profile: Profile {
            opt_level: "3".to_owned(),
            debuginfo: 0,
            debug_assertions: false,
            overflow_checks: false,
            panic: PanicStrategy::Unwind,
            strip: StripLevel::None,
        },
        emit: vec!["link".to_owned(), "metadata".to_owned()],
        min_glibc: None,
        unit_shape: UnitShape {
            side: UnitSide::Target,
            invocation: UnitInvocation::Native,
            kind: UnitKind::Linked,
        },
    }
}

#[cfg(test)]
mod tests {
    use stow_types::identity::{TargetTriple, WireRustcVersion};
    use stow_types::index::{ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndexHeader, ArtifactIndexRow};

    use super::*;
    use crate::config::VerifyMode;

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.91.1";

    fn test_config(cache_dir: &Path) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: std::time::Duration::from_secs(15),
            negative_cache_ttl: std::time::Duration::from_mins(5),
            circuit_reset_after: std::time::Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: std::time::Duration::from_mins(10),
            verify_mode: VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        }
    }

    fn test_row(c_metadata: &str) -> ArtifactIndexRow {
        index_test_row(c_metadata)
    }

    fn test_index(rows: Vec<ArtifactIndexRow>) -> ArtifactIndex {
        ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse(TARGET).expect("target"),
                rustc_version: WireRustcVersion::parse(RUSTC).expect("rustc"),
                generated_at: "2026-09-24T12:00:00Z".to_owned(),
                generation: 1,
                row_count: rows.len() as u64,
            },
            rows,
        }
    }

    /// stow#624: a build's slice fetches — the early one and the full
    /// analysis's, which runs on the enrichment's own clone of the
    /// config — draw their sessions from one client, built once.
    #[tokio::test]
    async fn every_clone_of_a_config_shares_one_registry_client() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let enrichment = config.clone();
        let (early, full) = tokio::join!(config.registry_http(), enrichment.registry_http());
        assert!(
            early
                .expect("build the registry client")
                .same_client(&full.expect("share the registry client"))
        );
    }

    #[test]
    fn blob_name_sanitizes_digest_colon() {
        assert_eq!(blob_name("sha256:ab12"), "sha256_ab12");
    }

    #[tokio::test]
    async fn store_pointer_then_load_cached_round_trips() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let index = test_index(vec![test_row("aaaa"), test_row("bbbb")]);
        let blob = stow_types::index::encode(&index).expect("encode");
        let digest = "sha256:deadbeef".to_owned();

        store_slice(&dir, &digest, &blob).await.expect("store");
        write_pointer(
            &dir,
            &SlicePointer {
                manifest_digest: digest.clone(),
                fetched_at: 1234,
                row_count: 2,
            },
        )
        .await
        .expect("write pointer");

        let pointer = read_pointer(&dir).await.expect("pointer");
        assert_eq!(pointer.manifest_digest, digest);
        let loaded = load_cached(&dir, &pointer)
            .await
            .expect("load cached")
            .expect("readable format");
        assert_eq!(loaded.manifest_digest, digest);
        assert_eq!(loaded.index, index);
    }

    /// A cached blob of another index format decodes to no slice — the
    /// fetch path then treats it as stale and re-pulls through the
    /// ordinary refresh.
    #[tokio::test]
    async fn load_cached_returns_none_on_a_foreign_format() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let mut index = test_index(vec![test_row("aaaa")]);
        index.header.format_version += 1;
        let blob = stow_types::index::encode(&index).expect("encode");
        store_slice(&dir, "sha256:aaaa", &blob)
            .await
            .expect("store");
        write_pointer(
            &dir,
            &SlicePointer {
                manifest_digest: "sha256:aaaa".to_owned(),
                fetched_at: 1,
                row_count: 1,
            },
        )
        .await
        .expect("pointer");

        let pointer = read_pointer(&dir).await.expect("pointer");
        assert!(
            load_cached(&dir, &pointer)
                .await
                .expect("load cached")
                .is_none(),
            "a foreign format reads as an absent slice, not an error"
        );
    }

    #[tokio::test]
    async fn store_slice_evicts_stale_blobs_and_pointer_stays() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let blob = stow_types::index::encode(&test_index(vec![test_row("aaaa")])).expect("encode");

        store_slice(&dir, "sha256:aaaa", &blob)
            .await
            .expect("first store");
        write_pointer(
            &dir,
            &SlicePointer {
                manifest_digest: "sha256:aaaa".to_owned(),
                fetched_at: 1,
                row_count: 1,
            },
        )
        .await
        .expect("pointer");
        store_slice(&dir, "sha256:bbbb", &blob)
            .await
            .expect("second store");

        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["current.json", "sha256_bbbb"]);
    }

    #[tokio::test]
    async fn cached_slices_reports_pointer_fields() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let index = test_index(vec![test_row("aaaa")]);
        let blob = stow_types::index::encode(&index).expect("encode");
        store_slice(&dir, "sha256:aaaa", &blob)
            .await
            .expect("store");
        write_pointer(
            &dir,
            &SlicePointer {
                manifest_digest: "sha256:aaaa".to_owned(),
                fetched_at: 4242,
                row_count: 1,
            },
        )
        .await
        .expect("pointer");

        let slices = cached_slices(&config).await.expect("cached slices");
        assert_eq!(slices.len(), 1);
        let slice = &slices[0];
        assert_eq!(slice.target, TARGET);
        assert_eq!(slice.rustc_version, RUSTC);
        assert_eq!(slice.manifest_digest, "sha256:aaaa");
        assert_eq!(slice.fetched_at, 4242);
        assert_eq!(slice.row_count, 1);
    }

    #[tokio::test]
    async fn cached_slices_empty_without_cache() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        assert!(
            cached_slices(&config)
                .await
                .expect("cached slices")
                .is_empty()
        );
    }

    /// stow#788: "will the enrichment fetch" is `fetch_slice`'s own
    /// freshness rule — an absent pointer, one older than the refresh
    /// interval, and a zero interval all mean the next fetch consults
    /// the registry; a pointer inside the interval is final.
    #[tokio::test]
    async fn slice_fetch_pending_is_the_fetchs_freshness_rule() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        assert!(
            slice_fetch_pending(&config, TARGET, RUSTC).await,
            "no pointer: the fetch runs"
        );

        let dir = slice_dir(&config, TARGET, RUSTC);
        std::fs::create_dir_all(&dir).expect("create slice dir");
        let pointer = SlicePointer {
            manifest_digest: "sha256:aaaa".to_owned(),
            fetched_at: now_secs(),
            row_count: 1,
        };
        write_pointer(&dir, &pointer).await.expect("write pointer");
        assert!(
            !slice_fetch_pending(&config, TARGET, RUSTC).await,
            "a pointer inside the interval serves as-is"
        );

        write_pointer(
            &dir,
            &SlicePointer {
                fetched_at: 0,
                ..pointer
            },
        )
        .await
        .expect("write stale pointer");
        assert!(
            slice_fetch_pending(&config, TARGET, RUSTC).await,
            "a pointer older than the interval revalidates"
        );

        let mut eager = test_config(tempdir.path());
        eager.index_refresh_interval = std::time::Duration::ZERO;
        assert!(
            slice_fetch_pending(&eager, TARGET, RUSTC).await,
            "a zero interval revalidates every call"
        );
    }
}
