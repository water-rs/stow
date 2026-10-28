//! The locally cached, signature-verified artifact index (stow#194).
//!
//! Each `(target, rustc_version)` slice is published to the OCI registry as
//! `index.<target>.<rustc>` by `.github/workflows/index-publish.yml`. The
//! wrapper pulls the slice's manifest and single zstd layer, verifies the
//! cosign signature against the index-publish workflow identity, and caches
//! the verified blob under `cache_dir/index/<target>/<rustc_version>/`: the
//! blob named by manifest digest plus a `current.json` pointer carrying
//! `{manifest_digest, fetched_at, row_count}`. A `slice.lock` beside them
//! orders every process's reads and commits of the slice.
//!
//! Refresh policy: a pointer younger than `index_refresh_interval`
//! short-circuits the network entirely; past it, one manifest request
//! re-validates the digest and only a moved digest costs a download and
//! re-verification. Network failure with a cached slice logs at `info` and
//! serves it — except on the build prefetch's path, which takes only the
//! registry's answer; no cached slice and no reachable registry is a hard
//! error naming the tag — resolution then proceeds only from signed bytes.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use futures_lite::StreamExt as _;
use serde::{Deserialize, Serialize};
use stow_types::error::Context;
use stow_types::identity::{TargetTriple, WireRustcVersion};
use stow_types::index::{ArtifactIndex, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::registry::{CacheRepository, cache_repository};

use crate::config::StowConfig;
use crate::file_lock::FileLock;
use crate::verify;

/// The pointer file inside each slice directory.
const POINTER_FILE: &str = "current.json";

/// The lock file inside each slice directory (see [`LockedSlice`]).
const LOCK_FILE: &str = "slice.lock";

/// The cached-slice pointer: which verified blob `current` selects, when
/// the registry last confirmed it, and the row count it decoded to so
/// `stow index status` never pays a decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlicePointer {
    manifest_digest: String,
    fetched_at: u64,
    row_count: u64,
}

/// Why a slice fetch produced nothing usable, with the one class the
/// build's circuit trips on: `transport` marks a request the registry
/// never answered — connect, TLS or body-read failure — as opposed to a
/// refusal it sent (stow#977).
#[derive(Debug)]
pub struct SliceFetchError {
    error: stow_types::error::Error,
    transport: bool,
}

impl SliceFetchError {
    /// Whether the fetch failed in transport — the registry answered
    /// nothing, so the outage is reachability rather than a verdict.
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        self.transport
    }

    /// A `RegistryError` with its context kept, the transport class
    /// carried over from the session's own classification.
    fn registry(context: impl std::fmt::Display, error: &stow_oci::RegistryError) -> Self {
        Self {
            transport: error.is_transport(),
            error: stow_types::stow_error!("{context}: {error}"),
        }
    }
}

impl std::fmt::Display for SliceFetchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SliceFetchError {}

/// A slice-fetch failure that is not a registry answer — local I/O,
/// verification, decode. None of them is a transport outage.
impl From<stow_types::error::Error> for SliceFetchError {
    fn from(error: stow_types::error::Error) -> Self {
        Self {
            error,
            transport: false,
        }
    }
}

/// A verified index slice: the decoded rows plus the manifest digest that
/// carried them, so callers can report what they resolved against.
#[derive(Debug, Clone)]
pub struct IndexSlice {
    /// `sha256:…` of the OCI manifest the blob came from — `None` when the
    /// slice is the empty index of a package that does not exist yet,
    /// which has no manifest to name.
    pub manifest_digest: Option<String>,
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
/// Returns an error when no usable slice can be produced — a
/// [`SliceFetchError`] whose `is_transport` marks the registry having
/// answered nothing (stow#977).
pub async fn ensure_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> Result<IndexSlice, SliceFetchError> {
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
    let slice = fetch_slice(config, target, rustc_version, Revalidation::PastInterval).await?;
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
/// Returns an error when the slice cannot be locked or the cached bytes
/// cannot be read or decoded — corruption is surfaced, absence and
/// foreign formats are not errors.
pub async fn cached_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<IndexSlice>> {
    load_cached(&slice_dir(config, target, rustc_version)).await
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
) -> Result<IndexSlice, SliceFetchError> {
    fetch_slice(config, target, rustc_version, Revalidation::Always).await
}

/// The build prefetch's slice: the registry's current answer and nothing
/// older. A cached slice may predate the publish the scheduler's
/// dependency gate counted, so serving it when the registry cannot be
/// reached would stage nothing for a dependency the gate promised and
/// compile it instead (stow#817).
///
/// # Errors
///
/// Returns an error when the registry is unreachable, when the fetched
/// artifact fails signature or digest verification, or when the cached
/// bytes cannot be decoded.
pub async fn confirmed_slice(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> Result<IndexSlice, SliceFetchError> {
    fetch_slice(config, target, rustc_version, Revalidation::Required).await
}

/// How much of the cached slice [`fetch_slice`] may serve without the
/// registry confirming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Revalidation {
    /// A pointer inside `index_refresh_interval` serves as-is; past it the
    /// registry is asked, and the cached slice serves when it cannot
    /// answer.
    PastInterval,
    /// The registry is always asked, and the cached slice serves when it
    /// cannot answer.
    Always,
    /// The registry is always asked, and only its answer serves.
    Required,
}

/// Every cached slice under `cache_dir/index/`, for `stow index status`.
///
/// # Errors
///
/// Returns an error when the index directory cannot be traversed or a
/// slice cannot be locked.
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
            if !version_entry
                .file_type()
                .await
                .is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            let Some(pointer) = read_pointer(&version_entry.path()).await? else {
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
    revalidation: Revalidation,
) -> Result<IndexSlice, SliceFetchError> {
    let dir = slice_dir(config, target, rustc_version);
    let pointer = read_pointer(&dir).await?;
    // A commit landing between the pointer read and the load serves its
    // newer generation, which is at least as fresh.
    if revalidation == Revalidation::PastInterval
        && let Some(pointer) = &pointer
        && pointer_is_fresh(pointer, config.index_refresh_interval)
        && let Some(slice) = load_cached(&dir).await?
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
    if pointer.is_some() {
        match session.fetch_manifest_digest(&reference).await {
            // The package itself is absent — the registry's definitive
            // answer is an empty index; even a cached slice names
            // artifacts a package reset took away.
            Err(error) if error.is_package_missing() => {
                return empty_slice(target, rustc_version).map_err(Into::into);
            }
            Ok(remote_digest) => {
                if let Some((pointer, blob)) =
                    write_slice(&dir, move |slice| slice.confirm(&remote_digest)).await?
                    && let Some(slice) = decode_cached(pointer.manifest_digest, blob).await?
                {
                    return Ok(slice);
                }
                // The registry moved, or a sibling committed another
                // generation since the pointer above was read, and the
                // pull below fetches the registry's; or the tag still
                // names the foreign-format manifest — it is the
                // *published* slice that cannot be read, and the pull
                // surfaces that `Format` error.
            }
            Err(error) if revalidation == Revalidation::Required => {
                return Err(SliceFetchError::registry(
                    format!("revalidate index slice {tag}"),
                    &error,
                ));
            }
            Err(error) => {
                tracing::info!(
                    error = %error,
                    tag = %tag,
                    "index refresh failed; serving cached slice"
                );
                if let Some(slice) = load_cached(&dir).await? {
                    return Ok(slice);
                }
            }
        }
    }

    let Some((blob, manifest_digest, index)) = download_verified_slice(
        config,
        &session,
        &repository,
        &reference,
        &tag,
        target,
        rustc_version,
    )
    .await?
    else {
        return empty_slice(target, rustc_version).map_err(Into::into);
    };
    commit_slice(&dir, &manifest_digest, blob, index.rows.len() as u64).await?;
    Ok(IndexSlice {
        manifest_digest: Some(manifest_digest),
        index,
    })
}

/// The slice a missing `stow-cache-<rustc>` package resolves to: no
/// published manifest, zero rows — every lookup misses, which is exactly
/// what a rustc nothing has published for means. `stow-cache-<rustc>`
/// deleted and rebuilt reads the same until the first publish lands.
fn empty_slice(target: &str, rustc_version: &str) -> stow_types::error::Result<IndexSlice> {
    Ok(IndexSlice {
        manifest_digest: None,
        index: ArtifactIndex {
            header: stow_types::index::ArtifactIndexHeader {
                format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse(target)
                    .map_err(|error| stow_types::stow_error!("index target {target}: {error}"))?,
                rustc_version: WireRustcVersion::parse(rustc_version).map_err(|error| {
                    stow_types::stow_error!("rustc version {rustc_version}: {error}")
                })?,
                generated_at: String::new(),
                generation: 0,
                row_count: 0,
            },
            rows: Vec::new(),
        },
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
) -> Result<Option<(Vec<u8>, String, ArtifactIndex)>, SliceFetchError> {
    let trust = verify::spawn_trust(config);
    // A package that does not exist is the registry's answer of "empty
    // index", not a pull failure — the same `None` every other index
    // reader gives; a missing tag on an existing package stays an error.
    let (bytes, manifest_digest) = match session.pull_manifest(reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_package_missing() => return Ok(None),
        Err(error) => {
            return Err(SliceFetchError::registry(
                format!("pull manifest {reference}"),
                &error,
            ));
        }
    };
    let manifest: oci_client::manifest::OciImageManifest = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("parse manifest for {reference}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "index manifest {reference} carries {} layers, expected exactly one",
            manifest.layers.len()
        )
        .into());
    };
    if layer.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "index manifest {reference} layer is {}, expected {STOW_INDEX_MEDIA_TYPE}",
            layer.media_type
        )
        .into());
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
        )
        .into());
    }
    Ok(Some((blob, manifest_digest, index)))
}

/// What a refresh writes once its download verified, under the slice's
/// exclusive lock: the blob, the pointer naming it, then the eviction of
/// every other file.
async fn commit_slice(
    dir: &Path,
    manifest_digest: &str,
    blob: Vec<u8>,
    row_count: u64,
) -> stow_types::error::Result<()> {
    let manifest_digest = manifest_digest.to_owned();
    write_slice(dir, move |slice| {
        slice.commit(&manifest_digest, &blob, row_count)
    })
    .await
}

/// The pointer `dir` holds, read under the slice's shared lock; `None`
/// when nothing is cached there.
async fn read_pointer(dir: &Path) -> stow_types::error::Result<Option<SlicePointer>> {
    Ok(read_slice(dir, |slice| Ok(slice.pointer()))
        .await?
        .flatten())
}

/// The cached slice `dir` holds: the pointer and the blob it names, read
/// together under the slice's shared lock so no commit lands between
/// them, then decoded off the lock.
async fn load_cached(dir: &Path) -> stow_types::error::Result<Option<IndexSlice>> {
    let Some(Some((pointer, blob))) = read_slice(dir, LockedSlice::load).await? else {
        return Ok(None);
    };
    decode_cached(pointer.manifest_digest, blob).await
}

/// Decode a cached blob. `None` when it carries a foreign
/// `format_version`, a publish format this build does not read: not
/// corruption — the caller re-pulls (or, on the read-only path, counts
/// the slice as absent). Any other decode failure is corrupt cache and is
/// surfaced.
async fn decode_cached(
    manifest_digest: String,
    blob: Vec<u8>,
) -> stow_types::error::Result<Option<IndexSlice>> {
    match smol::unblock(move || ArtifactIndex::decode(&blob)).await {
        Ok(index) => Ok(Some(IndexSlice {
            manifest_digest: Some(manifest_digest),
            index,
        })),
        Err(stow_types::index::IndexDecodeError::Format { .. }) => Ok(None),
        Err(error) => Err(error).wrap_err("decode cached index slice"),
    }
}

/// Run `read` on a blocking thread under the slice's shared lock. `None`
/// when the slice directory does not exist: nothing was ever cached
/// there, and a read never creates it.
async fn read_slice<T, F>(dir: &Path, read: F) -> stow_types::error::Result<Option<T>>
where
    T: Send + 'static,
    F: FnOnce(&LockedSlice<Shared>) -> stow_types::error::Result<T> + Send + 'static,
{
    let dir = dir.to_path_buf();
    smol::unblock(move || {
        LockedSlice::shared(&dir)?
            .map(|slice| read(&slice))
            .transpose()
    })
    .await
}

/// Run `write` on a blocking thread under the slice's exclusive lock,
/// creating the slice directory.
async fn write_slice<T, F>(dir: &Path, write: F) -> stow_types::error::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&LockedSlice<Exclusive>) -> stow_types::error::Result<T> + Send + 'static,
{
    let dir = dir.to_path_buf();
    smol::unblock(move || write(&LockedSlice::exclusive(&dir)?)).await
}

/// A slice directory held under its lock file: [`Shared`] while a reader
/// reads the pointer and the blob it names, [`Exclusive`] while a commit
/// replaces them and evicts the previous generation. Every access to a
/// slice's files goes through one, and only on a blocking thread whose
/// closure owns the lock, so the lock is released after the last file
/// handle closes even when the awaiting future is dropped. The release is
/// an explicit unlock ([`FileLock`]), never the lock file's close, which a
/// child spawned meanwhile would delay (stow#1003).
///
/// Refreshes of one slice share its directory — two `stow` processes on
/// one `cache_dir`, every local CI build of one target — and run at once
/// exactly when a new generation lands (stow#817). Without the lock that
/// is only POSIX-correct: on Windows a rename over a file another handle
/// holds open fails with `ERROR_ACCESS_DENIED`, and so does a rename over
/// or a delete of a name an earlier delete left pending because a reader
/// still had it open. Under it, a commit never meets another handle on
/// the files it replaces or deletes, so every delete completes before it
/// returns and no name is ever left pending.
struct LockedSlice<Mode> {
    dir: PathBuf,
    _lock: FileLock,
    _mode: PhantomData<Mode>,
}

/// The lock mode readers share.
enum Shared {}

/// The lock mode a commit holds, excluding every reader and every other
/// commit.
enum Exclusive {}

impl<Mode> LockedSlice<Mode> {
    fn open_lock(dir: &Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE))
    }

    fn pointer(&self) -> Option<SlicePointer> {
        let bytes = std::fs::read(self.dir.join(POINTER_FILE)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The pointer and the blob it names. `None` when there is no
    /// pointer, or when its blob is gone — a cache an unlocked refresh
    /// left behind, whose eviction could remove the blob another
    /// refresh's pointer named (stow#817) — so the fetch pulls over it.
    fn load(&self) -> stow_types::error::Result<Option<(SlicePointer, Vec<u8>)>> {
        let Some(pointer) = self.pointer() else {
            return Ok(None);
        };
        let path = self.dir.join(blob_name(&pointer.manifest_digest));
        match std::fs::read(&path) {
            Ok(blob) => Ok(Some((pointer, blob))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).wrap_err_with(|| format!("read cached index {}", path.display()))
            }
        }
    }
}

impl LockedSlice<Shared> {
    fn shared(dir: &Path) -> stow_types::error::Result<Option<Self>> {
        let lock = match Self::open_lock(dir) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("open index slice lock in {}", dir.display()));
            }
        };
        let lock = FileLock::shared(lock)
            .wrap_err_with(|| format!("lock index slice {} shared", dir.display()))?;
        Ok(Some(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            _mode: PhantomData,
        }))
    }
}

impl LockedSlice<Exclusive> {
    fn exclusive(dir: &Path) -> stow_types::error::Result<Self> {
        std::fs::create_dir_all(dir)
            .wrap_err_with(|| format!("create index dir {}", dir.display()))?;
        let lock = Self::open_lock(dir)
            .wrap_err_with(|| format!("open index slice lock in {}", dir.display()))?;
        let lock = FileLock::exclusive(lock)
            .wrap_err_with(|| format!("lock index slice {} exclusive", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            _mode: PhantomData,
        })
    }

    /// Swap a verified generation in: the blob under its digest-named
    /// slot, the pointer naming it, then every other file out, so one
    /// slice dir never holds two generations. Nothing else writes here
    /// while the lock is held, so any other file is a stale blob or a
    /// staging file a crashed write left. The pointer lands before the
    /// eviction: a write that dies in between leaves a stale blob for the
    /// next commit, never a pointer naming a deleted one.
    fn commit(
        &self,
        manifest_digest: &str,
        blob: &[u8],
        row_count: u64,
    ) -> stow_types::error::Result<()> {
        let keep = blob_name(manifest_digest);
        self.commit_file("blob", &keep, blob)?;
        self.write_pointer(&SlicePointer {
            manifest_digest: manifest_digest.to_owned(),
            fetched_at: now_secs(),
            row_count,
        })?;
        for entry in std::fs::read_dir(&self.dir)
            .wrap_err_with(|| format!("read index dir {}", self.dir.display()))?
        {
            let entry =
                entry.wrap_err_with(|| format!("traverse index dir {}", self.dir.display()))?;
            let name = entry.file_name();
            if name == POINTER_FILE || name == LOCK_FILE || name == keep.as_str() {
                continue;
            }
            std::fs::remove_file(entry.path())
                .wrap_err_with(|| format!("evict stale index file {}", entry.path().display()))?;
        }
        Ok(())
    }

    /// Re-stamp the pointer as confirmed when it still names
    /// `remote_digest`, returning it with its blob. `None` when it names
    /// another generation — a sibling committed one since the caller's
    /// read — or when nothing usable is cached.
    fn confirm(
        &self,
        remote_digest: &str,
    ) -> stow_types::error::Result<Option<(SlicePointer, Vec<u8>)>> {
        let Some((pointer, blob)) = self.load()? else {
            return Ok(None);
        };
        if pointer.manifest_digest != remote_digest {
            return Ok(None);
        }
        let pointer = SlicePointer {
            fetched_at: now_secs(),
            ..pointer
        };
        self.write_pointer(&pointer)?;
        Ok(Some((pointer, blob)))
    }

    fn write_pointer(&self, pointer: &SlicePointer) -> stow_types::error::Result<()> {
        self.commit_file(POINTER_FILE, POINTER_FILE, &serde_json::to_vec(pointer)?)
    }

    /// Write `bytes` as `name` atomically: staged under a `.<hint>.tmp-*`
    /// name, then renamed over `name`. A write that fails removes its
    /// staging file.
    fn commit_file(&self, hint: &str, name: &str, bytes: &[u8]) -> stow_types::error::Result<()> {
        let committed = self.dir.join(name);
        let mut staged = tempfile::Builder::new()
            .prefix(&format!(".{hint}.tmp-"))
            .tempfile_in(&self.dir)
            .wrap_err_with(|| format!("create index staging file in {}", self.dir.display()))?;
        staged
            .write_all(bytes)
            .wrap_err_with(|| format!("write index staging file {}", staged.path().display()))?;
        staged
            .persist(&committed)
            .map_err(|error| error.error)
            .wrap_err_with(|| format!("commit {}", committed.display()))?;
        Ok(())
    }
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
///
/// # Errors
///
/// Returns an error when the slice cannot be locked.
pub async fn slice_fetch_pending(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<bool> {
    Ok(read_pointer(&slice_dir(config, target, rustc_version))
        .await?
        .is_none_or(|pointer| !pointer_is_fresh(&pointer, config.index_refresh_interval)))
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
    commit_slice(&dir, &digest, blob, index.rows.len() as u64).await?;
    Ok(digest)
}

/// A syntactically valid index row keyed by `c_metadata` — the
/// slice-memo tests need a row whose key a lookup can name (stow#797).
#[cfg(test)]
pub fn index_test_row(c_metadata: &str) -> stow_types::index::ArtifactIndexRow {
    use semver::Version;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson,
    };
    use stow_types::index::ArtifactIndexRow;
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};
    use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};

    ArtifactIndexRow {
        dependency_task_ids: Vec::new(),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            experimental: crate::config::ExperimentalConfig::default(),
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

    /// Overwrite the pointer under the slice's exclusive lock, the only
    /// way the module writes one.
    async fn write_test_pointer(dir: &Path, pointer: SlicePointer) {
        write_slice(dir, move |slice| slice.write_pointer(&pointer))
            .await
            .expect("write pointer");
    }

    fn slice_dir_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
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
        names
    }

    #[tokio::test]
    async fn commit_then_load_cached_round_trips() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let index = test_index(vec![test_row("aaaa"), test_row("bbbb")]);
        let blob = stow_types::index::encode(&index).expect("encode");
        let digest = "sha256:deadbeef".to_owned();

        commit_slice(&dir, &digest, blob, 2).await.expect("commit");

        let pointer = read_pointer(&dir)
            .await
            .expect("read pointer")
            .expect("pointer");
        assert_eq!(pointer.manifest_digest, digest);
        assert_eq!(pointer.row_count, 2);
        let loaded = load_cached(&dir)
            .await
            .expect("load cached")
            .expect("readable format");
        assert_eq!(loaded.manifest_digest.as_deref(), Some(digest.as_str()));
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
        commit_slice(&dir, "sha256:aaaa", blob, 1)
            .await
            .expect("commit");

        assert!(
            load_cached(&dir).await.expect("load cached").is_none(),
            "a foreign format reads as an absent slice, not an error"
        );
    }

    /// A commit leaves its own generation and nothing else: the previous
    /// blob and a staging file a crashed write left are both evicted,
    /// since nothing else writes while the commit holds the lock.
    #[tokio::test]
    async fn a_commit_evicts_stale_blobs_and_leftover_staging_files() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let blob = stow_types::index::encode(&test_index(vec![test_row("aaaa")])).expect("encode");

        commit_slice(&dir, "sha256:aaaa", blob.clone(), 1)
            .await
            .expect("first commit");
        std::fs::write(dir.join(".blob.tmp-crashed"), b"partial").expect("leftover staging");
        commit_slice(&dir, "sha256:bbbb", blob, 1)
            .await
            .expect("second commit");

        assert_eq!(
            slice_dir_names(&dir),
            vec!["current.json", "sha256_bbbb", LOCK_FILE]
        );
        assert_eq!(
            read_pointer(&dir)
                .await
                .expect("read pointer")
                .expect("pointer")
                .manifest_digest,
            "sha256:bbbb"
        );
    }

    /// Readers share a slice's lock and a commit excludes them — the
    /// property that keeps a commit from ever renaming over or deleting a
    /// file another handle holds open, which Windows refuses (stow#817).
    /// A read of a slice never cached creates nothing.
    #[test]
    fn readers_share_a_slice_and_a_commit_excludes_them() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        assert!(
            LockedSlice::shared(&dir)
                .expect("lock an absent slice")
                .is_none()
        );
        assert!(!dir.exists(), "a read never creates the slice directory");

        let blob = stow_types::index::encode(&test_index(vec![test_row("aaaa")])).expect("encode");
        smol::block_on(commit_slice(&dir, "sha256:aaaa", blob, 1)).expect("commit");
        let probe = std::fs::File::open(dir.join(LOCK_FILE)).expect("open the lock file");

        let reader = LockedSlice::shared(&dir).expect("lock").expect("cached");
        let sibling = LockedSlice::shared(&dir).expect("lock").expect("cached");
        assert!(
            matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "a commit waits while a reader holds the slice"
        );
        drop((reader, sibling));

        let writer = LockedSlice::exclusive(&dir).expect("lock");
        assert!(
            matches!(
                probe.try_lock_shared(),
                Err(std::fs::TryLockError::WouldBlock)
            ),
            "a read waits while a commit holds the slice"
        );
        drop(writer);
        probe
            .try_lock()
            .expect("the slice is free once both release it");
    }

    #[tokio::test]
    async fn cached_slices_reports_pointer_fields() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let index = test_index(vec![test_row("aaaa")]);
        let blob = stow_types::index::encode(&index).expect("encode");
        commit_slice(&dir, "sha256:aaaa", blob, 1)
            .await
            .expect("commit");
        write_test_pointer(
            &dir,
            SlicePointer {
                manifest_digest: "sha256:aaaa".to_owned(),
                fetched_at: 4242,
                row_count: 1,
            },
        )
        .await;

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
        let pending = |config: &StowConfig| {
            let config = config.clone();
            async move {
                slice_fetch_pending(&config, TARGET, RUSTC)
                    .await
                    .expect("slice fetch pending")
            }
        };
        assert!(pending(&config).await, "no pointer: the fetch runs");

        let dir = slice_dir(&config, TARGET, RUSTC);
        let pointer = SlicePointer {
            manifest_digest: "sha256:aaaa".to_owned(),
            fetched_at: now_secs(),
            row_count: 1,
        };
        write_test_pointer(&dir, pointer.clone()).await;
        assert!(
            !pending(&config).await,
            "a pointer inside the interval serves as-is"
        );

        write_test_pointer(
            &dir,
            SlicePointer {
                fetched_at: 0,
                ..pointer
            },
        )
        .await;
        assert!(
            pending(&config).await,
            "a pointer older than the interval revalidates"
        );

        let mut eager = test_config(tempdir.path());
        eager.index_refresh_interval = std::time::Duration::ZERO;
        assert!(
            pending(&eager).await,
            "a zero interval revalidates every call"
        );
    }

    /// stow#817: with a cached slice and a registry that cannot confirm
    /// it, `stow index refresh` serves the cache, while the build prefetch
    /// fails naming the slice — a cached slice may predate the publish its
    /// task was dispatched on.
    #[tokio::test]
    async fn the_build_slice_never_falls_back_to_the_cache() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tempdir = tempfile::tempdir().expect("tempdir");
        // A registry that answers every request `404` — a refusal, which
        // the client does not retry, unlike a dropped connection.
        let registry = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = registry.local_addr().expect("local addr");
        std::thread::spawn(move || {
            for stream in registry.incoming() {
                let mut stream = stream.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.ends_with(b"\r\n\r\n") {
                    let read = std::io::Read::read(&mut stream, &mut buffer).expect("read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .expect("respond");
            }
        });
        let config = StowConfig {
            registry_base_url: format!("http://{address}"),
            ..test_config(tempdir.path())
        };
        let dir = slice_dir(&config, TARGET, RUSTC);
        let blob = stow_types::index::encode(&test_index(vec![test_row("aaaa")])).expect("encode");
        commit_slice(&dir, "sha256:aaaa", blob, 1)
            .await
            .expect("seed the cache");

        let refreshed = refresh_slice(&config, TARGET, RUSTC)
            .await
            .expect("refresh serves the cached slice");
        assert_eq!(refreshed.manifest_digest.as_deref(), Some("sha256:aaaa"));
        let error = confirmed_slice(&config, TARGET, RUSTC)
            .await
            .expect_err("the build path takes only the registry's answer");
        assert!(
            error.to_string().contains(&format!(
                "revalidate index slice {}",
                index_tag(TARGET, RUSTC)
            )),
            "names the slice: {error}"
        );
    }

    /// stow#844: a registry whose `stow-cache-<rustc>` package does not
    /// exist answers the anonymous token exchange `403 DENIED` — the
    /// slice it resolves to is the empty index, not an error, on every
    /// pull path.
    #[tokio::test]
    async fn a_missing_package_serves_the_empty_index() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tempdir = tempfile::tempdir().expect("tempdir");
        // A registry that answers the challenge then refuses the token
        // exchange the way GHCR does for a package that does not exist.
        let registry = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = registry.local_addr().expect("local addr");
        let realm = format!("http://{address}/token");
        std::thread::spawn(move || {
            for stream in registry.incoming() {
                let mut stream = stream.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.ends_with(b"\r\n\r\n") {
                    let read = std::io::Read::read(&mut stream, &mut buffer).expect("read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let path = request
                    .split(|byte| *byte == b' ')
                    .nth(1)
                    .unwrap_or_default()
                    .to_vec();
                let response = if path == b"/v2/" {
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{realm}\",service=\"mock\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    let body = r#"{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}"#;
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                stream.write_all(response.as_bytes()).expect("respond");
            }
        });
        let config = StowConfig {
            registry_base_url: format!("http://{address}"),
            ..test_config(tempdir.path())
        };

        let slice = refresh_slice(&config, TARGET, RUSTC)
            .await
            .expect("a missing package serves the empty index");
        assert_eq!(slice.index.rows.len(), 0);
        assert_eq!(slice.manifest_digest, None);
        let slice = confirmed_slice(&config, TARGET, RUSTC)
            .await
            .expect("the build path takes the registry's empty answer");
        assert_eq!(slice.index.rows.len(), 0);
    }

    fn generation_digest(generation: usize) -> String {
        format!("sha256:{generation:064x}")
    }

    fn generation_slice(generation: usize) -> (String, Vec<u8>) {
        let mut index = test_index(vec![test_row("aaaa")]);
        index.header.generation = i64::try_from(generation).expect("generation");
        let blob = stow_types::index::encode(&index).expect("encode");
        (generation_digest(generation), blob)
    }

    /// One refresher's turn at `generation`: commit it, then re-confirm
    /// it as an unchanged-digest revalidation does.
    fn refresh_to(dir: &Path, generation: usize) -> Vec<String> {
        let (digest, blob) = generation_slice(generation);
        let mut failures = Vec::new();
        if let Err(error) = smol::block_on(commit_slice(dir, &digest, blob, 1)) {
            failures.push(format!("refresh to generation {generation}: {error:#}"));
        }
        match smol::block_on(write_slice(dir, move |slice| slice.confirm(&digest))) {
            Ok(Some(_)) => {}
            Ok(None) => failures.push(format!(
                "confirm generation {generation}: the pointer moved"
            )),
            Err(error) => failures.push(format!("confirm generation {generation}: {error:#}")),
        }
        failures
    }

    /// One read while `generation` lands: the previous or the new
    /// generation, whole, under its own digest.
    fn read_during(config: &StowConfig, generation: usize) -> Option<String> {
        match smol::block_on(cached_slice(config, TARGET, RUSTC)) {
            Err(error) => Some(format!("read during generation {generation}: {error:#}")),
            Ok(None) => Some(format!(
                "read during generation {generation}: no slice cached"
            )),
            Ok(Some(slice)) => {
                let served = usize::try_from(slice.index.header.generation).expect("generation");
                (slice.manifest_digest.as_deref() != Some(generation_digest(served).as_str())
                    || !(generation - 1..=generation).contains(&served))
                .then(|| {
                    format!(
                        "read during generation {generation} served generation {served} under pointer {:?}",
                        slice.manifest_digest
                    )
                })
            }
        }
    }

    /// stow#817: refreshes that share one slice directory — two `stow`
    /// processes on one `cache_dir`, every local CI build of one target —
    /// all commit the same new generation at once when it lands, then
    /// re-confirm it as an unchanged-digest revalidation does, while
    /// readers keep reading. Every refresh succeeds, every read serves
    /// the previous or the new generation whole, and each generation
    /// leaves exactly its own blob.
    ///
    /// On Windows, without the slice lock, a commit renames over a blob
    /// or `current.json` a reader holds open and evicts a blob a reader
    /// holds open, leaving its name delete-pending for a sibling's
    /// eviction and a reader's open: each fails with
    /// `ERROR_ACCESS_DENIED`, and lands here as a refresh or read failure.
    #[test]
    fn concurrent_refreshes_across_generation_changes_all_succeed() {
        const REFRESHES: usize = 6;
        const READERS: usize = 2;
        const GENERATIONS: usize = 40;
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = test_config(tempdir.path());
        let dir = slice_dir(&config, TARGET, RUSTC);
        let (digest, blob) = generation_slice(0);
        smol::block_on(commit_slice(&dir, &digest, blob, 1)).expect("seed generation 0");

        // Each thread records its failures and keeps meeting the barrier:
        // a thread that panicked mid-generation would strand the rest.
        let barrier = std::sync::Barrier::new(REFRESHES + READERS);
        let committed = AtomicUsize::new(0);
        let failures = std::thread::scope(|scope| {
            let refreshes = (0..REFRESHES).map(|_| {
                scope.spawn(|| {
                    let mut failures = Vec::new();
                    for generation in 1..=GENERATIONS {
                        barrier.wait();
                        failures.extend(refresh_to(&dir, generation));
                        committed.fetch_add(1, Ordering::SeqCst);
                        barrier.wait();
                    }
                    failures
                })
            });
            // Readers read until every refresh of the generation has
            // committed, so reads land all over the window in which a
            // commit replaces the pointer and evicts the blob it named.
            let readers = (0..READERS).map(|_| {
                scope.spawn(|| {
                    let mut failures = Vec::new();
                    for generation in 1..=GENERATIONS {
                        barrier.wait();
                        loop {
                            let generation_committed =
                                committed.load(Ordering::SeqCst) >= REFRESHES * generation;
                            failures.extend(read_during(&config, generation));
                            if generation_committed {
                                break;
                            }
                        }
                        barrier.wait();
                    }
                    failures
                })
            });
            refreshes
                .collect::<Vec<_>>()
                .into_iter()
                .chain(readers.collect::<Vec<_>>())
                .flat_map(|thread| thread.join().expect("refresh thread"))
                .collect::<Vec<_>>()
        });
        assert!(
            failures.is_empty(),
            "{} failures across {} refreshes:\n{}",
            failures.len(),
            REFRESHES * GENERATIONS,
            failures.join("\n")
        );
        assert_eq!(
            slice_dir_names(&dir),
            vec![
                "current.json".to_owned(),
                blob_name(&generation_digest(GENERATIONS)),
                LOCK_FILE.to_owned(),
            ],
            "the last generation's blob and pointer, no stale blob or staging file"
        );
    }
}
