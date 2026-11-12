use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::UNIX_EPOCH;
use stow_types::bundle::ArtifactBundleFile;
use stow_types::error::Context;
use stow_types::public_cache::{StableUnitIdentity, stable_c_metadata_for_compile_key};

use crate::artifact_cache::CachedArtifactBundle;
use crate::rustc_args::ParsedRustcArgs;

const MATERIALIZED_MARKERS_DIR: &str = ".stow-materialized";
const MATERIALIZED_MARKER_VERSION: &str = "stow-materialized-v1";

/// Who else can write to the directory the outputs land in.
///
/// It decides whether a materialization marker may be believed. A marker
/// records that a previous inject already put these exact bytes at this
/// path, so the injector can skip re-hashing a large rlib; it proves that
/// only while nothing else writes there. On a user's machine nothing does
/// — the target directory is cargo's and stow's. Inside the build sandbox
/// third-party build scripts hold write access to the same directory, and
/// every field a marker is checked against — the output's length, its
/// mtime, and the hash the marker itself records — is something a build
/// script can write. Believing one there would let a planted file stand in
/// for a verified artifact, and the plan would then publish the plant's
/// hash as the genuine one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDirWriters {
    /// Cargo and stow only: a user's own target directory.
    StowOnly,
    /// Untrusted code writes here too. Markers are ignored and every
    /// existing output is hashed before it is left in place.
    UntrustedCodeToo,
}

impl OutputDirWriters {
    /// Whether a marker found beside an output may stand in for hashing it.
    const fn trusts_markers(self) -> bool {
        matches!(self, Self::StowOnly)
    }
}

pub async fn write_artifacts(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    host: &str,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let out_dir = parsed
        .out_dir
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("cached rustc invocation is missing --out-dir"))?;
    async_fs::create_dir_all(out_dir)
        .await
        .wrap_err_with(|| format!("create rustc out dir {}", out_dir.display()))?;

    let mut materialized_outputs = BTreeSet::new();
    for file in &bundle.outputs {
        let output_path = expected_output_path(parsed, out_dir, file, host)?;
        if materialized_outputs.insert(output_path.clone()) {
            write_artifact_file(&output_path, file, bundle, writers).await?;
        }
    }
    materialize_cached_bundle_stable_aliases(parsed, bundle, host, writers).await?;
    write_dep_info(parsed).await?;
    Ok(())
}

async fn write_artifact_file(
    output_path: &std::path::Path,
    file: &ArtifactBundleFile,
    bundle: &CachedArtifactBundle,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let source_path = bundle.output_source_path(file);
    if !source_path.exists() {
        return Err(stow_types::stow_error!(
            "cached artifact source {} does not exist",
            source_path.display()
        ));
    }
    write_cached_output(
        &source_path,
        output_path,
        Some(file.sha256.as_str()),
        is_build_script(file),
        writers,
    )
    .await
}

/// A build script is run by cargo, so its served file carries the
/// executable mode rustc would have given it: a bundle's pack records no
/// modes, and the cache entry it unpacked into holds a plain file.
fn is_build_script(file: &ArtifactBundleFile) -> bool {
    file.media_type == stow_types::bundle::STOW_BUILD_SCRIPT_MEDIA_TYPE
}

/// Give `file`, open at `path`, the executable mode a build script
/// needs ([`is_build_script`]) when `executable`; the mode goes on the
/// handle, never on the path a concurrent serve may be placing.
fn set_served_mode(
    file: &std::fs::File,
    path: &std::path::Path,
    executable: bool,
) -> stow_types::error::Result<()> {
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .wrap_err_with(|| format!("mark served build script {} executable", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (file, path, executable);
    Ok(())
}

pub async fn materialize_original_outputs(
    out_dir: &std::path::Path,
    bundle: &CachedArtifactBundle,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    for file in &bundle.outputs {
        let source_path = bundle.output_source_path(file);
        if !source_path.exists() {
            return Err(stow_types::stow_error!(
                "cached artifact source {} does not exist",
                source_path.display()
            ));
        }
        let original_path = original_output_path(out_dir, file)?;
        materialize_bundle_output_paths(
            &source_path,
            &original_path,
            None,
            file.sha256.as_str(),
            is_build_script(file),
            writers,
        )
        .await?;
    }
    Ok(())
}

pub async fn materialize_local_build_stable_aliases(
    parsed: &ParsedRustcArgs,
    identity: &StableUnitIdentity,
    host: &str,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let stable_parsed =
        parsed_with_stable_identity(parsed, &identity.c_metadata, &identity.extra_filename);

    materialize_optional_local_alias(
        parsed.output_rlib_path(),
        stable_parsed.output_rlib_path(),
        writers,
    )
    .await?;
    materialize_optional_local_alias(
        parsed.output_rmeta_path(),
        stable_parsed.output_rmeta_path(),
        writers,
    )
    .await?;
    materialize_optional_local_alias(
        parsed
            .output_linked_image_path(host)
            .map_err(stow_types::error::Error::msg)?,
        stable_parsed
            .output_linked_image_path(host)
            .map_err(stow_types::error::Error::msg)?,
        writers,
    )
    .await?;
    Ok(())
}

async fn materialize_cached_bundle_stable_aliases(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    host: &str,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let stable_c_metadata = stable_c_metadata_for_compile_key(&bundle.compile_key)?;
    let stable_parsed =
        parsed_with_stable_identity(parsed, &stable_c_metadata, &format!("-{stable_c_metadata}"));

    materialize_optional_local_alias(
        parsed.output_rlib_path(),
        stable_parsed.output_rlib_path(),
        writers,
    )
    .await?;
    materialize_optional_local_alias(
        parsed.output_rmeta_path(),
        stable_parsed.output_rmeta_path(),
        writers,
    )
    .await?;
    materialize_optional_local_alias(
        parsed
            .output_linked_image_path(host)
            .map_err(stow_types::error::Error::msg)?,
        stable_parsed
            .output_linked_image_path(host)
            .map_err(stow_types::error::Error::msg)?,
        writers,
    )
    .await?;
    Ok(())
}

pub fn parsed_with_stable_identity(
    parsed: &ParsedRustcArgs,
    c_metadata: &str,
    extra_filename: &str,
) -> ParsedRustcArgs {
    let mut stable = parsed.clone();
    stable.c_metadata = Some(c_metadata.to_owned());
    stable.extra_filename.clone_from(&extra_filename.to_owned());
    stable
}

async fn materialize_optional_local_alias(
    source_path: Option<std::path::PathBuf>,
    alias_path: Option<std::path::PathBuf>,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let (Some(source_path), Some(alias_path)) = (source_path, alias_path) else {
        return Ok(());
    };
    if source_path == alias_path {
        return Ok(());
    }
    if !source_path.exists() {
        return Ok(());
    }
    // The alias is a clone of this build's own output and keeps its mode.
    write_cached_output(&source_path, &alias_path, None, false, writers).await
}

pub fn expected_output_path(
    parsed: &ParsedRustcArgs,
    out_dir: &std::path::Path,
    file: &ArtifactBundleFile,
    host: &str,
) -> stow_types::error::Result<std::path::PathBuf> {
    let expected = if file.media_type == stow_types::bundle::STOW_RLIB_MEDIA_TYPE {
        parsed.output_rlib_path()
    } else if file.media_type == stow_types::bundle::STOW_RMETA_MEDIA_TYPE {
        parsed.output_rmeta_path()
    } else if file.media_type == stow_types::bundle::STOW_DYLIB_MEDIA_TYPE
        || file.media_type == stow_types::bundle::STOW_PROC_MACRO_MEDIA_TYPE
        || file.media_type == stow_types::bundle::STOW_BUILD_SCRIPT_MEDIA_TYPE
    {
        parsed
            .output_linked_image_path(host)
            .map_err(stow_types::error::Error::msg)?
    } else {
        return Err(stow_types::stow_error!(
            "unexpected cached artifact media type {}",
            file.media_type
        ));
    };

    let expected = expected.ok_or_else(|| {
        stow_types::stow_error!(
            "cached artifact media type {} does not match this rustc invocation",
            file.media_type
        )
    })?;
    if expected.parent() != Some(out_dir) {
        return Err(stow_types::stow_error!(
            "expected output path {} escaped rustc out dir {}",
            expected.display(),
            out_dir.display()
        ));
    }

    Ok(expected)
}

pub fn original_output_path(
    out_dir: &std::path::Path,
    file: &ArtifactBundleFile,
) -> stow_types::error::Result<std::path::PathBuf> {
    let file_name = std::path::Path::new(&file.file_name);
    if file_name.components().count() != 1 {
        return Err(stow_types::stow_error!(
            "cached artifact file name {} is not a single path component",
            file.file_name
        ));
    }
    Ok(out_dir.join(file_name))
}

pub async fn write_cached_output(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
    executable: bool,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create cached artifact parent {}", parent.display()))?;
    }

    let source_path = source_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    let expected_sha256 = expected_sha256.map(str::to_owned);
    let source_for_copy = source_path.clone();
    let output_for_copy = output_path.clone();
    let materialized = smol::unblock(move || {
        materialize_cached_file_blocking(
            &source_for_copy,
            &output_for_copy,
            expected_sha256.as_deref(),
            executable,
            writers,
        )
    })
    .await?;
    if materialized {
        tracing::debug!(
            source = %source_path.display(),
            output = %output_path.display(),
            "materialized cached artifact"
        );
    } else {
        tracing::debug!(
            output = %output_path.display(),
            "cached artifact already materialized in target"
        );
    }
    Ok(())
}

async fn materialize_bundle_output_paths(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    additional_output_path: Option<&std::path::Path>,
    expected_sha256: &str,
    executable: bool,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    write_cached_output(
        source_path,
        output_path,
        Some(expected_sha256),
        executable,
        writers,
    )
    .await?;
    if let Some(additional_output_path) = additional_output_path
        && additional_output_path != output_path
    {
        write_cached_output(
            source_path,
            additional_output_path,
            Some(expected_sha256),
            executable,
            writers,
        )
        .await?;
    }
    Ok(())
}

/// Write a dep-info file cargo parses into an empty dependency list.
///
/// The file must exist — cargo only translates dep-info into the unit's
/// fingerprint when `rustc_dep_info_loc.exists()`, and a missing fingerprint
/// dep-info is a `StaleItem::MissingFile` that forces a rebuild — but it must
/// name no path: every path it names lands in the fingerprint dep-info and is
/// compared against this unit's invocation time, which cargo took before the
/// wrapper wrote anything, so a named path is always newer and always dirties
/// the unit (stow#634). Registry sources need no entry — cargo's own
/// translation drops package-relative paths for registry packages — and the
/// build script's products are tracked through the build-script-run unit, not
/// this one. The file keeps the make-rule shape (`<stem>:` with no
/// prerequisites): `parse_rustc_dep_info` reads prerequisites only from the
/// first line containing `": "`, which a bare trailing colon never forms, so
/// the parsed list stays empty.
async fn write_dep_info(parsed: &ParsedRustcArgs) -> stow_types::error::Result<()> {
    let dep_info_path = parsed.output_dep_info_path().ok_or_else(|| {
        stow_types::stow_error!("cached rustc invocation is missing dep-info path")
    })?;
    let stem = dep_info_path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            stow_types::stow_error!("dep-info path {} is not UTF-8", dep_info_path.display())
        })?;
    let out_dir = dep_info_path.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "dep-info path {} has no parent directory",
            dep_info_path.display()
        )
    })?;
    async_fs::create_dir_all(out_dir)
        .await
        .wrap_err_with(|| format!("create dep-info dir {}", out_dir.display()))?;
    write_file_if_changed(&dep_info_path, format!("{stem}:\n").as_bytes()).await?;
    Ok(())
}

async fn write_file_if_changed(
    path: &std::path::Path,
    contents: &[u8],
) -> stow_types::error::Result<()> {
    match async_fs::read(path).await {
        Ok(existing) if existing == contents => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(
                stow_types::error::Error::from(error).wrap_err(format!("read {}", path.display()))
            );
        }
    }
    async_fs::write(path, contents)
        .await
        .wrap_err_with(|| format!("write {}", path.display()))
}

fn materialize_cached_file_blocking(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
    executable: bool,
    writers: OutputDirWriters,
) -> stow_types::error::Result<bool> {
    let source_len = std::fs::metadata(source_path)
        .wrap_err_with(|| format!("stat cached artifact source {}", source_path.display()))?
        .len();
    let served = serve_output(
        output_path,
        |found| {
            output_holds_cached_file(
                found,
                source_path,
                output_path,
                source_len,
                expected_sha256,
                writers,
            )
        },
        || {
            let staged = stage_clone(source_path, output_path).wrap_err_with(|| {
                format!(
                    "clone or copy cached artifact {} into {}",
                    source_path.display(),
                    output_path.display()
                )
            })?;
            // The stamp and the mode go on the staged file: a rename keeps
            // the file, its mtime and its mode, so the final path never
            // holds an unstamped output or a build script cargo cannot
            // run. The handle stays open so the marker reads the placed
            // file's metadata from it, not from a path.
            let (_, path) = staged.into_parts();
            let file = open_to_read_and_stamp(&path)
                .wrap_err_with(|| format!("open staged artifact {}", path.display()))?;
            set_served_mode(&file, &path, executable)?;
            stamp_materialized_mtime(&file, &path)?;
            Ok(tempfile::NamedTempFile::from_parts(file, path))
        },
    )
    .wrap_err_with(|| {
        format!(
            "materialize cached artifact {} at {}",
            source_path.display(),
            output_path.display()
        )
    })?;
    let (file, placed) = match served {
        Served::Kept(found) => {
            set_served_mode(&found, output_path, executable)?;
            stamp_materialized_mtime(&found, output_path)?;
            (found, false)
        }
        Served::Placed(staged) => (staged, true),
    };
    let output_metadata = file
        .metadata()
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    write_materialized_marker(output_path, &output_metadata, expected_sha256)?;
    Ok(placed)
}

/// Whether `found`, the file open at `output_path`, already holds the
/// cached file's bytes. Every check reads the open file, never the path
/// again, so what is judged is what is left in place.
fn output_holds_cached_file(
    found: &std::fs::File,
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    source_len: u64,
    expected_sha256: Option<&str>,
    writers: OutputDirWriters,
) -> stow_types::error::Result<bool> {
    let output_metadata = found
        .metadata()
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    if output_metadata.len() != source_len {
        return Ok(false);
    }
    // A marker is a claim about bytes someone else may have replaced, so
    // it is only evidence where nobody else writes. The bytes are hashed
    // otherwise, which is what makes ignoring the marker safe rather than
    // merely slower.
    if writers.trusts_markers()
        && materialized_marker_matches(output_path, &output_metadata, source_len, expected_sha256)?
    {
        return Ok(true);
    }
    let output_hash = sha256_open_file(found, output_path)?;
    if let Some(expected_sha256) = expected_sha256 {
        return Ok(output_hash == expected_sha256);
    }
    Ok(output_hash == sha256_file(source_path)?)
}

/// What [`serve_output`] left at its destination.
pub enum Served<F> {
    /// The destination already held the served bytes and was left in
    /// place; the handle is open on that file.
    Kept(std::fs::File),
    /// A staged file was placed at the destination; `F` is what staging
    /// produced alongside it.
    Placed(F),
}

/// Put the bytes `stage` produces at `destination`, one of several serves
/// that may be placing the same bytes there at once (stow#1444).
///
/// A destination that already holds them — `holds_served_bytes` judges
/// the open file — is never replaced: once any serve has placed the
/// bytes, the path keeps that file, and no reader, in stow or outside it,
/// can find the path absent or half-written. An absent destination is
/// filled by a no-replace rename of a whole staged file, so of the serves
/// that found it absent the first one's file is placed and the others
/// find it there. Only a destination holding other bytes is replaced by
/// a rename over it, which is the one step whose replace a concurrent
/// lookup can observe: on Windows `std::fs::rename` is `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING`, which does not keep the name resolvable
/// to an opener throughout. Every serve looks the destination up by name
/// at most twice and handles absence as absence, so no serve fails on
/// another's replace.
///
/// # Errors
/// The destination cannot be opened, judged, staged or placed.
pub fn serve_output<F>(
    destination: &std::path::Path,
    holds_served_bytes: impl Fn(&std::fs::File) -> stow_types::error::Result<bool>,
    stage: impl Fn() -> stow_types::error::Result<tempfile::NamedTempFile<F>>,
) -> stow_types::error::Result<Served<F>> {
    let found_other_bytes = match open_served_output(destination)? {
        Some(found) if holds_served_bytes(&found)? => return Ok(Served::Kept(found)),
        Some(_) => true,
        None => false,
    };
    if found_other_bytes {
        return replace_output(stage()?, destination).map(Served::Placed);
    }
    match stage()?.persist_noclobber(destination) {
        Ok(placed) => Ok(Served::Placed(placed)),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another serve placed a file after this one found the path
            // empty. Its file is kept when it holds the bytes; otherwise
            // the bytes are placed over it. This staged file is dropped
            // either way — tempfile marks a staged file it failed to
            // persist as temporary on Windows, which no served output
            // may carry — and a replacement is staged afresh.
            drop(error);
            match open_served_output(destination)? {
                Some(found) if holds_served_bytes(&found)? => Ok(Served::Kept(found)),
                Some(_) | None => replace_output(stage()?, destination).map(Served::Placed),
            }
        }
        Err(error) => Err(error.error)
            .wrap_err_with(|| format!("place staged output at {}", destination.display())),
    }
}

/// The file at `destination` opened for [`serve_output`]'s judgment, or
/// `None` when nothing is there.
fn open_served_output(
    destination: &std::path::Path,
) -> stow_types::error::Result<Option<std::fs::File>> {
    match open_to_read_and_stamp(destination) {
        Ok(found) => Ok(Some(found)),
        // Another serve's replace of the output in flight leaves nothing to
        // judge, the same as an absent output: this serve places its own.
        Err(error) if replace_in_flight(&error) => Ok(None),
        Err(error) => Err(error).wrap_err_with(|| format!("open {}", destination.display())),
    }
}

/// Open `path` to read it and to restamp its modification time through
/// the same handle.
///
/// Windows checks a handle's access on `SetFileInformationByHandle`, and
/// a timestamp needs `FILE_WRITE_ATTRIBUTES`, which read access does not
/// carry; it is asked for without write access to the data, which a
/// running executable refuses. Unix checks the caller's ownership of the
/// file, not the descriptor's mode, for an explicit `futimens`.
fn open_to_read_and_stamp(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES};
        options.access_mode(FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES);
    }
    options.open(path)
}

/// Rename `staged` over `destination`, which holds other bytes, returning
/// what staging produced.
fn replace_output<F>(
    staged: tempfile::NamedTempFile<F>,
    destination: &std::path::Path,
) -> stow_types::error::Result<F> {
    let (file, mut path) = staged.into_parts();
    std::fs::rename(&path, destination).wrap_err_with(|| {
        format!(
            "replace {} with staged {}",
            destination.display(),
            path.display()
        )
    })?;
    path.disable_cleanup(true);
    Ok(file)
}

/// Clone `source` (APFS `clonefile`, Linux `FICLONE`, else a byte copy) to a
/// uniquely named file beside `destination`, not yet visible at it, for
/// [`serve_output`] to place. The staged file is removed on drop if it is
/// never placed.
pub fn stage_clone(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<tempfile::NamedTempFile<Option<u64>>> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    tempfile::Builder::new()
        .prefix(".stow-stage-")
        .make_in(parent, |staged| {
            reflink_copy::reflink_or_copy(source, staged)
        })
}

/// Rename `staged` over `destination`, whose contents change from one
/// write to the next.
///
/// The rename is `std::fs::rename`: `rename(2)`, and on Windows
/// `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, retried as a
/// POSIX-semantics `FileRenameInfoEx` only when that is refused with
/// `ERROR_ACCESS_DENIED` — which a destination another handle holds open,
/// or another replace of it in flight, causes. Neither path keeps the
/// name resolvable to a concurrent opener on Windows, so a destination
/// placed here is read only under a lock that excludes the replace, or
/// by a reader that takes its absence for what it is. A destination that
/// every writer fills with the same bytes goes through [`serve_output`]
/// instead, which never replaces it once it holds them.
pub fn place_staged<F>(
    staged: tempfile::NamedTempFile<F>,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    // Closing the staged file first: the rename moves a path, and the
    // staged file is removed with it if the rename fails.
    let mut staged = staged.into_temp_path();
    std::fs::rename(&staged, destination)?;
    staged.disable_cleanup(true);
    Ok(())
}

/// Whether `error`, from opening or reading a destination that
/// [`place_staged`] or [`replace_output`] renames over, without a lock
/// excluding the replace, is the replace in flight rather
/// than a fault: the name is absent, or on Windows refused for the
/// moment the replace holds it.
///
/// `ERROR_ACCESS_DENIED` is what `CreateFileW` returns for a name whose
/// previous file the replace has marked delete-pending (the NT status
/// `STATUS_DELETE_PENDING` maps to it); the Rust standard library opens
/// with every share mode, so a reader never gets
/// `ERROR_SHARING_VIOLATION` from it. See the `MoveFileExW` and
/// `CreateFileW` documentation, and stow#1472 for the observed failure.
fn replace_in_flight(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || refused_open(error)
}

/// Whether `error` is Windows refusing to open a file a rename is
/// replacing (`ERROR_ACCESS_DENIED`).
#[cfg(windows)]
fn refused_open(error: &std::io::Error) -> bool {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    error.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok()
}

/// No other platform refuses an open during a replace.
#[cfg(not(windows))]
const fn refused_open(_error: &std::io::Error) -> bool {
    false
}

/// Stamp a materialized output with the mtime rustc's own write would
/// have left: this invocation, not the moment the cache entry was
/// staged. A reflink shares the source's inode metadata, so without the
/// stamp a served output keeps an older build's mtime — older than the
/// files cargo's other units wrote this build, which cargo's
/// dependency-mtime check reads as "a dependency was rebuilt" and
/// rebuilds the unit forever (stow#634).
fn stamp_materialized_mtime(
    file: &std::fs::File,
    path: &std::path::Path,
) -> stow_types::error::Result<()> {
    file.set_modified(std::time::SystemTime::now())
        .wrap_err_with(|| format!("stamp mtime on {}", path.display()))
}

/// Whether the marker beside `output_path` records the output whose
/// metadata is `output_metadata` as holding `expected_sha256`.
fn materialized_marker_matches(
    output_path: &std::path::Path,
    output_metadata: &std::fs::Metadata,
    expected_len: u64,
    expected_sha256: Option<&str>,
) -> stow_types::error::Result<bool> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(false);
    };
    if output_metadata.len() != expected_len {
        return Ok(false);
    }
    let marker_path = materialized_marker_path(output_path)?;
    // Every serve rewrites the marker by renaming over it, which a read
    // racing it can find absent or refused on Windows (`place_staged`).
    // Neither is evidence, and the caller hashes the bytes instead.
    let contents = match std::fs::read_to_string(&marker_path) {
        Ok(contents) => contents,
        Err(error) if replace_in_flight(&error) => return Ok(false),
        Err(error) => {
            return Err(error).wrap_err_with(|| {
                format!(
                    "read materialized artifact marker {}",
                    marker_path.display()
                )
            });
        }
    };
    let (modified_secs, modified_nanos) = file_modified_time(output_metadata, output_path)?;
    let mut fields = contents.split_whitespace();
    let version = fields.next();
    let len = fields.next().and_then(|value| value.parse::<u64>().ok());
    let marker_modified_secs = fields.next().and_then(|value| value.parse::<u64>().ok());
    let marker_modified_nanos = fields.next().and_then(|value| value.parse::<u32>().ok());
    let sha256 = fields.next();
    if fields.next().is_some() {
        return Ok(false);
    }
    Ok(version == Some(MATERIALIZED_MARKER_VERSION)
        && len == Some(expected_len)
        && marker_modified_secs == Some(modified_secs)
        && marker_modified_nanos == Some(modified_nanos)
        && sha256 == Some(expected_sha256))
}

/// Record that `output_path`, whose metadata — read from the handle the
/// serve placed or kept — is `output_metadata`, holds `expected_sha256`.
fn write_materialized_marker(
    output_path: &std::path::Path,
    output_metadata: &std::fs::Metadata,
    expected_sha256: Option<&str>,
) -> stow_types::error::Result<()> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };
    let (modified_secs, modified_nanos) = file_modified_time(output_metadata, output_path)?;
    let marker_path = materialized_marker_path(output_path)?;
    let marker_dir = marker_path.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "materialized artifact marker {} has no parent directory",
            marker_path.display()
        )
    })?;
    std::fs::create_dir_all(marker_dir).wrap_err_with(|| {
        format!(
            "create materialized artifact marker directory {}",
            marker_dir.display()
        )
    })?;
    // Two materializers of one output both write this marker. Each writes
    // its own staged file and renames it over the marker, so the marker is
    // always one writer's whole line, never an interleaving of two.
    let mut staged = tempfile::Builder::new()
        .prefix(".stow-marker-")
        .make_in(marker_dir, |staged| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(staged)
        })
        .wrap_err_with(|| {
            format!(
                "stage materialized artifact marker for {}",
                marker_path.display()
            )
        })?;
    std::io::Write::write_all(
        &mut staged,
        format!(
            "{} {} {} {} {}\n",
            MATERIALIZED_MARKER_VERSION,
            output_metadata.len(),
            modified_secs,
            modified_nanos,
            expected_sha256
        )
        .as_bytes(),
    )
    .wrap_err_with(|| {
        format!(
            "write materialized artifact marker {}",
            marker_path.display()
        )
    })?;
    place_staged(staged, &marker_path).wrap_err_with(|| {
        format!(
            "write materialized artifact marker {}",
            marker_path.display()
        )
    })
}

fn file_modified_time(
    metadata: &std::fs::Metadata,
    path: &std::path::Path,
) -> stow_types::error::Result<(u64, u32)> {
    let modified = metadata
        .modified()
        .wrap_err_with(|| format!("read modified time for {}", path.display()))?;
    let duration = modified.duration_since(UNIX_EPOCH).map_err(|error| {
        stow_types::stow_error!(
            "modified time for {} predates UNIX_EPOCH: {}",
            path.display(),
            error
        )
    })?;
    Ok((duration.as_secs(), duration.subsec_nanos()))
}

fn materialized_marker_path(
    output_path: &std::path::Path,
) -> stow_types::error::Result<std::path::PathBuf> {
    let parent = output_path.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "cached artifact target {} has no parent",
            output_path.display()
        )
    })?;
    let output = output_path.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "cached artifact target path {} is not UTF-8",
            output_path.display()
        )
    })?;
    let marker_name = hex::encode(Sha256::digest(output.as_bytes()));
    Ok(parent
        .join(MATERIALIZED_MARKERS_DIR)
        .join(format!("{marker_name}.marker")))
}

fn sha256_file(path: &std::path::Path) -> stow_types::error::Result<String> {
    let bytes =
        std::fs::read(path).wrap_err_with(|| format!("read artifact file {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// The hash of the bytes `file`, freshly opened at `path`, holds.
fn sha256_open_file(
    mut file: &std::fs::File,
    path: &std::path::Path,
) -> stow_types::error::Result<String> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .wrap_err_with(|| format!("read artifact file {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use sha2::Digest;
    use stow_types::artifact::ArtifactKind;
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_RMETA_MEDIA_TYPE,
    };

    use super::{
        OutputDirWriters, materialize_cached_file_blocking, materialized_marker_matches,
        materialized_marker_path, write_artifacts, write_materialized_marker,
    };
    use crate::artifact_cache::CachedArtifactBundle;
    use crate::rustc_args::ParsedRustcArgs;

    /// `ParsedRustcArgs` fixture for the semantic-bundle test: an `itoa` lib
    /// unit whose `-C metadata` (`expected`) deliberately differs from the
    /// bundle's `c_metadata` (`0123abcd`) — the mismatch under test.
    fn semantic_test_parsed_args(out_dir: &Path) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: "itoa".to_owned(),
            crate_types: vec!["lib".to_owned()],
            features: BTreeSet::default(),
            cfgs: BTreeSet::default(),
            cfg_args: Vec::new(),
            emit: BTreeSet::default(),
            json: BTreeSet::default(),
            input_path: Some(PathBuf::from(
                "/root/.cargo/registry/src/index.crates.io-0123abcd/itoa-1.0.18/src/lib.rs",
            )),
            target: Some("aarch64-apple-darwin".to_owned()),
            c_metadata: Some("expected".to_owned()),
            out_dir: Some(out_dir.to_path_buf()),
            extra_filename: "-expected".to_owned(),
            opt_level: Some("0".to_owned()),
            debuginfo: None,
            panic_strategy: None,
            debug_assertions: Some(true),
            overflow_checks: None,
            strip: None,
            native_search_paths: Vec::new(),
            build_script_out_dir: None,
            extern_crates: Vec::new(),
            embed_metadata: None,
            embed_bitcode: false,
            extra_codegen: Vec::new(),
            link_options: Vec::new(),
        }
    }

    /// Cache entry fixture: a remote `itoa` artifact whose only output is
    /// `bundle_file`, staged under `cache_dir` with a lease lock in
    /// `temp_dir`.
    fn semantic_test_bundle(
        cache_dir: PathBuf,
        temp_dir: &Path,
        bundle_file: &str,
    ) -> CachedArtifactBundle {
        let lease_lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(temp_dir.join("lease.lock"))
            .and_then(crate::file_lock::FileLock::shared)
            .expect("create lease lock");
        let manifest = ArtifactBundleManifest {
            oci_reference: "ghcr.io/water-rs/stow-cache-v2-1.91.1:itoa.test".to_owned(),
            oci_digest: "sha256:test".to_owned(),
            config: ArtifactBlobConfig {
                dependency_identity: stow_types::identity::DependencyIdentity::leaf()
                    .expect("leaf identity"),
                compile_key: "0123456789abcdef0123456789abcdef".to_owned(),
                crate_name: stow_types::identity::CrateName::parse("itoa").unwrap(),
                crate_version: stow_types::identity::CrateVersion::new(
                    semver::Version::parse("1.0.17").unwrap(),
                ),
                c_metadata: stow_types::identity::CMetadata::parse("0123abcd").unwrap(),
                extra_filename: "-0123abcd".to_owned(),
                target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
                rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
                features_json: stow_types::identity::FeaturesJson::default(),
                dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson::default(
                ),
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
                artifact_size: 4,
                compile_millis: 0,
                kind: ArtifactKind::Rlib,
                crate_types: vec![stow_types::artifact::RustCrateType::Lib],
                outputs: vec![ArtifactBundleFile {
                    file_name: bundle_file.to_owned(),
                    media_type: STOW_RMETA_MEDIA_TYPE.to_owned(),
                    sha256: "deadbeef".to_owned(),
                }],
                native: None,
                native_archive: None,
            },
            sigstore_signatures: Vec::new(),
        };
        let profile = manifest.config.profile.clone();
        let emit = manifest.config.emit.clone();
        let kind = manifest.config.kind.clone();
        let crate_types = manifest.config.crate_types.clone();
        CachedArtifactBundle {
            provenance: crate::artifact_cache::ArtifactProvenance::Remote,
            reach: stow_types::public_cache::Reach::Public,
            oci_reference: manifest.oci_reference,
            oci_digest: manifest.oci_digest,
            compile_key: manifest.config.compile_key.clone(),
            crate_name: manifest.config.crate_name.as_str().to_owned(),
            crate_version: manifest.config.crate_version.to_string(),
            c_metadata: manifest.config.c_metadata.as_str().to_owned(),
            features_json: manifest.config.features_json.raw(),
            dependency_c_metadata_json: manifest.config.dependency_c_metadata_json.raw(),
            dependency_compile_keys_json: manifest.config.dependency_compile_keys_json.clone(),
            dependency_instances_json: "[]".to_owned(),
            compile_millis: manifest.config.compile_millis,
            size_bytes: 0,
            profile,
            emit,
            kind,
            crate_types,
            outputs: manifest.config.outputs,
            sigstore_signatures: manifest.sigstore_signatures,
            entry_dir: cache_dir,
            rustc_version: "1.91.1".to_owned(),
            cache_key: "v2/aarch64-apple-darwin/0123abcd".to_owned(),
            verified_marker_version: None,
            verified_marker_policy: None,
            _lease_lock: lease_lock,
        }
    }

    /// A served build script is a real file at the path cargo asked
    /// rustc to write, runnable by the cargo that spawns it, whichever
    /// invocation spelling and output directory asked: one bundle serves
    /// the native and the `--target` builds alike.
    #[test]
    fn a_build_script_is_served_as_an_executable_file_for_every_spelling() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let cache_dir = tempdir.path().join("cache-entry");
            std::fs::create_dir_all(cache_dir.join("files")).expect("cache files dir");
            let image = b"#!/bin/sh\nexit 0\n";
            let bundle_file = "build_script_build-0123abcd";
            std::fs::write(cache_dir.join("files").join(bundle_file), image).expect("image");
            let mut bundle = semantic_test_bundle(cache_dir, tempdir.path(), bundle_file);
            bundle.outputs = vec![ArtifactBundleFile {
                file_name: bundle_file.to_owned(),
                media_type: stow_types::bundle::STOW_BUILD_SCRIPT_MEDIA_TYPE.to_owned(),
                sha256: hex::encode(sha2::Sha256::digest(image)),
            }];
            bundle.kind = ArtifactKind::BuildScript;
            bundle.crate_types = vec![stow_types::artifact::RustCrateType::Bin];

            // A plain build, and a `--target` build whose cargo hands the
            // host unit the target's debug settings.
            for (label, codegen) in [
                ("native", vec![]),
                (
                    "target",
                    vec!["-C", "debuginfo=2", "-C", "split-debuginfo=unpacked"],
                ),
            ] {
                let out_dir = tempdir.path().join(label).join("build/pkg-aaaa");
                let out_dir_arg = out_dir.to_str().expect("utf8").to_owned();
                let mut args = vec![
                    "--crate-name",
                    "build_script_build",
                    "--edition=2021",
                    "/root/.cargo/registry/src/index.crates.io-0123abcd/itoa-1.0.18/build.rs",
                    "--crate-type",
                    "bin",
                    "--emit=dep-info,link",
                    "-C",
                    "metadata=expected",
                    "-C",
                    "extra-filename=-expected",
                ];
                args.extend(codegen);
                args.extend(["--out-dir", out_dir_arg.as_str()]);
                let args = args
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>();
                let parsed = ParsedRustcArgs::parse(&args).expect("parse build script");
                assert!(parsed.is_build_script());

                write_artifacts(
                    &parsed,
                    &bundle,
                    "aarch64-apple-darwin",
                    OutputDirWriters::StowOnly,
                )
                .await
                .expect("serve the build script");

                let served = out_dir.join("build_script_build-expected");
                let metadata = std::fs::symlink_metadata(&served).expect("served file");
                assert!(metadata.is_file(), "{label}: a real file, not a link");
                assert_eq!(std::fs::read(&served).expect("read"), image, "{label}");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    assert_eq!(metadata.permissions().mode() & 0o111, 0o111, "{label}");
                }
            }
        });
    }

    #[test]
    fn accepts_semantic_bundle_file_name_mismatch() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            let cache_dir = tempdir.path().join("cache-entry");
            let expected_file = "libitoa-expected.rmeta";
            let bundle_file = "libitoa-other.rmeta";
            let parsed = semantic_test_parsed_args(&out_dir);
            std::fs::create_dir_all(cache_dir.join("files")).expect("cache files dir");
            std::fs::write(cache_dir.join("files").join(bundle_file), b"test")
                .expect("write cached test artifact");
            let bundle = semantic_test_bundle(cache_dir, tempdir.path(), bundle_file);

            write_artifacts(
                &parsed,
                &bundle,
                "aarch64-apple-darwin",
                OutputDirWriters::StowOnly,
            )
            .await
            .expect("semantic bundle should be copied to expected output name");
            assert!(out_dir.join(expected_file).exists());
            assert!(out_dir.join("libitoa-0123456789abcdef.rmeta").exists());
            assert!(out_dir.join("itoa-expected.d").exists());
        });
    }

    #[test]
    fn cached_file_materialization_records_marker_after_sha_verified_materialization() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source = tempdir.path().join("cache").join("lib.rlib");
        let output = tempdir.path().join("target").join("lib.rlib");
        std::fs::create_dir_all(source.parent().unwrap()).expect("source parent");
        std::fs::create_dir_all(output.parent().unwrap()).expect("output parent");
        std::fs::write(&source, b"artifact").expect("source");
        let sha256 = hex::encode(sha2::Sha256::digest(b"artifact"));

        assert!(
            materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                false,
                OutputDirWriters::StowOnly,
            )
            .expect("first materialization")
        );
        let marker = materialized_marker_path(&output).expect("marker path");
        assert!(marker.exists());
        assert!(
            !materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                false,
                OutputDirWriters::StowOnly,
            )
            .expect("marker hit avoids copy")
        );
    }

    /// Inside the build sandbox the output directory is not stow's alone:
    /// third-party build scripts hold write access to it. A marker found
    /// there is a file they can write, so it proves nothing and the bytes
    /// must be hashed — otherwise a planted rlib stands in for a verified
    /// artifact and the plan publishes the plant's hash as genuine.
    #[test]
    fn a_forged_marker_cannot_stand_in_for_the_bytes_when_untrusted_code_writes_there() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source.rlib");
        let output = dir.path().join("deps/libvictim-abc.rlib");
        std::fs::create_dir_all(output.parent().unwrap()).expect("output parent");
        std::fs::write(&source, b"genuine artifact").expect("source");
        let sha256 = hex::encode(sha2::Sha256::digest(b"genuine artifact"));

        // What a build script can do: write a file of the declared length
        // and a marker that names the declared hash. Neither is the hash
        // of what it actually wrote.
        std::fs::write(&output, b"poisoned artifac").expect("plant");
        assert_eq!(
            std::fs::metadata(&output).expect("plant metadata").len(),
            std::fs::metadata(&source).expect("source metadata").len(),
            "the plant has to match the declared length or nothing is being tested"
        );
        let plant_metadata = std::fs::metadata(&output).expect("plant metadata");
        write_materialized_marker(&output, &plant_metadata, Some(&sha256)).expect("forged marker");
        assert!(
            materialized_marker_matches(
                &output,
                &plant_metadata,
                std::fs::metadata(&source).expect("source metadata").len(),
                Some(&sha256),
            )
            .expect("marker check"),
            "the forgery has to convince the marker check or nothing is being tested"
        );

        assert!(
            materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                false,
                OutputDirWriters::UntrustedCodeToo,
            )
            .expect("materialization"),
            "the plant must be replaced, not believed"
        );
        assert_eq!(
            std::fs::read(&output).expect("output"),
            b"genuine artifact",
            "the bytes left behind are the verified ones"
        );
    }

    #[test]
    fn stale_materialization_marker_does_not_hide_changed_output() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source = tempdir.path().join("cache").join("lib.rlib");
        let output = tempdir.path().join("target").join("lib.rlib");
        std::fs::create_dir_all(source.parent().unwrap()).expect("source parent");
        std::fs::create_dir_all(output.parent().unwrap()).expect("output parent");
        std::fs::write(&source, b"artifact").expect("source");
        let sha256 = hex::encode(sha2::Sha256::digest(b"artifact"));

        materialize_cached_file_blocking(
            &source,
            &output,
            Some(&sha256),
            false,
            OutputDirWriters::StowOnly,
        )
        .expect("first materialization");
        std::fs::write(&output, b"changed!").expect("change materialized file with same length");
        // The marker records the output's length and mtime. Filesystem
        // timestamps tick coarsely (NTFS ~1-15 ms), so a same-length rewrite
        // in the same tick would leave the marker matching; the change under
        // test is the mtime moving, so move it explicitly.
        let changed = std::fs::File::options()
            .write(true)
            .open(&output)
            .expect("open changed output");
        changed
            .set_modified(
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            )
            .expect("set changed output mtime");
        drop(changed);

        assert!(
            materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                false,
                OutputDirWriters::StowOnly,
            )
            .expect("stale marker is rejected")
        );
        assert_eq!(std::fs::read(&output).expect("output"), b"artifact");
    }

    /// The materialized output is a clone-or-copy of the cache entry,
    /// never a view of it: a rewrite of the cached source afterwards
    /// must not reach the bytes a build already materialized — a
    /// hardlink would carry it straight through.
    #[test]
    fn materialized_output_keeps_its_bytes_when_the_cache_entry_changes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source = tempdir.path().join("cache").join("lib.rlib");
        let output = tempdir.path().join("target").join("lib.rlib");
        std::fs::create_dir_all(source.parent().unwrap()).expect("source parent");
        std::fs::create_dir_all(output.parent().unwrap()).expect("output parent");
        std::fs::write(&source, b"artifact").expect("source");
        let sha256 = hex::encode(sha2::Sha256::digest(b"artifact"));

        materialize_cached_file_blocking(
            &source,
            &output,
            Some(&sha256),
            false,
            OutputDirWriters::StowOnly,
        )
        .expect("materialize cached file");

        std::fs::write(&source, b"replaced").expect("rewrite cache entry");
        assert_eq!(
            std::fs::read(&output).expect("output"),
            b"artifact",
            "a rewrite of the cache entry reached the materialized output"
        );
    }

    /// Two serves of one build can need the same dependency output at
    /// once. Every one of them must succeed and the output must be the
    /// cached bytes whole, whichever placement wins — from an empty path,
    /// and from a path holding other bytes of the same length, which every
    /// serve that finds them replaces while the others look the path up.
    #[test]
    fn concurrent_materializations_of_one_output_all_succeed() {
        const THREADS: usize = 32;
        const ROUNDS: usize = 20;
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source = tempdir.path().join("cache").join("lib.rlib");
        let output_dir = tempdir.path().join("target").join("deps");
        std::fs::create_dir_all(source.parent().unwrap()).expect("source parent");
        std::fs::create_dir_all(&output_dir).expect("output parent");
        let contents = vec![0x5a_u8; 256 * 1024];
        std::fs::write(&source, &contents).expect("source");
        let sha256 = hex::encode(sha2::Sha256::digest(&contents));

        for writers in [
            OutputDirWriters::StowOnly,
            OutputDirWriters::UntrustedCodeToo,
        ] {
            for round in 0..ROUNDS {
                let output = output_dir.join(format!("lib-{writers:?}-{round}.rlib"));
                if round % 2 == 1 {
                    std::fs::write(&output, vec![0xa5_u8; contents.len()]).expect("stale output");
                }
                let barrier = std::sync::Barrier::new(THREADS);
                std::thread::scope(|scope| {
                    let handles: Vec<_> = (0..THREADS)
                        .map(|_| {
                            scope.spawn(|| {
                                barrier.wait();
                                materialize_cached_file_blocking(
                                    &source,
                                    &output,
                                    Some(&sha256),
                                    false,
                                    writers,
                                )
                            })
                        })
                        .collect();
                    for handle in handles {
                        handle
                            .join()
                            .expect("materializer thread")
                            .expect("every concurrent materialization succeeds");
                    }
                });
                assert_eq!(std::fs::read(&output).expect("output"), contents);
            }
        }
        for dir in [
            output_dir.clone(),
            output_dir.join(super::MATERIALIZED_MARKERS_DIR),
        ] {
            let leftovers: Vec<_> = std::fs::read_dir(&dir)
                .expect("read dir")
                .map(|entry| entry.expect("entry").file_name())
                .filter(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with(".stow-stage-") || name.starts_with(".stow-marker-")
                })
                .collect();
            assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
        }
    }

    #[test]
    fn dep_info_write_preserves_mtime_when_contents_match() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = tempdir.path().join("crate.d");
            super::write_file_if_changed(&path, b"crate: crate.d\n")
                .await
                .expect("initial write");
            // A fixed mtime far in the past: any rewrite moves it to now,
            // whatever the filesystem's timestamp granularity — no sleep
            // to step past a tick (stow#810).
            let before =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
            std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("open the dep-info file")
                .set_modified(before)
                .expect("set the dep-info mtime");
            super::write_file_if_changed(&path, b"crate: crate.d\n")
                .await
                .expect("idempotent write");
            let after = std::fs::metadata(&path)
                .expect("metadata after")
                .modified()
                .expect("mtime after");

            assert_eq!(before, after);
        });
    }

    #[test]
    fn replace_in_flight_is_absence_and_on_windows_a_refused_open() {
        assert!(super::replace_in_flight(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
        assert!(!super::replace_in_flight(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
        assert!(!super::replace_in_flight(&std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof
        )));
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_DISK_FULL};
            let os = |code: u32| std::io::Error::from_raw_os_error(code as i32);
            assert!(super::replace_in_flight(&os(ERROR_ACCESS_DENIED)));
            assert!(!super::replace_in_flight(&os(ERROR_DISK_FULL)));
        }
    }
}
