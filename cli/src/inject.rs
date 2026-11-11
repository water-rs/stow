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
        writers,
    )
    .await?;
    mark_executable_if_build_script(output_path, file).await
}

/// A build script is run by cargo, so its served file carries the
/// executable mode rustc would have given it: a bundle's pack records no
/// modes, and the cache entry it unpacked into holds a plain file.
async fn mark_executable_if_build_script(
    output_path: &std::path::Path,
    file: &ArtifactBundleFile,
) -> stow_types::error::Result<()> {
    if file.media_type != stow_types::bundle::STOW_BUILD_SCRIPT_MEDIA_TYPE {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        async_fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o755))
            .await
            .wrap_err_with(|| {
                format!(
                    "mark served build script {} executable",
                    output_path.display()
                )
            })?;
    }
    #[cfg(not(unix))]
    let _ = output_path;
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
            writers,
        )
        .await?;
        mark_executable_if_build_script(&original_path, file).await?;
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
    write_cached_output(&source_path, &alias_path, None, writers).await
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
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    write_cached_output(source_path, output_path, Some(expected_sha256), writers).await?;
    if let Some(additional_output_path) = additional_output_path
        && additional_output_path != output_path
    {
        write_cached_output(
            source_path,
            additional_output_path,
            Some(expected_sha256),
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
    writers: OutputDirWriters,
) -> stow_types::error::Result<bool> {
    let source_metadata = std::fs::metadata(source_path)
        .wrap_err_with(|| format!("stat cached artifact source {}", source_path.display()))?;
    // A marker is a claim about bytes someone else may have replaced, so
    // it is only evidence where nobody else writes. `target_matches_cached_file`
    // below hashes the output either way, which is what makes ignoring the
    // marker safe rather than merely slower.
    if writers.trusts_markers()
        && materialized_marker_matches(output_path, source_metadata.len(), expected_sha256)?
    {
        stamp_materialized_mtime(output_path)?;
        write_materialized_marker(output_path, expected_sha256)?;
        return Ok(false);
    }
    if target_matches_cached_file(
        source_path,
        output_path,
        expected_sha256,
        source_metadata.len(),
    )? {
        stamp_materialized_mtime(output_path)?;
        write_materialized_marker(output_path, expected_sha256)?;
        return Ok(false);
    }
    let staged = stage_clone(source_path, output_path).wrap_err_with(|| {
        format!(
            "clone or copy cached artifact {} into {}",
            source_path.display(),
            output_path.display()
        )
    })?;
    // The stamp goes on the staged file: a rename keeps the inode and its
    // mtime, so the final path never holds an unstamped output.
    stamp_materialized_mtime(staged.path())?;
    let source_len = source_metadata.len();
    place_staged(staged, output_path, || {
        target_matches_cached_file(source_path, output_path, expected_sha256, source_len)
            .unwrap_or(false)
    })
    .wrap_err_with(|| {
        format!(
            "move cached artifact {} into place at {}",
            source_path.display(),
            output_path.display()
        )
    })?;
    write_materialized_marker(output_path, expected_sha256)?;
    Ok(true)
}

/// Clone `source` (APFS `clonefile`, Linux `FICLONE`, else a byte copy) to a
/// uniquely named file beside `destination`, not yet visible at it.
///
/// Placing a file at a path another serve may be placing at the same moment
/// is `persist` onto the final path — a rename, which replaces atomically
/// and leaves a reader either the old file or the whole new one — never a
/// check or remove followed by a create at that path, where the second
/// creator finds the first one's file (stow#1444). The staged file is
/// removed on drop if it is never persisted.
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

/// The pauses between attempts to rename a staged file over a destination
/// that another placement is replacing at the same moment.
///
/// `rename(2)` replaces atomically, so elsewhere there is one attempt. On
/// Windows a rename that meets a concurrent replace of its destination is
/// refused with access denied while the other rename is in flight, which
/// lasts microseconds: five pauses doubling from one millisecond outlast it
/// by three orders of magnitude and bound the wait at 31 ms before the
/// refusal is reported.
#[cfg(windows)]
const REPLACE_RETRY_PAUSES: [std::time::Duration; 5] = [
    std::time::Duration::from_millis(1),
    std::time::Duration::from_millis(2),
    std::time::Duration::from_millis(4),
    std::time::Duration::from_millis(8),
    std::time::Duration::from_millis(16),
];
#[cfg(not(windows))]
const REPLACE_RETRY_PAUSES: [std::time::Duration; 0] = [];

/// Rename `staged` over `destination`, which other placements of the same
/// bytes may be replacing at the same moment.
///
/// A rename refused because the destination is being replaced has lost to
/// a placement of the same bytes: `already_placed` says whether the
/// destination now holds them, which is this placement's own postcondition.
/// Where it does not yet, the rename is tried again after each of
/// [`REPLACE_RETRY_PAUSES`], and the last refusal is the error.
pub fn place_staged<F>(
    mut staged: tempfile::NamedTempFile<F>,
    destination: &std::path::Path,
    already_placed: impl Fn() -> bool,
) -> std::io::Result<()> {
    for pause in REPLACE_RETRY_PAUSES {
        match staged.persist(destination) {
            Ok(_) => return Ok(()),
            Err(refused) if refused.error.kind() == std::io::ErrorKind::PermissionDenied => {
                if already_placed() {
                    return Ok(());
                }
                staged = refused.file;
                std::thread::sleep(pause);
            }
            Err(refused) => return Err(refused.error),
        }
    }
    match staged.persist(destination) {
        Ok(_) => Ok(()),
        Err(refused)
            if refused.error.kind() == std::io::ErrorKind::PermissionDenied && already_placed() =>
        {
            Ok(())
        }
        Err(refused) => Err(refused.error),
    }
}

/// Stamp a materialized output with the mtime rustc's own write would
/// have left: this invocation, not the moment the cache entry was
/// staged. A reflink shares the source's inode metadata, so without the
/// stamp a served output keeps an older build's mtime — older than the
/// files cargo's other units wrote this build, which cargo's
/// dependency-mtime check reads as "a dependency was rebuilt" and
/// rebuilds the unit forever (stow#634).
fn stamp_materialized_mtime(output_path: &std::path::Path) -> stow_types::error::Result<()> {
    std::fs::File::options()
        .write(true)
        .open(output_path)
        .and_then(|file| file.set_modified(std::time::SystemTime::now()))
        .wrap_err_with(|| format!("stamp mtime on {}", output_path.display()))
}

fn target_matches_cached_file(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
    source_len: u64,
) -> stow_types::error::Result<bool> {
    if !output_path.exists() {
        return Ok(false);
    }
    let output_metadata = std::fs::metadata(output_path)
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    if source_len != output_metadata.len() {
        return Ok(false);
    }
    let output_hash = sha256_file(output_path)?;
    if let Some(expected_sha256) = expected_sha256 {
        return Ok(output_hash == expected_sha256);
    }
    Ok(output_hash == sha256_file(source_path)?)
}

fn materialized_marker_matches(
    output_path: &std::path::Path,
    expected_len: u64,
    expected_sha256: Option<&str>,
) -> stow_types::error::Result<bool> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(false);
    };
    if !output_path.exists() {
        return Ok(false);
    }
    let marker_path = materialized_marker_path(output_path)?;
    if !marker_path.exists() {
        return Ok(false);
    }
    let output_metadata = std::fs::metadata(output_path)
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    if output_metadata.len() != expected_len {
        return Ok(false);
    }
    let (modified_secs, modified_nanos) = file_modified_time(&output_metadata, output_path)?;
    let contents = std::fs::read_to_string(&marker_path).wrap_err_with(|| {
        format!(
            "read materialized artifact marker {}",
            marker_path.display()
        )
    })?;
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

fn write_materialized_marker(
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
) -> stow_types::error::Result<()> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };
    let output_metadata = std::fs::metadata(output_path)
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    let (modified_secs, modified_nanos) = file_modified_time(&output_metadata, output_path)?;
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
        .tempfile_in(marker_dir)
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
    let output_len = output_metadata.len();
    place_staged(staged, &marker_path, || {
        materialized_marker_matches(output_path, output_len, Some(expected_sha256)).unwrap_or(false)
    })
    .wrap_err_with(|| {
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
        write_materialized_marker(&output, Some(&sha256)).expect("forged marker");
        assert!(
            materialized_marker_matches(
                &output,
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
    /// cached bytes whole, whichever placement wins.
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
                let output = output_dir.join(format!("lib-{round}.rlib"));
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
}
