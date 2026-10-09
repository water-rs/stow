use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::UNIX_EPOCH;
use stow_types::artifact::NativeArtifacts;
use stow_types::bundle::ArtifactBundleFile;
use stow_types::error::Context;
use stow_types::public_cache::{StableRegistryArtifactIdentity, stable_c_metadata_for_compile_key};

use crate::artifact_cache::CachedArtifactBundle;
use crate::rustc_args::ParsedRustcArgs;

const MATERIALIZED_MARKERS_DIR: &str = ".stow-materialized";
const MATERIALIZED_MARKER_VERSION: &str = "stow-materialized-v1";
const STOW_CACHED_ARTIFACT_MATERIALIZATION_ENV: &str = "STOW_CACHED_ARTIFACT_MATERIALIZATION";
const REFLINK_OR_COPY_MATERIALIZATION: &str = "reflink-or-copy";
const SYMLINK_MATERIALIZATION: &str = "symlink";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedArtifactMaterialization {
    ReflinkOrCopy,
    Symlink,
}

impl CachedArtifactMaterialization {
    fn load() -> stow_types::error::Result<Self> {
        let Some(raw) = std::env::var_os(STOW_CACHED_ARTIFACT_MATERIALIZATION_ENV) else {
            return Ok(Self::ReflinkOrCopy);
        };
        let raw = raw.to_str().ok_or_else(|| {
            stow_types::stow_error!(
                "{STOW_CACHED_ARTIFACT_MATERIALIZATION_ENV} must be valid UTF-8"
            )
        })?;
        Self::parse(raw)
    }

    fn parse(raw: &str) -> stow_types::error::Result<Self> {
        match raw {
            REFLINK_OR_COPY_MATERIALIZATION => Ok(Self::ReflinkOrCopy),
            SYMLINK_MATERIALIZATION => Ok(Self::Symlink),
            other => Err(stow_types::stow_error!(
                "unsupported cached artifact materialization `{other}`; expected `{REFLINK_OR_COPY_MATERIALIZATION}` or `{SYMLINK_MATERIALIZATION}`"
            )),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ReflinkOrCopy => REFLINK_OR_COPY_MATERIALIZATION,
            Self::Symlink => SYMLINK_MATERIALIZATION,
        }
    }

    fn materialize(
        self,
        source_path: &std::path::Path,
        output_path: &std::path::Path,
    ) -> stow_types::error::Result<()> {
        match self {
            Self::ReflinkOrCopy => reflink::reflink_or_copy(source_path, output_path)
                .map(|_| ())
                .wrap_err_with(|| {
                    format!(
                        "clone or copy cached artifact {} into {}",
                        source_path.display(),
                        output_path.display()
                    )
                }),
            Self::Symlink => symlink_file(source_path, output_path).wrap_err_with(|| {
                format!(
                    "symlink cached artifact {} into {}",
                    source_path.display(),
                    output_path.display()
                )
            }),
        }
    }
}

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
        let output_path = expected_output_path(parsed, out_dir, file)?;
        if materialized_outputs.insert(output_path.clone()) {
            write_artifact_file(&output_path, file, bundle, writers).await?;
        }
    }
    materialize_cached_bundle_stable_aliases(parsed, bundle, writers).await?;
    if let Some(native) = bundle.native.as_ref() {
        write_native_artifacts(parsed, bundle, native, writers).await?;
    }
    write_dep_info(parsed).await?;
    touch_invoked_timestamp(parsed, out_dir).await?;
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
    }
    Ok(())
}

pub async fn materialize_local_build_stable_aliases(
    parsed: &ParsedRustcArgs,
    identity: &StableRegistryArtifactIdentity,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let stable_parsed = parsed_with_stable_identity(parsed, identity);

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
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        stable_parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        writers,
    )
    .await?;
    Ok(())
}

async fn materialize_cached_bundle_stable_aliases(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let stable_c_metadata = stable_c_metadata_for_compile_key(&bundle.compile_key)?;
    let stable_identity = StableRegistryArtifactIdentity {
        compile_key: bundle.compile_key.clone(),
        c_metadata: stable_c_metadata.clone(),
        extra_filename: format!("-{stable_c_metadata}"),
        crate_name: bundle.crate_name.clone(),
        version: bundle.crate_version.clone(),
    };
    let stable_parsed = parsed_with_stable_identity(parsed, &stable_identity);

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
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        stable_parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        writers,
    )
    .await?;
    Ok(())
}

pub fn parsed_with_stable_identity(
    parsed: &ParsedRustcArgs,
    identity: &StableRegistryArtifactIdentity,
) -> ParsedRustcArgs {
    let mut stable = parsed.clone();
    stable.c_metadata = Some(identity.c_metadata.clone());
    stable.extra_filename.clone_from(&identity.extra_filename);
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
) -> stow_types::error::Result<std::path::PathBuf> {
    let expected = if file.media_type == stow_types::bundle::STOW_RLIB_MEDIA_TYPE {
        parsed.output_rlib_path()
    } else if file.media_type == stow_types::bundle::STOW_RMETA_MEDIA_TYPE {
        parsed.output_rmeta_path()
    } else if file.media_type == stow_types::bundle::STOW_DYLIB_MEDIA_TYPE
        || file.media_type == stow_types::bundle::STOW_PROC_MACRO_MEDIA_TYPE
    {
        parsed
            .output_dynamic_library_path()
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
    let materialization = CachedArtifactMaterialization::load()?;
    write_cached_output_with_materialization(
        source_path,
        output_path,
        expected_sha256,
        materialization,
        writers,
    )
    .await
}

async fn write_cached_output_with_materialization(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
    materialization: CachedArtifactMaterialization,
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
            materialization,
            writers,
        )
    })
    .await?;
    if materialized {
        tracing::debug!(
            source = %source_path.display(),
            output = %output_path.display(),
            materialization = materialization.name(),
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

/// Write the native artifacts the bundle carries for a crate whose build
/// script produced native outputs — `-sys` crates and any crate with `links`.
///
/// Cargo exports `OUT_DIR` to the rustc invocation of a crate with a build
/// script, and the wrapper records it on `parsed.build_script_out_dir`: that
/// is where the build script's outputs belong — the `static_libs` from the
/// archive and the `out_dir_files` snapshot — while the `output` file belongs
/// one level up, in the build dir. No `-L native=` path is ever a usable
/// substitute for the recorded `OUT_DIR`: a build script may publish a search
/// path outside it (`cargo:rustc-link-search=native=<manifest>/lib`), which
/// made a read-only registry source dir the write target (stow#431).
async fn write_native_artifacts(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    native: &NativeArtifacts,
    writers: OutputDirWriters,
) -> stow_types::error::Result<()> {
    let Some(native_dir) = parsed.build_script_out_dir.as_deref() else {
        return Err(stow_types::stow_error!(
            "a bundle for {} carries native artifacts but the rustc invocation \
             has no OUT_DIR to restore them into",
            parsed.crate_name
        ));
    };
    async_fs::create_dir_all(native_dir)
        .await
        .wrap_err_with(|| format!("create native output dir {}", native_dir.display()))?;

    for file in &native.out_dir_files {
        let output_path = native_dir.join(&file.relative_path);
        let source_path = bundle.native_output_source_path(&file.relative_path);
        if !source_path.exists() {
            return Err(stow_types::stow_error!(
                "cached native artifact source {} does not exist",
                source_path.display()
            ));
        }
        write_cached_output(&source_path, &output_path, None, writers).await?;
    }

    let build_dir = native_dir.parent().ok_or_else(|| {
        stow_types::stow_error!("native output dir {} has no parent", native_dir.display())
    })?;
    let output_contents = rewrite_native_directives(native, native_dir)?;
    async_fs::write(build_dir.join("output"), output_contents)
        .await
        .wrap_err_with(|| format!("write build script output {}", build_dir.display()))?;
    Ok(())
}

async fn touch_invoked_timestamp(
    parsed: &ParsedRustcArgs,
    out_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    let profile_dir = out_dir.parent().ok_or_else(|| {
        stow_types::stow_error!("rustc out dir {} has no profile parent", out_dir.display())
    })?;
    // Cargo names the fingerprint dir after the PACKAGE (`<pkg>-<meta>`),
    // not the lib target `parsed.crate_name` records — a `[lib] name`
    // rename puts the timestamp where cargo never looks (stow#578). The
    // registry source path carries the package name verbatim. A unit
    // with none is a locally-built (non-registry) entry — the local cache
    // restores those too — whose package name is the rustc spelling with
    // cargo's `-` fold.
    let fingerprint_name = stow_types::public_cache::detect_registry_crate_version(parsed)?
        .map_or_else(
            || parsed.crate_name.replace('_', "-"),
            |(name, _version)| name,
        );
    let fingerprint_dir = profile_dir
        .join(".fingerprint")
        .join(format!("{fingerprint_name}{}", parsed.extra_filename));
    let timestamp_path = fingerprint_dir.join("invoked.timestamp");
    smol::unblock(move || {
        std::fs::create_dir_all(&fingerprint_dir).wrap_err_with(|| {
            format!("create cargo fingerprint dir {}", fingerprint_dir.display())
        })?;
        std::fs::write(&timestamp_path, [])
            .wrap_err_with(|| format!("write {}", timestamp_path.display()))
    })
    .await
}

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
    let dependency_line = format!("{stem}: {}\n", dep_info_path.display());
    async_fs::create_dir_all(out_dir)
        .await
        .wrap_err_with(|| format!("create dep-info dir {}", out_dir.display()))?;
    write_file_if_changed(&dep_info_path, dependency_line.as_bytes()).await?;
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
    materialization: CachedArtifactMaterialization,
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
        return Ok(false);
    }
    if target_matches_cached_file(
        source_path,
        output_path,
        expected_sha256,
        source_metadata.len(),
    )? {
        write_materialized_marker(output_path, expected_sha256)?;
        return Ok(false);
    }
    remove_existing_output(output_path)?;
    materialization.materialize(source_path, output_path)?;
    write_materialized_marker(output_path, expected_sha256)?;
    Ok(true)
}

fn remove_existing_output(output_path: &std::path::Path) -> stow_types::error::Result<()> {
    match std::fs::symlink_metadata(output_path) {
        Ok(_) => std::fs::remove_file(output_path)
            .wrap_err_with(|| format!("remove existing cached artifact {}", output_path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(stow_types::error::Error::from(error).wrap_err(format!(
            "stat existing cached artifact {}",
            output_path.display()
        ))),
    }
}

#[cfg(unix)]
fn symlink_file(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
) -> std::io::Result<()> {
    std::os::unix::fs::symlink(source_path, output_path)
}

#[cfg(windows)]
fn symlink_file(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(source_path, output_path)
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
    std::fs::write(
        &marker_path,
        format!(
            "{} {} {} {} {}\n",
            MATERIALIZED_MARKER_VERSION,
            output_metadata.len(),
            modified_secs,
            modified_nanos,
            expected_sha256
        ),
    )
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

fn rewrite_native_directives(
    native: &NativeArtifacts,
    native_dir: &std::path::Path,
) -> stow_types::error::Result<String> {
    let native_dir_str = native_dir.to_str().ok_or_else(|| {
        stow_types::stow_error!("native output dir {} is not UTF-8", native_dir.display())
    })?;
    let original_out_dir = native.original_out_dir.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "recorded OUT_DIR {} is not UTF-8",
            native.original_out_dir.display()
        )
    })?;
    // The bundle records the producing build's OUT_DIR; a directive naming
    // anything else — a search path under the package's own source tree,
    // for instance — passes through untouched.
    let mut lines = Vec::with_capacity(native.cargo_directives.len());
    for directive in &native.cargo_directives {
        if directive.starts_with("cargo:rustc-link-search=native=") {
            let current = directive
                .strip_prefix("cargo:rustc-link-search=native=")
                .ok_or_else(|| stow_types::stow_error!("invalid native link-search directive"))?;
            if current == original_out_dir {
                lines.push(format!("cargo:rustc-link-search=native={native_dir_str}"));
            } else {
                lines.push(directive.clone());
            }
        } else if directive.contains(original_out_dir) {
            lines.push(directive.replace(original_out_dir, native_dir_str));
        } else {
            lines.push(directive.clone());
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use sha2::Digest;
    use stow_types::artifact::{ArtifactKind, NativeArtifacts};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_RMETA_MEDIA_TYPE,
    };

    use super::{
        CachedArtifactMaterialization, OutputDirWriters, materialize_cached_file_blocking,
        materialized_marker_matches, materialized_marker_path, rewrite_native_directives,
        write_artifacts, write_materialized_marker,
    };
    use crate::artifact_cache::CachedArtifactBundle;
    use crate::rustc_args::ParsedRustcArgs;

    /// stow#578: cargo names the fingerprint dir after the package
    /// (`<pkg>-<meta>`), so a `[lib] name` rename must not send the
    /// timestamp under the lib name.
    #[test]
    fn invoked_timestamp_uses_the_package_fingerprint_name() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("target/debug/deps");
            std::fs::create_dir_all(&out_dir).expect("out dir");

            let mut parsed = semantic_test_parsed_args(&out_dir);
            parsed.crate_name = "debug_unreachable".to_owned();
            parsed.input_path = Some(PathBuf::from(
                "/root/.cargo/registry/src/index.crates.io-0123abcd/new_debug_unreachable-1.0.6/src/lib.rs",
            ));
            parsed.extra_filename = "-0123456789abcdef".to_owned();

            super::touch_invoked_timestamp(&parsed, &out_dir)
                .await
                .expect("touch timestamp");

            assert!(
                tempdir
                    .path()
                    .join("target/debug/.fingerprint/new_debug_unreachable-0123456789abcdef/invoked.timestamp")
                    .exists()
            );
        });
    }

    /// A locally-built (non-registry) entry restores through the same path:
    /// its fingerprint dir takes the rustc spelling's `-` fold — the local
    /// package's name.
    #[test]
    fn invoked_timestamp_uses_the_rustc_spelling_for_a_non_registry_unit() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("target/debug/deps");
            std::fs::create_dir_all(&out_dir).expect("out dir");
            let mut parsed = semantic_test_parsed_args(&out_dir);
            parsed.crate_name = "my_crate".to_owned();
            parsed.input_path = Some(PathBuf::from("src/lib.rs"));

            super::touch_invoked_timestamp(&parsed, &out_dir)
                .await
                .expect("touch timestamp");

            assert!(
                tempdir
                    .path()
                    .join("target/debug/.fingerprint/my-crate-expected/invoked.timestamp")
                    .exists()
            );
        });
    }

    /// `ParsedRustcArgs` fixture for the semantic-bundle test: an `itoa` lib
    /// unit whose `-C metadata` (`expected`) deliberately differs from the
    /// bundle's `c_metadata` (`0123abcd`) — the mismatch under test.
    fn semantic_test_parsed_args(out_dir: &Path) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: "itoa".to_owned(),
            crate_types: vec!["lib".to_owned()],
            features: BTreeSet::default(),
            cfgs: BTreeSet::default(),
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
            has_custom_codegen: false,
            link_options: std::collections::BTreeSet::new(),
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
            .expect("create lease lock");
        let manifest = ArtifactBundleManifest {
            oci_reference: "ghcr.io/water-rs/stow-cache:itoa.test".to_owned(),
            oci_digest: "sha256:test".to_owned(),
            config: ArtifactBlobConfig {
                dependency_identity: None,
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
            oci_reference: manifest.oci_reference,
            oci_digest: manifest.oci_digest,
            compile_key: manifest.config.compile_key.clone(),
            crate_name: manifest.config.crate_name.as_str().to_owned(),
            crate_version: manifest.config.crate_version.to_string(),
            c_metadata: manifest.config.c_metadata.as_str().to_owned(),
            features_json: manifest.config.features_json.raw(),
            dependency_c_metadata_json: manifest.config.dependency_c_metadata_json.raw(),
            dependency_compile_keys_json: manifest.config.dependency_compile_keys_json.clone(),
            compile_millis: manifest.config.compile_millis,
            size_bytes: 0,
            profile,
            emit,
            kind,
            crate_types,
            outputs: manifest.config.outputs,
            native: manifest.config.native,
            sigstore_signatures: manifest.sigstore_signatures,
            entry_dir: cache_dir,
            rustc_version: "1.91.1".to_owned(),
            cache_key: "v2/aarch64-apple-darwin/0123abcd".to_owned(),
            verified_marker_version: None,
            verified_marker_policy: None,
            _lease_lock: lease_lock,
        }
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

            write_artifacts(&parsed, &bundle, OutputDirWriters::StowOnly)
                .await
                .expect("semantic bundle should be copied to expected output name");
            assert!(out_dir.join(expected_file).exists());
            assert!(out_dir.join("libitoa-0123456789abcdef.rmeta").exists());
            assert!(out_dir.join("itoa-expected.d").exists());
            assert!(
                tempdir
                    .path()
                    .join(".fingerprint")
                    .join("itoa-expected")
                    .join("invoked.timestamp")
                    .exists()
            );
        });
    }

    #[test]
    fn rewrite_native_directives_rewrites_metadata_paths_from_original_out_dir() {
        let native = NativeArtifacts {
            static_libs: Vec::new(),
            cargo_directives: vec![
                "cargo:rustc-link-search=native=/tmp/original/build/out".to_owned(),
                "cargo:root=/tmp/original/build/out".to_owned(),
                "cargo:include=/tmp/original/build/out/include".to_owned(),
                "cargo:rustc-link-lib=static=ring-core".to_owned(),
                "cargo:rustc-link-search=native=/usr/lib".to_owned(),
            ],
            dep_env_vars: std::collections::BTreeMap::new(),
            out_dir_files: Vec::new(),
            original_out_dir: PathBuf::from("/tmp/original/build/out"),
        };
        let rewritten = rewrite_native_directives(&native, std::path::Path::new("/tmp/new/out"))
            .expect("rewrite directives");
        assert!(rewritten.contains("cargo:rustc-link-search=native=/tmp/new/out"));
        assert!(rewritten.contains("cargo:root=/tmp/new/out"));
        assert!(rewritten.contains("cargo:include=/tmp/new/out/include"));
        assert!(rewritten.contains("cargo:rustc-link-search=native=/usr/lib"));
    }

    /// The bundle's recorded `OUT_DIR` is the only path rewritten; a
    /// link-search path outside it — another build's `out`, a library dir
    /// under the package source — passes through untouched.
    #[test]
    fn rewrite_native_directives_passes_through_paths_outside_the_recorded_out_dir() {
        let native = NativeArtifacts {
            static_libs: Vec::new(),
            cargo_directives: vec![
                "cargo:rustc-link-search=native=/original/build/out".to_owned(),
                "cargo:rustc-link-search=native=/other/build/out".to_owned(),
                "cargo:root=/original/build/out".to_owned(),
            ],
            dep_env_vars: std::collections::BTreeMap::new(),
            out_dir_files: Vec::new(),
            original_out_dir: PathBuf::from("/original/build/out"),
        };
        let rewritten = rewrite_native_directives(&native, std::path::Path::new("/tmp/new/out"))
            .expect("rewrite directives");
        assert!(rewritten.contains("cargo:rustc-link-search=native=/tmp/new/out"));
        assert!(rewritten.contains("cargo:root=/tmp/new/out"));
        assert!(rewritten.contains("cargo:rustc-link-search=native=/other/build/out"));
    }

    /// stow#431: `windows_x86_64_msvc`'s build script emits
    /// `cargo:rustc-link-search=native=<CARGO_MANIFEST_DIR>/lib`, so the only
    /// `-L native=` path on the invocation is the read-only registry source
    /// dir. Native artifacts must restore under the invocation's own `OUT_DIR`
    /// (cargo exports it on the rustc invocation) and the package source
    /// tree must never be written.
    #[test]
    fn write_native_artifacts_uses_invocation_out_dir_not_search_paths() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            let manifest_dir = tempdir
                .path()
                .join("registry/src/windows_x86_64_msvc-0.52.6");
            let manifest_lib = manifest_dir.join("lib");
            std::fs::create_dir_all(&manifest_lib).expect("manifest lib dir");
            let new_out_dir = tempdir
                .path()
                .join("build/windows_x86_64_msvc-bbbb2222/out");

            let mut parsed = semantic_test_parsed_args(&out_dir);
            parsed.native_search_paths = vec![manifest_lib.clone()];
            parsed.build_script_out_dir = Some(new_out_dir.clone());

            let cache_dir = tempdir.path().join("cache-entry");
            std::fs::create_dir_all(cache_dir.join("files")).expect("cache files dir");
            std::fs::write(cache_dir.join("files").join("libitoa-other.rmeta"), b"test")
                .expect("write cached test artifact");
            let mut bundle = semantic_test_bundle(cache_dir, tempdir.path(), "libitoa-other.rmeta");
            bundle.native = Some(NativeArtifacts {
                static_libs: Vec::new(),
                cargo_directives: vec![
                    format!("cargo:rustc-link-search=native={}", manifest_lib.display()),
                    "cargo:rustc-link-lib=static=windows.0.52.0".to_owned(),
                ],
                dep_env_vars: std::collections::BTreeMap::new(),
                out_dir_files: Vec::new(),
                original_out_dir: tempdir.path().join("original/build/out"),
            });

            write_artifacts(&parsed, &bundle, OutputDirWriters::StowOnly)
                .await
                .expect("restore bundle");

            let output =
                std::fs::read_to_string(new_out_dir.parent().expect("build dir").join("output"))
                    .expect("read rewritten build script output");
            // The search path outside OUT_DIR passes through untouched.
            assert!(output.contains(&format!(
                "cargo:rustc-link-search=native={}",
                manifest_lib.display()
            )));
            assert!(output.contains("cargo:rustc-link-lib=static=windows.0.52.0"));

            // The registry source tree is read-only: nothing may be written
            // into or under it.
            assert!(!manifest_dir.join("output").exists());
            assert_eq!(
                std::fs::read_dir(&manifest_lib)
                    .expect("read manifest lib dir")
                    .count(),
                0
            );
        });
    }

    /// An invocation carrying no `OUT_DIR` cannot restore native artifacts —
    /// writing them under a `-L` path was the stow#431 defect.
    #[test]
    fn write_native_artifacts_errors_without_invocation_out_dir() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            let cache_dir = tempdir.path().join("cache-entry");
            std::fs::create_dir_all(cache_dir.join("files")).expect("cache files dir");
            std::fs::write(cache_dir.join("files").join("libitoa-other.rmeta"), b"test")
                .expect("write cached test artifact");
            let mut parsed = semantic_test_parsed_args(&out_dir);
            parsed.native_search_paths = vec![tempdir.path().join("anywhere")];
            let mut bundle = semantic_test_bundle(cache_dir, tempdir.path(), "libitoa-other.rmeta");
            bundle.native = Some(NativeArtifacts {
                static_libs: Vec::new(),
                cargo_directives: Vec::new(),
                dep_env_vars: std::collections::BTreeMap::new(),
                out_dir_files: Vec::new(),
                original_out_dir: PathBuf::from("/original/build/out"),
            });

            let error = write_artifacts(&parsed, &bundle, OutputDirWriters::StowOnly)
                .await
                .expect_err("native bundle without OUT_DIR must error");
            assert!(error.to_string().contains("no OUT_DIR"), "{error}");
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
                CachedArtifactMaterialization::ReflinkOrCopy,
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
                CachedArtifactMaterialization::ReflinkOrCopy,
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
                CachedArtifactMaterialization::ReflinkOrCopy,
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
    fn cached_artifact_materialization_accepts_documented_strategies() {
        assert_eq!(
            CachedArtifactMaterialization::parse("reflink-or-copy")
                .expect("default strategy parses"),
            CachedArtifactMaterialization::ReflinkOrCopy
        );
        assert_eq!(
            CachedArtifactMaterialization::parse("symlink").expect("symlink strategy parses"),
            CachedArtifactMaterialization::Symlink
        );
        let error = CachedArtifactMaterialization::parse("copy")
            .expect_err("unsupported materialization must fail fast");
        assert!(error.to_string().contains("reflink-or-copy"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_materialization_links_cached_artifact_without_copying_bytes() {
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
                CachedArtifactMaterialization::Symlink,
                OutputDirWriters::StowOnly,
            )
            .expect("first symlink materialization")
        );
        assert!(
            std::fs::symlink_metadata(&output)
                .expect("output metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_link(&output).expect("read link"), source);
        assert_eq!(std::fs::read(&output).expect("output"), b"artifact");
        let marker = materialized_marker_path(&output).expect("marker path");
        assert!(marker.exists());
        assert!(
            !materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                CachedArtifactMaterialization::Symlink,
                OutputDirWriters::StowOnly,
            )
            .expect("marker hit avoids rematerialization")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_materialization_replaces_dangling_output_symlink() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let source = tempdir.path().join("cache").join("lib.rlib");
        let output = tempdir.path().join("target").join("lib.rlib");
        let missing_target = tempdir.path().join("missing").join("lib.rlib");
        std::fs::create_dir_all(source.parent().unwrap()).expect("source parent");
        std::fs::create_dir_all(output.parent().unwrap()).expect("output parent");
        std::fs::write(&source, b"artifact").expect("source");
        std::os::unix::fs::symlink(&missing_target, &output).expect("dangling link");
        let sha256 = hex::encode(sha2::Sha256::digest(b"artifact"));

        assert!(
            materialize_cached_file_blocking(
                &source,
                &output,
                Some(&sha256),
                CachedArtifactMaterialization::Symlink,
                OutputDirWriters::StowOnly,
            )
            .expect("replace dangling symlink")
        );
        assert_eq!(std::fs::read_link(&output).expect("read link"), source);
        assert_eq!(std::fs::read(&output).expect("output"), b"artifact");
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
            CachedArtifactMaterialization::ReflinkOrCopy,
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
                CachedArtifactMaterialization::ReflinkOrCopy,
                OutputDirWriters::StowOnly,
            )
            .expect("stale marker is rejected")
        );
        assert_eq!(std::fs::read(&output).expect("output"), b"artifact");
    }

    #[test]
    fn dep_info_write_preserves_mtime_when_contents_match() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let path = tempdir.path().join("crate.d");
            super::write_file_if_changed(&path, b"crate: crate.d\n")
                .await
                .expect("initial write");
            let before = std::fs::metadata(&path)
                .expect("metadata before")
                .modified()
                .expect("mtime before");
            std::thread::sleep(std::time::Duration::from_millis(20));
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
