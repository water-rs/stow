use eyre::Context;
use sha2::{Digest, Sha256};
use stow_types::artifact::NativeArtifacts;
use stow_types::bundle::ArtifactBundleFile;

use crate::artifact_cache::CachedArtifactBundle;
use crate::rustc_args::ParsedRustcArgs;

pub async fn write_artifacts(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
) -> eyre::Result<()> {
    let out_dir = parsed
        .out_dir
        .as_ref()
        .ok_or_else(|| eyre::eyre!("cached rustc invocation is missing --out-dir"))?;
    async_fs::create_dir_all(out_dir)
        .await
        .wrap_err_with(|| format!("create rustc out dir {}", out_dir.display()))?;

    for file in &bundle.manifest.config.outputs {
        write_artifact_file(parsed, out_dir, file, bundle).await?;
    }
    if let Some(native) = bundle.manifest.config.native.as_ref() {
        write_native_artifacts(parsed, bundle, native).await?;
    }
    Ok(())
}

async fn write_artifact_file(
    parsed: &ParsedRustcArgs,
    out_dir: &std::path::Path,
    file: &ArtifactBundleFile,
    bundle: &CachedArtifactBundle,
) -> eyre::Result<()> {
    let output_path = expected_output_path(parsed, out_dir, file)?;
    let source_path = bundle.output_source_path(file);
    if !source_path.exists() {
        return Err(eyre::eyre!(
            "cached artifact source {} does not exist",
            source_path.display()
        ));
    }
    write_cached_output(&source_path, &output_path, Some(file.sha256.as_str())).await?;

    Ok(())
}

fn expected_output_path(
    parsed: &ParsedRustcArgs,
    out_dir: &std::path::Path,
    file: &ArtifactBundleFile,
) -> eyre::Result<std::path::PathBuf> {
    let expected = if file.media_type == stow_types::bundle::STOW_RLIB_MEDIA_TYPE {
        parsed.output_rlib_path()
    } else if file.media_type == stow_types::bundle::STOW_RMETA_MEDIA_TYPE {
        parsed.output_rmeta_path()
    } else if file.media_type == stow_types::bundle::STOW_DYLIB_MEDIA_TYPE
        || file.media_type == stow_types::bundle::STOW_PROC_MACRO_MEDIA_TYPE
    {
        Some(
            parsed
                .output_dynamic_library_path()
                .map_err(eyre::Report::msg)?,
        )
    } else {
        return Err(eyre::eyre!(
            "unexpected cached artifact media type {}",
            file.media_type
        ));
    };

    let expected = expected.ok_or_else(|| {
        eyre::eyre!(
            "cached artifact media type {} does not match this rustc invocation",
            file.media_type
        )
    })?;
    if expected.parent() != Some(out_dir) {
        return Err(eyre::eyre!(
            "expected output path {} escaped rustc out dir {}",
            expected.display(),
            out_dir.display()
        ));
    }

    Ok(expected)
}

async fn write_cached_output(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
) -> eyre::Result<()> {
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
        copy_cached_file_blocking(
            &source_for_copy,
            &output_for_copy,
            expected_sha256.as_deref(),
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

async fn write_native_artifacts(
    parsed: &ParsedRustcArgs,
    bundle: &CachedArtifactBundle,
    native: &NativeArtifacts,
) -> eyre::Result<()> {
    let Some(native_dir) = parsed.native_search_paths.first() else {
        return Ok(());
    };
    async_fs::create_dir_all(native_dir)
        .await
        .wrap_err_with(|| format!("create native output dir {}", native_dir.display()))?;

    for file in &native.out_dir_files {
        let output_path = native_dir.join(&file.relative_path);
        let source_path = bundle.native_output_source_path(&file.relative_path);
        if !source_path.exists() {
            return Err(eyre::eyre!(
                "cached native artifact source {} does not exist",
                source_path.display()
            ));
        }
        write_cached_output(&source_path, &output_path, None).await?;
    }

    let build_dir = native_dir
        .parent()
        .ok_or_else(|| eyre::eyre!("native output dir {} has no parent", native_dir.display()))?;
    let output_contents = rewrite_native_directives(native, native_dir)?;
    async_fs::write(build_dir.join("output"), output_contents)
        .await
        .wrap_err_with(|| format!("write build script output {}", build_dir.display()))?;
    Ok(())
}

fn copy_cached_file_blocking(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
) -> eyre::Result<bool> {
    if target_matches_cached_file(source_path, output_path, expected_sha256)? {
        return Ok(false);
    }
    if output_path.exists() {
        std::fs::remove_file(output_path).wrap_err_with(|| {
            format!("remove existing cached artifact {}", output_path.display())
        })?;
    }
    reflink::reflink_or_copy(source_path, output_path).wrap_err_with(|| {
        format!(
            "clone cached artifact {} into {}",
            source_path.display(),
            output_path.display()
        )
    })?;
    Ok(true)
}

fn target_matches_cached_file(
    source_path: &std::path::Path,
    output_path: &std::path::Path,
    expected_sha256: Option<&str>,
) -> eyre::Result<bool> {
    if !output_path.exists() {
        return Ok(false);
    }
    let source_metadata = std::fs::metadata(source_path)
        .wrap_err_with(|| format!("stat cached artifact source {}", source_path.display()))?;
    let output_metadata = std::fs::metadata(output_path)
        .wrap_err_with(|| format!("stat cached artifact target {}", output_path.display()))?;
    if source_metadata.len() != output_metadata.len() {
        return Ok(false);
    }
    let output_hash = sha256_file(output_path)?;
    if let Some(expected_sha256) = expected_sha256 {
        return Ok(output_hash == expected_sha256);
    }
    Ok(output_hash == sha256_file(source_path)?)
}

fn sha256_file(path: &std::path::Path) -> eyre::Result<String> {
    let bytes =
        std::fs::read(path).wrap_err_with(|| format!("read artifact file {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn rewrite_native_directives(
    native: &NativeArtifacts,
    native_dir: &std::path::Path,
) -> eyre::Result<String> {
    let native_dir_str = native_dir
        .to_str()
        .ok_or_else(|| eyre::eyre!("native output dir {} is not UTF-8", native_dir.display()))?;
    let mut lines = Vec::with_capacity(native.cargo_directives.len());
    for directive in &native.cargo_directives {
        if directive.starts_with("cargo:rustc-link-search=native=") {
            lines.push(format!("cargo:rustc-link-search=native={native_dir_str}"));
        } else {
            lines.push(directive.clone());
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use stow_types::artifact::ArtifactKind;
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_RMETA_MEDIA_TYPE,
    };

    use super::write_artifacts;
    use crate::artifact_cache::CachedArtifactBundle;
    use crate::rustc_args::ParsedRustcArgs;

    #[test]
    fn accepts_semantic_bundle_file_name_mismatch() {
        smol::block_on(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            let cache_dir = tempdir.path().join("cache-entry");
            let expected_file = "libitoa-expected.rmeta";
            let bundle_file = "libitoa-other.rmeta";
            let parsed = ParsedRustcArgs {
                crate_name: "itoa".to_owned(),
                crate_types: vec!["lib".to_owned()],
                features: Default::default(),
                target: Some("aarch64-apple-darwin".to_owned()),
                c_metadata: Some("expected".to_owned()),
                out_dir: Some(out_dir.clone()),
                extra_filename: "-expected".to_owned(),
                opt_level: Some("0".to_owned()),
                debuginfo: None,
                panic_strategy: None,
                debug_assertions: Some(true),
                overflow_checks: None,
                native_search_paths: Vec::new(),
                has_custom_codegen: false,
            };
            std::fs::create_dir_all(cache_dir.join("files")).expect("cache files dir");
            std::fs::write(cache_dir.join("files").join(bundle_file), b"test")
                .expect("write cached test artifact");
            let lease_lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(tempdir.path().join("lease.lock"))
                .expect("create lease lock");
            let manifest = ArtifactBundleManifest {
                oci_reference: "ghcr.io/stow-rs/cache/itoa:test".to_owned(),
                oci_digest: "sha256:test".to_owned(),
                config: ArtifactBlobConfig {
                    crate_name: "itoa".to_owned(),
                    crate_version: "1.0.17".to_owned(),
                    c_metadata: "other".to_owned(),
                    target: "aarch64-apple-darwin".to_owned(),
                    rustc_version: "1.91.1".to_owned(),
                    features_json: "[]".to_owned(),
                    artifact_size: 4,
                    kind: ArtifactKind::Rlib,
                    crate_types: vec![stow_types::artifact::RustCrateType::Lib],
                    outputs: vec![ArtifactBundleFile {
                        file_name: bundle_file.to_owned(),
                        media_type: STOW_RMETA_MEDIA_TYPE.to_owned(),
                        sha256: "deadbeef".to_owned(),
                    }],
                    native: None,
                },
                sigstore_signatures: Vec::new(),
            };
            let bundle = CachedArtifactBundle {
                manifest,
                entry_dir: cache_dir,
                _lease_lock: lease_lock,
            };

            write_artifacts(&parsed, &bundle)
                .await
                .expect("semantic bundle should be copied to expected output name");
            assert!(PathBuf::from(&out_dir).join(expected_file).exists());
        });
    }
}
