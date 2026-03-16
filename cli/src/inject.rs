use eyre::Context;
use stow_types::bundle::ArtifactBundleFile;
use stow_types::artifact::NativeArtifacts;

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
    let expected_file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| eyre::eyre!("expected output path {} has no UTF-8 file name", output_path.display()))?;
    if file.file_name != expected_file_name {
        return Err(eyre::eyre!(
            "cached artifact file name mismatch: expected {}, got {}",
            expected_file_name,
            file.file_name
        ));
    }
    let source_path = bundle.output_source_path(file);
    if !source_path.exists() {
        return Err(eyre::eyre!(
            "cached artifact source {} does not exist",
            source_path.display()
        ));
    }
    write_cached_output(&source_path, &output_path).await?;

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

async fn write_cached_output(source_path: &std::path::Path, output_path: &std::path::Path) -> eyre::Result<()> {
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create cached artifact parent {}", parent.display()))?;
    }

    let source_path = source_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    let source_for_copy = source_path.clone();
    let output_for_copy = output_path.clone();
    smol::unblock(move || copy_cached_file_blocking(&source_for_copy, &output_for_copy)).await?;
    tracing::debug!(
        source = %source_path.display(),
        output = %output_path.display(),
        "materialized cached artifact"
    );
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
        write_cached_output(&source_path, &output_path).await?;
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

fn copy_cached_file_blocking(source_path: &std::path::Path, output_path: &std::path::Path) -> eyre::Result<()> {
    if output_path.exists() {
        std::fs::remove_file(output_path)
            .wrap_err_with(|| format!("remove existing cached artifact {}", output_path.display()))?;
    }
    reflink::reflink_or_copy(source_path, output_path)
        .wrap_err_with(|| {
            format!(
                "clone cached artifact {} into {}",
                source_path.display(),
                output_path.display()
            )
        })?;
    Ok(())
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

    use crate::artifact_cache::CachedArtifactBundle;
    use super::write_artifacts;
    use crate::rustc_args::ParsedRustcArgs;

    #[test]
    fn rejects_bundle_file_name_mismatch() {
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
            std::fs::write(
                cache_dir.join("files").join(bundle_file),
                b"test",
            )
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

            let error = write_artifacts(&parsed, &bundle)
                .await
                .expect_err("mismatched file name must fail");
            let message = error.to_string();

            assert!(message.contains("cached artifact file name mismatch"));
            assert!(message.contains(expected_file));
            assert!(message.contains(bundle_file));
            assert!(!PathBuf::from(&out_dir).join(expected_file).exists());
        });
    }
}
