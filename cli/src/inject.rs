use eyre::Context;
use stow_types::bundle::ArtifactBundleFile;
use stow_types::artifact::NativeArtifacts;

use crate::fetch::{bundle_file_path, ArtifactBundle};
use crate::rustc_args::ParsedRustcArgs;

pub async fn write_artifacts(
    parsed: &ParsedRustcArgs,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let out_dir = parsed
        .out_dir
        .as_ref()
        .ok_or_else(|| eyre::eyre!("cached rustc invocation is missing --out-dir"))?;
    async_fs::create_dir_all(out_dir)
        .await
        .wrap_err_with(|| format!("create rustc out dir {}", out_dir.display()))?;

    write_artifact_file(parsed, out_dir, bundle.manifest.config.rlib.as_ref(), bundle).await?;
    write_artifact_file(parsed, out_dir, bundle.manifest.config.rmeta.as_ref(), bundle).await?;
    write_artifact_file(parsed, out_dir, bundle.manifest.config.proc_macro.as_ref(), bundle)
        .await?;
    if let Some(native) = bundle.manifest.config.native.as_ref() {
        write_native_artifacts(parsed, native).await?;
    }
    Ok(())
}

async fn write_artifact_file(
    parsed: &ParsedRustcArgs,
    out_dir: &std::path::Path,
    file: Option<&ArtifactBundleFile>,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let Some(file) = file else {
        return Ok(());
    };
    validate_expected_output(parsed, file)?;
    let bundle_path = bundle_file_path(&file.file_name);
    let contents = bundle
        .files
        .get(&bundle_path)
        .ok_or_else(|| eyre::eyre!("bundle is missing {bundle_path}"))?;
    let output_path = out_dir.join(&file.file_name);
    async_fs::write(&output_path, contents)
        .await
        .wrap_err_with(|| format!("write cached artifact {}", output_path.display()))?;
    tracing::debug!(path = %output_path.display(), "wrote cached artifact");
    Ok(())
}

fn validate_expected_output(parsed: &ParsedRustcArgs, file: &ArtifactBundleFile) -> eyre::Result<()> {
    let expected = if file.media_type == stow_types::bundle::STOW_RLIB_MEDIA_TYPE {
        parsed.output_rlib_path()
    } else if file.media_type == stow_types::bundle::STOW_RMETA_MEDIA_TYPE {
        parsed.output_rmeta_path()
    } else {
        None
    };

    if let Some(expected) = expected {
        let expected_name = expected
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| eyre::eyre!("expected output path is missing a UTF-8 filename"))?;
        if expected_name != file.file_name {
            return Err(eyre::eyre!(
                "cached artifact filename mismatch: expected {expected_name}, got {}",
                file.file_name
            ));
        }
    }

    Ok(())
}

async fn write_native_artifacts(
    parsed: &ParsedRustcArgs,
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
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            async_fs::create_dir_all(parent)
                .await
                .wrap_err_with(|| format!("create native output parent {}", parent.display()))?;
        }
        async_fs::write(&output_path, &file.contents)
            .await
            .wrap_err_with(|| format!("write native artifact {}", output_path.display()))?;
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
