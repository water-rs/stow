use std::path::Path;

use futures_lite::StreamExt;
use sha2::{Digest, Sha256};
use stow_types::artifact::{NativeArtifacts, NativeLib, OutDirFile};
use stow_types::error::Context;

/// Capture the build-script products for one rustc invocation.
///
/// `build_script_out_dir` is the `OUT_DIR` cargo passed to that exact
/// invocation (recorded by the capture wrapper), so there is no directory
/// scanning by crate-name prefix — which would mis-attribute artifacts across
/// duplicate crate versions and prefix-colliding sibling crates.
pub async fn capture_native_artifacts(
    crate_name: &str,
    build_script_out_dir: Option<&Path>,
) -> stow_types::error::Result<Option<NativeArtifacts>> {
    let Some(out_dir) = build_script_out_dir else {
        return Ok(None);
    };
    let build_dir = out_dir.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "build script OUT_DIR {} for {crate_name} has no parent build dir",
            out_dir.display()
        )
    })?;
    let output_path = build_dir.join("output");
    if !output_path.exists() {
        return Err(stow_types::stow_error!(
            "build script output file {} for {crate_name} is missing",
            output_path.display()
        ));
    }

    let cargo_directives = parse_output_file(&output_path).await?;
    let (static_libs, out_dir_files) = if out_dir.exists() {
        collect_out_dir(out_dir).await?
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(Some(NativeArtifacts {
        static_libs,
        cargo_directives,
        dep_env_vars: std::collections::BTreeMap::new(),
        out_dir_files,
    }))
}

async fn parse_output_file(output_path: &Path) -> stow_types::error::Result<Vec<String>> {
    let raw = async_fs::read_to_string(output_path)
        .await
        .wrap_err_with(|| format!("read build script output {}", output_path.display()))?;
    let directives = raw
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("cargo:") {
                return None;
            }
            if line.starts_with("cargo:rerun-if-") {
                return None;
            }
            if line.starts_with("cargo:warning=") {
                return None;
            }
            Some(line.to_owned())
        })
        .collect::<Vec<_>>();
    Ok(directives)
}

async fn collect_out_dir(
    out_dir: &Path,
) -> stow_types::error::Result<(Vec<NativeLib>, Vec<OutDirFile>)> {
    let mut stack = vec![out_dir.to_path_buf()];
    let mut static_libs = Vec::new();
    let mut out_dir_files = Vec::new();

    while let Some(dir) = stack.pop() {
        let mut entries = async_fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let bytes = async_fs::read(&path)
                .await
                .wrap_err_with(|| format!("read native artifact file {}", path.display()))?;
            let relative_path = relative_path(out_dir, &path)?;
            if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|ext| ext == "a" || ext == "lib")
            {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        stow_types::stow_error!(
                            "native library path {} is not UTF-8",
                            path.display()
                        )
                    })?;
                static_libs.push(NativeLib {
                    name,
                    bytes_sha256: hex::encode(Sha256::digest(&bytes)),
                });
            }
            out_dir_files.push(OutDirFile {
                relative_path,
                sha256: hex::encode(Sha256::digest(&bytes)),
            });
        }
    }

    out_dir_files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    static_libs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((static_libs, out_dir_files))
}

fn relative_path(root: &Path, path: &Path) -> stow_types::error::Result<String> {
    path.strip_prefix(root)
        .map_err(|error| stow_types::stow_error!("strip native out dir prefix: {error}"))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            stow_types::stow_error!("native relative path {} is not UTF-8", path.display())
        })
}
