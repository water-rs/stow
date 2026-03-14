use std::path::Path;

use eyre::Context;
use futures_lite::StreamExt;
use sha2::{Digest, Sha256};
use stow_types::artifact::{NativeArtifacts, NativeLib, OutDirFile};

pub async fn capture_native_artifacts(
    build_root: &Path,
    crate_name: &str,
) -> eyre::Result<Option<NativeArtifacts>> {
    let crate_prefix = format!("{crate_name}-");
    let mut entries = async_fs::read_dir(build_root).await?;
    while let Some(entry) = entries.next().await {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !file_name.starts_with(&crate_prefix) {
            continue;
        }
        let output_path = path.join("output");
        if !output_path.exists() {
            continue;
        }

        let cargo_directives = parse_output_file(&output_path).await?;
        let out_dir = path.join("out");
        let (static_libs, out_dir_files) = if out_dir.exists() {
            collect_out_dir(&out_dir).await?
        } else {
            (Vec::new(), Vec::new())
        };
        return Ok(Some(NativeArtifacts {
            static_libs,
            cargo_directives,
            dep_env_vars: std::collections::BTreeMap::new(),
            out_dir_files,
        }));
    }

    Ok(None)
}

async fn parse_output_file(output_path: &Path) -> eyre::Result<Vec<String>> {
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

async fn collect_out_dir(out_dir: &Path) -> eyre::Result<(Vec<NativeLib>, Vec<OutDirFile>)> {
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
            if path.extension().and_then(|value| value.to_str()).is_some_and(|ext| ext == "a" || ext == "lib") {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| eyre::eyre!("native library path {} is not UTF-8", path.display()))?;
                static_libs.push(NativeLib {
                    name,
                    bytes_sha256: hex::encode(Sha256::digest(&bytes)),
                });
            }
            out_dir_files.push(OutDirFile {
                relative_path,
                contents: bytes,
            });
        }
    }

    out_dir_files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    static_libs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((static_libs, out_dir_files))
}

fn relative_path(root: &Path, path: &Path) -> eyre::Result<String> {
    path.strip_prefix(root)
        .map_err(|error| eyre::eyre!("strip native out dir prefix: {error}"))?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| eyre::eyre!("native relative path {} is not UTF-8", path.display()))
}
