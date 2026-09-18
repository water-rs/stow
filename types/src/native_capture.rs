//! Capture of a build script's `OUT_DIR` products into [`NativeArtifacts`].
//!
//! Shared by the CI builder and the CLI's local artifact cache. Both learn
//! the exact `OUT_DIR` from the process environment — CI records it off the
//! build-script invocation's environment, while cargo exports the same
//! `OUT_DIR` on the library's `rustc` invocation so `env!("OUT_DIR")` works
//! in crate source — so neither side scans directories by crate-name prefix,
//! which would mis-attribute artifacts across duplicate crate versions and
//! prefix-colliding sibling crates.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::artifact::{NativeArtifacts, NativeLib, OutDirFile};
use crate::error::Context;

/// Capture the build-script products for one rustc invocation.
///
/// Returns `None` when the invocation had no build script `OUT_DIR`.
///
/// # Errors
///
/// A set `OUT_DIR` whose sibling `output` file is missing is an error: cargo
/// always runs the build script (and writes `output`) before compiling the
/// crate, so its absence means the directory is not what cargo promised.
/// Filesystem and UTF-8 failures while walking `OUT_DIR` are likewise errors.
pub fn capture_native_artifacts(
    crate_name: &str,
    build_script_out_dir: Option<&Path>,
) -> crate::error::Result<Option<NativeArtifacts>> {
    let Some(out_dir) = build_script_out_dir else {
        return Ok(None);
    };
    let build_dir = out_dir.parent().ok_or_else(|| {
        crate::stow_error!(
            "build script OUT_DIR {} for {crate_name} has no parent build dir",
            out_dir.display()
        )
    })?;
    let output_path = build_dir.join("output");
    if !output_path.exists() {
        return Err(crate::stow_error!(
            "build script output file {} for {crate_name} is missing",
            output_path.display()
        ));
    }

    let raw = std::fs::read_to_string(&output_path)
        .wrap_err_with(|| format!("read build script output {}", output_path.display()))?;
    let cargo_directives = parse_build_script_output(&raw);
    let (static_libs, out_dir_files) = if out_dir.exists() {
        collect_out_dir(out_dir)?
    } else {
        (Vec::new(), Vec::new())
    };
    Ok(Some(NativeArtifacts {
        static_libs,
        cargo_directives,
        dep_env_vars: BTreeMap::new(),
        out_dir_files,
    }))
}

/// Keep the `cargo:` directive lines of a build script's `output` file.
///
/// `rerun-if-*` and `warning=` are dropped: rebuild hints and diagnostics are
/// irrelevant to a cached artifact, while every other directive
/// (`rustc-link-lib`, `rustc-link-search`, `rustc-cfg`, `rustc-env`, `KEY=VAL`
/// metadata) is exactly what a consumer needs replayed.
#[must_use]
pub fn parse_build_script_output(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("cargo:")
                || line.starts_with("cargo:rerun-if-")
                || line.starts_with("cargo:warning=")
            {
                return None;
            }
            Some(line.to_owned())
        })
        .collect()
}

/// Walk `out_dir` and hash every regular file. `.a`/`.lib` files additionally
/// land in `static_libs` by file name; every file (libs included) lands in
/// `out_dir_files` by relative path.
fn collect_out_dir(out_dir: &Path) -> crate::error::Result<(Vec<NativeLib>, Vec<OutDirFile>)> {
    let mut stack = vec![out_dir.to_path_buf()];
    let mut static_libs = Vec::new();
    let mut out_dir_files = Vec::new();

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .wrap_err_with(|| format!("read native out dir {}", dir.display()))?
        {
            let entry = entry.wrap_err_with(|| format!("read entry in {}", dir.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .wrap_err_with(|| format!("stat native out entry {}", path.display()))?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let bytes = std::fs::read(&path)
                .wrap_err_with(|| format!("read native artifact file {}", path.display()))?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
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
                        crate::stow_error!("native library path {} is not UTF-8", path.display())
                    })?;
                static_libs.push(NativeLib {
                    name,
                    bytes_sha256: sha256.clone(),
                });
            }
            out_dir_files.push(OutDirFile {
                relative_path,
                sha256,
            });
        }
    }

    out_dir_files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    static_libs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((static_libs, out_dir_files))
}

/// The bundle-portable relative path of `path` under `root`: components
/// joined with `/` whatever the host separator, because the bundle is
/// produced on one platform and restored on another.
fn relative_path(root: &Path, path: &Path) -> crate::error::Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|error| crate::stow_error!("strip native out dir prefix: {error}"))?;
    let mut components = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(crate::stow_error!(
                "native relative path {} has a non-normal component",
                relative.display()
            ));
        };
        components.push(name.to_str().ok_or_else(|| {
            crate::stow_error!("native relative path {} is not UTF-8", path.display())
        })?);
    }
    Ok(components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::capture_native_artifacts;

    #[test]
    fn nested_out_dir_files_use_slash_separators_on_every_host() {
        let build_dir = tempfile::tempdir().expect("tempdir");
        let out_dir = build_dir.path().join("out");
        std::fs::create_dir_all(out_dir.join("gen")).expect("create out dir");
        std::fs::write(build_dir.path().join("output"), "cargo:rustc-cfg=demo\n")
            .expect("write output");
        std::fs::write(out_dir.join("gen").join("bindings.rs"), "pub fn f() {}\n")
            .expect("write nested file");

        let native = capture_native_artifacts("demo", Some(&out_dir))
            .expect("capture")
            .expect("out dir present");
        assert_eq!(
            native
                .out_dir_files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["gen/bindings.rs"]
        );
    }
}
