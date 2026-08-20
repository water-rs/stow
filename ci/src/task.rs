use std::path::{Path, PathBuf};

use async_fs::{create_dir_all, read_to_string};
use async_process::Command;
use stow_types::api::BuildTaskPayload;
use tempfile::TempDir;
use zenwave::Client;

use crate::capture::STOW_BUILD_CAPTURE_DIR_ENV;
use crate::workspace_mirror;
use stow_shim as wrapper_shim;

const STOW_BUILD_WORKSPACE_ROOT_ENV: &str = "STOW_BUILD_WORKSPACE_ROOT";
const STOW_BUILD_CARGO_SUBCOMMAND_ENV: &str = "STOW_BUILD_CARGO_SUBCOMMAND";
const STOW_BUILD_SOURCE_ROOT_ENV: &str = "STOW_BUILD_SOURCE_ROOT";

pub struct BuildWorkspace {
    _tempdir: Option<TempDir>,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    capture_dir: PathBuf,
}

impl BuildWorkspace {
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn capture_dir(&self) -> &Path {
        &self.capture_dir
    }
}

pub async fn create_workspace(
    task: &BuildTaskPayload,
) -> stow_types::error::Result<BuildWorkspace> {
    if let Some(workspace) = open_source_workspace().await? {
        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            version = %task.version,
            target = %task.target,
            manifest_path = %workspace.manifest_path().display(),
            workspace_root = %workspace.workspace_root().display(),
            "using existing source workspace for trusted build"
        );
        return Ok(workspace);
    }

    let (tempdir, workspace_root) = create_workspace_root().await?;
    let manifest_path = download_crate_manifest(task, &workspace_root).await?;
    let source_root = manifest_path
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "downloaded crate manifest {} has no parent directory",
                manifest_path.display()
            )
        })?
        .to_path_buf();
    let capture_dir = source_root.join(".stow-rustc-capture");
    create_dir_all(&capture_dir).await?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        manifest_path = %manifest_path.display(),
        workspace_root = %source_root.display(),
        "created CI build workspace"
    );

    Ok(BuildWorkspace {
        _tempdir: tempdir,
        manifest_path,
        workspace_root: source_root,
        capture_dir,
    })
}

pub async fn build(task: &BuildTaskPayload) -> stow_types::error::Result<BuildWorkspace> {
    let mirror_key = workspace_mirror::MirrorTaskKey {
        target: task.target.as_str().to_owned(),
        rustc_version: task.rustc_version.as_str().to_owned(),
        preserve_lockfile: task.preserve_lockfile,
    };
    let workspace =
        stabilize_workspace(create_workspace(task).await?, &mirror_key).await?;
    let remap_flag = format!(
        "--remap-path-prefix={}={}",
        workspace.workspace_root().display(),
        "stow-ci://workspace"
    );
    let rustflags = merged_rustflags(&remap_flag);
    let cargo_subcommand = cargo_subcommand()?;

    let capture_wrapper = std::env::current_exe().map_err(|error| {
        stow_types::stow_error!("resolve current stow-build executable: {error}")
    })?;
    let runtime_wrapper = sibling_runtime_wrapper(&capture_wrapper)?;
    let wrappers = wrapper_shim::materialize_wrapper_shims(&runtime_wrapper, &capture_wrapper)?;
    for &phase in cargo_phases(cargo_subcommand) {
        let target_dir = phase_target_dir(&workspace, cargo_subcommand, phase);
        let mut command = Command::new("cargo");
        command.arg(phase.as_str());
        if phase == CargoSubcommand::Test {
            command.arg("--no-run");
        }
        CargoFeatureArgs::from_task(task).apply(&mut command);
        command.arg("--manifest-path").arg(workspace.manifest_path());
        // Only cross-compiles pass `--target`. Passing it for a host build
        // splits cargo's unit graph into host and target halves and changes
        // the flags it gives the host half — build scripts, proc macros and
        // everything they depend on lose `-C debuginfo`, which the lookup side
        // normalizes differently. Users run plain `cargo build`, so a host
        // build here has to be a plain `cargo build` too or the entire
        // proc-macro graph is keyed differently from theirs, and every crate
        // deriving through it misses.
        if !target_is_host(task.target.as_str()).await? {
            command.arg("--target").arg(&task.target);
        }
        let status = command
            .env("RUSTUP_TOOLCHAIN", &task.rustc_version)
            .env("RUSTFLAGS", &rustflags)
            .env("RUSTC_WRAPPER", &wrappers.rustc_wrapper)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env(STOW_BUILD_CAPTURE_DIR_ENV, workspace.capture_dir())
            .status()
            .await?;

        if !status.success() {
            return Err(stow_types::stow_error!(
                "cargo {} failed for {} {} on {} with status {}",
                phase.as_str(),
                task.crate_name,
                task.version,
                task.target,
                status
            ));
        }

        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            version = %task.version,
            target = %task.target,
            cargo_target_dir = %target_dir.display(),
            cargo_subcommand = phase.as_str(),
            rustc_capture_dir = %workspace.capture_dir().display(),
            "cargo phase completed"
        );
    }

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        cargo_subcommand = cargo_subcommand.as_str(),
        rustc_capture_dir = %workspace.capture_dir().display(),
        "cargo build completed"
    );

    Ok(workspace)
}

pub async fn read_built_manifest(workspace: &BuildWorkspace) -> stow_types::error::Result<String> {
    read_to_string(workspace.manifest_path())
        .await
        .map_err(Into::into)
}

fn merged_rustflags(remap_flag: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag.to_owned(),
    }
}

pub struct CargoFeatureArgs {
    no_default_features: bool,
    features: Vec<String>,
}

impl CargoFeatureArgs {
    pub(crate) fn from_task(task: &BuildTaskPayload) -> Self {
        // `FeaturesJson` is already validated (sorted + deduplicated + valid
        // feature names) at deserialize time, so we can read the canonical
        // list directly instead of re-parsing.
        let mut features: Vec<String> = task.features_json.features().to_vec();
        let no_default_features = !features.iter().any(|feature| feature == "default");
        features.retain(|feature| feature != "default");
        Self {
            no_default_features,
            features,
        }
    }

    pub(crate) fn apply(self, command: &mut Command) {
        if self.no_default_features {
            command.arg("--no-default-features");
        }
        if !self.features.is_empty() {
            command.arg("--features").arg(self.features.join(","));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoSubcommand {
    Build,
    Check,
    Test,
}

const fn cargo_phases(cargo_subcommand: CargoSubcommand) -> &'static [CargoSubcommand] {
    match cargo_subcommand {
        CargoSubcommand::Build => &[CargoSubcommand::Check, CargoSubcommand::Build],
        CargoSubcommand::Check => &[CargoSubcommand::Check],
        CargoSubcommand::Test => &[CargoSubcommand::Check, CargoSubcommand::Test],
    }
}

fn phase_target_dir(
    workspace: &BuildWorkspace,
    cargo_subcommand: CargoSubcommand,
    phase: CargoSubcommand,
) -> PathBuf {
    if phase == cargo_subcommand {
        return workspace.workspace_root().join("target");
    }
    workspace
        .workspace_root()
        .join(format!("target-{}", phase.as_str()))
}

impl CargoSubcommand {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Check => "check",
            Self::Test => "test",
        }
    }
}

/// Whether `target` is the triple this machine natively compiles for.
///
/// Decides whether the trusted build passes `--target`, which in turn decides
/// whether cargo splits its unit graph into host and target halves.
pub(crate) async fn target_is_host(target: &str) -> stow_types::error::Result<bool> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .await
        .map_err(|error| stow_types::stow_error!("run rustc -vV to detect host triple: {error}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| stow_types::stow_error!("rustc -vV output is not UTF-8: {error}"))?;
    let host = stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| stow_types::stow_error!("rustc -vV output has no host line"))?
        .trim();
    Ok(host == target)
}

fn cargo_subcommand() -> stow_types::error::Result<CargoSubcommand> {
    match std::env::var(STOW_BUILD_CARGO_SUBCOMMAND_ENV)
        .ok()
        .as_deref()
        .unwrap_or("build")
    {
        "build" => Ok(CargoSubcommand::Build),
        "check" => Ok(CargoSubcommand::Check),
        "test" => Ok(CargoSubcommand::Test),
        other => Err(stow_types::stow_error!(
            "{STOW_BUILD_CARGO_SUBCOMMAND_ENV} must be one of build/check/test, got {other}"
        )),
    }
}

async fn create_workspace_root() -> stow_types::error::Result<(Option<TempDir>, PathBuf)> {
    let Some(path) = std::env::var_os(STOW_BUILD_WORKSPACE_ROOT_ENV) else {
        let tempdir = TempDir::new()?;
        let workspace_root = tempdir.path().to_path_buf();
        return Ok((Some(tempdir), workspace_root));
    };

    let workspace_root = PathBuf::from(path);
    if workspace_root.exists() {
        return Err(stow_types::stow_error!(
            "{STOW_BUILD_WORKSPACE_ROOT_ENV} path already exists: {}",
            workspace_root.display()
        ));
    }
    create_dir_all(&workspace_root).await?;
    Ok((None, workspace_root))
}

async fn open_source_workspace() -> stow_types::error::Result<Option<BuildWorkspace>> {
    let Some(path) = std::env::var_os(STOW_BUILD_SOURCE_ROOT_ENV) else {
        return Ok(None);
    };

    let workspace_root = PathBuf::from(path);
    let manifest_path = workspace_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(stow_types::stow_error!(
            "{STOW_BUILD_SOURCE_ROOT_ENV} must point to a Cargo workspace root with Cargo.toml: {}",
            manifest_path.display()
        ));
    }

    let capture_dir = workspace_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing capture dir {}: {error}",
                    capture_dir.display()
                )
            })?;
    }
    create_dir_all(&capture_dir).await?;

    Ok(Some(BuildWorkspace {
        _tempdir: None,
        manifest_path,
        workspace_root,
        capture_dir,
    }))
}

async fn stabilize_workspace(
    workspace: BuildWorkspace,
    mirror_key: &workspace_mirror::MirrorTaskKey,
) -> stow_types::error::Result<BuildWorkspace> {
    let source_root = workspace.workspace_root().to_path_buf();
    let manifest_relative = workspace
        .manifest_path()
        .strip_prefix(workspace.workspace_root())
        .map_err(|_| {
            stow_types::stow_error!(
                "manifest path {} is outside workspace root {}",
                workspace.manifest_path().display(),
                workspace.workspace_root().display()
            )
        })?
        .to_path_buf();
    let mirror_key_owned = mirror_key.clone();
    let stable_root = smol::unblock(move || {
        workspace_mirror::materialize_workspace(&source_root, &mirror_key_owned)
    })
    .await?;
    if !mirror_key.preserve_lockfile {
        remove_bundled_lockfile(&stable_root)?;
    }
    remove_existing_phase_target_dirs(&stable_root).await?;
    let capture_dir = stable_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing capture dir {}: {error}",
                    capture_dir.display()
                )
            })?;
    }
    create_dir_all(&capture_dir).await?;

    Ok(BuildWorkspace {
        _tempdir: None,
        manifest_path: stable_root.join(manifest_relative),
        workspace_root: stable_root,
        capture_dir,
    })
}

async fn remove_existing_phase_target_dirs(workspace_root: &Path) -> stow_types::error::Result<()> {
    for dir_name in ["target", "target-check", "target-test"] {
        let target_dir = workspace_root.join(dir_name);
        if !target_dir.exists() {
            continue;
        }
        async_fs::remove_dir_all(&target_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing target dir {}: {error}",
                    target_dir.display()
                )
            })?;
    }
    Ok(())
}

fn sibling_runtime_wrapper(capture_wrapper: &Path) -> stow_types::error::Result<PathBuf> {
    let parent = capture_wrapper.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "cannot determine parent directory of capture wrapper {}",
            capture_wrapper.display()
        )
    })?;

    let stow = parent.join("stow");
    if stow.exists() {
        return Ok(stow);
    }

    let stow_cli = parent.join("stow-cli");
    if stow_cli.exists() {
        return Ok(stow_cli);
    }

    Err(stow_types::stow_error!(
        "neither 'stow' nor 'stow-cli' found next to capture wrapper {}",
        capture_wrapper.display()
    ))
}

async fn download_crate_manifest(
    task: &BuildTaskPayload,
    workspace_root: &Path,
) -> stow_types::error::Result<PathBuf> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        task.crate_name, task.version
    );
    let mut client = zenwave::client().follow_redirect();
    let response = client
        .get(&url)
        .map_err(|error| stow_types::stow_error!("build crates.io download request: {error}"))?
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "download crate {} {}: {error}",
                task.crate_name,
                task.version
            )
        })?;
    let body = response.into_body().into_bytes().await.map_err(|error| {
        stow_types::stow_error!(
            "read crate download body {} {}: {error}",
            task.crate_name,
            task.version
        )
    })?;

    let crate_name = task.crate_name.as_str().to_owned();
    let crate_version = task.version.to_string();
    let workspace_root = workspace_root.to_path_buf();
    smol::unblock(move || unpack_crate_archive(&workspace_root, &crate_name, &crate_version, &body))
        .await
}

fn unpack_crate_archive(
    workspace_root: &Path,
    crate_name: &str,
    crate_version: &str,
    compressed: &[u8],
) -> stow_types::error::Result<PathBuf> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed));
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(workspace_root).map_err(|error| {
        stow_types::stow_error!(
            "unpack crate archive {} {}: {error}",
            crate_name,
            crate_version
        )
    })?;

    let preferred_root = workspace_root.join(format!("{crate_name}-{crate_version}"));
    let source_root = if preferred_root.exists() {
        preferred_root
    } else {
        let mut top_dirs = std::fs::read_dir(workspace_root)
            .map_err(|error| {
                stow_types::stow_error!(
                    "read unpacked workspace root {}: {error}",
                    workspace_root.display()
                )
            })?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        top_dirs.sort();
        if top_dirs.len() != 1 {
            return Err(stow_types::stow_error!(
                "unexpected crate archive layout for {} {} under {}",
                crate_name,
                crate_version,
                workspace_root.display()
            ));
        }
        top_dirs.remove(0)
    };

    let manifest_path = source_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(stow_types::stow_error!(
            "downloaded crate source is missing Cargo.toml: {}",
            manifest_path.display()
        ));
    }
    Ok(manifest_path)
}

fn remove_bundled_lockfile(source_root: &Path) -> stow_types::error::Result<()> {
    let lockfile_path = source_root.join("Cargo.lock");
    if !lockfile_path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&lockfile_path).map_err(|error| {
        stow_types::stow_error!(
            "remove bundled Cargo.lock {}: {error}",
            lockfile_path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use tempfile::TempDir;

    use super::{remove_bundled_lockfile, unpack_crate_archive};

    #[test]
    fn unpack_crate_archive_keeps_bundled_lockfile_for_stabilize_stage() {
        let workspace_root = TempDir::new().expect("create workspace root");
        let archive_bytes = build_archive(
            "demo-1.2.3/Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
            "demo-1.2.3/Cargo.lock",
            b"# bundled lockfile",
        );

        let manifest_path =
            unpack_crate_archive(workspace_root.path(), "demo", "1.2.3", &archive_bytes)
                .expect("unpack crate archive");

        assert_eq!(
            manifest_path,
            workspace_root.path().join("demo-1.2.3/Cargo.toml")
        );
        assert!(
            workspace_root.path().join("demo-1.2.3/Cargo.lock").exists(),
            "unpack must not delete the bundled Cargo.lock; stabilize_workspace decides via preserve_lockfile"
        );
    }

    #[test]
    fn remove_bundled_lockfile_deletes_lockfile() {
        let source_root = TempDir::new().expect("create source root");
        std::fs::write(source_root.path().join("Cargo.lock"), "# stale lockfile")
            .expect("write lockfile");

        remove_bundled_lockfile(source_root.path()).expect("remove bundled lockfile");

        assert!(
            !source_root.path().join("Cargo.lock").exists(),
            "bundled Cargo.lock should be removed so CI resolves latest semver-compatible deps"
        );
    }

    fn build_archive(
        manifest_path: &str,
        manifest_bytes: &[u8],
        lockfile_path: &str,
        lockfile_bytes: &[u8],
    ) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append_file(&mut builder, manifest_path, manifest_bytes);
        append_file(&mut builder, lockfile_path, lockfile_bytes);
        let encoder = builder.into_inner().expect("finish tar archive");
        encoder.finish().expect("finish gzip archive")
    }

    fn append_file<W: Write>(builder: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(contents.len()).expect("contents length fits in u64"));
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, contents)
            .expect("append archive entry");
    }
}
