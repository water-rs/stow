use std::path::{Path, PathBuf};

use async_fs::{create_dir_all, read_to_string};
use async_process::Command;
use stow_types::api::BuildTaskPayload;
use tempfile::TempDir;
use zenwave::Client;

use crate::capture::STOW_BUILD_CAPTURE_DIR_ENV;
use crate::workspace_mirror;
use crate::wrapper_shim;

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

pub async fn create_workspace(task: &BuildTaskPayload) -> eyre::Result<BuildWorkspace> {
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
            eyre::eyre!(
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

pub async fn build(task: &BuildTaskPayload) -> eyre::Result<BuildWorkspace> {
    let workspace = stabilize_workspace(create_workspace(task).await?).await?;
    let remap_flag = format!(
        "--remap-path-prefix={}={}",
        workspace.workspace_root().display(),
        "stow-ci://workspace"
    );
    let rustflags = merged_rustflags(&remap_flag);
    let cargo_subcommand = cargo_subcommand()?;

    let capture_wrapper = std::env::current_exe()
        .map_err(|error| eyre::eyre!("resolve current stow-build executable: {error}"))?;
    let runtime_wrapper = sibling_runtime_wrapper(&capture_wrapper)?;
    let wrappers = wrapper_shim::materialize_wrapper_shims(&runtime_wrapper, &capture_wrapper)?;
    for &phase in cargo_phases(cargo_subcommand) {
        let target_dir = phase_target_dir(&workspace, cargo_subcommand, phase);
        let mut command = Command::new("cargo");
        command.arg(phase.as_str());
        if phase == CargoSubcommand::Test {
            command.arg("--no-run");
        }
        CargoFeatureArgs::from_task(task)?.apply(&mut command);
        let status = command
            .arg("--manifest-path")
            .arg(workspace.manifest_path())
            .arg("--target")
            .arg(&task.target)
            .env("RUSTUP_TOOLCHAIN", &task.rustc_version)
            .env("RUSTFLAGS", &rustflags)
            .env("RUSTC_WRAPPER", &wrappers.rustc_wrapper)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env(STOW_BUILD_CAPTURE_DIR_ENV, workspace.capture_dir())
            .status()
            .await?;

        if !status.success() {
            return Err(eyre::eyre!(
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

pub async fn read_built_manifest(workspace: &BuildWorkspace) -> eyre::Result<String> {
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

pub(crate) struct CargoFeatureArgs {
    no_default_features: bool,
    features: Vec<String>,
}

impl CargoFeatureArgs {
    pub(crate) fn from_task(task: &BuildTaskPayload) -> eyre::Result<Self> {
        let mut features = serde_json::from_str::<Vec<String>>(task.features_json.as_str())
            .map_err(|error| eyre::eyre!("parse task features_json: {error}"))?;
        for feature in &features {
            if feature.is_empty()
                || feature.len() > 128
                || !feature
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            {
                return Err(eyre::eyre!("invalid task feature name: {feature}"));
            }
        }
        if features.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(eyre::eyre!(
                "task features_json must be sorted and deduplicated"
            ));
        }

        let no_default_features = !features.iter().any(|feature| feature == "default");
        features.retain(|feature| feature != "default");
        Ok(Self {
            no_default_features,
            features,
        })
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

fn cargo_phases(cargo_subcommand: CargoSubcommand) -> &'static [CargoSubcommand] {
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
    fn as_str(self) -> &'static str {
        match self {
            CargoSubcommand::Build => "build",
            CargoSubcommand::Check => "check",
            CargoSubcommand::Test => "test",
        }
    }
}

fn cargo_subcommand() -> eyre::Result<CargoSubcommand> {
    match std::env::var(STOW_BUILD_CARGO_SUBCOMMAND_ENV)
        .ok()
        .as_deref()
        .unwrap_or("build")
    {
        "build" => Ok(CargoSubcommand::Build),
        "check" => Ok(CargoSubcommand::Check),
        "test" => Ok(CargoSubcommand::Test),
        other => Err(eyre::eyre!(
            "{STOW_BUILD_CARGO_SUBCOMMAND_ENV} must be one of build/check/test, got {other}"
        )),
    }
}

async fn create_workspace_root() -> eyre::Result<(Option<TempDir>, PathBuf)> {
    let Some(path) = std::env::var_os(STOW_BUILD_WORKSPACE_ROOT_ENV) else {
        let tempdir = TempDir::new()?;
        let workspace_root = tempdir.path().to_path_buf();
        return Ok((Some(tempdir), workspace_root));
    };

    let workspace_root = PathBuf::from(path);
    if workspace_root.exists() {
        return Err(eyre::eyre!(
            "{STOW_BUILD_WORKSPACE_ROOT_ENV} path already exists: {}",
            workspace_root.display()
        ));
    }
    create_dir_all(&workspace_root).await?;
    Ok((None, workspace_root))
}

async fn open_source_workspace() -> eyre::Result<Option<BuildWorkspace>> {
    let Some(path) = std::env::var_os(STOW_BUILD_SOURCE_ROOT_ENV) else {
        return Ok(None);
    };

    let workspace_root = PathBuf::from(path);
    let manifest_path = workspace_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(eyre::eyre!(
            "{STOW_BUILD_SOURCE_ROOT_ENV} must point to a Cargo workspace root with Cargo.toml: {}",
            manifest_path.display()
        ));
    }

    let capture_dir = workspace_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                eyre::eyre!(
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

async fn stabilize_workspace(workspace: BuildWorkspace) -> eyre::Result<BuildWorkspace> {
    let source_root = workspace.workspace_root().to_path_buf();
    let manifest_relative = workspace
        .manifest_path()
        .strip_prefix(workspace.workspace_root())
        .map_err(|_| {
            eyre::eyre!(
                "manifest path {} is outside workspace root {}",
                workspace.manifest_path().display(),
                workspace.workspace_root().display()
            )
        })?
        .to_path_buf();
    let stable_root =
        smol::unblock(move || workspace_mirror::materialize_workspace(&source_root)).await?;
    remove_bundled_lockfile(&stable_root)?;
    remove_existing_phase_target_dirs(&stable_root).await?;
    let capture_dir = stable_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                eyre::eyre!(
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

async fn remove_existing_phase_target_dirs(workspace_root: &Path) -> eyre::Result<()> {
    for dir_name in ["target", "target-check", "target-test"] {
        let target_dir = workspace_root.join(dir_name);
        if !target_dir.exists() {
            continue;
        }
        async_fs::remove_dir_all(&target_dir)
            .await
            .map_err(|error| {
                eyre::eyre!(
                    "remove existing target dir {}: {error}",
                    target_dir.display()
                )
            })?;
    }
    Ok(())
}

fn sibling_runtime_wrapper(capture_wrapper: &Path) -> eyre::Result<PathBuf> {
    let parent = capture_wrapper.parent().ok_or_else(|| {
        eyre::eyre!(
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

    Err(eyre::eyre!(
        "neither 'stow' nor 'stow-cli' found next to capture wrapper {}",
        capture_wrapper.display()
    ))
}

async fn download_crate_manifest(
    task: &BuildTaskPayload,
    workspace_root: &Path,
) -> eyre::Result<PathBuf> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        task.crate_name, task.version
    );
    let mut client = zenwave::client().follow_redirect();
    let response = client
        .get(&url)
        .map_err(|error| eyre::eyre!("build crates.io download request: {error}"))?
        .await
        .map_err(|error| {
            eyre::eyre!(
                "download crate {} {}: {error}",
                task.crate_name,
                task.version
            )
        })?;
    let body = response.into_body().into_bytes().await.map_err(|error| {
        eyre::eyre!(
            "read crate download body {} {}: {error}",
            task.crate_name,
            task.version
        )
    })?;

    let crate_name = task.crate_name.clone();
    let crate_version = task.version.clone();
    let workspace_root = workspace_root.to_path_buf();
    smol::unblock(move || unpack_crate_archive(&workspace_root, &crate_name, &crate_version, &body))
        .await
}

fn unpack_crate_archive(
    workspace_root: &Path,
    crate_name: &str,
    crate_version: &str,
    compressed: &[u8],
) -> eyre::Result<PathBuf> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed));
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(workspace_root).map_err(|error| {
        eyre::eyre!(
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
                eyre::eyre!(
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
            return Err(eyre::eyre!(
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
        return Err(eyre::eyre!(
            "downloaded crate source is missing Cargo.toml: {}",
            manifest_path.display()
        ));
    }
    remove_bundled_lockfile(&source_root)?;
    Ok(manifest_path)
}

fn remove_bundled_lockfile(source_root: &Path) -> eyre::Result<()> {
    let lockfile_path = source_root.join("Cargo.lock");
    if !lockfile_path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&lockfile_path).map_err(|error| {
        eyre::eyre!(
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

    use super::unpack_crate_archive;

    #[test]
    fn unpack_crate_archive_removes_bundled_lockfile() {
        let workspace_root = TempDir::new().expect("create workspace root");
        let archive_bytes = build_archive(
            "demo-1.2.3/Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
            "demo-1.2.3/Cargo.lock",
            b"# stale lockfile",
        );

        let manifest_path =
            unpack_crate_archive(workspace_root.path(), "demo", "1.2.3", &archive_bytes)
                .expect("unpack crate archive");

        assert_eq!(
            manifest_path,
            workspace_root.path().join("demo-1.2.3/Cargo.toml")
        );
        assert!(
            !workspace_root.path().join("demo-1.2.3/Cargo.lock").exists(),
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
