use std::path::{Path, PathBuf};

use async_fs::{create_dir_all, read_to_string, write};
use async_process::Command;
use stow_types::api::BuildTaskPayload;
use tempfile::TempDir;

use crate::capture::STOW_BUILD_CAPTURE_DIR_ENV;
use crate::workspace_mirror;
use crate::wrapper_shim;

const CARGO_TEMPLATE: &str = include_str!("assets/Cargo.toml.tmpl");
const LIB_TEMPLATE: &str = include_str!("assets/lib.rs.tmpl");
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
    let src_dir = workspace_root.join("src");
    let capture_dir = workspace_root.join(".stow-rustc-capture");
    create_dir_all(&src_dir).await?;
    create_dir_all(&capture_dir).await?;

    let manifest = CARGO_TEMPLATE
        .replace("{{crate_name}}", &task.crate_name)
        .replace("{{crate_version}}", &task.version);
    let lib_rs = LIB_TEMPLATE.to_owned();

    let manifest_path = workspace_root.join("Cargo.toml");
    write(&manifest_path, manifest).await?;
    write(src_dir.join("lib.rs"), lib_rs).await?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        manifest_path = %manifest_path.display(),
        "created CI build workspace"
    );

    Ok(BuildWorkspace {
        _tempdir: tempdir,
        manifest_path,
        workspace_root,
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
    let runtime_wrapper = sibling_runtime_wrapper(&capture_wrapper);
    let wrapper = wrapper_shim::materialize_wrapper_shim(&runtime_wrapper, &capture_wrapper)?;
    let mut command = Command::new("cargo");
    command.arg(cargo_subcommand.as_str());
    if cargo_subcommand == CargoSubcommand::Test {
        command.arg("--no-run");
    }
    let status = command
        .arg("--manifest-path")
        .arg(workspace.manifest_path())
        .arg("--target")
        .arg(&task.target)
        .env("RUSTFLAGS", rustflags)
        .env("RUSTC_WRAPPER", &wrapper)
        .env(STOW_BUILD_CAPTURE_DIR_ENV, workspace.capture_dir())
        .status()
        .await?;

    if !status.success() {
        return Err(eyre::eyre!(
            "cargo build failed for {} {} on {} with status {}",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoSubcommand {
    Build,
    Check,
    Test,
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

fn sibling_runtime_wrapper(capture_wrapper: &Path) -> PathBuf {
    let stow = capture_wrapper
        .parent()
        .map(|parent| parent.join("stow"))
        .unwrap_or_else(|| PathBuf::from("stow"));
    if stow.exists() {
        return stow;
    }

    let stow_cli = capture_wrapper
        .parent()
        .map(|parent| parent.join("stow-cli"))
        .unwrap_or_else(|| PathBuf::from("stow-cli"));
    if stow_cli.exists() {
        return stow_cli;
    }

    capture_wrapper.to_path_buf()
}
