use std::path::{Path, PathBuf};

use async_fs::{create_dir_all, read_to_string, write};
use async_process::Command;
use stow_types::api::BuildTaskPayload;
use tempfile::TempDir;

const CARGO_TEMPLATE: &str = include_str!("assets/Cargo.toml.tmpl");
const LIB_TEMPLATE: &str = include_str!("assets/lib.rs.tmpl");

pub struct BuildWorkspace {
    _tempdir: TempDir,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
}

impl BuildWorkspace {
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }
}

pub async fn create_workspace(task: &BuildTaskPayload) -> eyre::Result<BuildWorkspace> {
    let tempdir = TempDir::new()?;
    let workspace_root = tempdir.path().to_path_buf();
    let src_dir = workspace_root.join("src");
    create_dir_all(&src_dir).await?;

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
    })
}

pub async fn build(task: &BuildTaskPayload) -> eyre::Result<BuildWorkspace> {
    let workspace = create_workspace(task).await?;
    let remap_flag = format!(
        "--remap-path-prefix={}={}",
        workspace.workspace_root().display(),
        "stow-ci://workspace"
    );
    let rustflags = merged_rustflags(&remap_flag);

    let status = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(workspace.manifest_path())
        .arg("--target")
        .arg(&task.target)
        .env("RUSTFLAGS", rustflags)
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
        "cargo build completed"
    );

    Ok(workspace)
}

pub async fn read_built_manifest(workspace: &BuildWorkspace) -> eyre::Result<String> {
    read_to_string(workspace.manifest_path()).await.map_err(Into::into)
}

fn merged_rustflags(remap_flag: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag.to_owned(),
    }
}
