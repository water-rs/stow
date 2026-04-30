use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use stow_types::error::Context;
use walkdir::{DirEntry, WalkDir};

const STABLE_MACOS_BASE: &str = "/private/tmp/stow-workspaces";
const STABLE_UNIX_BASE: &str = "/tmp/stow-workspaces";
const STABLE_WINDOWS_BASE: &str = "C:\\stow-workspaces";
const LOCKS_DIR: &str = "locks";
const READY_MARKER_FILE: &str = ".stow-workspace-ready";
const EXCLUDED_TOP_LEVEL_NAMES: &[&str] = &[".git", "target", ".stow-rustc-capture"];

pub fn materialize_workspace(source_root: &Path) -> stow_types::error::Result<PathBuf> {
    let source_root = source_root.canonicalize().wrap_err_with(|| {
        format!(
            "canonicalize source workspace root {}",
            source_root.display()
        )
    })?;
    let workspace_hash = compute_workspace_hash(&source_root)?;
    let base_root = stable_workspace_base();
    std::fs::create_dir_all(base_root.join(LOCKS_DIR))
        .wrap_err_with(|| format!("create stable workspace base {}", base_root.display()))?;
    let mirror_root = base_root.join(&workspace_hash);
    if mirror_root.exists() && mirror_is_ready(&mirror_root) {
        return Ok(mirror_root);
    }

    let lock_path = base_root
        .join(LOCKS_DIR)
        .join(format!("{workspace_hash}.lock"));
    let lock_file = open_lock_file(&lock_path)?;
    lock_file
        .lock_exclusive()
        .wrap_err_with(|| format!("lock stable workspace {}", lock_path.display()))?;

    let result = (|| {
        if mirror_root.exists() && mirror_is_ready(&mirror_root) {
            return Ok(mirror_root.clone());
        }
        if mirror_root.exists() {
            std::fs::remove_dir_all(&mirror_root).wrap_err_with(|| {
                format!(
                    "remove incomplete stable workspace {}",
                    mirror_root.display()
                )
            })?;
        }

        let temp_root = base_root.join(format!(
            "{}.tmp-{}-{}",
            workspace_hash,
            std::process::id(),
            now_nanos()?
        ));
        if temp_root.exists() {
            std::fs::remove_dir_all(&temp_root).wrap_err_with(|| {
                format!("remove stale temp stable workspace {}", temp_root.display())
            })?;
        }
        std::fs::create_dir_all(&temp_root)
            .wrap_err_with(|| format!("create temp stable workspace {}", temp_root.display()))?;

        let copy_result = populate_workspace(&source_root, &temp_root);
        if let Err(error) = copy_result {
            let _ = std::fs::remove_dir_all(&temp_root);
            return Err(error);
        }
        write_ready_marker(&temp_root)?;

        std::fs::rename(&temp_root, &mirror_root)
            .or_else(|rename_error| {
                // If another process raced us and the mirror already exists with a
                // valid ready marker, clean up our temp copy and proceed. Otherwise
                // the rename error is real and must propagate.
                let ready_marker = mirror_root.join(READY_MARKER_FILE);
                if ready_marker.exists() {
                    tracing::debug!(
                        mirror = %mirror_root.display(),
                        "workspace mirror already exists (concurrent create) — discarding temp copy"
                    );
                    std::fs::remove_dir_all(&temp_root).ok();
                    Ok(())
                } else {
                    Err(rename_error)
                }
            })
            .wrap_err_with(|| {
                format!(
                    "move stable workspace {} into place at {}",
                    temp_root.display(),
                    mirror_root.display()
                )
            })?;

        Ok(mirror_root.clone())
    })();

    let unlock_result = lock_file.unlock();
    match (result, unlock_result) {
        (Ok(path), Ok(())) => Ok(path),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(stow_types::stow_error!(
            "unlock stable workspace {}: {error}",
            lock_path.display()
        )),
        (Err(error), Err(_)) => Err(error),
    }
}

fn mirror_is_ready(mirror_root: &Path) -> bool {
    mirror_root.join("Cargo.toml").is_file() && mirror_root.join(READY_MARKER_FILE).is_file()
}

fn write_ready_marker(root: &Path) -> stow_types::error::Result<()> {
    let marker = root.join(READY_MARKER_FILE);
    std::fs::write(&marker, b"ready")
        .wrap_err_with(|| format!("write stable workspace marker {}", marker.display()))
}

fn compute_workspace_hash(source_root: &Path) -> stow_types::error::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stow-workspace-v1");

    for entry in WalkDir::new(source_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| should_include_entry(source_root, entry))
    {
        let entry = entry?;
        let path = entry.path();
        if path == source_root {
            continue;
        }
        let relative = path.strip_prefix(source_root).wrap_err_with(|| {
            format!(
                "strip workspace prefix {} from {}",
                source_root.display(),
                path.display()
            )
        })?;
        hash_path_component(&mut hasher, relative);
        if entry.file_type().is_dir() {
            hasher.update(b"dir");
            continue;
        }
        if entry.file_type().is_symlink() {
            hasher.update(b"symlink");
            let target = std::fs::read_link(path)
                .wrap_err_with(|| format!("read workspace symlink {}", path.display()))?;
            hash_path_component(&mut hasher, &target);
            continue;
        }
        if entry.file_type().is_file() {
            hasher.update(b"file");
            let bytes = std::fs::read(path)
                .wrap_err_with(|| format!("read workspace file {}", path.display()))?;
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            continue;
        }
        return Err(stow_types::stow_error!(
            "unsupported workspace entry type {}",
            path.display()
        ));
    }

    Ok(hasher.finalize().to_hex().to_string())
}

fn populate_workspace(source_root: &Path, mirror_root: &Path) -> stow_types::error::Result<()> {
    for entry in WalkDir::new(source_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| should_include_entry(source_root, entry))
    {
        let entry = entry?;
        let path = entry.path();
        if path == source_root {
            continue;
        }
        let relative = path.strip_prefix(source_root).wrap_err_with(|| {
            format!(
                "strip workspace prefix {} from {}",
                source_root.display(),
                path.display()
            )
        })?;
        let destination = mirror_root.join(relative);

        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&destination).wrap_err_with(|| {
                format!("create stable workspace dir {}", destination.display())
            })?;
            continue;
        }

        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .wrap_err_with(|| format!("create stable workspace parent {}", parent.display()))?;
        }

        if entry.file_type().is_symlink() {
            let target = std::fs::read_link(path)
                .wrap_err_with(|| format!("read workspace symlink {}", path.display()))?;
            create_symlink(&target, &destination).wrap_err_with(|| {
                format!(
                    "create stable workspace symlink {} -> {}",
                    destination.display(),
                    target.display()
                )
            })?;
            continue;
        }

        if entry.file_type().is_file() {
            reflink::reflink_or_copy(path, &destination).wrap_err_with(|| {
                format!(
                    "copy workspace file {} into stable mirror {}",
                    path.display(),
                    destination.display()
                )
            })?;
            let metadata = std::fs::metadata(path)
                .wrap_err_with(|| format!("read workspace metadata {}", path.display()))?;
            std::fs::set_permissions(&destination, metadata.permissions()).wrap_err_with(|| {
                format!(
                    "set stable workspace permissions on {}",
                    destination.display()
                )
            })?;
            continue;
        }

        return Err(stow_types::stow_error!(
            "unsupported workspace entry type {}",
            path.display()
        ));
    }

    Ok(())
}

fn should_include_entry(source_root: &Path, entry: &DirEntry) -> bool {
    if entry.path() == source_root {
        return true;
    }
    let Ok(relative) = entry.path().strip_prefix(source_root) else {
        return false;
    };
    let mut components = relative.components();
    let Some(first) = components.next() else {
        return true;
    };
    !EXCLUDED_TOP_LEVEL_NAMES.contains(&first.as_os_str().to_string_lossy().as_ref())
}

fn hash_path_component(hasher: &mut blake3::Hasher, path: &Path) {
    let encoded = path.to_string_lossy();
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(encoded.as_bytes());
}

fn open_lock_file(path: &Path) -> stow_types::error::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open stable workspace lock {}", path.display()))
}

fn now_nanos() -> stow_types::error::Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| stow_types::stow_error!("system clock before UNIX_EPOCH: {error}"))?
        .as_nanos())
}

fn stable_workspace_base() -> PathBuf {
    if cfg!(target_os = "macos") {
        return PathBuf::from(STABLE_MACOS_BASE);
    }
    if cfg!(windows) {
        return PathBuf::from(STABLE_WINDOWS_BASE);
    }
    PathBuf::from(STABLE_UNIX_BASE)
}

#[cfg(unix)]
fn create_symlink(target: &Path, destination: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, destination)
}

#[cfg(windows)]
fn create_symlink(target: &Path, destination: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(target)?;
    if metadata.file_type().is_dir() {
        std::os::windows::fs::symlink_dir(target, destination)
    } else {
        std::os::windows::fs::symlink_file(target, destination)
    }
}
