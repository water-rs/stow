//! Filesystem helpers shared across host crates.

use std::io;
use std::path::Path;

/// Remove `path` recursively, ignoring absence (`NotFound`).
///
/// When [`std::fs::remove_dir_all`] fails with `PermissionDenied` — for
/// example when a build script or copied workspace entry left a read-only
/// (`0444`/`0555`) directory or file behind — walks the tree without
/// following symlinks, grants owner write/search permissions on directories
/// (and clears read-only attributes on non-Unix files), and retries once.
///
/// # Errors
///
/// Returns the underlying I/O error if `path` cannot be made writable or
/// removed for any reason other than `NotFound`.
pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            make_tree_writable(path)?;
            match std::fs::remove_dir_all(path) {
                Ok(()) => Ok(()),
                Err(retry_error) if retry_error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(retry_error) => Err(retry_error),
            }
        }
        Err(error) => Err(error),
    }
}

fn make_tree_writable(root: &Path) -> io::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let meta = match std::fs::symlink_metadata(&dir) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        ensure_writable(&dir, &meta)?;
        if !meta.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let child_path = entry.path();
            let child_meta = match std::fs::symlink_metadata(&child_path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if child_meta.file_type().is_symlink() {
                continue;
            }
            if child_meta.is_dir() {
                stack.push(child_path);
            } else {
                ensure_writable(&child_path, &child_meta)?;
            }
        }
    }
    Ok(())
}

fn ensure_writable(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = meta.permissions().mode();
        let required = if meta.is_dir() { 0o700 } else { 0o200 };
        if (mode & required) != required {
            match std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | required)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            match std::fs::set_permissions(path, perms) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::remove_dir_all;

    #[test]
    fn missing_directory_is_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        remove_dir_all(&dir.path().join("does-not-exist")).expect("missing dir is ok");
    }

    #[cfg(unix)]
    #[test]
    fn read_only_nested_tree_and_symlinks_are_removed_safely() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).expect("outside dir");
        std::fs::write(outside.join("keep.txt"), b"keep").expect("outside file");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o555))
            .expect("chmod outside 0555");

        let target = dir.path().join("target");
        let nested_555 = target.join("a/b");
        let nested_444 = target.join("a/c");
        std::fs::create_dir_all(&nested_555).expect("nested 555");
        std::fs::create_dir_all(&nested_444).expect("nested 444");
        let ro_file = nested_555.join("file.txt");
        std::fs::write(&ro_file, b"hello").expect("write ro_file");
        std::fs::write(nested_444.join("hidden.txt"), b"world").expect("write hidden");
        symlink(&outside, target.join("a/link")).expect("create symlink");

        std::fs::set_permissions(&ro_file, std::fs::Permissions::from_mode(0o444))
            .expect("chmod file 0444");
        std::fs::set_permissions(&nested_555, std::fs::Permissions::from_mode(0o555))
            .expect("chmod 0555");
        std::fs::set_permissions(&nested_444, std::fs::Permissions::from_mode(0o444))
            .expect("chmod 0444");
        std::fs::set_permissions(target.join("a"), std::fs::Permissions::from_mode(0o555))
            .expect("chmod parent 0555");

        remove_dir_all(&target).expect("remove read-only tree");
        assert!(!target.exists());
        assert!(
            outside.join("keep.txt").exists(),
            "symlink target untouched"
        );
        assert_eq!(
            std::fs::metadata(&outside)
                .expect("outside meta")
                .permissions()
                .mode()
                & 0o777,
            0o555,
            "symlink target permissions untouched"
        );

        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755))
            .expect("restore outside perms for tempdir cleanup");
    }
}
