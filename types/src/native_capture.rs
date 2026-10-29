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
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};

use crate::artifact::{NativeArtifacts, NativeLib, OutDirFile};
use crate::error::Context;

/// Capture the build-script products for one rustc invocation.
///
/// Returns `None` when the invocation had no build script `OUT_DIR`.
///
/// `OUT_DIR` and everything under it come from an untrusted build, so the
/// root is opened without following a symlink and every entry is opened
/// relative to a directory handle, also without following one: nothing the
/// build planted can lead the host outside the tree. A symlinked `OUT_DIR`,
/// or a symlinked `output` file, is an error.
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
    let build_dir_path = out_dir.parent().ok_or_else(|| {
        crate::stow_error!(
            "build script OUT_DIR {} for {crate_name} has no parent build dir",
            out_dir.display()
        )
    })?;
    let out_dir_name = out_dir.file_name().ok_or_else(|| {
        crate::stow_error!(
            "build script OUT_DIR {} for {crate_name} has no directory name",
            out_dir.display()
        )
    })?;
    let build_dir = Dir::open_ambient_dir(build_dir_path, ambient_authority())
        .wrap_err_with(|| format!("open build dir {}", build_dir_path.display()))?;

    let output_path = build_dir_path.join("output");
    let mut output_file = open_regular(&build_dir, OsStr::new("output")).map_err(|error| {
        crate::stow_error!(
            "build script output file {} for {crate_name} is unreadable or missing: {error}",
            output_path.display()
        )
    })?;
    let mut raw = String::new();
    output_file
        .read_to_string(&mut raw)
        .wrap_err_with(|| format!("read build script output {}", output_path.display()))?;
    let cargo_directives = parse_build_script_output(&raw);
    let (static_libs, out_dir_files) = match OutDirRoot::open_in(&build_dir, out_dir_name)? {
        Some(root) => root.collect()?,
        None => (Vec::new(), Vec::new()),
    };
    Ok(Some(NativeArtifacts {
        static_libs,
        cargo_directives,
        dep_env_vars: BTreeMap::new(),
        out_dir_files,
        original_out_dir: out_dir.to_path_buf(),
    }))
}

/// A build script's `OUT_DIR`, held as a directory handle.
///
/// Every access resolves relative to the handle and refuses to traverse a
/// symlink in any component it walks, so a path swapped for a link after the
/// handle was opened cannot lead outside the tree, whether the host is
/// capturing or packing.
#[derive(Debug)]
pub struct OutDirRoot {
    dir: Dir,
}

impl OutDirRoot {
    /// Open the `OUT_DIR` at `out_dir`, refusing a symlink at the root.
    ///
    /// Returns `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// The root being a symlink or not a directory, or any I/O failure.
    pub fn open(out_dir: &Path) -> crate::error::Result<Option<Self>> {
        let parent = out_dir.parent().ok_or_else(|| {
            crate::stow_error!("OUT_DIR {} has no parent build dir", out_dir.display())
        })?;
        let name = out_dir.file_name().ok_or_else(|| {
            crate::stow_error!("OUT_DIR {} has no directory name", out_dir.display())
        })?;
        let parent_dir = Dir::open_ambient_dir(parent, ambient_authority())
            .wrap_err_with(|| format!("open build dir {}", parent.display()))?;
        Self::open_in(&parent_dir, name)
    }

    fn open_in(parent: &Dir, name: &OsStr) -> crate::error::Result<Option<Self>> {
        match parent.open_dir_nofollow(name) {
            Ok(dir) => Ok(Some(Self { dir })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(crate::stow_error!(
                "open OUT_DIR {} without following symlinks: {error}",
                Path::new(name).display()
            )),
        }
    }

    /// Open the regular file at the `/`-separated `relative_path`, check its
    /// bytes hash to `expected_sha256` (the digest recorded at capture), and
    /// return it rewound to the start.
    ///
    /// # Errors
    ///
    /// A symlink in any component, a non-regular file, a digest mismatch, or
    /// any I/O failure.
    pub fn open_verified(
        &self,
        relative_path: &str,
        expected_sha256: &str,
    ) -> crate::error::Result<std::fs::File> {
        let (parents, name) = relative_path
            .rsplit_once('/')
            .map_or((None, relative_path), |(parents, name)| {
                (Some(parents), name)
            });
        let mut dir = None::<Dir>;
        for component in parents.into_iter().flat_map(|parents| parents.split('/')) {
            if matches!(component, "" | "." | "..") {
                return Err(crate::stow_error!(
                    "native relative path {relative_path} has a non-normal component"
                ));
            }
            let next = dir
                .as_ref()
                .unwrap_or(&self.dir)
                .open_dir_nofollow(component)
                .wrap_err_with(|| format!("open native out dir directory in {relative_path}"))?;
            dir = Some(next);
        }
        if matches!(name, "" | "." | "..") {
            return Err(crate::stow_error!(
                "native relative path {relative_path} has a non-normal component"
            ));
        }
        let file = open_regular(dir.as_ref().unwrap_or(&self.dir), OsStr::new(name))
            .wrap_err_with(|| format!("open native out dir file {relative_path}"))?;
        verify_digest(file.into_std(), relative_path, expected_sha256)
    }

    /// Walk the tree and hash every regular file. `.a`/`.lib` files
    /// additionally land in the libs by file name; every file (libs
    /// included) lands in the files by relative path. Symlinks and special
    /// files are skipped, never followed.
    fn collect(&self) -> crate::error::Result<(Vec<NativeLib>, Vec<OutDirFile>)> {
        let mut stack = vec![(
            self.dir.try_clone().wrap_err("clone OUT_DIR handle")?,
            String::new(),
        )];
        let mut static_libs = Vec::new();
        let mut out_dir_files = Vec::new();

        while let Some((dir, prefix)) = stack.pop() {
            for entry in dir
                .entries()
                .wrap_err_with(|| format!("read native out dir {prefix}"))?
            {
                let entry = entry.wrap_err_with(|| format!("read entry in {prefix}"))?;
                let name = entry.file_name();
                let name_str = name.to_str().ok_or_else(|| {
                    crate::stow_error!("native relative path under {prefix} is not UTF-8")
                })?;
                let relative_path = format!("{prefix}{name_str}");
                let file_type = entry
                    .file_type()
                    .wrap_err_with(|| format!("stat native out entry {relative_path}"))?;
                if file_type.is_dir() {
                    let child = dir.open_dir_nofollow(&name).wrap_err_with(|| {
                        format!("open native out dir {relative_path} without following symlinks")
                    })?;
                    stack.push((child, format!("{relative_path}/")));
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }

                let mut file = open_regular(&dir, &name)
                    .wrap_err_with(|| format!("open native artifact file {relative_path}"))?
                    .into_std();
                let sha256 = hash_file(&mut file)
                    .wrap_err_with(|| format!("read native artifact file {relative_path}"))?;
                if is_static_library(Path::new(name_str)) {
                    static_libs.push(NativeLib {
                        name: name_str.to_owned(),
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
}

/// Open `name` in `dir` for reading without following a symlink, and check
/// the opened handle (not the path) is a regular file.
fn open_regular(dir: &Dir, name: &OsStr) -> std::io::Result<cap_std::fs::File> {
    let file = dir.open_with(
        name,
        OpenOptions::new().read(true).follow(FollowSymlinks::No),
    )?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// Open the regular file at `path` without following a symlink at its final
/// component, and check the opened handle (not the path) is a regular file.
///
/// The parent directory is the host's own (cargo's `deps/`), so only the
/// file name is untrusted: it resolves relative to a directory handle with
/// the same no-follow discipline as [`OutDirRoot`].
///
/// # Errors
///
/// A symlink at `path`, a non-regular file, or any I/O failure.
pub fn open_regular_nofollow(path: &Path) -> crate::error::Result<std::fs::File> {
    let (dir, name) = parent_handle(path)?;
    let file = open_regular(&dir, name)
        .wrap_err_with(|| format!("open {} without following symlinks", path.display()))?;
    Ok(file.into_std())
}

/// [`open_regular_nofollow`], additionally requiring the bytes to hash to
/// `expected_sha256`; the handle is returned rewound, so a copy of it carries
/// exactly the verified bytes.
///
/// # Errors
///
/// As [`open_regular_nofollow`], or a digest mismatch.
pub fn open_verified_nofollow(
    path: &Path,
    expected_sha256: &str,
) -> crate::error::Result<std::fs::File> {
    let file = open_regular_nofollow(path)?;
    verify_digest(file, &path.display().to_string(), expected_sha256)
}

fn parent_handle(path: &Path) -> crate::error::Result<(Dir, &OsStr)> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::stow_error!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| crate::stow_error!("{} has no file name", path.display()))?;
    let dir = Dir::open_ambient_dir(parent, ambient_authority())
        .wrap_err_with(|| format!("open directory {}", parent.display()))?;
    Ok((dir, name))
}

/// Hash `file` from its start, require `expected_sha256`, and rewind it.
fn verify_digest(
    mut file: std::fs::File,
    what: &str,
    expected_sha256: &str,
) -> crate::error::Result<std::fs::File> {
    let actual = hash_file(&mut file).wrap_err_with(|| format!("hash {what}"))?;
    if actual != expected_sha256 {
        return Err(crate::stow_error!(
            "{what} changed since capture: sha256 {actual}, captured {expected_sha256}"
        ));
    }
    file.seek(SeekFrom::Start(0))
        .wrap_err_with(|| format!("rewind {what}"))?;
    Ok(file)
}

/// Hex SHA-256 of everything `file` yields from its current position.
///
/// # Errors
///
/// Any read failure.
pub fn hash_file(file: &mut std::fs::File) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
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

/// Whether `path` is named like a static library — what a consumer's
/// link takes out of an `OUT_DIR`.
#[must_use]
pub fn is_static_library(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext == "a" || ext == "lib")
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

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

    #[cfg(unix)]
    #[test]
    fn nofollow_open_refuses_a_symlink_and_checks_the_digest() {
        use super::{open_regular_nofollow, open_verified_nofollow};

        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real.rlib");
        std::fs::write(&real, b"bytes").expect("write");
        let link = dir.path().join("link.rlib");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let sha = hex::encode(sha2::Sha256::digest(b"bytes"));

        assert!(open_regular_nofollow(&link).is_err());
        assert!(open_verified_nofollow(&link, &sha).is_err());
        assert!(open_regular_nofollow(dir.path()).is_err());
        assert!(open_verified_nofollow(&real, &sha).is_ok());
        let error = open_verified_nofollow(&real, "00").expect_err("digest mismatch");
        assert!(
            error.to_string().contains("changed since capture"),
            "{error}"
        );
    }

    #[cfg(unix)]
    mod symlink_escape {
        use std::os::unix::fs::symlink;
        use std::path::Path;

        use super::super::{OutDirRoot, capture_native_artifacts};

        /// A build dir with an `output` file, plus a sibling directory
        /// outside the tree holding a secret.
        fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
            let root = tempfile::tempdir().expect("tempdir");
            let build_dir = root.path().join("build").join("demo-1");
            std::fs::create_dir_all(&build_dir).expect("create build dir");
            std::fs::write(build_dir.join("output"), "cargo:rustc-cfg=demo\n").expect("output");
            let outside = root.path().join("outside");
            std::fs::create_dir_all(&outside).expect("create outside");
            std::fs::write(outside.join("secret.a"), "host secret").expect("secret");
            (root, build_dir, outside)
        }

        #[test]
        fn symlinked_out_dir_root_is_rejected_by_capture() {
            let (_root, build_dir, outside) = fixture();
            symlink(&outside, build_dir.join("out")).expect("symlink out dir");

            let error = capture_native_artifacts("demo", Some(&build_dir.join("out")))
                .expect_err("a symlinked OUT_DIR must not be walked");
            assert!(
                error.to_string().contains("without following symlinks"),
                "{error}"
            );
        }

        #[test]
        fn symlinked_output_file_is_rejected_by_capture() {
            let (_root, build_dir, outside) = fixture();
            std::fs::remove_file(build_dir.join("output")).expect("remove output");
            symlink(outside.join("secret.a"), build_dir.join("output")).expect("symlink output");
            std::fs::create_dir(build_dir.join("out")).expect("out dir");

            capture_native_artifacts("demo", Some(&build_dir.join("out")))
                .expect_err("a symlinked output file must not be read");
        }

        #[test]
        fn symlinks_inside_out_dir_are_skipped_not_followed() {
            let (_root, build_dir, outside) = fixture();
            let out_dir = build_dir.join("out");
            std::fs::create_dir(&out_dir).expect("out dir");
            std::fs::write(out_dir.join("real.a"), "real").expect("real");
            symlink(&outside, out_dir.join("dir-link")).expect("dir link");
            symlink(outside.join("secret.a"), out_dir.join("file-link.a")).expect("file link");

            let native = capture_native_artifacts("demo", Some(&out_dir))
                .expect("capture")
                .expect("present");
            assert_eq!(
                native
                    .out_dir_files
                    .iter()
                    .map(|f| f.relative_path.as_str())
                    .collect::<Vec<_>>(),
                vec!["real.a"]
            );
        }

        /// Capture a tree holding `gen/lib.a`, return a root and the digest.
        fn captured(build_dir: &Path) -> (OutDirRoot, String) {
            let out_dir = build_dir.join("out");
            std::fs::create_dir_all(out_dir.join("gen")).expect("gen dir");
            std::fs::write(out_dir.join("gen").join("lib.a"), "captured").expect("lib");
            let native = capture_native_artifacts("demo", Some(&out_dir))
                .expect("capture")
                .expect("present");
            let sha = native.out_dir_files[0].sha256.clone();
            (
                OutDirRoot::open(&out_dir).expect("open").expect("present"),
                sha,
            )
        }

        #[test]
        fn file_swapped_for_a_symlink_after_capture_is_rejected() {
            let (_root, build_dir, outside) = fixture();
            let (root, sha) = captured(&build_dir);
            let file = build_dir.join("out").join("gen").join("lib.a");
            std::fs::remove_file(&file).expect("remove");
            symlink(outside.join("secret.a"), &file).expect("swap in link");

            root.open_verified("gen/lib.a", &sha)
                .expect_err("a swapped-in file symlink must not be opened");
        }

        #[test]
        fn directory_swapped_for_a_symlink_after_capture_is_rejected() {
            let (_root, build_dir, outside) = fixture();
            let (root, sha) = captured(&build_dir);
            let gen_dir = build_dir.join("out").join("gen");
            std::fs::remove_dir_all(&gen_dir).expect("remove");
            std::fs::write(outside.join("lib.a"), "captured").expect("same bytes outside");
            symlink(&outside, &gen_dir).expect("swap in link");

            root.open_verified("gen/lib.a", &sha)
                .expect_err("a swapped-in directory symlink must not be traversed");
        }

        #[test]
        fn out_dir_root_swapped_for_a_symlink_after_capture_is_rejected() {
            let (_root, build_dir, outside) = fixture();
            let (_held, _sha) = captured(&build_dir);
            let out_dir = build_dir.join("out");
            std::fs::remove_dir_all(&out_dir).expect("remove");
            std::fs::create_dir(outside.join("gen")).expect("gen");
            std::fs::write(outside.join("gen").join("lib.a"), "captured").expect("lib");
            symlink(&outside, &out_dir).expect("swap in link");

            // Packing opens the root afresh; the swapped root is refused.
            assert!(OutDirRoot::open(&out_dir).is_err());
        }

        #[test]
        fn regular_file_with_changed_bytes_is_rejected() {
            let (_root, build_dir, _outside) = fixture();
            let (root, sha) = captured(&build_dir);
            std::fs::write(build_dir.join("out").join("gen").join("lib.a"), "tampered")
                .expect("tamper");

            let error = root
                .open_verified("gen/lib.a", &sha)
                .expect_err("digest mismatch");
            assert!(
                error.to_string().contains("changed since capture"),
                "{error}"
            );
        }

        #[test]
        fn untouched_file_opens_and_is_rewound() {
            let (_root, build_dir, _outside) = fixture();
            let (root, sha) = captured(&build_dir);
            let mut file = root.open_verified("gen/lib.a", &sha).expect("opens");
            let mut contents = String::new();
            std::io::Read::read_to_string(&mut file, &mut contents).expect("read");
            assert_eq!(contents, "captured");
        }

        #[test]
        fn non_normal_relative_paths_are_rejected() {
            let (_root, build_dir, _outside) = fixture();
            let (root, sha) = captured(&build_dir);
            for bad in ["../output", "gen//lib.a", "./gen/lib.a", ""] {
                root.open_verified(bad, &sha).expect_err(bad);
            }
        }
    }
}
