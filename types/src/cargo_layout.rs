//! Where cargo lays out a unit's files in its build directory.
//!
//! Cargo hands every unit one directory: rustc's `--out-dir`, or a build
//! script's `OUT_DIR`. Everything stow derives from cargo's layout — the
//! build directory a build writes under, a unit's fingerprint directory,
//! the file a build script's stdout lands in, the program cargo runs as a
//! build script, the unit a dependency's artifact belongs to — is read off
//! that directory here and nowhere else.
//!
//! Cargo writes one of two layouts (`src/cargo/core/compiler/layout.rs`
//! and `build_runner/compilation_files.rs` in rust-lang/cargo):
//!
//! - [`Layout::Shared`], cargo's only stable layout up to 1.99, and in
//!   1.100 the one `__CARGO_TEMPORARY_BUILD_DIR_NEW_LAYOUT_OPT_OUT=1`
//!   selects: units share `<profile>/deps` (examples `<profile>/examples`),
//!   a build script compiles into `<profile>/build/<package>-<hash>` and
//!   runs with `OUT_DIR` `<profile>/build/<package>-<hash>/out`, its stdout
//!   in the sibling `output`, and fingerprints live in
//!   `<profile>/.fingerprint/<package>-<hash>`.
//! - [`Layout::BuildUnit`], the default from 1.100 (and on nightly since
//!   1.99): every unit owns `<profile>/build/<package>/<hash>`, holding
//!   `out` (its `--out-dir`, or a build script run's `OUT_DIR`),
//!   `fingerprint`, and for a build script run `run/stdout`.
//!
//! `<hash>` is cargo's unit hash, always 16 lowercase hex digits
//! (`UnitHash`'s `{:016x}` display), which is what tells the two apart:
//! the directory above a build-unit `out` is exactly a hash, the one above
//! a shared `out` is `<package>-<hash>`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Which of cargo's two build-directory layouts a directory belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Shared `deps`, `examples`, `.fingerprint` and `build/<package>-<hash>`.
    Shared,
    /// One `build/<package>/<hash>` directory per unit.
    BuildUnit,
}

/// A directory that is not one cargo hands a unit in either layout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{} is not an output directory of cargo's build-directory layout \
     (<profile>/deps, <profile>/examples, <profile>/build/<package>-<hash>[/out] \
     or <profile>/build/<package>/<hash>/out)",
    path.display()
)]
pub struct NotInLayout {
    path: PathBuf,
}

/// A directory one unit compiles into, or one build script runs with as
/// its `OUT_DIR`, placed in cargo's layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitDir {
    path: PathBuf,
    profile: PathBuf,
    place: Place,
}

/// What the directory is in its layout.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Place {
    /// `<profile>/deps`, `<profile>/examples` or
    /// `<profile>/deps/artifact/<package>-<hash>/<kind>`: shared by many
    /// units, which tell themselves apart by `-C extra-filename`.
    SharedDeps,
    /// `<profile>/build/<package>-<hash>`: a compiled build script.
    SharedBuildScript,
    /// `<profile>/build/<package>-<hash>/out`: a build script run's
    /// `OUT_DIR`.
    SharedOutDir,
    /// `<profile>/build/<package>/<hash>/out`, or an artifact
    /// dependency's `<profile>/build/<package>/<hash>/artifact/<kind>`.
    BuildUnit {
        /// `<profile>/build/<package>/<hash>`.
        unit: PathBuf,
        /// `<hash>`.
        hash: String,
    },
}

/// The kinds an artifact dependency's directory is named after
/// (`compilation_files.rs`, `artifact_dir`).
const ARTIFACT_KINDS: [&str; 3] = ["bin", "cdylib", "staticlib"];

impl UnitDir {
    /// Place `path` — absolute, as cargo spells `--out-dir` and `OUT_DIR` —
    /// in cargo's layout.
    ///
    /// # Errors
    ///
    /// `path` is not a directory cargo hands a unit in either layout.
    pub fn new(path: &Path) -> Result<Self, NotInLayout> {
        place(path)
            .map(|(profile, place)| Self {
                path: path.to_path_buf(),
                profile,
                place,
            })
            .ok_or_else(|| NotInLayout {
                path: path.to_path_buf(),
            })
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `<build-dir>[/<triple>]/<profile>`, the directory every unit of one
    /// profile lies under.
    #[must_use]
    pub fn profile_dir(&self) -> &Path {
        &self.profile
    }

    /// The layout the directory belongs to.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        match self.place {
            Place::SharedDeps | Place::SharedBuildScript | Place::SharedOutDir => Layout::Shared,
            Place::BuildUnit { .. } => Layout::BuildUnit,
        }
    }

    /// The directory of cargo's fingerprint for the unit of `package`
    /// that compiled into this directory with `-C extra-filename`
    /// `extra_filename`: `<profile>/.fingerprint/<package><extra>` in the
    /// shared layout, `<unit>/fingerprint` in the build-unit one.
    #[must_use]
    pub fn fingerprint_dir(&self, package: &str, extra_filename: &str) -> PathBuf {
        match &self.place {
            Place::BuildUnit { unit, .. } => unit.join("fingerprint"),
            Place::SharedDeps | Place::SharedBuildScript | Place::SharedOutDir => self
                .profile
                .join(".fingerprint")
                .join(format!("{package}{extra_filename}")),
        }
    }

    /// The file a build script that ran with this directory as its
    /// `OUT_DIR` wrote its stdout to, as the directories and the file name
    /// under the directory's parent: `output` in the shared layout
    /// (`BuildScriptRunFiles`), `run/stdout` in the build-unit one.
    ///
    /// # Errors
    ///
    /// The directory is one a build script never runs with.
    pub fn build_script_stdout(
        &self,
    ) -> Result<(&'static [&'static str], &'static str), NotInLayout> {
        match self.place {
            Place::SharedOutDir => Ok((&[], "output")),
            Place::BuildUnit { .. } if self.path.file_name() == Some(OsStr::new("out")) => {
                Ok((&["run"], "stdout"))
            }
            Place::SharedDeps | Place::SharedBuildScript | Place::BuildUnit { .. } => {
                Err(NotInLayout {
                    path: self.path.clone(),
                })
            }
        }
    }

    /// The program cargo runs for the build script `crate_name` compiled
    /// into this directory, before any executable suffix: the target name
    /// (`build-script-build`) in the shared layout, where cargo links it
    /// beside rustc's output, and rustc's own output named after the crate
    /// in the build-unit one (`custom_build.rs`). `None` for a directory no
    /// build script compiles into.
    #[must_use]
    pub fn build_script_program(&self, crate_name: &str) -> Option<PathBuf> {
        match self.place {
            Place::SharedBuildScript => Some(self.path.join(crate_name.replace('_', "-"))),
            Place::BuildUnit { .. } if self.path.file_name() == Some(OsStr::new("out")) => {
                Some(self.path.join(crate_name))
            }
            Place::SharedDeps | Place::SharedOutDir | Place::BuildUnit { .. } => None,
        }
    }

    /// The name of the unit that wrote `file_stem` into this directory —
    /// `<crate><extra>`, the stem of a rustc output with any `lib` prefix
    /// already dropped — as `<crate>-<unit hash>`, or `None` when the
    /// stem carries no unit hash.
    ///
    /// Shared directories hold many units, so the hash is the stem's own
    /// `-<16 hex>` tail. A build-unit directory holds one, and names it:
    /// cargo leaves the hash off a dylib's, cdylib's or executable's file
    /// name there, so the directory's hash stands in, and a stem that
    /// already ends in it is not counted twice.
    #[must_use]
    pub fn unit_name(&self, file_stem: &str) -> Option<String> {
        match &self.place {
            Place::BuildUnit { hash, .. } => {
                let crate_name = file_stem
                    .strip_suffix(hash.as_str())
                    .and_then(|stem| stem.strip_suffix('-'))
                    .unwrap_or(file_stem);
                (!crate_name.is_empty()).then(|| format!("{crate_name}-{hash}"))
            }
            Place::SharedDeps | Place::SharedBuildScript | Place::SharedOutDir => {
                let (crate_name, hash) = file_stem.rsplit_once('-')?;
                (!crate_name.is_empty() && is_unit_hash(hash)).then(|| file_stem.to_owned())
            }
        }
    }
}

/// The profile directory and place of `path`, when cargo lays a unit out
/// there.
fn place(path: &Path) -> Option<(PathBuf, Place)> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent()?;
    let parent_name = parent.file_name().and_then(OsStr::to_str);
    if name == "out" {
        if let Some((profile, unit, hash)) = build_unit(parent) {
            return Some((profile, Place::BuildUnit { unit, hash }));
        }
        if parent_name.is_some_and(is_shared_unit_name) {
            return Some((build_profile(parent.parent()?)?, Place::SharedOutDir));
        }
        return None;
    }
    if is_shared_unit_name(name) {
        return Some((build_profile(parent)?, Place::SharedBuildScript));
    }
    if name == "deps" || name == "examples" {
        return Some((parent.to_path_buf(), Place::SharedDeps));
    }
    if ARTIFACT_KINDS.contains(&name) {
        if parent_name == Some("artifact")
            && let Some((profile, unit, hash)) = build_unit(parent.parent()?)
        {
            return Some((profile, Place::BuildUnit { unit, hash }));
        }
        let artifact = parent.parent()?;
        let deps = artifact.parent()?;
        if parent_name.is_some_and(is_shared_unit_name)
            && artifact.file_name() == Some(OsStr::new("artifact"))
            && deps.file_name() == Some(OsStr::new("deps"))
        {
            return Some((deps.parent()?.to_path_buf(), Place::SharedDeps));
        }
    }
    None
}

/// `<profile>`, `<profile>/build/<package>/<hash>` and `<hash>` of a
/// build-unit directory `unit`.
fn build_unit(unit: &Path) -> Option<(PathBuf, PathBuf, String)> {
    let hash = unit.file_name()?.to_str()?;
    if !is_unit_hash(hash) {
        return None;
    }
    let package = unit.parent()?;
    package.file_name()?;
    Some((
        build_profile(package.parent()?)?,
        unit.to_path_buf(),
        hash.to_owned(),
    ))
}

/// The profile directory a `<profile>/build` directory `build` lies in.
fn build_profile(build: &Path) -> Option<PathBuf> {
    if build.file_name() != Some(OsStr::new("build")) {
        return None;
    }
    build.parent().map(Path::to_path_buf)
}

/// Whether `name` is a shared layout's `<package>-<hash>`.
fn is_shared_unit_name(name: &str) -> bool {
    name.rsplit_once('-')
        .is_some_and(|(package, hash)| !package.is_empty() && is_unit_hash(hash))
}

/// Whether `text` is a cargo unit hash: 16 lowercase hex digits.
fn is_unit_hash(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Layout, UnitDir};

    const PROFILE: &str = "/proj/target/debug";

    fn unit(path: &str) -> UnitDir {
        UnitDir::new(Path::new(path)).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn every_unit_directory_of_the_shared_layout_names_its_profile() {
        for (path, profile) in [
            ("/proj/target/debug/deps", PROFILE),
            ("/proj/target/release-lto/deps", "/proj/target/release-lto"),
            ("/proj/target/debug/examples", PROFILE),
            ("/proj/target/debug/build/serde-0123456789abcdef", PROFILE),
            (
                "/proj/target/debug/build/serde-0123456789abcdef/out",
                PROFILE,
            ),
            (
                "/proj/target/debug/deps/artifact/tool-0123456789abcdef/bin",
                PROFILE,
            ),
            (
                "/proj/target/aarch64-apple-darwin/debug/build/cc-0123456789abcdef/out",
                "/proj/target/aarch64-apple-darwin/debug",
            ),
        ] {
            let dir = unit(path);
            assert_eq!(dir.profile_dir(), Path::new(profile), "{path}");
            assert_eq!(dir.layout(), Layout::Shared, "{path}");
        }
    }

    #[test]
    fn every_unit_directory_of_the_build_unit_layout_names_its_profile() {
        for (path, profile) in [
            (
                "/proj/target/debug/build/serde/0123456789abcdef/out",
                PROFILE,
            ),
            (
                "/proj/target/debug/build/smoke-crate/95898b630903615e/out",
                PROFILE,
            ),
            (
                "/proj/target/debug/build/tool/0123456789abcdef/artifact/cdylib",
                PROFILE,
            ),
            (
                "/proj/target/wasm32-unknown-unknown/release/build/cc/0123456789abcdef/out",
                "/proj/target/wasm32-unknown-unknown/release",
            ),
            // A package named `build` keeps its place.
            (
                "/proj/target/debug/build/build/0123456789abcdef/out",
                PROFILE,
            ),
        ] {
            let dir = unit(path);
            assert_eq!(dir.profile_dir(), Path::new(profile), "{path}");
            assert_eq!(dir.layout(), Layout::BuildUnit, "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_out_dir_with_mixed_separators_is_placed() {
        // The `OUT_DIR` cargo 1.100 printed on a Windows runner.
        let dir =
            unit(r"D:\a\stow\smoke-crate\target\debug\build\smoke-crate/e808bfe7d7f8a9e0\out");
        assert_eq!(dir.layout(), Layout::BuildUnit);
        assert_eq!(
            dir.profile_dir(),
            Path::new(r"D:\a\stow\smoke-crate\target\debug")
        );
    }

    #[test]
    fn a_directory_outside_either_layout_is_refused_by_name() {
        for path in [
            "/tmp/out",
            "/proj/target",
            "/",
            "/proj/target/debug/other",
            "/proj/target/debug/build",
            // A hash that is not cargo's: wrong length, upper case.
            "/proj/target/debug/build/serde-0123abcd/out",
            "/proj/target/debug/build/serde/0123456789ABCDEF/out",
            "/proj/target/debug/build/serde/0123456789abcdef",
            "/proj/target/debug/build/serde/0123456789abcdef/fingerprint",
            "/proj/target/debug/notbuild/serde/0123456789abcdef/out",
        ] {
            let error = UnitDir::new(Path::new(path)).expect_err(path);
            assert!(error.to_string().starts_with(path), "{error}");
        }
    }

    #[test]
    fn the_fingerprint_follows_the_layout() {
        assert_eq!(
            unit("/proj/target/debug/deps")
                .fingerprint_dir("new_debug_unreachable", "-0123456789abcdef"),
            PathBuf::from("/proj/target/debug/.fingerprint/new_debug_unreachable-0123456789abcdef")
        );
        assert_eq!(
            unit("/proj/target/debug/build/new_debug_unreachable/0123456789abcdef/out")
                .fingerprint_dir("new_debug_unreachable", "-0123456789abcdef"),
            PathBuf::from(
                "/proj/target/debug/build/new_debug_unreachable/0123456789abcdef/fingerprint"
            )
        );
    }

    #[test]
    fn a_build_scripts_stdout_follows_the_layout() {
        assert_eq!(
            unit("/proj/target/debug/build/zstd-sys-0123456789abcdef/out").build_script_stdout(),
            Ok((&[][..], "output"))
        );
        assert_eq!(
            unit("/proj/target/debug/build/zstd-sys/0123456789abcdef/out").build_script_stdout(),
            Ok((&["run"][..], "stdout"))
        );
        for path in [
            "/proj/target/debug/deps",
            "/proj/target/debug/build/zstd-sys-0123456789abcdef",
            "/proj/target/debug/build/tool/0123456789abcdef/artifact/bin",
        ] {
            assert!(unit(path).build_script_stdout().is_err(), "{path}");
        }
    }

    #[test]
    fn the_build_script_program_follows_the_layout() {
        assert_eq!(
            unit("/proj/target/debug/build/zstd-sys-0123456789abcdef")
                .build_script_program("build_script_build"),
            Some(PathBuf::from(
                "/proj/target/debug/build/zstd-sys-0123456789abcdef/build-script-build"
            ))
        );
        assert_eq!(
            unit("/proj/target/debug/build/zstd-sys/0123456789abcdef/out")
                .build_script_program("build_script_build"),
            Some(PathBuf::from(
                "/proj/target/debug/build/zstd-sys/0123456789abcdef/out/build_script_build"
            ))
        );
        assert_eq!(
            unit("/proj/target/debug/deps").build_script_program("build_script_build"),
            None
        );
        assert_eq!(
            unit("/proj/target/debug/build/zstd-sys-0123456789abcdef/out")
                .build_script_program("build_script_build"),
            None
        );
    }

    #[test]
    fn a_unit_is_named_by_crate_and_hash_in_either_layout() {
        let shared = unit("/proj/target/debug/deps");
        assert_eq!(
            shared.unit_name("serde-0123456789abcdef").as_deref(),
            Some("serde-0123456789abcdef")
        );
        // A shared directory's file without a hash names no unit.
        assert_eq!(shared.unit_name("serde"), None);
        assert_eq!(shared.unit_name("-0123456789abcdef"), None);

        let build_unit = unit("/proj/target/debug/build/serde/0123456789abcdef/out");
        for stem in ["serde-0123456789abcdef", "serde"] {
            assert_eq!(
                build_unit.unit_name(stem).as_deref(),
                Some("serde-0123456789abcdef"),
                "{stem}"
            );
        }
    }
}
