//! Build-script *output* types (vendored verbatim).
//!
//! `cargo::core::compiler::custom_build` runs `build.rs` binaries; the
//! resolver only needs the data types those runs would produce —
//! `BuildOutput`/`LibraryPath`/`LinkArgTarget` — because
//! `util::context::target` fills `links_overrides` with them when a config
//! file overrides a `links` build script. The parse helpers
//! (`parse_rustc_flags`/`parse_rustc_env`) are carried verbatim.

use std::path::PathBuf;

use anyhow::bail;

use crate::CargoResult;
use crate::core::Target;
use crate::core::compiler::CompileMode;

/// A path to add to the `-L` flags, in order of preference.
///
/// WARNING: Even though this type implements PartialOrd + Ord, this is a lexicographic ordering.
/// The linker line will require an explicit sorting algorithm. PartialOrd + Ord is derived because
/// BuildOutput requires it but that ordering is different from the one for the linker search path,
/// at least today.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum LibraryPath {
    /// The path is pointing within the output folder of the crate and takes priority over
    /// external paths when passed to the linker.
    CargoArtifact(PathBuf),
    /// The path is pointing outside of the crate's build location. The linker will always
    /// receive such paths after `CargoArtifact`.
    External(PathBuf),
}

impl LibraryPath {
    pub fn into_path_buf(self) -> PathBuf {
        match self {
            LibraryPath::CargoArtifact(p) | LibraryPath::External(p) => p,
        }
    }
}

impl AsRef<PathBuf> for LibraryPath {
    fn as_ref(&self) -> &PathBuf {
        match self {
            LibraryPath::CargoArtifact(p) | LibraryPath::External(p) => p,
        }
    }
}

/// Contains the parsed output of a custom build script.
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuildOutput {
    /// Paths to pass to rustc with the `-L` flag.
    pub library_paths: Vec<LibraryPath>,
    /// Names and link kinds of libraries, suitable for the `-l` flag.
    pub library_links: Vec<String>,
    /// Linker arguments suitable to be passed to `-C link-arg=<args>`
    pub linker_args: Vec<(LinkArgTarget, String)>,
    /// Various `--cfg` flags to pass to the compiler.
    pub cfgs: Vec<String>,
    /// Various `--check-cfg` flags to pass to the compiler.
    pub check_cfgs: Vec<String>,
    /// Additional environment variables to run the compiler with.
    pub env: Vec<(String, String)>,
    /// Metadata to pass to the immediate dependencies.
    pub metadata: Vec<(String, String)>,
    /// Paths to trigger a rerun of this build script.
    /// May be absolute or relative paths (relative to package root).
    pub rerun_if_changed: Vec<PathBuf>,
    /// Environment variables which, when changed, will cause a rebuild.
    pub rerun_if_env_changed: Vec<String>,
}

impl BuildOutput {
    /// Parses [`cargo::rustc-flags`] instruction.
    ///
    /// [`cargo::rustc-flags`]: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#cargorustc-flagsflags
    pub fn parse_rustc_flags(
        value: &str,
        whence: &str,
    ) -> CargoResult<(Vec<PathBuf>, Vec<String>)> {
        let value = value.trim();
        let mut flags_iter = value
            .split(|c: char| c.is_whitespace())
            .filter(|w| w.chars().any(|c| !c.is_whitespace()));
        let (mut library_paths, mut library_links) = (Vec::new(), Vec::new());

        while let Some(flag) = flags_iter.next() {
            if flag.starts_with("-l") || flag.starts_with("-L") {
                // Check if this flag has no space before the value as is
                // common with tools like pkg-config
                // e.g. -L/some/dir/local/lib or -licui18n
                let (flag, mut value) = flag.split_at(2);
                if value.is_empty() {
                    value = match flags_iter.next() {
                        Some(v) => v,
                        None => bail! {
                            "flag in rustc-flags has no value in {}: {}",
                            whence,
                            value
                        },
                    }
                }

                match flag {
                    "-l" => library_links.push(value.to_string()),
                    "-L" => library_paths.push(PathBuf::from(value)),

                    // This was already checked above
                    _ => unreachable!(),
                };
            } else {
                bail!(
                    "only `-l` and `-L` flags are allowed in {}: `{}`",
                    whence,
                    value
                )
            }
        }
        Ok((library_paths, library_links))
    }

    /// Parses [`cargo::rustc-env`] instruction.
    ///
    /// [`cargo::rustc-env`]: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rustc-env
    pub fn parse_rustc_env(value: &str, whence: &str) -> CargoResult<(String, String)> {
        match value.split_once('=') {
            Some((n, v)) => Ok((n.to_owned(), v.to_owned())),
            _ => bail!("Variable rustc-env has no value in {whence}: {value}"),
        }
    }
}

/// Represents one of the instructions from `cargo::rustc-link-arg-*` build
/// script instruction family.
///
/// In other words, indicates targets that custom linker arguments applies to.
///
/// See the [build script documentation][1] for more.
///
/// [1]: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#cargorustc-link-argflag
#[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkArgTarget {
    /// Represents `cargo::rustc-link-arg=FLAG`.
    All,
    /// Represents `cargo::rustc-cdylib-link-arg=FLAG`.
    Cdylib,
    /// Represents `cargo::rustc-link-arg-bins=FLAG`.
    Bin,
    /// Represents `cargo::rustc-link-arg-bin=BIN=FLAG`.
    SingleBin(String),
    /// Represents `cargo::rustc-link-arg-tests=FLAG`.
    Test,
    /// Represents `cargo::rustc-link-arg-benches=FLAG`.
    Bench,
    /// Represents `cargo::rustc-link-arg-examples=FLAG`.
    Example,
}

impl LinkArgTarget {
    /// Checks if this link type applies to a given [`Target`].
    pub fn applies_to(&self, target: &Target, mode: CompileMode) -> bool {
        let is_test = mode.is_any_test();
        match self {
            LinkArgTarget::All => true,
            LinkArgTarget::Cdylib => !is_test && target.is_cdylib(),
            LinkArgTarget::Bin => target.is_bin(),
            LinkArgTarget::SingleBin(name) => target.is_bin() && target.name() == name,
            LinkArgTarget::Test => target.is_test(),
            LinkArgTarget::Bench => target.is_bench(),
            LinkArgTarget::Example => target.is_exe_example(),
        }
    }
}
