//! The toolchain a build compiles with, resolved once.
//!
//! Every fact the cache path needs about rustc — where it is, which file
//! it is, the host triple it compiles for, its release and the CPU
//! `native` stands for — is read from the build's own rustc. The driver
//! resolves a [`BuildToolchain`] before cargo starts; a standalone wrapper
//! resolves one from its own rustc through the same code. A rustc spelling
//! a request carries is only ever compared against it, never run.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use async_process::Command;
use same_file::Handle;

use crate::rustc_args::{self, BuildRustc};

/// The build's rustc and the facts probed from it.
#[derive(Debug)]
pub struct BuildToolchain {
    /// The rustc file, resolved to the path it was found at.
    rustc: PathBuf,
    /// The rustc's file identity: what a request's executable is compared
    /// with.
    rustc_file: Handle,
    /// The configured `RUSTC_WORKSPACE_WRAPPER`, which cargo runs with the
    /// rustc as its first argument for workspace members.
    workspace_wrapper: Option<Handle>,
    /// The `PATH` bare spellings resolve through, read when the toolchain
    /// was resolved.
    search_path: OsString,
    /// The rustc's own `host:` triple — where a unit with no `--target`
    /// compiles, which is not the consumer target under a `--target` build.
    host_target: String,
    /// The rustc's `release:` version.
    release: String,
    /// The concrete CPU `native` resolves to, probed on first use.
    native_cpu: tokio::sync::OnceCell<Option<String>>,
}

impl BuildToolchain {
    /// Resolve the toolchain of the build's rustc from the driver's shared
    /// `rustc -vV`. `workspace_wrapper` is the configured
    /// `RUSTC_WORKSPACE_WRAPPER`, when there is one.
    ///
    /// # Errors
    ///
    /// A failed probe, or a rustc or wrapper that does not resolve to a
    /// file: the build fails there, as plain cargo would.
    pub async fn for_build(
        build_rustc: &BuildRustc,
        workspace_wrapper: Option<PathBuf>,
        vv: &rustc_args::SharedRustcVv,
    ) -> Result<Self, String> {
        let (spelling, vv) =
            tokio::join!(build_rustc.facade_spelling(), async { vv.clone().await });
        Self::from_probe(spelling?, workspace_wrapper, &vv?).await
    }

    /// Resolve the toolchain of the rustc a standalone wrapper was invoked
    /// for: the user's own process runs the user's own rustc.
    ///
    /// # Errors
    ///
    /// As [`Self::for_build`].
    pub async fn for_executable(executable: &OsStr) -> Result<Self, String> {
        let vv = rustc_args::rustc_vv(executable).await?;
        Self::from_probe(executable.to_owned(), None, &vv).await
    }

    async fn from_probe(
        spelling: OsString,
        workspace_wrapper: Option<PathBuf>,
        vv: &str,
    ) -> Result<Self, String> {
        let host_target = rustc_args::vv_host(vv)?;
        let release = rustc_args::vv_release(vv)?;
        let search_path = std::env::var_os("PATH").unwrap_or_default();
        let files = {
            let search_path = search_path.clone();
            tokio::task::spawn_blocking(move || {
                let (rustc, rustc_file) = resolve_file(&spelling, &search_path)?;
                let workspace_wrapper = workspace_wrapper
                    .map(|wrapper| resolve_file(wrapper.as_os_str(), &search_path))
                    .transpose()?
                    .map(|(_, file)| file);
                Ok::<_, String>((rustc, rustc_file, workspace_wrapper))
            })
            .await
            .map_err(|error| format!("join the rustc resolution task: {error}"))??
        };
        let (rustc, rustc_file, workspace_wrapper) = files;
        Ok(Self {
            rustc,
            rustc_file,
            workspace_wrapper,
            search_path,
            host_target,
            release,
            native_cpu: tokio::sync::OnceCell::new(),
        })
    }

    /// The compiling rustc's `host:` triple.
    #[must_use]
    pub fn host_target(&self) -> &str {
        &self.host_target
    }

    /// The compiling rustc's release version.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The rustc this toolchain is.
    #[must_use]
    pub fn rustc(&self) -> &Path {
        &self.rustc
    }

    /// The concrete CPU `rustc --print target-cpus` reports for `native`,
    /// probed once from this toolchain's rustc. `None` when the probe or
    /// its parse fails: `target-cpu=native` then classifies as unfoldable
    /// and the unit compiles uncached.
    pub async fn native_cpu(&self) -> Option<&str> {
        self.native_cpu
            .get_or_init(|| async {
                Command::new(&self.rustc)
                    .arg("--print")
                    .arg("target-cpus")
                    .output()
                    .await
                    .ok()
                    .filter(|output| output.status.success())
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .and_then(|stdout| parse_native_cpu(&stdout))
            })
            .await
            .as_deref()
    }

    /// Whether `spelling` names this toolchain's rustc file: a bare name
    /// resolves through the `PATH` the toolchain was resolved under, and
    /// the two files are compared by identity, not by string (stow#608).
    /// Stats the file system; callers run it off the runtime workers.
    #[must_use]
    pub fn is_rustc(&self, spelling: &OsStr) -> bool {
        names_file(spelling, &self.search_path, &self.rustc_file)
    }

    /// Whether `spelling` names the configured workspace wrapper.
    #[must_use]
    pub fn is_workspace_wrapper(&self, spelling: &OsStr) -> bool {
        self.workspace_wrapper
            .as_ref()
            .is_some_and(|wrapper| names_file(spelling, &self.search_path, wrapper))
    }
}

#[cfg(test)]
impl BuildToolchain {
    /// The test environment's own `rustc`, resolved through `PATH` as a
    /// standalone wrapper resolves its.
    pub async fn for_tests() -> std::sync::Arc<Self> {
        std::sync::Arc::new(
            Self::for_executable(OsStr::new("rustc"))
                .await
                .expect("resolve the test environment's rustc"),
        )
    }

    /// [`Self::for_tests`] with `wrapper` as the configured workspace
    /// wrapper.
    pub async fn for_tests_with_workspace_wrapper(wrapper: &Path) -> std::sync::Arc<Self> {
        let mut toolchain = Self::for_executable(OsStr::new("rustc"))
            .await
            .expect("resolve the test environment's rustc");
        toolchain.workspace_wrapper =
            Some(Handle::from_path(wrapper).expect("identify the workspace wrapper"));
        std::sync::Arc::new(toolchain)
    }

    /// [`Self::for_tests`] answering the host triple and release a test
    /// fixture names instead of the machine's own.
    pub async fn for_tests_with_facts(host_target: &str, release: &str) -> std::sync::Arc<Self> {
        let mut toolchain = Self::for_executable(OsStr::new("rustc"))
            .await
            .expect("resolve the test environment's rustc");
        host_target.clone_into(&mut toolchain.host_target);
        release.clone_into(&mut toolchain.release);
        std::sync::Arc::new(toolchain)
    }
}

/// The `native` line of `--print target-cpus` names the detected CPU:
/// `    native          - Select the CPU of the current host (currently
/// apple-m2).`
fn parse_native_cpu(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix("native")?;
        rest.split("currently ")
            .nth(1)?
            .split(')')
            .next()
            .map(str::to_owned)
    })
}

/// The file `spelling` resolves to under `search_path`, and its identity.
fn resolve_file(spelling: &OsStr, search_path: &OsStr) -> Result<(PathBuf, Handle), String> {
    let cwd =
        std::env::current_dir().map_err(|error| format!("resolve current directory: {error}"))?;
    let path = which::which_in(spelling, Some(search_path), &cwd)
        .map_err(|error| format!("resolve {}: {error}", Path::new(spelling).display()))?;
    let file = Handle::from_path(&path)
        .map_err(|error| format!("identify {}: {error}", path.display()))?;
    Ok((path, file))
}

fn names_file(spelling: &OsStr, search_path: &OsStr, target: &Handle) -> bool {
    resolve_file(spelling, search_path).is_ok_and(|(_, file)| file == *target)
}

#[cfg(test)]
mod tests {
    use super::parse_native_cpu;

    #[test]
    fn native_cpu_is_the_cpu_named_on_the_native_line() {
        let stdout = "Available CPUs for this target:\n    native          - Select the CPU of the current host (currently apple-m2).\n    generic\n";
        assert_eq!(parse_native_cpu(stdout).as_deref(), Some("apple-m2"));
        assert_eq!(parse_native_cpu("    generic\n"), None);
    }
}
