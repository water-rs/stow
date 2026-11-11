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

use same_file::Handle;

use crate::rustc_args::{self, BuildRustc};
use crate::session_env::SessionEnv;

/// The build's rustc and the facts probed from it.
#[derive(Debug)]
pub struct BuildToolchain {
    /// The rustc file, resolved to the path it was found at.
    rustc: PathBuf,
    /// The rustc's file identity: what a request's executable is compared
    /// with.
    rustc_file: Handle,
    /// The file the build's own rustc spelling resolves to — what the
    /// driver itself runs. Under rustup with no `RUSTC` set that is the
    /// `rustc` proxy on `PATH`, a different file from the toolchain's
    /// `<sysroot>/bin/rustc`; cargo hands its wrapper one or the other
    /// depending on whether it took its rustup bypass.
    launcher_file: Handle,
    /// The configured `RUSTC_WORKSPACE_WRAPPER`, which cargo runs with the
    /// rustc as its first argument for workspace members.
    workspace_wrapper: Option<Handle>,
    /// The environment the toolchain was resolved in: its `PATH` and
    /// working directory are what bare and relative spellings resolve
    /// against, and the rustc probes run in it.
    env: SessionEnv,
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
    /// `RUSTC_WORKSPACE_WRAPPER`, when there is one; `env` is the build's
    /// environment, which bare spellings resolve in.
    ///
    /// # Errors
    ///
    /// A failed probe, or a rustc or wrapper that does not resolve to a
    /// file: the build fails there, as plain cargo would.
    pub async fn for_build(
        build_rustc: &BuildRustc,
        workspace_wrapper: Option<PathBuf>,
        vv: &rustc_args::SharedRustcVv,
        env: &SessionEnv,
    ) -> Result<Self, String> {
        let (spelling, vv) =
            tokio::join!(build_rustc.facade_spelling(), async { vv.clone().await });
        Self::from_probe(
            spelling?,
            build_rustc.executable().to_owned(),
            workspace_wrapper,
            &vv?,
            env,
        )
        .await
    }

    /// Resolve the toolchain of the rustc a standalone wrapper was invoked
    /// for: the user's own process runs the user's own rustc, in the
    /// environment `env` names — its own.
    ///
    /// # Errors
    ///
    /// As [`Self::for_build`].
    pub async fn for_executable(executable: &OsStr, env: &SessionEnv) -> Result<Self, String> {
        let vv = rustc_args::rustc_vv(executable).await?;
        Self::from_probe(executable.to_owned(), executable.to_owned(), None, &vv, env).await
    }

    async fn from_probe(
        spelling: OsString,
        launcher: OsString,
        workspace_wrapper: Option<PathBuf>,
        vv: &str,
        env: &SessionEnv,
    ) -> Result<Self, String> {
        let host_target = rustc_args::vv_host(vv)?;
        let release = rustc_args::vv_release(vv)?;
        let env = env.clone();
        let (files, env) = tokio::task::spawn_blocking(move || {
            let (rustc, rustc_file) = resolve_file(&spelling, &env, env.cwd())?;
            let (_, launcher_file) = resolve_file(&launcher, &env, env.cwd())?;
            let workspace_wrapper = workspace_wrapper
                .map(|wrapper| resolve_file(wrapper.as_os_str(), &env, env.cwd()))
                .transpose()?
                .map(|(_, file)| file);
            Ok::<_, String>(((rustc, rustc_file, launcher_file, workspace_wrapper), env))
        })
        .await
        .map_err(|error| format!("join the rustc resolution task: {error}"))??;
        let (rustc, rustc_file, launcher_file, workspace_wrapper) = files;
        Ok(Self {
            rustc,
            rustc_file,
            launcher_file,
            workspace_wrapper,
            env,
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
                self.env
                    .command(&self.rustc)
                    .ok()?
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

    /// Whether `spelling`, written in a process running in `cwd`, names
    /// this toolchain's rustc — the toolchain file or the file the driver
    /// launches it through: a bare name resolves through the `PATH` the
    /// toolchain was resolved under, a relative path against `cwd`, and
    /// files are compared by identity, not by string (stow#608). Stats
    /// the file system; callers run it off the runtime workers.
    #[must_use]
    pub fn is_rustc(&self, spelling: &OsStr, cwd: &Path) -> bool {
        resolve_file(spelling, &self.env, cwd)
            .is_ok_and(|(_, file)| file == self.rustc_file || file == self.launcher_file)
    }

    /// Whether `spelling`, written in a process running in `cwd`, names
    /// the configured workspace wrapper.
    #[must_use]
    pub fn is_workspace_wrapper(&self, spelling: &OsStr, cwd: &Path) -> bool {
        self.workspace_wrapper
            .as_ref()
            .is_some_and(|wrapper| names_file(spelling, &self.env, cwd, wrapper))
    }
}

#[cfg(test)]
impl BuildToolchain {
    /// The test environment's own `rustc`, resolved through `PATH` as a
    /// standalone wrapper resolves its.
    pub async fn for_tests() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::of_the_test_rustc().await)
    }

    async fn of_the_test_rustc() -> Self {
        let env = SessionEnv::of_this_process().expect("the test process's environment");
        Self::for_executable(OsStr::new("rustc"), &env)
            .await
            .expect("resolve the test environment's rustc")
    }

    /// [`Self::for_tests`] with `wrapper` as the configured workspace
    /// wrapper.
    pub async fn for_tests_with_workspace_wrapper(wrapper: &Path) -> std::sync::Arc<Self> {
        let mut toolchain = Self::of_the_test_rustc().await;
        toolchain.workspace_wrapper =
            Some(Handle::from_path(wrapper).expect("identify the workspace wrapper"));
        std::sync::Arc::new(toolchain)
    }

    /// [`Self::for_tests`] answering the host triple and release a test
    /// fixture names instead of the machine's own.
    pub async fn for_tests_with_facts(host_target: &str, release: &str) -> std::sync::Arc<Self> {
        let mut toolchain = Self::of_the_test_rustc().await;
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

/// The file `spelling` resolves to — through `env`'s `PATH`, from `cwd` —
/// and its identity.
fn resolve_file(
    spelling: &OsStr,
    env: &SessionEnv,
    cwd: &Path,
) -> Result<(PathBuf, Handle), String> {
    let path = which::which_in(spelling, Some(env.search_path()), cwd)
        .map_err(|error| format!("resolve {}: {error}", Path::new(spelling).display()))?;
    let file = Handle::from_path(&path)
        .map_err(|error| format!("identify {}: {error}", path.display()))?;
    Ok((path, file))
}

fn names_file(spelling: &OsStr, env: &SessionEnv, cwd: &Path, target: &Handle) -> bool {
    resolve_file(spelling, env, cwd).is_ok_and(|(_, file)| file == *target)
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

    /// Cargo hands its wrapper the toolchain's own rustc or the spelling
    /// the driver launched — under rustup two different files. Both are
    /// the build's rustc; a third file is not.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_launcher_and_the_toolchain_file_are_both_the_builds_rustc() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let launcher = dir.path().join("launcher");
        let other = dir.path().join("other");
        for program in [&launcher, &other] {
            std::fs::write(program, b"#!/bin/sh\n").expect("write the program");
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o755))
                .expect("chmod the program");
        }
        let rustc = which::which("rustc").expect("the test machine has rustc on PATH");
        let vv = crate::rustc_args::rustc_vv(rustc.as_os_str())
            .await
            .expect("rustc -vV");
        let toolchain = super::BuildToolchain::from_probe(
            rustc.clone().into_os_string(),
            launcher.clone().into_os_string(),
            None,
            &vv,
            &crate::session_env::SessionEnv::of_this_process()
                .expect("the test process's environment"),
        )
        .await
        .expect("resolve the toolchain");
        let cwd = dir.path();
        assert!(toolchain.is_rustc(rustc.as_os_str(), cwd));
        assert!(toolchain.is_rustc(launcher.as_os_str(), cwd));
        assert!(!toolchain.is_rustc(other.as_os_str(), cwd));
    }
}
