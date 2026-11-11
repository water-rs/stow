//! The environment a build's analysis runs in, as a value.
//!
//! The analysis of a build — the unit-graph query, the cache key, the
//! toolchain resolution — reads the environment and working directory the
//! build was started in, which is not the process that runs the analysis
//! once a daemon does. A [`SessionEnv`] carries exactly those inputs, so a
//! process answers for the build it serves and never for its own start-up
//! state.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use stow_types::env_name;
use stow_types::error::Context as _;

/// The environment, working directory and cargo home one build runs in.
#[derive(Debug, Clone)]
pub struct SessionEnv {
    environ: Vec<(OsString, OsString)>,
    cwd: PathBuf,
    /// Where cargo reads its user-level config and keeps its registry,
    /// resolved from `environ` the way cargo does. `None` when neither
    /// `CARGO_HOME` nor a home directory is available.
    cargo_home: Option<PathBuf>,
}

impl SessionEnv {
    /// A session over `environ` and `cwd`; the cargo home is resolved from
    /// them.
    #[must_use]
    pub fn new(environ: Vec<(OsString, OsString)>, cwd: PathBuf) -> Self {
        // The home `CARGO_HOME` falls back to is this environment's too.
        let cargo_home = crate::config::cargo_home_with(|key| {
            environ
                .iter()
                .find(|(name, _)| env_name::eq(name, key))
                .map(|(_, value)| value.clone())
        });
        Self {
            environ,
            cwd,
            cargo_home,
        }
    }

    /// The environment and working directory of this process: what a
    /// command run by the user starts with.
    ///
    /// # Errors
    ///
    /// The working directory cannot be read.
    pub fn of_this_process() -> stow_types::error::Result<Self> {
        let cwd = std::env::current_dir().wrap_err("resolve current directory")?;
        Ok(Self::new(std::env::vars_os().collect(), cwd))
    }

    /// Every variable, in the order the process listed them.
    #[must_use]
    pub fn environ(&self) -> &[(OsString, OsString)] {
        &self.environ
    }

    /// The working directory bare and relative spellings resolve against.
    #[must_use]
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Cargo's home directory in this environment.
    #[must_use]
    pub fn cargo_home(&self) -> Option<&Path> {
        self.cargo_home.as_deref()
    }

    /// The value of `key`; a name compares as the platform compares
    /// variable names.
    #[must_use]
    pub fn var_os(&self, key: &str) -> Option<&OsStr> {
        self.environ
            .iter()
            .find(|(name, _)| env_name::eq(name, key))
            .map(|(_, value)| value.as_os_str())
    }

    /// The home directory this environment names, as cargo resolves it.
    #[must_use]
    pub fn home_dir(&self) -> Option<PathBuf> {
        crate::config::home_dir_with(|key| self.var_os(key).map(OsStr::to_owned))
    }

    /// The file `program`, written in a process running in `cwd`, names
    /// in this environment: a bare name through this environment's `PATH`
    /// — and on Windows its `PATHEXT` — a relative path against `cwd`.
    /// Every variable the lookup reads is this environment's, never the
    /// resolving process's: a daemon resolves for the build it serves.
    ///
    /// # Errors
    ///
    /// `program` does not resolve to an executable.
    pub fn resolve_program(&self, program: &OsStr, cwd: &Path) -> which::Result<PathBuf> {
        which::WhichConfig::new_with_sys(BuildSys(self))
            .binary_name(program.to_owned())
            .custom_cwd(cwd.to_owned())
            .first_result()
    }

    /// A command that runs `program` in this environment: `program`
    /// resolves as [`Self::resolve_program`] resolves it from this
    /// environment's working directory, the child starts with exactly
    /// this environment, and its working directory is this one until the
    /// caller sets its own.
    ///
    /// # Errors
    ///
    /// `program` does not resolve to an executable.
    pub fn command(
        &self,
        program: impl AsRef<OsStr>,
    ) -> stow_types::error::Result<async_process::Command> {
        let program = program.as_ref();
        let path = self
            .resolve_program(program, &self.cwd)
            .wrap_err_with(|| format!("resolve {}", Path::new(program).display()))?;
        let mut command = async_process::Command::new(path);
        command
            .env_clear()
            .envs(self.environ.iter().map(|(name, value)| (name, value)))
            .current_dir(&self.cwd);
        Ok(command)
    }
}

/// The system as a program lookup sees it from inside one build's
/// environment: the variables `which` reads — `PATH`, `PATHEXT`, the home
/// directory `~` expands to — and the working directory are the build's;
/// the file system is the machine's. `which`'s own system answers the
/// variables from the resolving process, which in a daemon is not the
/// build's: a daemon a client started runs with a cleared environment.
struct BuildSys<'env>(&'env SessionEnv);

impl which::sys::Sys for BuildSys<'_> {
    type ReadDirEntry = <which::sys::RealSys as which::sys::Sys>::ReadDirEntry;
    type Metadata = <which::sys::RealSys as which::sys::Sys>::Metadata;

    fn is_windows(&self) -> bool {
        which::sys::RealSys.is_windows()
    }

    fn current_dir(&self) -> std::io::Result<PathBuf> {
        Ok(self.0.cwd.clone())
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.0.home_dir()
    }

    fn env_split_paths(&self, paths: &OsStr) -> Vec<PathBuf> {
        which::sys::RealSys.env_split_paths(paths)
    }

    fn env_path(&self) -> Option<OsString> {
        self.0.var_os("PATH").map(OsStr::to_owned)
    }

    fn env_path_ext(&self) -> Option<OsString> {
        self.0.var_os("PATHEXT").map(OsStr::to_owned)
    }

    fn metadata(&self, path: &Path) -> std::io::Result<Self::Metadata> {
        which::sys::RealSys.metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> std::io::Result<Self::Metadata> {
        which::sys::RealSys.symlink_metadata(path)
    }

    fn read_dir(
        &self,
        path: &Path,
    ) -> std::io::Result<Box<dyn Iterator<Item = std::io::Result<Self::ReadDirEntry>>>> {
        which::sys::RealSys.read_dir(path)
    }

    fn is_valid_executable(&self, path: &Path) -> std::io::Result<bool> {
        which::sys::RealSys.is_valid_executable(path)
    }
}

impl SessionEnv {
    /// This environment with `key` set to `value`, the cargo home
    /// re-resolved.
    #[must_use]
    pub fn with_var(self, key: &str, value: impl AsRef<OsStr>) -> Self {
        let mut environ = self.environ;
        environ.retain(|(name, _)| !env_name::eq(name, key));
        environ.push((OsString::from(key), value.as_ref().to_owned()));
        Self::new(environ, self.cwd)
    }
}

#[cfg(test)]
impl SessionEnv {
    /// A session over exactly `vars`, in the test's own working directory.
    ///
    /// # Panics
    ///
    /// The test's working directory cannot be read.
    #[must_use]
    pub fn for_tests<const N: usize>(vars: [(&str, &OsStr); N]) -> Self {
        Self::new(
            vars.into_iter()
                .map(|(name, value)| (OsString::from(name), value.to_owned()))
                .collect(),
            std::env::current_dir().expect("the test's working directory"),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    use super::SessionEnv;

    /// An executable named `stem` — `stem.exe` on Windows — in `dir`.
    fn executable_in(dir: &Path, stem: &str) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let program = dir.join(stem);
            std::fs::write(&program, b"#!/bin/sh\n").expect("write the program");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("make the program executable");
            program
        }
        #[cfg(windows)]
        {
            // A lookup checks the file is an executable image, so the
            // program is a real one: the test machine's rustc.
            let program = dir.join(format!("{stem}.exe"));
            std::fs::copy(
                which::which("rustc").expect("the test machine has rustc on PATH"),
                &program,
            )
            .expect("copy an executable");
            program
        }
    }

    /// A bare name resolves through the environment's `PATH`, which here
    /// names a directory the test process's own `PATH` does not.
    #[test]
    fn a_bare_name_resolves_through_the_environments_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = executable_in(dir.path(), "stow-probe");
        let mut vars = vec![(OsString::from("PATH"), dir.path().as_os_str().to_owned())];
        if cfg!(windows) {
            vars.push((OsString::from("PATHEXT"), OsString::from(".EXE")));
        }
        let env = SessionEnv::new(vars, dir.path().to_path_buf());
        let found = env
            .resolve_program(OsStr::new("stow-probe"), dir.path())
            .expect("the environment's PATH holds the program");
        assert_eq!(
            std::fs::canonicalize(found).expect("resolve the found program"),
            std::fs::canonicalize(program).expect("resolve the program")
        );
    }

    /// Windows completes a bare name with the extensions `PATHEXT` lists:
    /// the environment's list, never the resolving process's. A daemon a
    /// client started runs with none, and a bare `rustc` must still name
    /// the build's `rustc.exe`.
    #[cfg(windows)]
    #[test]
    fn a_bare_name_takes_its_extension_from_the_environments_pathext() {
        let dir = tempfile::tempdir().expect("tempdir");
        executable_in(dir.path(), "stow-probe");
        let path = (OsString::from("PATH"), dir.path().as_os_str().to_owned());
        assert!(
            std::env::var_os("PATHEXT").is_some(),
            "the test process lists extensions of its own"
        );
        let with = SessionEnv::new(
            vec![
                path.clone(),
                (OsString::from("PATHEXT"), OsString::from(".COM;.EXE")),
            ],
            dir.path().to_path_buf(),
        );
        with.resolve_program(OsStr::new("stow-probe"), dir.path())
            .expect("the environment's PATHEXT completes the name");
        let without = SessionEnv::new(vec![path], dir.path().to_path_buf());
        without
            .resolve_program(OsStr::new("stow-probe"), dir.path())
            .expect_err("an environment without PATHEXT completes no name");
    }

    /// With no `CARGO_HOME`, cargo's home is `.cargo` under the home
    /// directory the environment names, not the resolving process's.
    #[test]
    fn the_cargo_home_falls_back_to_the_environments_home() {
        let home = tempfile::tempdir().expect("home");
        let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let env = SessionEnv::new(
            vec![(OsString::from(variable), home.path().as_os_str().to_owned())],
            home.path().to_path_buf(),
        );
        assert_eq!(env.cargo_home(), Some(home.path().join(".cargo").as_path()));
        assert_eq!(env.home_dir().as_deref(), Some(home.path()));
    }
}
