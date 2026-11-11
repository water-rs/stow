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

    /// The `PATH` bare program names resolve through.
    #[must_use]
    pub fn search_path(&self) -> &OsStr {
        self.var_os("PATH").unwrap_or_default()
    }

    /// A command that runs `program` in this environment: `program`
    /// resolves through this environment's `PATH` and working directory,
    /// the child starts with exactly this environment, and its working
    /// directory is this one until the caller sets its own.
    ///
    /// # Errors
    ///
    /// `program` does not resolve to an executable.
    pub fn command(
        &self,
        program: impl AsRef<OsStr>,
    ) -> stow_types::error::Result<async_process::Command> {
        let program = program.as_ref();
        let path = which::which_in(program, Some(self.search_path()), &self.cwd)
            .wrap_err_with(|| format!("resolve {}", Path::new(program).display()))?;
        let mut command = async_process::Command::new(path);
        command
            .env_clear()
            .envs(self.environ.iter().map(|(name, value)| (name, value)))
            .current_dir(&self.cwd);
        Ok(command)
    }
}

#[cfg(test)]
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

    /// A session over exactly `vars`, in the test's own working directory.
    pub fn for_tests<const N: usize>(vars: [(&str, &OsStr); N]) -> Self {
        Self::new(
            vars.into_iter()
                .map(|(name, value)| (OsString::from(name), value.to_owned()))
                .collect(),
            std::env::current_dir().expect("the test's working directory"),
        )
    }
}
