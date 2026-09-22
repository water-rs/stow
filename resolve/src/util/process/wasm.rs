//! `wasm32` implementation of the `cargo-util` process surface.
//!
//! There is no process model on `wasm32-unknown-unknown`: every exec
//! entry point returns the same `could_not_execute` error cargo produces
//! for unspawnable binaries. The builder API is kept identical so vendored
//! code that *constructs* probe commands compiles unchanged; those commands
//! are never executed on wasm because rustc/target data is injected.

use anyhow::Result;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, ExitStatus, Output};

use super::error::ProcessError;

/// Placeholder for `jobserver::Client` — uninhabited: a jobserver cannot
/// exist on wasm, so `GlobalContext::jobserver_from_env` is always `None`
/// and this is never constructed.
#[derive(Debug)]
pub enum JobserverClient {}

#[derive(Clone, Debug)]
pub struct ProcessBuilder {
    program: OsString,
    arg0: Option<OsString>,
    args: Vec<OsString>,
    env: BTreeMap<String, Option<OsString>>,
    cwd: Option<OsString>,
    wrappers: Vec<OsString>,
    display_env_vars: bool,
}

impl ProcessBuilder {
    pub fn new<T: AsRef<OsStr>>(cmd: T) -> ProcessBuilder {
        ProcessBuilder {
            program: cmd.as_ref().to_os_string(),
            arg0: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            wrappers: Vec::new(),
            display_env_vars: false,
        }
    }

    pub fn program<T: AsRef<OsStr>>(&mut self, program: T) -> &mut ProcessBuilder {
        self.program = program.as_ref().to_os_string();
        self
    }

    pub fn arg0<T: AsRef<OsStr>>(&mut self, arg: T) -> &mut ProcessBuilder {
        self.arg0 = Some(arg.as_ref().to_os_string());
        self
    }

    pub fn arg<T: AsRef<OsStr>>(&mut self, arg: T) -> &mut ProcessBuilder {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<T: AsRef<OsStr>>(&mut self, args: &[T]) -> &mut ProcessBuilder {
        self.args
            .extend(args.iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn args_replace<T: AsRef<OsStr>>(&mut self, args: &[T]) -> &mut ProcessBuilder {
        self.args = args.iter().map(|a| a.as_ref().to_os_string()).collect();
        self
    }

    pub fn cwd<T: AsRef<OsStr>>(&mut self, path: T) -> &mut ProcessBuilder {
        self.cwd = Some(path.as_ref().to_os_string());
        self
    }

    pub fn env<T: AsRef<OsStr>>(&mut self, key: &str, val: T) -> &mut ProcessBuilder {
        self.env
            .insert(key.to_string(), Some(val.as_ref().to_os_string()));
        self
    }

    pub fn env_remove(&mut self, key: &str) -> &mut ProcessBuilder {
        self.env.insert(key.to_string(), None);
        self
    }

    pub fn get_program(&self) -> &OsString {
        &self.program
    }

    pub fn get_arg0(&self) -> Option<&OsStr> {
        self.arg0.as_deref()
    }

    pub fn get_args(&self) -> impl Iterator<Item = &OsString> {
        self.args.iter()
    }

    pub fn get_cwd(&self) -> Option<&Path> {
        self.cwd.as_ref().map(Path::new)
    }

    pub fn get_env(&self, var: &str) -> Option<OsString> {
        self.env
            .get(var)
            .cloned()
            .unwrap_or_else(|| std::env::var_os(var))
    }

    pub fn get_envs(&self) -> &BTreeMap<String, Option<OsString>> {
        &self.env
    }

    pub fn inherit_jobserver(&mut self, _jobserver: &JobserverClient) -> &mut Self {
        self
    }

    pub fn display_env_vars(&mut self) -> &mut Self {
        self.display_env_vars = true;
        self
    }

    pub fn retry_with_argfile(&mut self, _enabled: bool) -> &mut Self {
        self
    }

    pub fn stdin<T: Into<Vec<u8>>>(&mut self, _stdin: T) -> &mut Self {
        self
    }

    fn no_process(&self) -> anyhow::Error {
        ProcessError::could_not_execute(format!(
            "`{}` (processes cannot be spawned on wasm32)",
            self.display_env_vars
                .then(|| format!("{}", self.get_program().to_string_lossy()))
                .unwrap_or_else(|| self.get_program().to_string_lossy().into_owned())
        ))
        .into()
    }

    pub fn status(&self) -> Result<ExitStatus> {
        Err(self.no_process())
    }

    pub fn exec(&self) -> Result<()> {
        Err(self.no_process())
    }

    pub fn exec_replace(&self) -> Result<()> {
        Err(self.no_process())
    }

    pub fn output(&self) -> Result<Output> {
        Err(self.no_process())
    }

    pub fn exec_with_output(&self) -> Result<Output> {
        Err(self.no_process())
    }

    pub fn exec_with_streaming(
        &self,
        _on_stdout_line: &mut dyn FnMut(&str) -> Result<()>,
        _on_stderr_line: &mut dyn FnMut(&str) -> Result<()>,
        _capture_output: bool,
    ) -> Result<Output> {
        Err(self.no_process())
    }

    /// Kept for API parity; constructing a `Command` is harmless as it is
    /// never spawned.
    pub fn build_command(&self) -> Command {
        Command::new(&self.program)
    }

    pub fn wrapped(mut self, wrapper: Option<impl AsRef<OsStr>>) -> Self {
        if let Some(wrapper) = wrapper {
            self.wrappers.push(wrapper.as_ref().to_os_string());
        }
        self
    }
}

impl std::fmt::Display for ProcessBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`")?;
        write!(f, "{}", self.get_program().to_string_lossy())?;
        for arg in self.get_args() {
            write!(f, " {}", arg.to_string_lossy())?;
        }
        write!(f, "`")
    }
}
