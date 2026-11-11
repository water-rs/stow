//! The one door a request passes before the supervisor acts on it.
//!
//! A frame's contents are the sender's word. [`VerifiedInvocation`] can
//! only be obtained from [`VerifiedInvocation::verify`], so every handler
//! that takes one has seen the checks pass; a failed check is a
//! [`Refusal`] naming the field.

use std::ffi::OsString;
use std::sync::Arc;

use crate::toolchain::BuildToolchain;

/// The request field a [`Refusal`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The executable the request names.
    Executable,
}

impl std::fmt::Display for Field {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Executable => "executable",
        })
    }
}

/// A request the supervisor refuses to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    field: Field,
    reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "refused the request's {}: {}",
            self.field, self.reason
        )
    }
}

impl std::error::Error for Refusal {}

/// What the build does with a request the supervisor refused. A refusal
/// is a contract violation between stow's own wrapper and supervisor, so
/// it is surfaced where the build is developed and survived where it is
/// used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalPolicy {
    /// Answer the request as a failure and fail the build once cargo has
    /// exited, naming the field.
    FailBuild,
    /// Take no cache action for the request: the unit compiles as plain
    /// cargo would, and a one-way report or mark is dropped.
    CompileUncached,
}

impl RefusalPolicy {
    /// The policy of this build of stow: fail in a debug build, compile
    /// uncached in a release build.
    #[must_use]
    pub const fn of_this_build() -> Self {
        if cfg!(debug_assertions) {
            Self::FailBuild
        } else {
            Self::CompileUncached
        }
    }
}

/// An invocation whose fields the supervisor has checked against the
/// build's own facts.
#[derive(Debug)]
pub struct VerifiedInvocation {
    args: Vec<OsString>,
}

impl VerifiedInvocation {
    /// Check one request's fields against the build.
    ///
    /// The executable must be the build's rustc, or the configured
    /// workspace wrapper with the build's rustc as its first argument —
    /// the shape cargo gives a workspace member. It is compared, never
    /// run: no toolchain fact comes from a request.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] naming the first field that failed.
    pub async fn verify(
        toolchain: &Arc<BuildToolchain>,
        executable: OsString,
        args: Vec<OsString>,
    ) -> Result<Self, Refusal> {
        let checked = {
            let toolchain = Arc::clone(toolchain);
            tokio::task::spawn_blocking(move || {
                let allowed = toolchain.is_rustc(&executable)
                    || (toolchain.is_workspace_wrapper(&executable)
                        && args.first().is_some_and(|rustc| toolchain.is_rustc(rustc)));
                (allowed, executable, args)
            })
            .await
        };
        let (allowed, executable, args) = checked.map_err(|error| Refusal {
            field: Field::Executable,
            reason: format!("the check did not finish: {error}"),
        })?;
        if !allowed {
            return Err(Refusal {
                field: Field::Executable,
                reason: format!(
                    "{} is neither the build's rustc ({}) nor the configured workspace wrapper invoking it",
                    std::path::Path::new(&executable).display(),
                    toolchain.rustc().display()
                ),
            });
        }
        Ok(Self { args })
    }

    /// Everything after the executable, in order.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// Take the arguments.
    #[must_use]
    pub fn into_args(self) -> Vec<OsString> {
        self.args
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::VerifiedInvocation;
    use crate::toolchain::BuildToolchain;

    /// A program that records that it ran: `sentinel` exists afterwards
    /// only if something started it.
    fn tripwire(dir: &Path, name: &str, sentinel: &Path) -> PathBuf {
        let program = dir.join(name);
        std::fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
        )
        .expect("write the tripwire");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the tripwire");
        program
    }

    fn real_rustc() -> PathBuf {
        which::which("rustc").expect("the test machine has rustc on PATH")
    }

    #[tokio::test]
    async fn the_builds_rustc_passes_under_any_spelling_of_the_same_file() {
        let toolchain = BuildToolchain::for_tests().await;
        let rustc = real_rustc();
        let link_dir = tempfile::tempdir().expect("link dir");
        std::os::unix::fs::symlink(
            rustc.parent().expect("rustc has a parent"),
            link_dir.path().join("bin"),
        )
        .expect("symlink the bin dir");
        for spelling in [
            OsString::from("rustc"),
            rustc.clone().into_os_string(),
            link_dir.path().join("bin").join("rustc").into_os_string(),
        ] {
            VerifiedInvocation::verify(&toolchain, spelling.clone(), Vec::new())
                .await
                .unwrap_or_else(|refusal| panic!("{spelling:?}: {refusal}"));
        }
    }

    #[tokio::test]
    async fn another_executable_is_refused_naming_the_field_and_never_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("ran");
        let other = tripwire(dir.path(), "rustc", &sentinel);
        let toolchain = BuildToolchain::for_tests().await;
        let refusal = VerifiedInvocation::verify(&toolchain, other.into_os_string(), Vec::new())
            .await
            .expect_err("a program that is not the build's rustc is refused");
        assert!(refusal.to_string().contains("executable"), "{refusal}");
        assert!(!sentinel.exists(), "the refused program was started");
    }

    #[tokio::test]
    async fn a_workspace_wrapper_passes_only_with_the_builds_rustc_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("ran");
        let wrapper = tripwire(dir.path(), "wrapper", &sentinel);
        let toolchain = BuildToolchain::for_tests_with_workspace_wrapper(&wrapper).await;
        let rustc = real_rustc().into_os_string();
        let args = |first: &std::ffi::OsStr| vec![first.to_owned(), OsString::from("--crate-name")];

        VerifiedInvocation::verify(&toolchain, wrapper.clone().into_os_string(), args(&rustc))
            .await
            .expect("the configured wrapper invoking the build's rustc passes");
        VerifiedInvocation::verify(
            &toolchain,
            wrapper.clone().into_os_string(),
            args(std::ffi::OsStr::new("/bin/sh")),
        )
        .await
        .expect_err("the wrapper invoking another program is refused");
        VerifiedInvocation::verify(&toolchain, wrapper.into_os_string(), Vec::new())
            .await
            .expect_err("the wrapper with no rustc is refused");
        assert!(!sentinel.exists(), "the wrapper was started");
    }
}
