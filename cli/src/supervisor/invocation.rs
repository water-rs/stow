//! The one door a request passes before the supervisor acts on it.
//!
//! A frame's contents are the sender's word. [`VerifiedInvocation`] can
//! only be obtained from [`VerifiedInvocation::verify`], so every handler
//! that takes one has seen the checks pass; a failed check is a
//! [`Refusal`] naming the field.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::protocol::InvocationEnv;
use crate::toolchain::BuildToolchain;

/// The request field a [`Refusal`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The executable the request names.
    Executable,
    /// The working directory the request runs in.
    Cwd,
    /// The `--out-dir` argument or the `OUT_DIR` variable the request
    /// names.
    OutDir,
}

impl std::fmt::Display for Field {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Executable => "executable",
            Self::Cwd => "cwd",
            Self::OutDir => "out-dir",
        })
    }
}

/// The directories one build writes compiler outputs under: the target
/// directory and, when cargo is configured with a separate build
/// directory, that one too. A path a request names as its output must lie
/// under one of them, so a build's roots never authorize another build's
/// paths.
#[derive(Debug, Clone)]
pub struct OutputRoots {
    dirs: Vec<PathBuf>,
}

impl OutputRoots {
    /// The roots of a build with `target_dir` and, when it has one,
    /// `build_dir`. Both are absolute.
    #[must_use]
    pub fn new(target_dir: PathBuf, build_dir: Option<PathBuf>) -> Self {
        let mut dirs = vec![target_dir];
        dirs.extend(build_dir);
        Self { dirs }
    }

    /// The root directories, as the driver resolved them.
    #[must_use]
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// Whether `path`, written in a process running in `cwd`, lies under a
    /// root once links and `..` are resolved. The path need not exist
    /// yet: its longest existing ancestor is resolved and the rest is
    /// appended. Stats the file system.
    fn contain(&self, path: &Path, cwd: &Path) -> Result<(), String> {
        let real = resolve_lenient(&cwd.join(path))
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
        let under = self
            .dirs
            .iter()
            .any(|dir| resolve_lenient(dir).is_ok_and(|root| real.starts_with(root)));
        if under {
            return Ok(());
        }
        let roots = self
            .dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "{} is outside the build's target and build directories ({roots})",
            path.display()
        ))
    }
}

/// `path` with every existing ancestor resolved through the file system.
/// A tail that does not exist yet is kept as spelled and may not hold
/// `..`, which could climb out of the resolved part.
fn resolve_lenient(path: &Path) -> std::io::Result<PathBuf> {
    let mut missing = Vec::new();
    let mut head = path;
    loop {
        match head.canonicalize() {
            Ok(mut real) => {
                real.extend(missing.iter().rev());
                return Ok(real);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = head.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "a missing path holds `..` or no parent",
                    )
                })?;
                missing.push(name);
                head = head.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// The values of `--out-dir` in `args`, in either spelling.
fn out_dir_args(args: &[OsString]) -> Vec<&OsStr> {
    let mut found = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--out-dir" {
            found.extend(iter.next().map(OsString::as_os_str));
        } else if let Some(value) = arg.to_str().and_then(|arg| arg.strip_prefix("--out-dir=")) {
            found.push(OsStr::new(value));
        }
    }
    found
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
    /// run: no toolchain fact comes from a request. Relative spellings
    /// resolve against the request's own working directory, and every
    /// `--out-dir` and `OUT_DIR` it names must lie under the build's
    /// `roots`; a build whose roots are unknown accepts none.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] naming the first field that failed.
    pub async fn verify(
        toolchain: &Arc<BuildToolchain>,
        roots: Option<&OutputRoots>,
        executable: OsString,
        args: Vec<OsString>,
        env: &InvocationEnv,
    ) -> Result<Self, Refusal> {
        let refuse = |field, reason: String| Refusal { field, reason };
        let cwd = env
            .cwd()
            .map_err(|error| refuse(Field::Cwd, error))?
            .ok_or_else(|| {
                refuse(
                    Field::Cwd,
                    "the request names no working directory".to_owned(),
                )
            })?;
        let out_dir = env
            .out_dir()
            .map_err(|error| refuse(Field::OutDir, error))?;
        let roots = roots.cloned();
        let rustc = toolchain.rustc().to_path_buf();
        let checked = {
            let toolchain = Arc::clone(toolchain);
            tokio::task::spawn_blocking(move || {
                let allowed = toolchain.is_rustc(&executable, &cwd)
                    || (toolchain.is_workspace_wrapper(&executable, &cwd)
                        && args
                            .first()
                            .is_some_and(|rustc| toolchain.is_rustc(rustc, &cwd)));
                if !allowed {
                    return Err(refuse(
                        Field::Executable,
                        format!(
                            "{} is neither the build's rustc ({}) nor the configured workspace wrapper invoking it",
                            Path::new(&executable).display(),
                            rustc.display()
                        ),
                    ));
                }
                let named = out_dir_args(&args)
                    .into_iter()
                    .map(PathBuf::from)
                    .chain(out_dir);
                for path in named {
                    let Some(roots) = &roots else {
                        return Err(refuse(
                            Field::OutDir,
                            format!(
                                "{} cannot be checked: the build's target directory is unknown",
                                path.display()
                            ),
                        ));
                    };
                    roots
                        .contain(&path, &cwd)
                        .map_err(|reason| refuse(Field::OutDir, reason))?;
                }
                Ok(args)
            })
            .await
        };
        let args = checked.map_err(|error| {
            refuse(
                Field::Executable,
                format!("the check did not finish: {error}"),
            )
        })??;
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

    use super::{OutputRoots, VerifiedInvocation};
    use crate::supervisor::protocol::InvocationEnv;
    use crate::toolchain::BuildToolchain;

    /// A request running in the test's own working directory.
    fn here() -> InvocationEnv {
        InvocationEnv::in_dir(&std::env::current_dir().expect("the test's working directory"))
    }

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
            VerifiedInvocation::verify(&toolchain, None, spelling.clone(), Vec::new(), &here())
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
        let refusal = VerifiedInvocation::verify(
            &toolchain,
            None,
            other.into_os_string(),
            Vec::new(),
            &here(),
        )
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

        VerifiedInvocation::verify(
            &toolchain,
            None,
            wrapper.clone().into_os_string(),
            args(&rustc),
            &here(),
        )
        .await
        .expect("the configured wrapper invoking the build's rustc passes");
        VerifiedInvocation::verify(
            &toolchain,
            None,
            wrapper.clone().into_os_string(),
            args(std::ffi::OsStr::new("/bin/sh")),
            &here(),
        )
        .await
        .expect_err("the wrapper invoking another program is refused");
        VerifiedInvocation::verify(
            &toolchain,
            None,
            wrapper.into_os_string(),
            Vec::new(),
            &here(),
        )
        .await
        .expect_err("the wrapper with no rustc is refused");
        assert!(!sentinel.exists(), "the wrapper was started");
    }

    /// A relative spelling is the request's own: `./rustc` names the
    /// build's rustc from the directory that holds a link to it, and
    /// names nothing from any other.
    #[tokio::test]
    async fn a_relative_spelling_resolves_against_the_requests_cwd() {
        let toolchain = BuildToolchain::for_tests().await;
        let holder = tempfile::tempdir().expect("holder dir");
        let elsewhere = tempfile::tempdir().expect("other dir");
        std::os::unix::fs::symlink(real_rustc(), holder.path().join("rustc"))
            .expect("link the rustc");
        let spelling = OsString::from("./rustc");

        VerifiedInvocation::verify(
            &toolchain,
            None,
            spelling.clone(),
            Vec::new(),
            &InvocationEnv::in_dir(holder.path()),
        )
        .await
        .expect("the spelling resolves where the request ran");
        let refusal = VerifiedInvocation::verify(
            &toolchain,
            None,
            spelling,
            Vec::new(),
            &InvocationEnv::in_dir(elsewhere.path()),
        )
        .await
        .expect_err("the same spelling names nothing elsewhere");
        assert!(refusal.to_string().contains("executable"), "{refusal}");
    }

    #[tokio::test]
    async fn a_request_without_a_working_directory_is_refused_naming_the_field() {
        let toolchain = BuildToolchain::for_tests().await;
        let refusal = VerifiedInvocation::verify(
            &toolchain,
            None,
            OsString::from("rustc"),
            Vec::new(),
            &InvocationEnv::default(),
        )
        .await
        .expect_err("no working directory, no check");
        assert!(refusal.to_string().contains("cwd"), "{refusal}");
    }

    #[tokio::test]
    async fn an_out_dir_outside_the_target_directory_is_refused_naming_the_field() {
        let toolchain = BuildToolchain::for_tests().await;
        let target = tempfile::tempdir().expect("target dir");
        let outside = tempfile::tempdir().expect("outside dir");
        let roots = OutputRoots::new(target.path().to_path_buf(), None);
        let deps = target.path().join("debug").join("deps");
        let check = |args: Vec<OsString>, env: InvocationEnv| {
            let toolchain = &toolchain;
            let roots = &roots;
            async move {
                VerifiedInvocation::verify(
                    toolchain,
                    Some(roots),
                    OsString::from("rustc"),
                    args,
                    &env,
                )
                .await
            }
        };
        let out_dir = |dir: &Path| vec![OsString::from("--out-dir"), dir.as_os_str().to_owned()];

        // A directory that does not exist yet, under the target, passes in
        // both spellings, and so does a relative one from the target.
        check(out_dir(&deps), here())
            .await
            .expect("under the target");
        check(
            vec![OsString::from(format!("--out-dir={}", deps.display()))],
            here(),
        )
        .await
        .expect("the joined spelling");
        check(
            vec![OsString::from("--out-dir"), OsString::from("debug/deps")],
            InvocationEnv::in_dir(target.path()),
        )
        .await
        .expect("a relative spelling resolves against the request's cwd");

        for (label, args, env) in [
            ("outside", out_dir(outside.path()), here()),
            (
                "climbing out of the target",
                out_dir(&target.path().join("..").join("escape")),
                here(),
            ),
            (
                "relative to another cwd",
                vec![OsString::from("--out-dir"), OsString::from("debug/deps")],
                InvocationEnv::in_dir(outside.path()),
            ),
            (
                "the variable",
                Vec::new(),
                InvocationEnv {
                    out_dir: Some(super::super::os_bytes::encode(outside.path().as_os_str())),
                    ..here()
                },
            ),
        ] {
            let refusal = check(args, env).await.expect_err(label);
            assert!(
                refusal.to_string().contains("out-dir"),
                "{label}: {refusal}"
            );
        }
    }

    /// With a build directory configured, the intermediate outputs live
    /// there and the target directory holds only the final ones: both
    /// are the build's.
    #[tokio::test]
    async fn the_build_directory_is_a_root_beside_the_target_directory() {
        let toolchain = BuildToolchain::for_tests().await;
        let target = tempfile::tempdir().expect("target dir");
        let build = tempfile::tempdir().expect("build dir");
        let roots = OutputRoots::new(
            target.path().to_path_buf(),
            Some(build.path().to_path_buf()),
        );
        for dir in [target.path(), build.path()] {
            VerifiedInvocation::verify(
                &toolchain,
                Some(&roots),
                OsString::from("rustc"),
                vec![
                    OsString::from("--out-dir"),
                    dir.join("debug").into_os_string(),
                ],
                &here(),
            )
            .await
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", dir.display()));
        }
    }
}
