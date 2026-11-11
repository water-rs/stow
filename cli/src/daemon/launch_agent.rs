//! The macOS login trigger: a `LaunchAgent` that starts `stow daemon` at
//! login and again only after a crash.
//!
//! Only `stow setup` installs it. A daemon the agent starts beside one a
//! client started finds the lock held and exits 0, which `KeepAlive`'s
//! `Crashed` condition does not treat as a crash, so launchd leaves it be.
//! Clients never ask launchd anything.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use askama::Template;
use stow_types::error::{Context, Result};

/// The agent's launchd label, and the stem of its plist's file name.
pub const LABEL: &str = "dev.waterui.stow";

/// Overrides the `launchctl` executable `stow setup` runs.
const STOW_LAUNCHCTL_ENV: &str = "STOW_LAUNCHCTL";

#[derive(Template)]
#[template(path = "launch_agent.xml")]
struct LaunchAgentPlist<'a> {
    label: &'a str,
    program: &'a str,
}

/// The agent's plist for a daemon run from `runtime_executable`.
///
/// # Errors
///
/// The executable's path is not UTF-8 or the template fails to render.
pub fn render(runtime_executable: &Path) -> Result<String> {
    let program = runtime_executable.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "the stow executable path {} is not UTF-8",
            runtime_executable.display()
        )
    })?;
    LaunchAgentPlist {
        label: LABEL,
        program,
    }
    .render()
    .map(|mut plist| {
        // The template engine drops the file's final newline; a text file
        // ends with one.
        plist.push('\n');
        plist
    })
    .wrap_err("render the launch agent plist")
}

/// The `launchctl` operations `stow setup` needs, so a test can stand in
/// for launchd.
pub trait Launchctl {
    /// Whether the agent is loaded in the user's GUI domain.
    fn is_loaded(&self, uid: u32) -> Result<bool>;
    /// `launchctl bootstrap gui/<uid> <plist>`.
    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<()>;
    /// `launchctl bootout gui/<uid>/<label>`.
    fn bootout(&self, uid: u32) -> Result<()>;
}

/// The real `launchctl`.
#[derive(Debug)]
pub struct SystemLaunchctl {
    program: OsString,
}

impl SystemLaunchctl {
    /// `launchctl`, or the executable `STOW_LAUNCHCTL` names.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            program: std::env::var_os(STOW_LAUNCHCTL_ENV)
                .unwrap_or_else(|| OsString::from("launchctl")),
        }
    }

    fn run(&self, args: &[OsString]) -> Result<std::process::Output> {
        Command::new(&self.program)
            .args(args)
            .output()
            .wrap_err_with(|| format!("run {}", self.program.to_string_lossy()))
    }

    fn checked(&self, args: &[OsString]) -> Result<()> {
        let output = self.run(args)?;
        if output.status.success() {
            return Ok(());
        }
        Err(stow_types::stow_error!(
            "{} {} failed with {}: {}",
            self.program.to_string_lossy(),
            args.first()
                .map(|arg| arg.to_string_lossy())
                .unwrap_or_default(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn domain(uid: u32) -> OsString {
    OsString::from(format!("gui/{uid}"))
}

fn service(uid: u32) -> OsString {
    OsString::from(format!("gui/{uid}/{LABEL}"))
}

impl Launchctl for SystemLaunchctl {
    fn is_loaded(&self, uid: u32) -> Result<bool> {
        // `print` of an unknown service exits non-zero; that is the
        // answer, not a failure of the command.
        Ok(self
            .run(&[OsString::from("print"), service(uid)])?
            .status
            .success())
    }

    fn bootstrap(&self, uid: u32, plist: &Path) -> Result<()> {
        self.checked(&[
            OsString::from("bootstrap"),
            domain(uid),
            plist.as_os_str().to_owned(),
        ])
    }

    fn bootout(&self, uid: u32) -> Result<()> {
        self.checked(&[OsString::from("bootout"), service(uid)])
    }
}

/// What [`install`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The plist's path.
    pub plist: PathBuf,
    /// Whether the agent was (re)loaded into launchd by this call.
    pub loaded: bool,
}

/// Write the agent's plist into `agents_dir` and load it into the user's
/// GUI domain. Running it again leaves a loaded, unchanged agent alone and
/// reloads one whose plist changed.
///
/// # Errors
///
/// The plist cannot be written or launchctl refuses it.
pub fn install(
    agents_dir: &Path,
    runtime_executable: &Path,
    uid: u32,
    launchctl: &impl Launchctl,
) -> Result<Installed> {
    if !runtime_executable.is_absolute() {
        return Err(stow_types::stow_error!(
            "the stow executable path {} must be absolute for launchd",
            runtime_executable.display()
        ));
    }
    let plist = agents_dir.join(format!("{LABEL}.plist"));
    let content = render(runtime_executable)?;
    let changed = match std::fs::read_to_string(&plist) {
        Ok(existing) => existing != content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("read {}", plist.display()));
        }
    };
    if changed {
        std::fs::create_dir_all(agents_dir)
            .wrap_err_with(|| format!("create {}", agents_dir.display()))?;
        std::fs::write(&plist, &content).wrap_err_with(|| format!("write {}", plist.display()))?;
    }
    let loaded = launchctl.is_loaded(uid)?;
    if loaded && changed {
        launchctl.bootout(uid)?;
    }
    let load = !loaded || changed;
    if load {
        launchctl.bootstrap(uid, &plist)?;
    }
    Ok(Installed {
        plist,
        loaded: load,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use super::{Installed, Launchctl, install, render};

    const EXPECTED: &str = include_str!("../../tests/fixtures/launch_agent.plist");

    #[derive(Default)]
    struct Recorder {
        loaded: bool,
        calls: RefCell<Vec<String>>,
    }

    impl Launchctl for Recorder {
        fn is_loaded(&self, uid: u32) -> stow_types::error::Result<bool> {
            self.calls.borrow_mut().push(format!("print {uid}"));
            Ok(self.loaded)
        }

        fn bootstrap(&self, uid: u32, plist: &Path) -> stow_types::error::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("bootstrap {uid} {}", plist.display()));
            Ok(())
        }

        fn bootout(&self, uid: u32) -> stow_types::error::Result<()> {
            self.calls.borrow_mut().push(format!("bootout {uid}"));
            Ok(())
        }
    }

    #[test]
    fn the_plist_is_the_agent_that_runs_the_daemon_and_restarts_only_after_a_crash() {
        assert_eq!(
            render(Path::new("/opt/stow/bin/stow-cli")).expect("render"),
            EXPECTED
        );
    }

    #[test]
    fn a_path_is_escaped_into_the_plist() {
        let plist = render(Path::new("/Users/a&b/<stow>")).expect("render");
        assert!(plist.contains("/Users/a&#38;b/&#60;stow&#62;"), "{plist}");
    }

    #[test]
    fn install_writes_into_the_given_directory_and_bootstraps_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agents = dir.path().join("Library/LaunchAgents");
        let exe = PathBuf::from("/opt/stow/bin/stow-cli");
        let launchctl = Recorder::default();

        let installed = install(&agents, &exe, 501, &launchctl).expect("install");
        let plist = agents.join("dev.waterui.stow.plist");
        assert_eq!(
            installed,
            Installed {
                plist: plist.clone(),
                loaded: true
            }
        );
        assert_eq!(std::fs::read_to_string(&plist).expect("plist"), EXPECTED);
        assert_eq!(
            *launchctl.calls.borrow(),
            vec![
                "print 501".to_owned(),
                format!("bootstrap 501 {}", plist.display())
            ]
        );
    }

    #[test]
    fn a_loaded_unchanged_agent_is_left_alone_and_a_changed_one_reloaded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = PathBuf::from("/opt/stow/bin/stow-cli");
        install(dir.path(), &exe, 501, &Recorder::default()).expect("first install");

        let loaded = Recorder {
            loaded: true,
            ..Recorder::default()
        };
        let again = install(dir.path(), &exe, 501, &loaded).expect("second install");
        assert!(!again.loaded);
        assert_eq!(*loaded.calls.borrow(), vec!["print 501".to_owned()]);

        let moved = Recorder {
            loaded: true,
            ..Recorder::default()
        };
        let other = PathBuf::from("/opt/stow/bin/stow");
        let reloaded = install(dir.path(), &other, 501, &moved).expect("moved install");
        assert!(reloaded.loaded);
        assert_eq!(
            *moved.calls.borrow(),
            vec![
                "print 501".to_owned(),
                "bootout 501".to_owned(),
                format!("bootstrap 501 {}", reloaded.plist.display())
            ]
        );
    }

    #[test]
    fn a_relative_executable_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            install(dir.path(), Path::new("stow"), 501, &Recorder::default()).is_err(),
            "launchd runs from `/`, so a relative path would name nothing"
        );
    }
}
