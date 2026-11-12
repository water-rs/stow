//! Windows: the per-user scheduled task that starts the daemon.
//!
//! The Windows counterpart of the macOS `LaunchAgent`
//! ([`super::launch_agent`]). `stow setup` registers a task that runs
//! `stow daemon` when the user logs on, and the start path ([`super::start`])
//! asks the Task Scheduler to run that same task whenever a client finds no
//! daemon.
//!
//! A client cannot start the daemon itself: cargo runs in a job object that
//! ends every process in it when cargo ends, and a process cannot leave it
//! (cargo's job allows no breakaway), so a daemon a build's wrapper spawned
//! would die with that build's cargo and take every other build's session
//! with it. A process the Task Scheduler starts belongs to the scheduler,
//! not to its requester.
//!
//! The Task Scheduler is driven through the system's own `schtasks.exe`
//! rather than its COM interface: the lockfile's `windows` crate has no
//! Task Scheduler bindings, and the four operations needed are one command
//! each.
//!
//! A task serves one runtime directory and is named after it
//! ([`task_name`]), as the daemon's pipe is, so a private runtime directory
//! (`STOW_DAEMON_DIR`) has a task of its own.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output};

use askama::Template;
use stow_types::error::{Context, Result};

use super::RunDir;
use super::detached::arguments_text;

/// The Task Scheduler's command-line tool, found in the system directory.
const SCHTASKS: &str = "schtasks.exe";

/// The first two bytes of a UTF-16 little-endian file, which `schtasks`
/// needs to read the task's XML as the encoding its declaration names.
const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];

#[derive(Template)]
#[template(path = "scheduled_task.xml")]
struct TaskDefinition<'a> {
    user_sid: &'a str,
    program: &'a str,
    arguments: &'a str,
}

/// The task that starts the daemon serving `run_dir`.
#[must_use]
pub fn task_name(run_dir: &Path) -> String {
    RunDir::identity(run_dir)
}

/// The task's definition for the user `user_sid`, running `stow daemon` of
/// `runtime_executable` for `run_dir`.
fn render(user_sid: &str, runtime_executable: &Path, run_dir: &Path) -> Result<String> {
    let program = runtime_executable.to_str().ok_or_else(|| {
        stow_types::stow_error!(
            "the stow executable path {} is not UTF-8",
            runtime_executable.display()
        )
    })?;
    let arguments = arguments_text(&[
        OsString::from("daemon"),
        OsString::from("--run-dir"),
        run_dir.as_os_str().to_owned(),
    ])
    .wrap_err("quote the daemon's arguments")?;
    TaskDefinition {
        user_sid,
        program,
        arguments: &arguments,
    }
    .render()
    .map(|mut xml| {
        // The template engine drops the file's final newline; a text file
        // ends with one.
        xml.push('\n');
        xml
    })
    .wrap_err("render the scheduled task definition")
}

fn utf16_le_file(text: &str) -> Vec<u8> {
    let mut bytes = UTF16_LE_BOM.to_vec();
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

fn schtasks(args: &[OsString]) -> Result<Output> {
    Command::new(SCHTASKS)
        .args(args)
        .output()
        .wrap_err_with(|| format!("run {SCHTASKS}"))
}

fn checked(args: &[OsString]) -> Result<()> {
    let output = schtasks(args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "{SCHTASKS} {} failed with {}: {}",
        args.first()
            .map(|arg| arg.to_string_lossy())
            .unwrap_or_default(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn named(operation: &str, name: &str) -> Vec<OsString> {
    [operation, "/TN", name].map(OsString::from).to_vec()
}

/// Whether the task `name` is registered.
fn is_registered(name: &str) -> Result<bool> {
    // `/Query` of an unknown task exits non-zero; that is the answer, not
    // a failure of the command.
    Ok(schtasks(&named("/Query", name))?.status.success())
}

/// Register the task that starts the daemon serving `run_dir` from
/// `runtime_executable`, replacing one already registered. Returns the
/// task's name.
///
/// # Errors
///
/// Either path is relative, the executable's path is not UTF-8, the
/// definition cannot be written, or `schtasks` refuses it.
pub fn register(run_dir: &Path, runtime_executable: &Path) -> Result<String> {
    for path in [run_dir, runtime_executable] {
        if !path.is_absolute() {
            return Err(stow_types::stow_error!(
                "the path {} must be absolute for the scheduled task",
                path.display()
            ));
        }
    }
    let name = task_name(run_dir);
    let definition = render(
        &super::windows::current_user_sid().wrap_err("read the current user's SID")?,
        runtime_executable,
        run_dir,
    )?;
    std::fs::create_dir_all(run_dir).wrap_err_with(|| format!("create {}", run_dir.display()))?;
    let file = run_dir.join("scheduled-task.xml");
    std::fs::write(&file, utf16_le_file(&definition))
        .wrap_err_with(|| format!("write {}", file.display()))?;
    let created = checked(&[
        OsString::from("/Create"),
        OsString::from("/XML"),
        file.as_os_str().to_owned(),
        OsString::from("/TN"),
        OsString::from(&name),
        OsString::from("/F"),
    ]);
    // The task holds its own copy of the definition.
    let _ = std::fs::remove_file(&file);
    created.wrap_err_with(|| format!("register the scheduled task {name}"))?;
    Ok(name)
}

/// Ask the Task Scheduler to run the task that starts the daemon serving
/// `run_dir`. Returns when the scheduler has accepted the request, not
/// when the daemon is up.
///
/// # Errors
///
/// No task is registered for `run_dir`, which `stow setup` does, or the
/// scheduler refuses to run it.
///
/// The task ignores a request made while an instance runs, and the request
/// still succeeds: a caller that needs the daemon asks its endpoint too.
pub fn run(run_dir: &Path) -> Result<()> {
    let name = task_name(run_dir);
    let output = schtasks(&named("/Run", &name))?;
    if output.status.success() {
        return Ok(());
    }
    if !is_registered(&name)? {
        return Err(stow_types::stow_error!(
            "the stow daemon is not running and its scheduled task {name} is not registered; \
             run `stow setup` once to register it"
        ));
    }
    Err(stow_types::stow_error!(
        "the Task Scheduler would not run the stow daemon's task {name}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// Remove the task that starts the daemon serving `run_dir`; a running
/// daemon is left running.
///
/// # Errors
///
/// `schtasks` fails.
pub fn unregister(run_dir: &Path) -> Result<()> {
    let mut args = named("/Delete", &task_name(run_dir));
    args.push(OsString::from("/F"));
    checked(&args)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{render, task_name, utf16_le_file};

    const EXPECTED: &str = include_str!("../../tests/fixtures/scheduled_task.xml");

    #[test]
    fn the_definition_is_a_logon_task_that_runs_the_daemon_for_one_run_dir() {
        assert_eq!(
            render(
                "S-1-5-21-1-2-3-1001",
                Path::new(r"C:\Program Files\stow\stow-runtime.exe"),
                Path::new(r"C:\Users\a b\AppData\Local\stow\run"),
            )
            .expect("render"),
            EXPECTED
        );
    }

    #[test]
    fn a_path_is_escaped_into_the_definition() {
        let xml = render(
            "S-1-5-21-1",
            Path::new(r"C:\a&b\<stow>.exe"),
            Path::new(r"C:\run"),
        )
        .expect("render");
        assert!(xml.contains(r"C:\a&#38;b\&#60;stow&#62;.exe"), "{xml}");
    }

    #[test]
    fn a_task_is_named_after_its_run_dir() {
        let first = task_name(Path::new(r"C:\run\one"));
        assert!(first.starts_with("stow-daemon-"), "{first}");
        assert_eq!(first, task_name(Path::new(r"C:\run\one")));
        assert_ne!(first, task_name(Path::new(r"C:\run\two")));
    }

    #[test]
    fn the_file_is_utf16_with_a_byte_order_mark() {
        assert_eq!(utf16_le_file("a\u{e9}"), [0xFF, 0xFE, b'a', 0, 0xE9, 0]);
    }
}
