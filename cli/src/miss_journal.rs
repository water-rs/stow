//! Misses are admitted from a per-target-dir journal: one JSON line per
//! unit a build compiled locally, appended by whatever saw the compile —
//! the rustc wrapper under a plain `cargo build`, or the supervising
//! driver itself. A journal is turned into admissions detached from every
//! build's wall clock: the driver spawns a `stow __drain-misses` child as
//! soon as cargo exits, and under plain cargo the first wrapper of a
//! later build does the same for any journal whose cargo exited
//! (stow#317).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::artifact_cache::{LocalBuildArtifact, ObservedUnit};
use crate::config::StowConfig;
use crate::rustc_args::ParsedRustcArgs;

const JOURNAL_PREFIX: &str = "stow-misses.";
const JOURNAL_SUFFIX: &str = ".jsonl";
const DRAIN_LOG: &str = "stow-drain.log";

/// One journaled observation: the unit, plus what a drain needs to name
/// its build's misses — which rustc compiled it and which consumer target
/// the build was for.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JournalEntry {
    /// The rustc the wrapper invoked — the drain's `-vV` probe when the
    /// consumer target has to be inferred for a native build.
    rustc: String,
    /// The rustc version the unit compiled under.
    rustc_version: String,
    /// The unit's own `--target` when cargo passed one: for a `--target`
    /// build every consumer-side unit names the consumer while host-side
    /// units carry none; for a native build every entry is `None` and
    /// the consumer is the rustc's host.
    explicit_target: Option<String>,
    /// The compile observation itself.
    unit: ObservedUnit,
}

/// The compile observation one finished local compile leaves behind, or
/// `None` when its extern identities did not parse — the unit is not
/// observed and never mints a miss (stow#317).
pub fn observed_unit(parsed: &ParsedRustcArgs, build: &LocalBuildArtifact) -> Option<ObservedUnit> {
    let externs = match serde_json::from_str(&build.dependency_c_metadata_json) {
        Ok(externs) => externs,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                "compiled unit's extern identities did not parse; not observing it"
            );
            return None;
        }
    };
    Some(ObservedUnit {
        crate_name: build.identity.crate_name.clone(),
        crate_version: build.identity.version.clone(),
        features: parsed.features.iter().cloned().collect(),
        target: build.target.clone(),
        externs,
    })
}

/// The journal a build's writers append to:
/// `<target_dir>/stow-misses.<build>.jsonl`.
fn journal_path(target_dir: &Path, build: &str) -> PathBuf {
    target_dir.join(format!("{JOURNAL_PREFIX}{build}{JOURNAL_SUFFIX}"))
}

/// The target dir a compile's out dir sits under — cargo lays units out
/// as `<target>/<profile>/deps`, so the journal lives two levels up.
/// `None` for an out dir outside that layout (a bare `--out-dir`): the
/// observation is dropped rather than written somewhere arbitrary.
fn target_dir_for(out_dir: &Path) -> Option<PathBuf> {
    if out_dir.file_name() != Some(OsStr::new("deps")) {
        return None;
    }
    out_dir.parent()?.parent().map(Path::to_path_buf)
}

/// The cargo build a standalone wrapper belongs to: the process that
/// spawned it. While that pid lives the journal is still being written.
fn cargo_build() -> String {
    #[cfg(unix)]
    {
        unsafe { libc::getppid() }.to_string()
    }
    #[cfg(not(unix))]
    {
        // No portable parent pid: each wrapper writes under its own
        // (short-lived) pid instead — more, smaller journals, same drain.
        std::process::id().to_string()
    }
}

/// The journal id for a supervised build: the driver writes the file
/// complete after cargo exits, so the `stow-` mark makes it drainable
/// without a liveness check.
fn supervised_build() -> String {
    format!("stow-{}", std::process::id())
}

/// Whether the journal's writing build has finished: a driver's `stow-*`
/// file is complete on write, and a cargo pid that no longer exists means
/// its build exited. Anything else is drained anyway — posting early is
/// harmless, admissions are additive.
fn build_finished(build: &str) -> bool {
    if build.starts_with("stow-") {
        return true;
    }
    let Ok(pid) = build.parse::<i32>() else {
        return true;
    };
    #[cfg(unix)]
    {
        // ESRCH: the cargo that owned this journal is gone.
        unsafe { libc::kill(pid, 0) != 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The journals in `target_dir` ready to post. Reading the directory is
/// the only cost a wrapper pays for the check, and only target dirs that
/// stow built in carry journals at all.
fn finished_journals(target_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(target_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| {
                    name.strip_prefix(JOURNAL_PREFIX)
                        .and_then(|rest| rest.strip_suffix(JOURNAL_SUFFIX))
                })
                .is_some_and(build_finished)
        })
        .map(|entry| entry.path())
        .collect()
}

/// Spawn the detached drainer for a target dir — but only when a journal
/// is actually pending, so steady-state invocations pay nothing.
/// Nobody waits on the child, so posting admissions never sits on a
/// build's wall clock.
pub fn spawn_drain(target_dir: &Path) {
    if finished_journals(target_dir).is_empty() {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            tracing::warn!(error = %error, "could not resolve stow-cli path for miss drain");
            return;
        }
    };
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(target_dir.join(DRAIN_LOG))
        .map_or_else(|_| Stdio::null(), Stdio::from);
    let mut command = std::process::Command::new(exe);
    command
        .arg("__drain-misses")
        .arg(target_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // DETACHED_PROCESS | CREATE_NO_WINDOW: no console flashes open.
        command.creation_flags(0x00000008 | 0x00000200);
    }
    if let Err(error) = command.spawn() {
        tracing::warn!(error = %error, "could not spawn the miss drain");
    }
}

/// Append `entries` to `journal` as JSON lines — one `write_all`, so
/// concurrent writers never interleave a line.
fn append_lines(journal: &Path, entries: &[JournalEntry]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal)?;
    let mut buffer = Vec::new();
    for entry in entries {
        serde_json::to_writer(&mut buffer, entry)?;
        buffer.push(b'\n');
    }
    file.write_all(&buffer)
}

/// Record one locally compiled unit to the standalone build's journal.
/// The wrapper's whole cost is a single append — the observation rides
/// the identity the compile already resolved.
pub fn record_observation(rustc: &OsStr, parsed: &ParsedRustcArgs, build: &LocalBuildArtifact) {
    let Some(unit) = observed_unit(parsed, build) else {
        return;
    };
    let Some(out_dir) = parsed.out_dir.as_deref() else {
        return;
    };
    let Some(target_dir) = target_dir_for(out_dir) else {
        tracing::warn!(
            out_dir = %out_dir.display(),
            "compile's out dir is outside cargo's target layout; observation dropped"
        );
        return;
    };
    let entry = JournalEntry {
        rustc: rustc.to_string_lossy().into_owned(),
        rustc_version: build.rustc_version.clone(),
        explicit_target: parsed.target.clone(),
        unit,
    };
    let journal = journal_path(&target_dir, &cargo_build());
    if let Err(error) = append_lines(&journal, &[entry]) {
        tracing::warn!(error = %error, journal = %journal.display(), "could not journal the compile observation");
    }
}

/// Write the supervising build's journal: one batch append by the driver
/// after cargo exits, then kick the drain — `stow build` returns as soon
/// as cargo does.
pub fn journal_supervised(
    rustc: &OsStr,
    consumer_target: &str,
    rustc_version: &str,
    observations: &[ObservedUnit],
    target_dir: &Path,
) {
    if observations.is_empty() {
        return;
    }
    let entries: Vec<JournalEntry> = observations
        .iter()
        .map(|unit| JournalEntry {
            rustc: rustc.to_string_lossy().into_owned(),
            rustc_version: rustc_version.to_owned(),
            // The driver knows its consumer target outright, so the
            // drain's inference degenerates to it.
            explicit_target: Some(consumer_target.to_owned()),
            unit: unit.clone(),
        })
        .collect();
    let journal = journal_path(target_dir, &supervised_build());
    if let Err(error) = append_lines(&journal, &entries) {
        tracing::warn!(error = %error, journal = %journal.display(), "could not journal the build's compile observations");
    }
}

/// Kick the deferred drain for journals left by builds that already
/// exited — the standalone path's way of admitting misses with no stow
/// parent process. The check is one directory listing that only finds
/// files in target dirs stow has built in.
pub fn drain_finished_builds(out_dir: &Path) {
    if let Some(target_dir) = target_dir_for(out_dir) {
        spawn_drain(&target_dir);
    }
}

/// `stow __drain-misses <target_dir>`: move each finished journal aside,
/// post its entries as that build's misses, and delete it. A journal
/// whose post fails moves back under its name so a later drain retries.
pub async fn drain(target_dir: &Path) -> stow_types::error::Result<()> {
    let config = StowConfig::load_local()?;
    for journal in finished_journals(target_dir) {
        drain_journal(&config, &journal).await;
    }
    Ok(())
}

async fn drain_journal(config: &StowConfig, journal: &Path) {
    let file_name = journal
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    let work = journal.with_file_name(format!("{file_name}.draining-{}", std::process::id()));
    if std::fs::rename(journal, &work).is_err() {
        // Another drain took it.
        return;
    }
    let restore = || {
        let _ = std::fs::rename(&work, journal);
    };
    let contents = match std::fs::read_to_string(&work) {
        Ok(contents) => contents,
        Err(error) => {
            tracing::warn!(error = %error, journal = %journal.display(), "could not read miss journal");
            restore();
            return;
        }
    };
    let mut entries = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<JournalEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    journal = %journal.display(),
                    line = line_number + 1,
                    "skipping a malformed miss journal line"
                );
            }
        }
    }
    if entries.is_empty() {
        let _ = std::fs::remove_file(&work);
        return;
    }
    // One journal is one build: every explicit `--target` in it names the
    // same consumer. A native build carries none, so the consumer is the
    // compiling rustc's own host triple.
    let consumer_target = match entries
        .iter()
        .find_map(|entry| entry.explicit_target.clone())
    {
        Some(target) => target,
        None => match crate::rustc_args::rustc_host_target(OsStr::new(&entries[0].rustc)).await {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(error = %error, journal = %journal.display(), "could not infer the journal's consumer target");
                restore();
                return;
            }
        },
    };
    let mut groups: BTreeMap<String, Vec<ObservedUnit>> = BTreeMap::new();
    for entry in entries {
        groups
            .entry(entry.rustc_version)
            .or_default()
            .push(entry.unit);
    }
    let mut failed = false;
    for (rustc_version, units) in groups {
        if let Err(error) = crate::cargo_cmd::admit_observed_misses(
            config,
            &consumer_target,
            &rustc_version,
            &units,
        )
        .await
        {
            tracing::warn!(error = %error, journal = %journal.display(), "could not admit a journal's misses");
            failed = true;
        }
    }
    if failed {
        restore();
    } else {
        let _ = std::fs::remove_file(&work);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_dir_resolves_cargo_deps_layout() {
        assert_eq!(
            target_dir_for(Path::new("/ws/target/debug/deps")),
            Some(PathBuf::from("/ws/target"))
        );
        assert_eq!(target_dir_for(Path::new("/ws/target")), None);
        assert_eq!(target_dir_for(Path::new("/custom/out")), None);
    }

    #[test]
    fn supervised_journals_are_always_finished() {
        assert!(build_finished("stow-123"));
        // The liveness check exists only where a parent pid is
        // checkable: everywhere else a numeric journal is drained.
        #[cfg(unix)]
        assert!(!build_finished(&std::process::id().to_string()));
    }

    #[test]
    fn a_dead_cargo_pid_makes_its_journal_finished() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        child.wait().expect("wait");
        assert!(build_finished(&child.id().to_string()));
    }

    #[test]
    fn journal_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal = journal_path(dir.path(), "stow-1");
        let entry = JournalEntry {
            rustc: "rustc".to_owned(),
            rustc_version: "1.85.0".to_owned(),
            explicit_target: Some("wasm32-unknown-unknown".to_owned()),
            unit: ObservedUnit {
                crate_name: "serde".to_owned(),
                crate_version: "1.0.0".to_owned(),
                features: vec!["derive".to_owned()],
                target: "x86_64-unknown-linux-gnu".to_owned(),
                externs: vec![crate::artifact_cache::DependencyCMetadataIdentity {
                    crate_name: "serde_core".to_owned(),
                    c_metadata: "abc".to_owned(),
                }],
            },
        };
        append_lines(&journal, &[entry]).expect("append");
        let read = std::fs::read_to_string(&journal).expect("read journal");
        let parsed: JournalEntry = serde_json::from_str(read.trim()).expect("parse entry");
        assert_eq!(parsed.unit.crate_name, "serde");
        assert_eq!(
            parsed.explicit_target.as_deref(),
            Some("wasm32-unknown-unknown")
        );
        assert_eq!(parsed.unit.externs.len(), 1);
    }

    #[test]
    fn only_finished_journals_are_listed() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(journal_path(dir.path(), "stow-1"), "{}\n").expect("write");
        // A live cargo pid's journal is held back only where liveness is
        // checkable; elsewhere every numeric journal is drained.
        #[cfg(unix)]
        std::fs::write(
            journal_path(dir.path(), &std::process::id().to_string()),
            "{}\n",
        )
        .expect("write");
        std::fs::write(dir.path().join("unrelated.txt"), "{}\n").expect("write");
        let finished = finished_journals(dir.path());
        assert_eq!(finished, vec![journal_path(dir.path(), "stow-1")]);
    }
}
