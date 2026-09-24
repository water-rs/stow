//! Misses are admitted from a per-target-dir journal: one JSON line per
//! unit a build compiled locally, appended by whatever saw the compile —
//! the rustc wrapper under a plain `cargo build`, or the supervising
//! driver itself. A journal is turned into admissions detached from every
//! build's wall clock: the driver spawns a `stow __drain-misses` child as
//! soon as cargo exits, and under plain cargo the first wrapper of a
//! later build does the same for any journal whose cargo exited
//! (stow#317).
//!
//! The drain detaches into its own session so a `SIGINT` that kills the
//! build's process group does not strand a claimed journal; a claim file
//! whose drainer died is itself reclaimable by the next drain.

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
const DRAIN_CLAIM: &str = ".draining-";
const DRAIN_LOG: &str = "stow-drain.log";
/// The drain's stderr log rotates into `stow-drain.log.1` past this size —
/// it exists for forensics, not to grow without bound.
const DRAIN_LOG_MAX_BYTES: u64 = 256 * 1024;

/// One journaled observation: the unit, plus what a drain needs to name
/// its build's misses — which rustc compiled it and which host the build
/// ran on.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JournalEntry {
    /// The rustc the wrapper invoked — diagnostic only.
    rustc: String,
    /// The rustc version the unit compiled under.
    rustc_version: String,
    /// The compiling rustc's probed `host:` triple, recorded at write
    /// time — drains never re-probe, so a toolchain swap between the
    /// build and the drain cannot relabel it (stow#317).
    build_host: String,
    /// Whether the consumer's cargo invocation spelled `--target` —
    /// including the `--target <host-triple>` spelling whose target
    /// units are the only ones that carry the flag. When every
    /// observed unit lacks `--target` this is the only evidence left
    /// that splits a spelled build's host units from a native build's
    /// target ones (stow#367).
    #[serde(default)]
    consumer_spelled_target: bool,
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
        explicit_target: parsed.target.clone(),
        build_override: parsed.debuginfo.is_none() && parsed.opt_level.is_none(),
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
    parent_pid().to_string()
}

/// The wrapper's parent process id — the cargo that spawned it on every
/// platform cargo runs it under, so one build journals to one file.
#[cfg(unix)]
fn parent_pid() -> u32 {
    u32::try_from(unsafe { libc::getppid() }).unwrap_or_else(|_| std::process::id())
}

/// Windows carries no parent-pid in `std`: read it out of the process
/// snapshot. `None` falls back to the wrapper's own (short-lived) pid —
/// more journals, same drain.
#[cfg(windows)]
fn parent_pid() -> u32 {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return std::process::id();
        }
        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        // A zero size makes Process32First fail, which falls back to
        // the wrapper's own pid — more journals, same drain.
        entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32>()).unwrap_or_default();
        let own = GetCurrentProcessId();
        let mut found = None;
        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == own {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found.unwrap_or_else(std::process::id)
    }
}

#[cfg(not(any(unix, windows)))]
fn parent_pid() -> u32 {
    std::process::id()
}

/// The journal id for a supervised build: the driver writes the file
/// complete after cargo exits, so the `stow-` mark makes it drainable
/// without a liveness check.
fn supervised_build() -> String {
    format!("stow-{}", std::process::id())
}

/// Whether a process id still names a live process. `EPERM` means the
/// process exists but cannot be signaled — that is alive, not finished.
/// Anything unanswerable reads as alive too: draining a live writer's
/// journal is worse than waiting one more build.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return true;
    };
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    // Only ESRCH means the process is gone; EPERM and friends mean alive.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code = 0u32;
        // STILL_ACTIVE is an NTSTATUS (i32); the exit code is a u32 —
        // any code that does not fit is an exit code, not 'running'.
        let alive =
            GetExitCodeProcess(handle, &mut code) != 0 && i32::try_from(code) == Ok(STILL_ACTIVE);
        CloseHandle(handle);
        alive
    }
}

#[cfg(not(any(unix, windows)))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// Whether the journal's writing build has finished: a driver's `stow-*`
/// file is complete on write, and a cargo pid that no longer names a
/// live process means its build exited. Anything unanswerable waits —
/// posting early is harmless only when the writer is actually done.
fn build_finished(build: &str) -> bool {
    if build.starts_with("stow-") {
        return true;
    }
    let Ok(pid) = build.parse::<u32>() else {
        return true;
    };
    !process_alive(pid)
}

/// The pid a `…{DRAIN_CLAIM}<pid>` claim name carries, if any.
fn claim_pid(file_name: &str) -> Option<u32> {
    file_name
        .split_once(DRAIN_CLAIM)
        .and_then(|(_, pid)| pid.parse().ok())
}

/// The journals in `target_dir` ready to post: finished builds' files
/// and stale claims whose drainer died mid-post (a SIGKILL, or a
/// `SIGINT` that reached the whole process group before the drain's
/// own session detached). Reading the directory is the only cost a
/// wrapper pays for the check, and only target dirs that stow built in
/// carry journals at all.
fn finished_journals(target_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(target_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            let rest = name.strip_prefix(JOURNAL_PREFIX)?;
            if let Some(build) = rest.strip_suffix(JOURNAL_SUFFIX) {
                return build_finished(build).then(|| entry.path());
            }
            // A `…jsonl.draining-<dead drainer pid>` claim is
            // reclaimable: its entries were never posted.
            if let Some(pid) = claim_pid(&name)
                && !process_alive(pid)
            {
                return Some(entry.path());
            }
            None
        })
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
    // Under a shim name `current_exe` is the runtime's role name —
    // `expand_wrapper_role` leaves the `__drain-misses` subcommand
    // untouched regardless of argv[0]'s name.
    let Ok(exe) = std::env::current_exe().inspect_err(|error| {
        tracing::warn!(error = %error, "could not resolve stow-cli path for miss drain");
    }) else {
        return;
    };
    let log = target_dir.join(DRAIN_LOG);
    // The log exists for forensics: rotate the last run aside rather
    // than appending without bound.
    if std::fs::metadata(&log).is_ok_and(|meta| meta.len() > DRAIN_LOG_MAX_BYTES) {
        let _ = std::fs::rename(&log, target_dir.join(format!("{DRAIN_LOG}.1")));
    }
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_or_else(|_| Stdio::null(), Stdio::from);
    let mut command = std::process::Command::new(&exe);
    command
        .arg("__drain-misses")
        .arg(target_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // A session of its own: a `SIGINT`/`SIGTERM` aimed at the
        // build's process group never kills the drain mid-claim.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
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
pub fn record_observation(
    rustc: &OsStr,
    parsed: &ParsedRustcArgs,
    build: &LocalBuildArtifact,
    build_host: &str,
) {
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
        build_host: build_host.to_owned(),
        consumer_spelled_target: unit.explicit_target.is_some(),
        unit,
    };
    let journal = journal_path(&target_dir, &cargo_build());
    if let Err(error) = append_lines(&journal, &[entry]) {
        tracing::warn!(error = %error, journal = %journal.display(), "could not journal the compile observation");
    }
}

/// The probed build host recorded for a supervised journal: a host
/// unit's recorded platform already is the compiling rustc's `host:`
/// triple (cargo passes it no `--target`); a build without host units
/// never consults the value, so the consumer stands in.
fn recorded_build_host(units: &[ObservedUnit], consumer_target: &str) -> String {
    units
        .iter()
        .find(|unit| unit.explicit_target.is_none())
        .map_or_else(|| consumer_target.to_owned(), |unit| unit.target.clone())
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
    consumer_spelled_target: bool,
) {
    if observations.is_empty() {
        return;
    }
    // The consumer's flag plus any observed explicit `--target` — the
    // flag covers a build where every observed unit is host-side and
    // none carries the flag itself.
    let consumer_spelled_target = consumer_spelled_target
        || observations
            .iter()
            .any(|unit| unit.explicit_target.is_some());
    let build_host = recorded_build_host(observations, consumer_target);
    let entries: Vec<JournalEntry> = observations
        .iter()
        .map(|unit| JournalEntry {
            rustc: rustc.to_string_lossy().into_owned(),
            rustc_version: rustc_version.to_owned(),
            build_host: build_host.clone(),
            consumer_spelled_target,
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
/// post its entries as that build's misses, and delete it. Entries whose
/// post fails go back under the journal's name so a later drain retries
/// only them.
pub async fn drain(target_dir: &Path) -> stow_types::error::Result<()> {
    let config = StowConfig::load_local()?;
    for journal in finished_journals(target_dir) {
        drain_journal(&config, &journal).await;
    }
    Ok(())
}

/// Put `entries` back for a later drain: append them under the journal's
/// own name — never a rename over a recreated same-named file, which
/// could belong to a live pid-reusing writer — then drop the claim. A
/// failed append keeps the claim file, which the next drain reclaims by
/// its now-dead drainer pid.
fn restore(work: &Path, journal: &Path, entries: &[JournalEntry]) {
    if !entries.is_empty()
        && let Err(error) = append_lines(journal, entries)
    {
        tracing::warn!(error = %error, journal = %journal.display(), "could not restore unposted miss observations; keeping the claim file");
        return;
    }
    let _ = std::fs::remove_file(work);
}

async fn drain_journal(config: &StowConfig, journal: &Path) {
    let file_name = journal
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    // A `.draining-<pid>` path is a claim a dead drainer left behind —
    // drain it in place under the journal's real name. Otherwise claim
    // by rename; a not-found means another drain took it, any other
    // error is logged and the journal is left where it is.
    let (journal_name, work) = if let Some((base, _)) = file_name.split_once(DRAIN_CLAIM) {
        (base.to_owned(), journal.to_path_buf())
    } else {
        let work =
            journal.with_file_name(format!("{file_name}{DRAIN_CLAIM}{}", std::process::id()));
        match std::fs::rename(journal, &work) {
            Ok(()) => (file_name, work),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(error = %error, journal = %journal.display(), "could not claim the miss journal; leaving it for a later drain");
                return;
            }
        }
    };
    let journal = journal.with_file_name(journal_name);
    let contents = match std::fs::read_to_string(&work) {
        Ok(contents) => contents,
        Err(error) => {
            tracing::warn!(error = %error, journal = %journal.display(), "could not read miss journal");
            restore(&work, &journal, &[]);
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
    // same consumer, and a native build's consumer is the host it built
    // on — both recorded at write time, so the drain never re-probes.
    let build_host = entries[0].build_host.clone();
    let consumer_target = entries
        .iter()
        .find_map(|entry| entry.unit.explicit_target.clone())
        .unwrap_or_else(|| build_host.clone());
    // The flag covers a spelled build whose observations were all
    // host-side; an older journal without the field still resolves via
    // each unit's own explicit `--target`.
    let consumer_spelled_target = entries.iter().any(|entry| {
        entry.consumer_spelled_target || entry.unit.explicit_target.is_some()
    });
    let mut groups: BTreeMap<String, Vec<ObservedUnit>> = BTreeMap::new();
    for entry in entries {
        groups
            .entry(entry.rustc_version)
            .or_default()
            .push(entry.unit);
    }
    let mut unposted = Vec::new();
    for (rustc_version, units) in groups {
        if let Err(error) = crate::cargo_cmd::admit_observed_misses(
            config,
            &consumer_target,
            &rustc_version,
            &build_host,
            consumer_spelled_target,
            &units,
        )
        .await
        {
            tracing::warn!(error = %error, journal = %journal.display(), "could not admit a journal's misses");
            unposted.extend(units.into_iter().map(|unit| JournalEntry {
                rustc: String::new(),
                rustc_version: rustc_version.clone(),
                build_host: build_host.clone(),
                consumer_spelled_target,
                unit,
            }));
        }
    }
    restore(&work, &journal, &unposted);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(crate_name: &str, explicit_target: Option<&str>) -> ObservedUnit {
        ObservedUnit {
            crate_name: crate_name.to_owned(),
            crate_version: "1.0.0".to_owned(),
            features: vec!["derive".to_owned()],
            target: "x86_64-unknown-linux-gnu".to_owned(),
            explicit_target: explicit_target.map(str::to_owned),
            build_override: false,
            externs: vec![crate::artifact_cache::DependencyCMetadataIdentity {
                crate_name: "serde_core".to_owned(),
                c_metadata: "abc".to_owned(),
            }],
        }
    }

    fn entry(crate_name: &str, rustc_version: &str) -> JournalEntry {
        let unit = unit(crate_name, Some("wasm32-unknown-unknown"));
        JournalEntry {
            rustc: "rustc".to_owned(),
            rustc_version: rustc_version.to_owned(),
            build_host: "x86_64-unknown-linux-gnu".to_owned(),
            consumer_spelled_target: unit.explicit_target.is_some(),
            unit,
        }
    }

    /// The pid a just-exited child leaves behind: guaranteed dead.
    fn dead_pid() -> u32 {
        #[cfg(unix)]
        let mut command = std::process::Command::new("true");
        #[cfg(windows)]
        let mut command = {
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/c", "exit", "0"]);
            cmd
        };
        let mut child = command.spawn().expect("spawn");
        child.wait().expect("wait");
        child.id()
    }

    fn test_config(cache_dir: &Path) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9/v2/stow".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: std::time::Duration::from_millis(200),
            negative_cache_ttl: std::time::Duration::ZERO,
            circuit_reset_after: std::time::Duration::ZERO,
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 0,
            index_refresh_interval: std::time::Duration::ZERO,
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db_pool: std::sync::Arc::default(),
            trust_material: std::sync::Arc::default(),
        }
    }

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
        assert!(!build_finished(&std::process::id().to_string()));
    }

    #[test]
    fn a_dead_cargo_pid_makes_its_journal_finished() {
        assert!(build_finished(&dead_pid().to_string()));
    }

    #[test]
    fn a_live_process_is_not_finished() {
        // EPERM would mean the same: an unsignalable process is alive,
        // never finished.
        assert!(!build_finished(&std::process::id().to_string()));
        assert!(process_alive(std::process::id()));
        assert!(!process_alive(dead_pid()));
    }

    #[test]
    fn journal_round_trip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal = journal_path(dir.path(), "stow-1");
        append_lines(&journal, &[entry("serde", "1.85.0")]).expect("append");
        let read = std::fs::read_to_string(&journal).expect("read journal");
        let parsed: JournalEntry = serde_json::from_str(read.trim()).expect("parse entry");
        assert_eq!(parsed.unit.crate_name, "serde");
        assert_eq!(
            parsed.unit.explicit_target.as_deref(),
            Some("wasm32-unknown-unknown")
        );
        assert_eq!(parsed.build_host, "x86_64-unknown-linux-gnu");
        assert_eq!(parsed.unit.externs.len(), 1);
    }

    #[test]
    fn only_finished_journals_are_listed() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(journal_path(dir.path(), "stow-1"), "{}\n").expect("write");
        std::fs::write(
            journal_path(dir.path(), &std::process::id().to_string()),
            "{}\n",
        )
        .expect("write");
        std::fs::write(dir.path().join("unrelated.txt"), "{}\n").expect("write");
        let finished = finished_journals(dir.path());
        assert_eq!(finished, vec![journal_path(dir.path(), "stow-1")]);
    }

    /// A drain killed mid-post leaves `…jsonl.draining-<pid>` behind:
    /// once that drainer's pid is dead the claim is reclaimable.
    #[test]
    fn a_dead_drainers_claim_is_reclaimed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let claim = dir
            .path()
            .join(format!("stow-misses.1.jsonl.draining-{}", dead_pid()));
        std::fs::write(&claim, "{}\n").expect("write claim");
        let finished = finished_journals(dir.path());
        assert_eq!(finished, vec![claim]);
    }

    /// A live drainer's claim is left alone: the listing never feeds an
    /// in-flight post to a second drainer.
    #[test]
    fn a_live_drainers_claim_is_left_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let claim = dir.path().join(format!(
            "stow-misses.1.jsonl.draining-{}",
            std::process::id()
        ));
        std::fs::write(&claim, "{}\n").expect("write claim");
        assert!(finished_journals(dir.path()).is_empty());
    }

    /// The recorded build host comes from the build's host units, with
    /// the consumer as the stand-in when nothing recorded one — never
    /// re-probed at drain time.
    #[test]
    fn build_host_comes_from_the_host_units() {
        let host_unit = ObservedUnit {
            target: "aarch64-unknown-linux-gnu".to_owned(),
            ..unit("serde_derive", None)
        };
        assert_eq!(
            recorded_build_host(
                &[unit("serde", Some("wasm32-unknown-unknown")), host_unit],
                "wasm32-unknown-unknown",
            ),
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(
            recorded_build_host(
                &[unit("serde", Some("wasm32-unknown-unknown"))],
                "wasm32-unknown-unknown",
            ),
            "wasm32-unknown-unknown"
        );
    }

    /// Restore over a recreated journal merges rather than renames over
    /// it: a pid-reusing live writer's entries survive alongside the
    /// restored ones.
    #[test]
    fn restore_merges_over_a_recreated_journal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let journal = journal_path(dir.path(), "1");
        let work = dir.path().join("stow-misses.1.jsonl.draining-12345");
        append_lines(&work, &[entry("serde", "1.85.0")]).expect("write claim");
        append_lines(&journal, &[entry("fresh", "1.85.0")]).expect("write journal");

        restore(
            &work,
            &journal,
            std::slice::from_ref(&entry("serde", "1.85.0")),
        );

        let contents = std::fs::read_to_string(&journal).expect("read journal");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"fresh\""));
        assert!(lines[1].contains("\"serde\""));
        assert!(!work.exists());
    }

    /// A failed restore keeps the claim file — the next drain reclaims
    /// it by the now-dead drainer pid in its name.
    #[test]
    fn restore_keeps_the_claim_when_the_append_fails() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A directory under the journal's name makes the append fail.
        let journal = journal_path(dir.path(), "1");
        std::fs::create_dir(&journal).expect("mkdir");
        let work = dir.path().join("stow-misses.1.jsonl.draining-12345");
        append_lines(&work, &[entry("serde", "1.85.0")]).expect("write claim");

        restore(
            &work,
            &journal,
            std::slice::from_ref(&entry("serde", "1.85.0")),
        );

        assert!(work.exists());
    }

    /// A drain that cannot post appends its unposted groups back under
    /// the journal's own name — the entries wait for the next drain
    /// instead of being lost or renamed over a live writer's file.
    #[tokio::test]
    async fn a_failed_drain_rejournals_only_the_unposted_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let journal = journal_path(dir.path(), "stow-1");
        // Group A's units carry a name no CrateName parses, so its
        // graph mints no roots and the group "posts" empty; group B's
        // unit mints a real miss whose POST fails against the dead
        // edge, so only it goes back.
        let broken = entry("not a crate", "1.85.0");
        let postable = JournalEntry {
            unit: ObservedUnit {
                crate_name: "serde".to_owned(),
                externs: Vec::new(),
                ..unit("serde", Some("wasm32-unknown-unknown"))
            },
            ..entry("serde", "1.99.0")
        };
        append_lines(&journal, &[broken, postable]).expect("write journal");

        drain_journal(&config, &journal).await;

        assert!(
            journal.exists(),
            "the unposted group went back to the journal"
        );
        let contents = std::fs::read_to_string(&journal).expect("read journal");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"serde\""));
        assert!(lines[0].contains("\"1.99.0\""));
        // The claim file is gone; the restored journal is itself
        // finished, so the next drain picks it up.
        assert_eq!(finished_journals(dir.path()), vec![journal]);
    }
}
