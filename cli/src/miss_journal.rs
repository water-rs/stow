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
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::artifact_cache::{LocalBuildArtifact, ObservedUnit};
use crate::config::StowConfig;
use crate::rustc_args::ParsedRustcArgs;
use crate::state_db::StateDb;

const JOURNAL_PREFIX: &str = "stow-misses.";
const JOURNAL_SUFFIX: &str = ".jsonl";
const DRAIN_CLAIM: &str = ".draining-";
const DRAIN_LOG: &str = "stow-drain.log";
/// The drain's stderr log rotates into `stow-drain.log.1` past this size —
/// it exists for forensics, not to grow without bound.
const DRAIN_LOG_MAX_BYTES: u64 = 256 * 1024;

/// One locally compiled unit's journal payload — the observation one
/// miss mints from, plus what a drain needs to name its build's misses —
/// which rustc compiled it and which host the build ran on.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct UnitLine {
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
    /// The `lockfile_graph_cache` key naming the build's persisted
    /// expanded graph — the drain mints each miss's dependency subgraph
    /// from its unit graph (stow#588). Empty on wrapper-journaled
    /// lines, whose builds carry no expanded graph — their units
    /// cannot mint a real subgraph and stay journaled until one can.
    #[serde(default)]
    expanded_cache_key: String,
    /// The compile observation itself.
    unit: ObservedUnit,
}

/// An inexact superset-hit report's journal payload (stow#882): the
/// exact chain — the direct-dep entries above the analysis's
/// superset-served nodes — minted off the group's resolved expanded
/// graph and posted behind the same proof-of-work admission a miss
/// takes.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct InexactReport {
    /// The rustc version the reporting build ran under.
    rustc_version: String,
    /// The build's `target_given` — the re-derivation's spelled
    /// `--target` fact when the journal holds no unit line to prove
    /// it (stow#367).
    #[serde(default)]
    consumer_spelled_target: bool,
    /// The `lockfile_graph_cache` key naming the build's persisted
    /// expanded graph — the group's own key (stow#588).
    #[serde(default)]
    expanded_cache_key: String,
    /// The consumer's compile target — the admission's `target`.
    target: String,
    /// The report's direct-dep entries — each node above a
    /// superset-served node, which the edge expands into the exact
    /// chain.
    entries: Vec<stow_types::api::DependencyGraphEntry>,
}

/// One journaled observation — a compiled unit the drain mints as a
/// miss, or an inexact-hit report carrying the exact chain the scheduler
/// should build (stow#882). Both kinds record the build's rustc and the
/// `lockfile_graph_cache` key of the graph they expand over, so the
/// drain groups and resolves them identically.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalEntry {
    /// One locally compiled unit — the observation one miss mints from.
    Unit(UnitLine),
    /// One inexact superset-hit report — the exact chain to queue.
    Inexact(InexactReport),
}

impl JournalEntry {
    /// The build's rustc — the group's first key part on both kinds.
    fn rustc_version(&self) -> &str {
        match self {
            Self::Unit(unit) => &unit.rustc_version,
            Self::Inexact(report) => &report.rustc_version,
        }
    }

    /// The persisted expanded graph's key — the group's second key part.
    fn expanded_cache_key(&self) -> &str {
        match self {
            Self::Unit(unit) => &unit.expanded_cache_key,
            Self::Inexact(report) => &report.expanded_cache_key,
        }
    }

    /// The compiling rustc's recorded `host:` — unit lines only.
    fn recorded_build_host(&self) -> Option<&str> {
        match self {
            Self::Unit(unit) => Some(&unit.build_host),
            Self::Inexact(_) => None,
        }
    }

    /// The consumer's compile target: a unit's explicit `--target`, or
    /// an inexact line's recorded project target.
    fn reported_target(&self) -> Option<&str> {
        match self {
            Self::Unit(unit) => unit.unit.explicit_target.as_deref(),
            Self::Inexact(report) => Some(&report.target),
        }
    }

    /// The line's own spelled-`--target` evidence: a unit's flag or its
    /// explicit `--target`; an inexact line's recorded `target_given`.
    const fn spelled_evidence(&self) -> bool {
        match self {
            Self::Unit(unit) => unit.consumer_spelled_target || unit.unit.explicit_target.is_some(),
            Self::Inexact(report) => report.consumer_spelled_target,
        }
    }
}

/// The compile observation one finished local compile leaves behind, or
/// `None` when its extern identities did not parse — the unit is not
/// observed and never mints a miss (stow#317).
pub fn observed_unit(parsed: &ParsedRustcArgs, build: &LocalBuildArtifact) -> Option<ObservedUnit> {
    // A local-only unit is never observed: its miss reports nothing the
    // admissions post could act on, so the journal skips it entirely
    // (stow#1006).
    if build.reach == stow_types::public_cache::Reach::LocalOnly {
        return None;
    }
    let externs = match serde_json::from_str(&build.dependencies.c_metadata_json) {
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
        // Cargo spells explicit codegen flags for target units but not
        // for the build-override units on the host half — the split a
        // target build leaves on the argv (stow#349).
        build_override: crate::unit_node::build_override_signal(parsed),
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
        if Process32First(snapshot, &raw mut entry) != 0 {
            loop {
                if entry.th32ProcessID == own {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32Next(snapshot, &raw mut entry) == 0 {
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
pub fn process_alive(pid: u32) -> bool {
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
pub fn process_alive(pid: u32) -> bool {
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
        let alive = GetExitCodeProcess(handle, &raw mut code) != 0
            && i32::try_from(code) == Ok(STILL_ACTIVE);
        CloseHandle(handle);
        alive
    }
}

#[cfg(not(any(unix, windows)))]
pub fn process_alive(_pid: u32) -> bool {
    true
}

/// The pid a just-exited child leaves behind: guaranteed dead.
#[cfg(test)]
pub fn dead_pid() -> u32 {
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
    spawn_drain_unconditional(target_dir);
}

/// Spawn the detached drainer whether or not a journal is pending — the
/// day's usage report rides in the same process, and an all-hit build
/// leaves no journal for [`spawn_drain`] to find (stow#889). The child
/// exits promptly when it finds nothing to do.
pub fn spawn_drain_unconditional(target_dir: &Path) {
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
    // Keep the file: a spawn failure is invisible otherwise — the
    // parent's `tracing::warn` lands on the build's own stderr, not in
    // the log the drain never started (stow#588).
    let mut log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .ok();
    let stderr = log_file
        .as_ref()
        .and_then(|file| file.try_clone().ok())
        .map_or_else(Stdio::null, Stdio::from);
    let mut command = std::process::Command::new(&exe);
    command
        .arg("__drain-misses")
        .arg(target_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        // The chrome trace file is one process's: a second writer
        // truncates it on open and the parent's spans are lost.
        .env_remove(crate::STOW_TRACE_FILE_ENV);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // A session of its own: a `SIGINT`/`SIGTERM` aimed at the
        // build's process group never kills the drain mid-claim. The
        // drain starts at the caller's own priority: its re-derivation
        // cargo holds the package-cache lock the user's next command
        // needs, so a niced cargo would hold it *longer* — the drain
        // lowers itself before the part that only burns CPU instead
        // (stow#667).
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
        // The drain starts at the caller's priority for the same
        // reason — its cargo holds the lock the user's next command
        // needs; it lowers itself once only CPU-bound posting remains
        // (stow#667).
        command.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    if let Err(error) = command.spawn() {
        tracing::warn!(error = %error, "could not spawn the miss drain");
        if let Some(file) = log_file.as_mut() {
            let _ = writeln!(file, "stow: could not spawn the miss drain: {error}");
        }
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
    let entry = JournalEntry::Unit(UnitLine {
        rustc: rustc.to_string_lossy().into_owned(),
        rustc_version: build.rustc_version.clone(),
        build_host: build_host.to_owned(),
        consumer_spelled_target: unit.explicit_target.is_some(),
        // The rustc wrapper has no project context — it cannot name
        // the build's expanded graph; the build's context sidecar does
        // (stow#588).
        expanded_cache_key: String::new(),
        unit,
    });
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

/// The consumer's recorded build facts a supervised journal carries:
/// its manifest directory — the project the drain re-derives the
/// expanded graph from when the enrichment's memoized store has not
/// landed — and the inputs `lockfile_graph_cache::key_of` hashes,
/// serialized into the sidecar so the drain can tell a same-inputs
/// re-derivation from a project that changed after the build
/// (stow#588).
pub struct JournalConsumer<'a> {
    pub manifest_dir: &'a Path,
    pub key: &'a crate::lockfile_graph_cache::KeyInputs<'a>,
}

/// Write the supervising build's journal: one batch append by the driver
/// after cargo exits, then kick the drain — `stow build` returns as soon
/// as cargo does. `inexact_entries` is the analysis's inexact superset-
/// hit report — the direct-dep entries above every superset-served node —
/// journaled as one `inexact` line so the report's admission rides the
/// same detached drain a miss does (stow#882).
pub fn journal_supervised(
    rustc: &OsStr,
    consumer: &JournalConsumer<'_>,
    observations: &[ObservedUnit],
    target_dir: &Path,
    expanded_cache_key: &str,
    inexact_entries: &[stow_types::api::DependencyGraphEntry],
) {
    if observations.is_empty() && inexact_entries.is_empty() {
        return;
    }
    // The consumer's flag plus any observed explicit `--target` — the
    // flag covers a build where every observed unit is host-side and
    // none carries the flag itself.
    let consumer_spelled_target = consumer.key.target_given
        || observations
            .iter()
            .any(|unit| unit.explicit_target.is_some());
    let build_host = recorded_build_host(observations, consumer.key.target);
    let mut entries: Vec<JournalEntry> = observations
        .iter()
        .map(|unit| {
            JournalEntry::Unit(UnitLine {
                rustc: rustc.to_string_lossy().into_owned(),
                rustc_version: consumer.key.rustc_version.to_owned(),
                build_host: build_host.clone(),
                consumer_spelled_target,
                expanded_cache_key: expanded_cache_key.to_owned(),
                unit: unit.clone(),
            })
        })
        .collect();
    if !inexact_entries.is_empty() {
        entries.push(JournalEntry::Inexact(InexactReport {
            rustc_version: consumer.key.rustc_version.to_owned(),
            consumer_spelled_target: consumer.key.target_given,
            expanded_cache_key: expanded_cache_key.to_owned(),
            target: consumer.key.target.to_owned(),
            entries: inexact_entries.to_vec(),
        }));
    }
    let journal = journal_path(target_dir, &supervised_build());
    if let Err(error) = append_lines(&journal, &entries) {
        tracing::warn!(error = %error, journal = %journal.display(), "could not journal the build's compile observations");
    }
    // The expanded graph's store lands only when the in-build analysis
    // reaches it — a build aborts that analysis when cargo exits, and a
    // fast build's cargo exits first — so the journal also carries the
    // context the drain re-derives the same graph from (stow#588).
    write_consumer_context(&journal, consumer.manifest_dir, Some(consumer.key));
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
///
/// The drain runs in two phases: *prepare* — claim, parse, group, and
/// resolve each group's graph, deriving through the gate a stow command
/// can stop — then, with the gate shut and the priority lowered, *post*
/// (stow#667).
pub async fn drain(target_dir: &Path, state_db: &StateDb) -> stow_types::error::Result<()> {
    let config = StowConfig::load_local(state_db.clone())?;
    let journals = finished_journals(target_dir);
    // The drain runs detached with stderr in `stow-drain.log`: one line
    // naming how many journals it found is what separates "the drain
    // never spawned" from "every keep-path was silent" in that file.
    tracing::info!(
        target_dir = %target_dir.display(),
        journals = journals.len(),
        "miss drain starting"
    );
    // The gate directory is the cargo home's: the package-cache lock a
    // derivation cargo holds is per cargo home, so the gate is too
    // (stow#667).
    let mut gate = crate::config::cargo_home().map_or_else(
        || {
            tracing::warn!(
                "could not resolve the cargo home; this drain will not re-derive unit graphs"
            );
            crate::derive_gate::DerivationGate::Shut
        },
        |cargo_home| crate::derive_gate::DerivationGate::unopened(cargo_home.join("stow")),
    );
    let mut prepared = Vec::new();
    for journal in &journals {
        if let Some(journal) = prepare_journal(&config, journal, &mut gate).await {
            prepared.push(journal);
        }
    }
    // Every derivation this drain will ever run has run — or a stow
    // command shut the gate mid-prepare — so the listener and pointer
    // go away here (stow#667).
    gate.shut().await;
    // Everything left only burns CPU — posting solves each admission's
    // proof of work — so the drain lowers itself now. Doing it at spawn
    // would have put the derivation phase's cargo at this priority
    // while it held the package-cache lock the user's next command
    // needs (stow#667).
    lower_own_priority();
    for journal in prepared {
        // A journal is one build; a `stow-`-named file is a supervised
        // build's journal, already counted at the driver's tail —
        // counting it again would double it.
        if is_plain_cargo_journal(&journal.journal) {
            crate::report::bump_build(&config).await;
        }
        post_journal(&config, journal).await;
    }
    crate::report::maybe_report(&config).await;
    Ok(())
}

/// Whether the journal file belongs to a plain `cargo` build — its
/// build token is the parent cargo's pid, so it lacks the `stow-`
/// prefix `supervised_build` writes.
fn is_plain_cargo_journal(journal: &Path) -> bool {
    journal
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(JOURNAL_PREFIX))
        .is_some_and(|rest| !rest.starts_with("stow-"))
}

/// Drop the drain's scheduling priority for its CPU-only posting
/// phase. Best-effort, as the spawn-time call was: a failure leaves
/// the drain no worse than before.
#[cfg(unix)]
fn lower_own_priority() {
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 15);
    }
}

/// [`lower_own_priority`]'s Windows spelling.
#[cfg(windows)]
fn lower_own_priority() {
    use windows_sys::Win32::System::Threading::{
        BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass,
    };
    unsafe {
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}

/// Nowhere to lower to on other platforms.
#[cfg(not(any(unix, windows)))]
fn lower_own_priority() {}

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

/// One journal carried from its prepare half to its post half: the
/// claim path and the real journal path, the build-level facts every
/// group posts under, and the groups themselves — each with the graph
/// it mints from, or `None` for one that stays journaled (stow#667).
struct PreparedJournal {
    journal: PathBuf,
    work: PathBuf,
    consumer_target: String,
    build_host: String,
    consumer_spelled_target: bool,
    groups: Vec<PreparedGroup>,
}

/// One `(rustc_version, expanded_cache_key)` group with its graph
/// resolution already done — `graph` is `None` when the units stay
/// journaled for a later drain. A dropped group (`MemoMiss::Drop`) is
/// simply absent from the list (stow#674).
struct PreparedGroup {
    key: DrainGroupKey,
    entries: Vec<JournalEntry>,
    graph: Option<crate::ExpandedDependencyGraph>,
}

/// Prepare then post one journal — the shape the tests that drive a
/// single journal use; the priority stays the caller's, only `drain`
/// lowers it (stow#667).
#[cfg(test)]
async fn drain_journal(
    config: &StowConfig,
    journal: &Path,
    gate: &mut crate::derive_gate::DerivationGate,
) {
    if let Some(prepared) = prepare_journal(config, journal, gate).await {
        post_journal(config, prepared).await;
    }
}

/// The prepare half of draining a journal: claim it, parse it, group
/// it, and resolve each group's graph — the memoized load first, else
/// a derivation through `gate`, which is where a stow command can stop
/// this drain's cargo (stow#667). `None` is a journal this drain did
/// not claim or could not read.
async fn prepare_journal(
    config: &StowConfig,
    journal: &Path,
    gate: &mut crate::derive_gate::DerivationGate,
) -> Option<PreparedJournal> {
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(error = %error, journal = %journal.display(), "could not claim the miss journal; leaving it for a later drain");
                return None;
            }
        }
    };
    let journal = journal.with_file_name(journal_name);
    let contents = match std::fs::read_to_string(&work) {
        Ok(contents) => contents,
        Err(error) => {
            tracing::warn!(error = %error, journal = %journal.display(), "could not read miss journal");
            restore(&work, &journal, &[]);
            return None;
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
        return None;
    }
    // One journal is one build: every explicit `--target` or recorded
    // project target in it names the same consumer, and a native
    // build's consumer is the host it built on — all recorded at write
    // time, so the drain never re-probes. An inexact-only journal's
    // line carries the consumer target itself (stow#882).
    let recorded_host = entries
        .iter()
        .find_map(|entry| entry.recorded_build_host().map(str::to_owned));
    let consumer_target = entries
        .iter()
        .find_map(|entry| entry.reported_target().map(str::to_owned))
        .or_else(|| recorded_host.clone())
        .expect("every journal line records a build host or a reported target");
    let build_host = recorded_host.unwrap_or_else(|| consumer_target.clone());
    // The flag covers a spelled build whose observations were all
    // host-side; each line's own recorded evidence counts too.
    let consumer_spelled_target = entries.iter().any(JournalEntry::spelled_evidence);
    // The build's context sidecar names the consumer manifest the
    // drain re-derives its unit graph from, and — for a supervised
    // build — the inputs its expanded-graph key hashed (stow#588).
    let context = read_context(&work);
    let mut groups: BTreeMap<DrainGroupKey, Vec<JournalEntry>> = BTreeMap::new();
    for entry in entries {
        groups
            .entry(DrainGroupKey {
                rustc_version: entry.rustc_version().to_owned(),
                expanded_cache_key: entry.expanded_cache_key().to_owned(),
            })
            .or_default()
            .push(entry);
    }
    let mut prepared_groups = Vec::new();
    for (key, group) in groups {
        if let Some(prepared) = prepare_group(
            config,
            &journal,
            DrainContext {
                consumer_target: &consumer_target,
                build_host: &build_host,
                spelled: consumer_spelled_target,
            },
            &key,
            context.as_ref(),
            group,
            gate,
        )
        .await
        {
            prepared_groups.push(prepared);
        }
    }
    Some(PreparedJournal {
        journal,
        work,
        consumer_target,
        build_host,
        consumer_spelled_target,
        groups: prepared_groups,
    })
}

/// The post half: admit each prepared group that has a graph, restore
/// the rest under the journal's own name, and remove the sidecar of a
/// fully drained journal. This is the phase that solves the
/// admissions' proof of work, which is why `drain` runs it after
/// lowering its own priority (stow#667).
async fn post_journal(config: &StowConfig, prepared: PreparedJournal) {
    let PreparedJournal {
        journal,
        work,
        consumer_target,
        build_host,
        consumer_spelled_target,
        groups,
    } = prepared;
    let mut unposted = Vec::new();
    for group in groups {
        unposted.extend(
            post_group(
                config,
                &journal,
                DrainContext {
                    consumer_target: &consumer_target,
                    build_host: &build_host,
                    spelled: consumer_spelled_target,
                },
                group,
            )
            .await,
        );
    }
    restore(&work, &journal, &unposted);
    if unposted.is_empty() {
        let _ = std::fs::remove_file(context_path(&work));
    }
}

/// What names one journal group: the rustc its build ran, plus the
/// supervised lane's persisted expanded graph (by cache key). Empty key
/// groups drain through the journal's context sidecar instead (stow#588).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DrainGroupKey {
    rustc_version: String,
    expanded_cache_key: String,
}

/// The context sidecar one standalone `cargo build` drops next to its
/// journal: the consumer package's manifest dir, so the drain can
/// re-derive the build's unit graph after the build exits (stow#588).
const CONTEXT_PREFIX: &str = "stow-context.";

/// Every wrapper invocation under the build's root package lands here:
/// cargo marks it `CARGO_PRIMARY_PACKAGE`, and `CARGO_MANIFEST_DIR` then
/// names the manifest the user is building — a path dep's or registry
/// crate's units never qualify (stow#588).
pub fn note_consumer_context(out_dir: &Path) {
    if std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none() {
        return;
    }
    let (Some(manifest_dir), Some(target_dir)) = (
        std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from),
        target_dir_for(out_dir),
    ) else {
        return;
    };
    write_consumer_context(
        &journal_path(&target_dir, &cargo_build()),
        &manifest_dir,
        None,
    );
}

/// The sidecar's serialized `cache_key` inputs: the owned mirror of
/// `KeyInputs` the drain hands back to `key_of` (stow#588).
#[derive(serde::Deserialize)]
struct SidecarKeyInputs {
    action: String,
    cargo_args: Vec<String>,
    current_dir: PathBuf,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    target: String,
    target_given: bool,
    rustc_version: String,
}

impl SidecarKeyInputs {
    /// Recompute the build's `cache_key` over the project's *current*
    /// files — equal to the journal's `expanded_cache_key` iff nothing
    /// the function hashes changed since the build (stow#588).
    fn key_of(&self) -> stow_types::error::Result<String> {
        let cargo_args: Vec<OsString> = self.cargo_args.iter().map(OsString::from).collect();
        let env = std::env::vars_os().collect::<Vec<_>>();
        crate::lockfile_graph_cache::key_of(&crate::lockfile_graph_cache::KeyInputs {
            action: &self.action,
            cargo_args: &cargo_args,
            current_dir: &self.current_dir,
            manifest_path: &self.manifest_path,
            workspace_root: &self.workspace_root,
            target: &self.target,
            target_given: self.target_given,
            rustc_version: &self.rustc_version,
            env: &env,
        })
    }
}

/// Drop a journal's context sidecar: the consumer manifest dir the
/// drain re-derives the build's unit graph from, plus — for a
/// supervised journal — the inputs its `expanded_cache_key` hashed, so
/// the drain's re-derivation is a memo of that one function rather
/// than a guess at whatever the project reads now (stow#588).
fn write_consumer_context(
    journal: &Path,
    manifest_dir: &Path,
    key: Option<&crate::lockfile_graph_cache::KeyInputs<'_>>,
) {
    let context = context_path(journal);
    let body = key.map_or_else(
        || serde_json::json!({ "consumer_manifest_dir": manifest_dir }),
        |key| serde_json::json!({
            "consumer_manifest_dir": manifest_dir,
            "cache_key": {
                "action": key.action,
                "cargo_args": key.cargo_args.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>(),
                "current_dir": key.current_dir,
                "manifest_path": key.manifest_path,
                "workspace_root": key.workspace_root,
                "target": key.target,
                "target_given": key.target_given,
                "rustc_version": key.rustc_version,
            },
        }),
    );
    if let Err(error) = std::fs::write(&context, body.to_string()) {
        tracing::warn!(error = %error, context = %context.display(), "could not write the build's context sidecar");
    }
}

/// The context sidecar one journal name maps to: `stow-misses.<id>.jsonl`
/// (or its `.draining-*` claim) pairs with `stow-context.<id>`.
fn context_path(journal: &Path) -> PathBuf {
    let name = journal
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let base = name.split_once(DRAIN_CLAIM).map_or(name, |(base, _)| base);
    let id = base
        .trim_start_matches(JOURNAL_PREFIX)
        .trim_end_matches(JOURNAL_SUFFIX);
    journal.with_file_name(format!("{CONTEXT_PREFIX}{id}"))
}

/// A journal's context sidecar: the consumer manifest dir to
/// re-derive the build's unit graph from, plus — for a supervised
/// journal — the `cache_key` inputs the memo check recomputes
/// (stow#588).
struct JournalContext {
    manifest_dir: PathBuf,
    cache_key: Option<SidecarKeyInputs>,
}

/// The context a journal's sidecar recorded, if any.
fn read_context(journal: &Path) -> Option<JournalContext> {
    let path = context_path(journal);
    let body = std::fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    let manifest_dir = value
        .get("consumer_manifest_dir")?
        .as_str()
        .map(PathBuf::from)?;
    let cache_key = value
        .get("cache_key")
        .and_then(|raw| serde_json::from_value(raw.clone()).ok());
    Some(JournalContext {
        manifest_dir,
        cache_key,
    })
}

/// The build-level facts every journal group drains under.
struct DrainContext<'a> {
    consumer_target: &'a str,
    build_host: &'a str,
    spelled: bool,
}

/// What a drain group's memo miss comes to.
enum MemoMiss {
    /// The same function of the same inputs, derived again.
    Derived(crate::ExpandedDependencyGraph),
    /// No graph now, and one may still arrive: the units stay journaled.
    Keep,
    /// The project no longer hashes to the key the build recorded and
    /// the memo holds nothing under it, so no build of the project as it
    /// now is will store this group's graph: its units are dropped
    /// (stow#674).
    Drop,
}

/// Re-derive a drain group's expanded graph when the keyed memo missed.
///
/// The keyed store is the memo of "the expanded graph for the inputs
/// `cache_key` hashes". A supervised journal's sidecar carries those
/// inputs, so the drain recomputes the key over the project's *current*
/// files before re-deriving: equal keys mean the same function of the
/// same inputs — the derived graph is the memo's own value and fills
/// the store under the build's key. A different key means the project
/// changed since the build: no build of the project as it now is will
/// ever store a graph under the recorded key, so the group's units can
/// never mint and are dropped (stow#674). A standalone build journals
/// no key; its re-derivation is the only graph it ever had (stow#588).
async fn rederive_memoized_graph(
    config: &StowConfig,
    journal: &Path,
    context: &JournalContext,
    key: &DrainGroupKey,
    units: usize,
    ctx: &DrainContext<'_>,
    gate: &mut crate::derive_gate::DerivationGate,
) -> MemoMiss {
    let consumer_target = ctx.consumer_target;
    let consumer_spelled_target = ctx.spelled;
    let DrainGroupKey {
        rustc_version,
        expanded_cache_key,
    } = key;
    if !expanded_cache_key.is_empty() {
        match context.cache_key.as_ref().map(SidecarKeyInputs::key_of) {
            Some(Ok(drain_key)) if drain_key == *expanded_cache_key => {}
            Some(Ok(drain_key)) => {
                tracing::warn!(
                    journal = %journal.display(),
                    cache_key = %expanded_cache_key,
                    drain_key = %drain_key,
                    units = units,
                    "the project changed since the build; dropping the miss journal's units"
                );
                return MemoMiss::Drop;
            }
            Some(Err(error)) => {
                tracing::warn!(error = %error, journal = %journal.display(), "could not recompute the miss journal's cache key; keeping its units");
                return MemoMiss::Keep;
            }
            None => {
                tracing::warn!(journal = %journal.display(), "the miss journal's context sidecar carries no cache-key inputs; keeping its units");
                return MemoMiss::Keep;
            }
        }
    }
    let expanded = match stow_types::identity::WireRustcVersion::parse(rustc_version.as_str()) {
        Err(error) => {
            tracing::warn!(error = %error, journal = %journal.display(), "miss journal's rustc version does not parse; keeping its units");
            return MemoMiss::Keep;
        }
        Ok(rustc) => {
            // A stow command's hold on the gate means its cargo is
            // next for the package-cache lock: this drain derives
            // nothing while one is present (stow#667).
            let Some(slot) = gate.slot().await else {
                tracing::info!(journal = %journal.display(), "a stow command is running; keeping the miss journal's units for a later drain");
                return MemoMiss::Keep;
            };
            match crate::workspace_deps::resolve_exact_dependency_graph_stoppable(
                &context.manifest_dir.join("Cargo.toml"),
                "build",
                &[],
                consumer_spelled_target.then_some(consumer_target),
                &context.manifest_dir,
                stow_types::api::runner_family(consumer_target)
                    .map_or(consumer_target, |family| family.host_triple()),
                &rustc,
                None,
                slot,
            )
            .await
            {
                Ok(Some(graph)) => graph,
                // A command asked for the stop mid-resolve: its cargo
                // is dead and reaped, so shut the gate — releasing the
                // requester — and keep the units (stow#667).
                Ok(None) => {
                    gate.shut().await;
                    tracing::info!(journal = %journal.display(), "a stow command started; stopped the miss drain's cargo and kept the units");
                    return MemoMiss::Keep;
                }
                Err(error) => {
                    tracing::warn!(error = %error, journal = %journal.display(), manifest = %context.manifest_dir.display(), "could not re-derive the miss journal's unit graph; keeping its units");
                    return MemoMiss::Keep;
                }
            }
        }
    };
    // A supervised re-derivation fills the memo under the build's own
    // key — the same function of the same inputs — so the next drain of
    // this key loads instead of re-deriving again.
    if !expanded_cache_key.is_empty()
        && let Err(error) =
            crate::lockfile_graph_cache::store(config, expanded_cache_key, &expanded).await
    {
        tracing::warn!(error = %error, journal = %journal.display(), "could not fill the expanded-graph memo");
    }
    MemoMiss::Derived(expanded)
}

/// The prepare half of draining one `(rustc_version,
/// expanded_cache_key)` group: the misses' subgraphs mint off the
/// build's own expanded graph — the memoized keyed value, or the same
/// function re-derived over unchanged inputs — and a journal line
/// whose build recorded none (a wrapper-written line, or a key whose
/// memo both missed and could not re-derive) cannot mint a real
/// context, so its units stay journaled (stow#588). A group the drain
/// can prove will never mint — the project no longer hashes to the
/// key its build recorded — is dropped: `None` (stow#674).
async fn prepare_group(
    config: &StowConfig,
    journal: &Path,
    ctx: DrainContext<'_>,
    key: &DrainGroupKey,
    context: Option<&JournalContext>,
    group: Vec<JournalEntry>,
    gate: &mut crate::derive_gate::DerivationGate,
) -> Option<PreparedGroup> {
    let mut expanded = if key.expanded_cache_key.is_empty() {
        None
    } else {
        match crate::lockfile_graph_cache::load(config, &key.expanded_cache_key).await {
            Ok(None) => {
                tracing::warn!(
                    journal = %journal.display(),
                    cache_key = %key.expanded_cache_key,
                    "miss journal's expanded graph is not in the lockfile graph cache"
                );
                None
            }
            Ok(graph) => graph,
            Err(error) => {
                tracing::warn!(error = %error, journal = %journal.display(), "could not load the miss journal's expanded graph");
                None
            }
        }
    };
    if expanded.is_none()
        && let Some(context) = context
    {
        match rederive_memoized_graph(config, journal, context, key, group.len(), &ctx, gate).await
        {
            MemoMiss::Derived(graph) => expanded = Some(graph),
            // Dropped units neither post nor go back: no build will
            // ever store the graph they mint off (stow#674).
            MemoMiss::Drop => return None,
            MemoMiss::Keep => {}
        }
    }
    Some(PreparedGroup {
        key: key.clone(),
        entries: group,
        graph: expanded,
    })
}

/// The post half of a prepared group: admit its units and post its
/// inexact-hit reports when it has a graph, returning the entries that
/// stay journaled — all of them on a failed post or a graph the prepare
/// phase could not get (stow#588, stow#882).
async fn post_group(
    config: &StowConfig,
    journal: &Path,
    ctx: DrainContext<'_>,
    group: PreparedGroup,
) -> Vec<JournalEntry> {
    let DrainContext {
        consumer_target,
        build_host,
        spelled: consumer_spelled_target,
    } = ctx;
    let PreparedGroup {
        key,
        entries: group,
        graph,
    } = group;
    let DrainGroupKey {
        rustc_version,
        expanded_cache_key,
    } = &key;
    let mut units: Vec<UnitLine> = Vec::new();
    let mut reports: Vec<InexactReport> = Vec::new();
    for entry in group {
        match entry {
            JournalEntry::Unit(unit) => units.push(unit),
            JournalEntry::Inexact(report) => reports.push(report),
        }
    }
    let mut unposted = Vec::new();
    if !units.is_empty() {
        let observations: Vec<ObservedUnit> = units.iter().map(|unit| unit.unit.clone()).collect();
        // The one keep-path that must name its cause: every other way
        // entries stay journaled already warns, and a silent failure
        // leaves the drain's own log saying nothing at all (stow#588).
        let posted = match &graph {
            Some(graph) => match crate::cargo_cmd::admit_observed_misses(
                config,
                consumer_target,
                rustc_version,
                build_host,
                consumer_spelled_target,
                &observations,
                graph,
            )
            .await
            {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        journal = %journal.display(),
                        "could not admit the miss journal's units; keeping them"
                    );
                    false
                }
            },
            None => false,
        };
        if !posted {
            unposted.extend(units.into_iter().map(|unit| {
                JournalEntry::Unit(UnitLine {
                    rustc: String::new(),
                    rustc_version: rustc_version.to_owned(),
                    build_host: build_host.to_owned(),
                    consumer_spelled_target,
                    expanded_cache_key: expanded_cache_key.to_owned(),
                    unit: unit.unit,
                })
            }));
        }
    }
    unposted.extend(
        post_inexact_reports(config, journal, graph.as_ref(), rustc_version, reports)
            .await
            .into_iter()
            .map(JournalEntry::Inexact),
    );
    unposted
}

/// [`post_group`]'s inexact half (stow#882): each report posts off the
/// group's resolved expanded graph — kept reports go back under the
/// journal's name like unposted units.
async fn post_inexact_reports(
    config: &StowConfig,
    journal: &Path,
    graph: Option<&crate::ExpandedDependencyGraph>,
    rustc_version: &str,
    reports: Vec<InexactReport>,
) -> Vec<InexactReport> {
    let mut unposted = Vec::new();
    for report in reports {
        let posted = match graph {
            Some(graph) => match crate::cargo_cmd::admit_inexact_report(
                config,
                &report.target,
                rustc_version,
                &report.entries,
                graph,
            )
            .await
            {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        journal = %journal.display(),
                        "could not post the journal's inexact-hit report; keeping it"
                    );
                    false
                }
            },
            None => false,
        };
        if !posted {
            unposted.push(report);
        }
    }
    unposted
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
        keyed_entry(crate_name, rustc_version, "")
    }

    fn keyed_entry(
        crate_name: &str,
        rustc_version: &str,
        expanded_cache_key: &str,
    ) -> JournalEntry {
        let unit = unit(crate_name, Some("wasm32-unknown-unknown"));
        JournalEntry::Unit(UnitLine {
            rustc: "rustc".to_owned(),
            rustc_version: rustc_version.to_owned(),
            build_host: "x86_64-unknown-linux-gnu".to_owned(),
            consumer_spelled_target: unit.explicit_target.is_some(),
            expanded_cache_key: expanded_cache_key.to_owned(),
            unit,
        })
    }

    fn test_config(cache_dir: &Path) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: cache_dir.to_path_buf(),
            request_timeout: std::time::Duration::from_millis(200),
            negative_cache_ttl: std::time::Duration::ZERO,
            circuit_reset_after: std::time::Duration::ZERO,
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 0,
            index_refresh_interval: std::time::Duration::ZERO,
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
            experimental: crate::config::ExperimentalConfig::default(),
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
        let JournalEntry::Unit(parsed) = serde_json::from_str(read.trim()).expect("parse entry")
        else {
            panic!("a unit line round-trips as a unit");
        };
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
        assert_eq!(finished_journals(dir.path()), [] as [std::path::PathBuf; 0]);
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

    /// A minimal resolvable project plus the key inputs its build's
    /// `cache_key` hashed — the supervised journal's sidecar record.
    fn keyed_project(dir: &Path) -> (PathBuf, crate::lockfile_graph_cache::KeyInputs<'static>) {
        let project = dir.join("consumer");
        std::fs::create_dir_all(project.join("src")).expect("src");
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(project.join("src/lib.rs"), "").expect("lib");
        (
            project.clone(),
            crate::lockfile_graph_cache::KeyInputs {
                action: "build",
                cargo_args: &[],
                current_dir: Box::leak(Box::new(project.clone())),
                manifest_path: Box::leak(Box::new(project.join("Cargo.toml"))),
                workspace_root: Box::leak(Box::new(project)),
                target: "wasm32-unknown-unknown",
                target_given: true,
                rustc_version: "1.99.0",
                // The same environment the drain's recompute sees —
                // `cache_key` reads `vars_os` on the live path, so the
                // memoized key must too (stow#617).
                env: Box::leak(Box::new(std::env::vars_os().collect::<Vec<_>>())).as_slice(),
            },
        )
    }

    /// A supervised journal whose keyed store is absent re-derives the
    /// graph by memo: the sidecar's recorded inputs still hash to the
    /// journal's key, so the drain mints off the derived graph and
    /// fills the store under the build's key (stow#588).
    #[tokio::test]
    async fn a_supervised_drain_memoizes_rederivation_under_the_builds_key() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let (project, key_inputs) = keyed_project(dir.path());
        let build_key = crate::lockfile_graph_cache::key_of(&key_inputs).expect("key");
        let journal = journal_path(dir.path(), "stow-1");
        write_consumer_context(&journal, &project, Some(&key_inputs));
        // The unit's name parses to no real crate — a drained graph
        // mints zero roots and "posts" empty, so the entry leaves the
        // journal; a kept entry proves the drain never re-derived.
        append_lines(
            &journal,
            &[keyed_entry("not a crate", "1.99.0", &build_key)],
        )
        .expect("write journal");

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        assert!(
            !journal.exists(),
            "the memo-derived group posted, so the journal is gone"
        );
        assert!(
            crate::lockfile_graph_cache::load(&config, &build_key)
                .await
                .expect("load")
                .is_some(),
            "the drain filled the memo under the build's key"
        );
    }

    /// The same journal whose project changed between build and drain
    /// — its manifest no longer hashes to the recorded key — drops its
    /// units: no build of the project as it now is will ever store a
    /// graph under that key, so the group can never mint (stow#674).
    #[tokio::test]
    async fn a_supervised_drain_drops_units_when_the_project_changed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let (project, key_inputs) = keyed_project(dir.path());
        let build_key = crate::lockfile_graph_cache::key_of(&key_inputs).expect("key");
        let journal = journal_path(dir.path(), "stow-1");
        write_consumer_context(&journal, &project, Some(&key_inputs));
        append_lines(
            &journal,
            &[keyed_entry("not a crate", "1.99.0", &build_key)],
        )
        .expect("write journal");
        // Between the build and the drain the user edits the manifest —
        // the recomputed key no longer equals the journal's.
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\nextra = []\n",
        )
        .expect("edit manifest");

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        assert!(
            !journal.exists(),
            "a group that can never mint is dropped, so the journal is gone"
        );
        assert!(
            !context_path(&journal).exists(),
            "a fully drained journal leaves no context sidecar"
        );
        assert!(
            crate::lockfile_graph_cache::load(&config, &build_key)
                .await
                .expect("load")
                .is_none(),
            "a changed project must not fill the memo"
        );
    }

    /// A drain that would re-derive — the project unchanged, the memo
    /// empty — derives nothing while a stow command holds the gate:
    /// the units stay journaled and the gate is shut for the rest of
    /// the drain (stow#667).
    #[tokio::test]
    async fn a_drain_does_not_derive_while_a_stow_command_runs() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let (project, key_inputs) = keyed_project(dir.path());
        let build_key = crate::lockfile_graph_cache::key_of(&key_inputs).expect("key");
        let journal = journal_path(dir.path(), "stow-1");
        write_consumer_context(&journal, &project, Some(&key_inputs));
        append_lines(
            &journal,
            &[keyed_entry("not a crate", "1.99.0", &build_key)],
        )
        .expect("write journal");
        let gate_dir = dir.path().join("gate");
        let hold = crate::derive_gate::ForegroundHold::enter(&gate_dir)
            .await
            .expect("enter the foreground hold");

        let mut gate = crate::derive_gate::DerivationGate::unopened(gate_dir);
        drain_journal(&config, &journal, &mut gate).await;

        let contents = std::fs::read_to_string(&journal).expect("journal kept");
        assert!(
            contents.contains("not a crate"),
            "a command-held gate keeps the units journaled"
        );
        assert!(
            crate::lockfile_graph_cache::load(&config, &build_key)
                .await
                .expect("load")
                .is_none(),
            "a drain that never derived fills nothing"
        );
        assert!(
            matches!(gate, crate::derive_gate::DerivationGate::Shut),
            "the gate is shut for the rest of this drain"
        );
        hold.release();
    }

    /// A journal mixing a never-mintable group with a kept one: the
    /// group whose recorded key the project no longer hashes to is
    /// dropped, while a group whose graph could not be re-derived
    /// stays journaled for a later drain (stow#674).
    #[tokio::test]
    async fn a_dropped_group_leaves_the_rest_of_the_journal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let (project, key_inputs) = keyed_project(dir.path());
        let build_key = crate::lockfile_graph_cache::key_of(&key_inputs).expect("key");
        let journal = journal_path(dir.path(), "stow-1");
        write_consumer_context(&journal, &project, Some(&key_inputs));
        let dropped = keyed_entry("not a crate", "1.99.0", &build_key);
        // The kept group is a wrapper-shaped line (no recorded key):
        // the manifest edit below breaks its re-derivation, so its
        // units stay journaled exactly as they did before.
        let mut postable = entry("serde", "1.99.0");
        if let JournalEntry::Unit(line) = &mut postable {
            line.unit.crate_name = "serde".to_owned();
            line.unit.externs = Vec::new();
        }
        append_lines(&journal, &[dropped, postable]).expect("write journal");
        // The edited manifest no longer hashes to the recorded key and
        // no longer parses, so the keyless group's re-derivation fails.
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\nbroken [[[",
        )
        .expect("edit manifest");

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        let contents = std::fs::read_to_string(&journal).expect("journal kept");
        assert!(
            !contents.contains("not a crate"),
            "the unmintable group's units were dropped"
        );
        assert!(
            contents.contains("\"serde\""),
            "the group that could not re-derive stayed journaled"
        );
        assert!(
            crate::lockfile_graph_cache::load(&config, &build_key)
                .await
                .expect("load")
                .is_none(),
            "a changed project must not fill the memo"
        );
    }

    /// A group whose recorded key cannot be recomputed — the sidecar
    /// carries no key inputs — is not proven unmintable: the units
    /// stay journaled (stow#674).
    #[tokio::test]
    async fn a_group_whose_key_cannot_be_recomputed_is_kept() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        let (project, _key_inputs) = keyed_project(dir.path());
        let journal = journal_path(dir.path(), "stow-1");
        // A context sidecar without `cache_key` inputs: the drain
        // cannot tell a changed project from an unchanged one.
        write_consumer_context(&journal, &project, None);
        append_lines(
            &journal,
            &[keyed_entry("serde", "1.99.0", "key-never-stored")],
        )
        .expect("write journal");

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        let contents = std::fs::read_to_string(&journal).expect("journal kept");
        assert!(contents.contains("\"serde\""));
        assert_eq!(finished_journals(dir.path()), vec![journal]);
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
        // edge, so only it goes back. Group A needs a loadable expanded
        // graph for its group key — an empty one mints zero roots and
        // "posts" immediately (stow#588).
        crate::lockfile_graph_cache::store(
            &config,
            "key-a",
            &crate::workspace_deps::ExpandedDependencyGraph {
                entries: Vec::new(),
                direct_dependencies: Vec::new(),
                local_manifests: Vec::new(),
                raw_unit_graph: br#"{"version":1,"units":[],"roots":[]}"#.to_vec(),
            },
        )
        .await
        .expect("store expanded graph");
        let broken = keyed_entry("not a crate", "1.85.0", "key-a");
        let mut postable = entry("serde", "1.99.0");
        if let JournalEntry::Unit(line) = &mut postable {
            line.unit.crate_name = "serde".to_owned();
            line.unit.externs = Vec::new();
        }
        append_lines(&journal, &[broken, postable]).expect("write journal");

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

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

    /// stow#882: an inexact line rides the same journal and grouping —
    /// serialized under its `(rustc_version, expanded_cache_key)` group,
    /// handed the group's loaded graph for its post, and restored whole
    /// when that post fails against the dead test edge.
    #[tokio::test]
    async fn an_inexact_line_round_trips_through_the_drain() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = test_config(dir.path());
        // The group's mint graph — an empty expanded graph is loadable
        // and lets the group reach its post (which fails at the dead
        // edge), proving the line went through grouping (stow#588).
        crate::lockfile_graph_cache::store(
            &config,
            "key-a",
            &crate::workspace_deps::ExpandedDependencyGraph {
                entries: Vec::new(),
                direct_dependencies: Vec::new(),
                local_manifests: Vec::new(),
                raw_unit_graph: br#"{"version":1,"units":[],"roots":[]}"#.to_vec(),
            },
        )
        .await
        .expect("store expanded graph");
        let journal = journal_path(dir.path(), "stow-1");
        let report = stow_types::api::DependencyGraphEntry {
            crate_name: "once_cell".parse().expect("crate name"),
            version: semver::Version::parse("1.20.0").expect("version"),
            features: vec!["alloc".to_owned()],
        };
        append_lines(
            &journal,
            &[JournalEntry::Inexact(InexactReport {
                rustc_version: "1.99.0".to_owned(),
                consumer_spelled_target: true,
                expanded_cache_key: "key-a".to_owned(),
                target: "wasm32-unknown-unknown".to_owned(),
                entries: vec![report],
            })],
        )
        .expect("write journal");

        // The grouping pass: one group holding the inexact line, with
        // its payload intact and the keyed graph resolved.
        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        let prepared = prepare_journal(&config, &journal, &mut gate)
            .await
            .expect("the journal prepares");
        assert_eq!(prepared.groups.len(), 1);
        assert!(prepared.groups[0].graph.is_some());
        let JournalEntry::Inexact(report) = &prepared.groups[0].entries[0] else {
            panic!("an inexact line groups as an inexact line");
        };
        assert_eq!(report.target, "wasm32-unknown-unknown");
        assert_eq!(report.expanded_cache_key, "key-a");
        assert_eq!(report.entries[0].crate_name.as_str(), "once_cell");

        // The post fails (dead edge): the line goes back to the journal
        // with its kind and payload preserved for the next drain.
        post_journal(&config, prepared).await;
        let contents = std::fs::read_to_string(&journal).expect("journal kept");
        assert!(contents.contains("\"kind\":\"inexact\""));
        let parsed: JournalEntry = serde_json::from_str(contents.trim()).expect("reparse");
        let JournalEntry::Inexact(report) = parsed else {
            panic!("the restored line stays an inexact line");
        };
        assert_eq!(report.target, "wasm32-unknown-unknown");
        assert_eq!(report.entries[0].crate_name.as_str(), "once_cell");
    }

    /// The admission a stub edge mints for the drain's report: difficulty
    /// 0, so its redemption is exactly the enqueue post's status.
    fn minted_admission() -> stow_types::api::EnqueueAdmission {
        let request = stow_types::api::EnqueueRequest {
            crate_name: "once_cell".parse().expect("crate name"),
            version: "1.20.0".parse().expect("version"),
            features_json: stow_types::identity::FeaturesJson::canonicalize(vec![
                "alloc".to_owned(),
            ])
            .expect("features"),
            target: "wasm32-unknown-unknown".parse().expect("target"),
            rustc_version: "1.99.0".parse().expect("rustc"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
            preserve_lockfile: false,
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        };
        stow_types::api::EnqueueAdmission {
            task_id: "once_cell-task".to_owned(),
            challenge: "abcdef0123456789".to_owned(),
            difficulty: 0,
            tree: stow_types::api::SubmissionTree::from_enqueue_requests(
                stow_types::api::SubmissionSource::InexactHit,
                &[request],
            )
            .expect("tree"),
        }
    }

    /// A stub edge: `POST /api/v1/admissions` mints `admissions` and
    /// `POST /api/v1/enqueue` answers `enqueue_status`.
    fn stub_edge(
        admissions: &[stow_types::api::EnqueueAdmission],
        enqueue_status: &'static str,
    ) -> crate::test_edge::StubEdge {
        crate::test_edge::serve(vec![
            crate::test_edge::Route {
                path: "/api/v1/admissions",
                status: "200 OK",
                body: serde_json::to_vec(admissions).expect("serialize admissions"),
            },
            crate::test_edge::Route {
                path: "/api/v1/enqueue",
                status: enqueue_status,
                body: Vec::new(),
            },
        ])
    }

    /// The inexact-line fixture `stub_edge`'s tests share: a keyed graph
    /// the group resolves, and the journal carrying the report.
    async fn inexact_journal(config: &StowConfig, dir: &Path) -> PathBuf {
        crate::lockfile_graph_cache::store(
            config,
            "key-a",
            &crate::workspace_deps::ExpandedDependencyGraph {
                entries: Vec::new(),
                direct_dependencies: Vec::new(),
                local_manifests: Vec::new(),
                raw_unit_graph: br#"{"version":1,"units":[],"roots":[]}"#.to_vec(),
            },
        )
        .await
        .expect("store expanded graph");
        let journal = journal_path(dir, "stow-1");
        let report = stow_types::api::DependencyGraphEntry {
            crate_name: "once_cell".parse().expect("crate name"),
            version: semver::Version::parse("1.20.0").expect("version"),
            features: vec!["alloc".to_owned()],
        };
        append_lines(
            &journal,
            &[JournalEntry::Inexact(InexactReport {
                rustc_version: "1.99.0".to_owned(),
                consumer_spelled_target: true,
                expanded_cache_key: "key-a".to_owned(),
                target: "wasm32-unknown-unknown".to_owned(),
                entries: vec![report],
            })],
        )
        .expect("write journal");
        journal
    }

    /// stow#929: an admission the drain could not redeem — here, an
    /// enqueue post the edge answered 503 — is not a posted report: the
    /// journal line goes back for a later drain's fresh challenge.
    #[tokio::test]
    async fn an_unredeemed_inexact_report_stays_journaled() {
        let dir = tempfile::tempdir().expect("temp dir");
        let edge = stub_edge(&[minted_admission()], "503 Service Unavailable");
        let mut config = test_config(dir.path());
        edge.configure(&mut config);
        let journal = inexact_journal(&config, dir.path()).await;

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        let contents = std::fs::read_to_string(&journal).expect("journal kept");
        assert!(
            contents.contains("\"kind\":\"inexact\""),
            "the unredeemed report stayed journaled"
        );
        assert_eq!(finished_journals(dir.path()), vec![journal]);
    }

    /// stow#929: a redeemed admission drains the report — the enqueue
    /// post's 2xx is the redemption, and nothing goes back.
    #[tokio::test]
    async fn a_redeemed_inexact_report_clears_the_journal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let edge = stub_edge(&[minted_admission()], "200 OK");
        let mut config = test_config(dir.path());
        edge.configure(&mut config);
        let journal = inexact_journal(&config, dir.path()).await;

        let mut gate = crate::derive_gate::DerivationGate::unopened(dir.path().join("gate"));
        drain_journal(&config, &journal, &mut gate).await;

        assert!(
            !journal.exists(),
            "the redeemed report left nothing journaled"
        );
        assert_eq!(finished_journals(dir.path()), [] as [std::path::PathBuf; 0]);
    }
}
