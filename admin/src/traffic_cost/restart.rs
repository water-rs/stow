//! `stow-admin traffic-cost restart` — the memory verdict of the
//! population scenario's restart (stow#1380).
//!
//! The harness traces V8's collections (`MINIFLARE_WORKERD_V8_FLAGS=
//! --trace-gc`) into the edge log, restarts the edge over the persisted
//! population and wakes the scheduler. This reads that log in two
//! windows, cut at byte offsets the harness recorded:
//!
//! - the empty scheduler's — from the start of the log to the end of the
//!   operator reset, before any population is seeded;
//! - the run's — from there to the end of the log, which the harness
//!   reads right after the restart's wake: the population pass, its
//!   snapshot write and the wake.
//!
//! and fails when
//!
//! - the traced JavaScript heap in use peaked more than
//!   [`HEAP_OVER_EMPTY_MIB`] above the empty scheduler's peak, or
//! - the Wasm linear memory the restart's wake logged exceeds the
//!   accounted graph storage its occupancy line reports by more than
//!   [`LINEAR_OVER_ACCOUNTED_BYTES`].
//!
//! A trace line reads `… ms: Scavenge 54.0 (68.4) -> 24.2 (32.7) MB, …`:
//! the number before the first parenthesis is the heap in use before the
//! collection, the parenthesized one the committed heap.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;
use stow_types::stow_error;

use crate::render::{Output, Table, emit};

/// The population scenario's JavaScript heap bound over an empty
/// scheduler's, in MiB: the 16 MiB V8's young generation grows to
/// under sustained allocation — every collection of a long-lived
/// isolate starts at the live heap plus that — and 8 MiB of live
/// strings, a page of the widest log rows. Megabyte snapshot rows
/// peaked 68 MiB over.
const HEAP_OVER_EMPTY_MIB: f64 = 24.0;

/// The bound of Wasm linear memory over the accounted graph storage
/// after the restart's wake: 10 MiB.
const LINEAR_OVER_ACCOUNTED_BYTES: u64 = 10 << 20;

/// The drive label the wake's occupancy lines carry (`store::restore`).
const WAKE_DRIVE: &str = "scheduler wake";

/// The phase of the wake's occupancy line after the log tail replayed.
const REPLAYED_PHASE: &str = "log tail replayed";

/// The message of the graph occupancy line.
const OCCUPANCY_MESSAGE: &str = "budget graph occupancy";

/// `stow-admin traffic-cost restart`.
#[derive(Debug, Args)]
pub struct RestartArgs {
    /// The edge log: the runtime's output with V8's collection trace.
    #[arg(long)]
    pub edge_log: PathBuf,
    /// The log length in bytes when the empty scheduler's window ended
    /// (after the operator reset, before the population pass).
    #[arg(long)]
    pub empty_bytes: usize,
    /// The log length in bytes when the edge restarted, before the
    /// wake: the wake line this reports is the last one after it.
    #[arg(long)]
    pub restart_bytes: usize,
}

/// What the wake logged after the log tail replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WakeSample {
    /// Wasm linear memory, bytes.
    pub wasm_linear_bytes: u64,
    /// The graph storage the occupancy line accounts for, bytes.
    pub accounted_storage_bytes: u64,
}

/// The restart verdict.
#[derive(Debug, Serialize)]
pub struct RestartReport {
    /// Peak JavaScript heap in use over the empty scheduler's window.
    pub empty_heap_peak_mib: f64,
    /// Peak JavaScript heap in use over the run.
    pub run_heap_peak_mib: f64,
    /// The bound on `run - empty`.
    pub heap_bound_mib: f64,
    /// The restart's wake.
    pub wake: WakeSample,
    /// The bound on `wasm_linear_bytes - accounted_storage_bytes`.
    pub linear_bound_bytes: u64,
}

impl RestartReport {
    /// Every failure, one line each.
    fn failures(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let over = self.run_heap_peak_mib - self.empty_heap_peak_mib;
        if over > self.heap_bound_mib {
            failures.push(format!(
                "JavaScript heap peaked at {:.1} MiB in use, {over:.1} MiB over the empty \
                 scheduler's {:.1} MiB (bound {:.1} MiB)",
                self.run_heap_peak_mib, self.empty_heap_peak_mib, self.heap_bound_mib
            ));
        }
        let linear_over = self
            .wake
            .wasm_linear_bytes
            .saturating_sub(self.wake.accounted_storage_bytes);
        if linear_over > self.linear_bound_bytes {
            failures.push(format!(
                "Wasm linear memory after the restart's wake is {} B, {linear_over} B over the \
                 {} B of accounted graph storage (bound {} B)",
                self.wake.wasm_linear_bytes,
                self.wake.accounted_storage_bytes,
                self.linear_bound_bytes
            ));
        }
        failures
    }
}

/// The heap in use, in MiB, before the collection a `--trace-gc` line
/// reports; `None` for any other line.
fn gc_in_use_mib(line: &str) -> Option<f64> {
    let (_, after) = line.split_once(" ms: ")?;
    let (before_arrow, after_arrow) = after.split_once(" -> ")?;
    if !after_arrow.contains(" MB") {
        return None;
    }
    let mut tokens = before_arrow.split_whitespace().rev();
    tokens
        .next()?
        .strip_prefix('(')?
        .strip_suffix(')')?
        .parse::<f64>()
        .ok()?;
    tokens.next()?.parse().ok()
}

/// The highest heap in use any traced collection reports in `window`.
fn heap_peak_mib(window: &str) -> Option<f64> {
    window.lines().filter_map(gc_in_use_mib).reduce(f64::max)
}

/// The value of the `key=` field of a `tracing` line: a quoted value up
/// to its closing quote, a bare one up to the next space.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!(" {key}=");
    let rest = &line[line.find(&needle)? + needle.len()..];
    rest.strip_prefix('"').map_or_else(
        || rest.split_whitespace().next(),
        |quoted| quoted.split_once('"').map(|(value, _)| value),
    )
}

/// The last occupancy line the wake logged after its log tail replayed.
fn wake_sample(window: &str) -> Result<Option<WakeSample>, String> {
    let Some(line) = window.lines().rfind(|line| {
        line.contains(OCCUPANCY_MESSAGE)
            && field(line, "drive") == Some(WAKE_DRIVE)
            && field(line, "phase") == Some(REPLAYED_PHASE)
    }) else {
        return Ok(None);
    };
    let number = |key: &str| {
        field(line, key)
            .ok_or_else(|| format!("the wake's occupancy line carries no `{key}`: {line}"))?
            .parse::<u64>()
            .map_err(|error| format!("the wake's `{key}` is not a number: {error}"))
    };
    Ok(Some(WakeSample {
        wasm_linear_bytes: number("wasm_linear_bytes")?,
        accounted_storage_bytes: number("accounted_storage_bytes")?,
    }))
}

/// One window of the raw log as text, without terminal escapes. The
/// offsets address the raw bytes, so a window is cut before it is
/// cleaned.
fn window(log: &[u8]) -> String {
    strip_ansi_escapes::strip_str(String::from_utf8_lossy(log))
}

/// Judge the three windows of an edge log.
fn judge(log: &[u8], empty_end: usize, restart: usize) -> Result<RestartReport, String> {
    if !(empty_end <= restart && restart <= log.len()) {
        return Err(format!(
            "the offsets are not ordered positions in the {}-byte log: empty window ends at \
             {empty_end}, restart at {restart}",
            log.len()
        ));
    }
    let empty = heap_peak_mib(&window(&log[..empty_end])).ok_or(
        "the empty scheduler's window holds no traced collection — is \
         MINIFLARE_WORKERD_V8_FLAGS=--trace-gc reaching the edge?",
    )?;
    let run = heap_peak_mib(&window(&log[empty_end..]))
        .ok_or("the run holds no traced collection after the empty scheduler's window")?;
    let wake = wake_sample(&window(&log[restart..]))?
        .ok_or("the restart logged no wake occupancy line after the log tail replayed")?;
    Ok(RestartReport {
        empty_heap_peak_mib: empty,
        run_heap_peak_mib: run,
        heap_bound_mib: HEAP_OVER_EMPTY_MIB,
        wake,
        linear_bound_bytes: LINEAR_OVER_ACCOUNTED_BYTES,
    })
}

/// Human rendering of the report.
fn render(report: &RestartReport) -> String {
    use std::fmt::Write as _;
    let mut table = Table::new(&["measure", "value", "bound"]);
    table.push([
        "JS heap in use, empty scheduler peak".to_owned(),
        format!("{:.1} MiB", report.empty_heap_peak_mib),
        String::new(),
    ]);
    table.push([
        "JS heap in use, run peak".to_owned(),
        format!("{:.1} MiB", report.run_heap_peak_mib),
        format!(
            "empty + {:.1} MiB = {:.1} MiB",
            report.heap_bound_mib,
            report.empty_heap_peak_mib + report.heap_bound_mib
        ),
    ]);
    table.push([
        "Wasm linear memory after the restart's wake".to_owned(),
        format!("{} B", report.wake.wasm_linear_bytes),
        format!(
            "accounted {} B + {} B",
            report.wake.accounted_storage_bytes, report.linear_bound_bytes
        ),
    ]);
    let mut out = table.render();
    let failures = report.failures();
    if failures.is_empty() {
        let _ = writeln!(out, "\nrestart memory: PASS");
    } else {
        let _ = writeln!(out, "\nrestart memory: FAIL");
        for failure in &failures {
            let _ = writeln!(out, "  {failure}");
        }
    }
    out
}

/// `stow-admin traffic-cost restart` — judge and exit nonzero on any
/// failure.
pub async fn run(args: &RestartArgs, output: Output) -> stow_types::error::Result<()> {
    let bytes = tokio::fs::read(&args.edge_log)
        .await
        .map_err(|error| stow_error!("read edge log {}: {error}", args.edge_log.display()))?;
    let report = judge(&bytes, args.empty_bytes, args.restart_bytes)
        .map_err(|error| stow_error!("{}: {error}", args.edge_log.display()))?;
    emit(output, &report, render)?;
    let failures = report.failures();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("restart memory: {} failure(s)", failures.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::{field, gc_in_use_mib, heap_peak_mib, judge, render, wake_sample};

    fn gc(in_use: f64, committed: f64) -> String {
        format!(
            "[1234:0x1] 99 ms: Scavenge {in_use:.1} ({committed:.1}) -> 24.2 (32.7) MB, \
             pooled: 0 MB, 1.2 / 0.0 ms  (average mu = 1.000) allocation failure;\n"
        )
    }

    fn wake_line(phase: &str, linear: u64, accounted: u64) -> String {
        format!(
            " INFO stow_edge::scheduler::graph: budget graph occupancy drive=\"scheduler wake\" \
             phase=\"{phase}\" boundary=\"observation\" graph_loaded=true node_storage_bytes=7 \
             accounted_storage_bytes={accounted} wasm_linear_bytes={linear}\n"
        )
    }

    #[test]
    fn a_collection_line_reads_the_heap_in_use() {
        assert_eq!(
            gc_in_use_mib(
                "[7:0x2]  120.5 ms: Mark-Compact 54.0 (68.4) -> 24.2 (32.7) MB, 3.0 / 0.0 ms"
            ),
            Some(54.0)
        );
        assert_eq!(gc_in_use_mib(&gc(45.3, 59.0)), Some(45.3));
        assert_eq!(gc_in_use_mib("CPU runtime ready {\"a\":1}"), None);
        assert_eq!(gc_in_use_mib("12 ms: Heap growing -> later"), None);
    }

    #[test]
    fn the_peak_is_the_highest_use_before_a_collection() {
        let window = [gc(10.0, 20.0), gc(70.2, 77.0), gc(30.0, 40.0)].concat();
        assert_eq!(heap_peak_mib(&window), Some(70.2));
        assert_eq!(heap_peak_mib("no trace here\n"), None);
    }

    #[test]
    fn fields_read_quoted_and_bare_values() {
        let line = wake_line("log tail replayed", 9, 4);
        assert_eq!(field(&line, "phase"), Some("log tail replayed"));
        assert_eq!(field(&line, "wasm_linear_bytes"), Some("9"));
        // A suffix of another key is not the key.
        assert_eq!(field(&line, "storage_bytes"), None);
    }

    #[test]
    fn the_last_replayed_wake_line_is_the_sample() {
        let window = [
            wake_line("log tail replayed", 1, 1),
            wake_line("snapshot loaded", 2, 2),
            wake_line("log tail replayed", 300, 200),
            wake_line("snapshot loaded", 4, 4),
        ]
        .concat();
        let sample = wake_sample(&window).expect("parse").expect("a sample");
        assert_eq!(sample.wasm_linear_bytes, 300);
        assert_eq!(sample.accounted_storage_bytes, 200);
        assert_eq!(wake_sample("nothing\n").expect("parse"), None);
        let broken = " INFO budget graph occupancy drive=\"scheduler wake\" \
                      phase=\"log tail replayed\" accounted_storage_bytes=1\n";
        assert!(wake_sample(broken).is_err());
    }

    /// An edge log: the empty window, then the run, then the restart.
    fn log(run_peak: f64, linear: u64, accounted: u64) -> (Vec<u8>, usize, usize) {
        // The runtime colours some lines; the offsets address raw bytes.
        let empty = [
            format!("\u{1b}[32m{}\u{1b}[0m", gc(8.0, 12.0)),
            "reset done\n".to_owned(),
        ]
        .concat();
        let run = [gc(run_peak, run_peak + 8.0), gc(20.0, 30.0)].concat();
        let restarted = [
            wake_line("snapshot loaded", linear / 2, accounted / 2),
            wake_line("log tail replayed", linear, accounted),
        ]
        .concat();
        let (a, b) = (empty.len(), empty.len() + run.len());
        ([empty, run, restarted].concat().into_bytes(), a, b)
    }

    #[test]
    fn a_run_inside_both_bounds_passes() {
        let (text, empty, restart) = log(31.5, (100 << 20) + 5, 100 << 20);
        let report = judge(&text, empty, restart).expect("judge");
        assert_eq!(report.empty_heap_peak_mib, 8.0);
        assert_eq!(report.run_heap_peak_mib, 31.5);
        assert!(report.failures().is_empty(), "{}", render(&report));
        assert!(render(&report).contains("restart memory: PASS"));
    }

    #[test]
    fn a_heap_peak_past_the_bound_over_empty_fails() {
        let (text, empty, restart) = log(32.1, 100 << 20, 100 << 20);
        let failures = judge(&text, empty, restart).expect("judge").failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("JavaScript heap"), "{failures:?}");
    }

    #[test]
    fn linear_memory_past_ten_mib_over_accounted_fails() {
        let (text, empty, restart) = log(10.0, (110 << 20) + 1, 100 << 20);
        let failures = judge(&text, empty, restart).expect("judge").failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("Wasm linear memory"), "{failures:?}");
    }

    #[test]
    fn missing_evidence_is_an_error_not_a_pass() {
        let (text, empty, restart) = log(10.0, 1, 1);
        assert!(judge(&text, empty, text.len() + 1).is_err());
        assert!(judge(&text, restart, empty).is_err());
        // No collection traced before the offset.
        assert!(judge(&text, 0, restart).is_err());
        // No wake line after the restart offset.
        assert!(judge(&text, empty, text.len()).is_err());
    }
}
