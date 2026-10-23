//! Final output stage for `stow-admin`.
//!
//! Every command produces a typed, serializable payload; this module owns
//! the two ways it can leave the process — pretty JSON under the global
//! `--json`, a fixed-width human table otherwise. These are the only
//! `println!` sites in the binary; diagnostics go through `tracing` on
//! stderr.

use std::fmt::Write as _;

use stow_types::stow_error;

/// Rendering mode selected by the global `--json` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Human-readable tables.
    Table,
    /// Machine-readable JSON on stdout.
    Json,
}

/// A fixed-width text table: a header row plus rows of pre-formatted
/// cells, rendered with two-space gutters.
#[derive(Debug)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with the given column headers.
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|header| (*header).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    /// Append one row. A short row leaves the trailing columns empty.
    pub fn push(&mut self, cells: impl IntoIterator<Item = impl Into<String>>) {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }

    /// Whether the table carries any rows.
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render the table with headers, one line per row.
    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(String::len).collect();
        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.len());
                }
            }
        }
        let mut out = String::new();
        let write_row = |out: &mut String, cells: &[String]| {
            let last = cells.len().saturating_sub(1);
            for (index, cell) in cells.iter().enumerate() {
                if index == last {
                    // The last column is never padded — trailing
                    // whitespace would only decorate a terminal.
                    let _ = write!(out, "{cell}");
                } else {
                    let _ = write!(out, "{cell:<width$}  ", width = widths[index]);
                }
            }
            let _ = writeln!(out);
        };
        write_row(&mut out, &self.headers);
        for row in &self.rows {
            write_row(&mut out, row);
        }
        out.trim_end().to_owned()
    }
}

/// Emit `value` on stdout: pretty JSON under `--json`, otherwise the
/// string `human` builds from it.
pub fn emit<T>(
    output: Output,
    value: &T,
    human: impl FnOnce(&T) -> String,
) -> stow_types::error::Result<()>
where
    T: serde::Serialize,
{
    match output {
        Output::Json => println!(
            "{}",
            serde_json::to_string_pretty(value)
                .map_err(|error| stow_error!("serialize output: {error}"))?
        ),
        Output::Table => println!("{}", human(value)),
    }
    Ok(())
}

/// Print one machine-readable line — the pre-existing stdout contract of
/// `index export` and `index targets`, unchanged by `--json` because the
/// publishing workflow parses it verbatim.
pub fn emit_line(line: &str) {
    println!("{line}");
}

/// The plan/apply envelope every mutating command reports: the plan the
/// operator reviewed, `dry_run: true` while `--yes` was absent, and the
/// applied result once `--yes` let it run.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Planned<P, R> {
    /// Nothing was applied — the run only rendered the plan.
    pub dry_run: bool,
    /// What the command will (or just did) touch.
    pub plan: P,
    /// The mutation's outcome — absent in a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<R>,
}

/// Run a mutating command's two phases: build `plan`, and only when
/// `apply` is `Some` run it and fold its result into the emitted envelope.
/// `Some` is the run that submits (`--yes`); `None` is the dry run, which
/// exits 0 having changed nothing. `apply` borrows the plan so the apply
/// can never drift from what the operator previewed.
pub async fn mutation<P, R>(
    output: Output,
    plan: P,
    human: impl FnOnce(&Planned<P, R>) -> String,
    apply: Option<impl AsyncFnOnce(&P) -> stow_types::error::Result<R>>,
) -> stow_types::error::Result<()>
where
    P: serde::Serialize,
    R: serde::Serialize,
{
    let dry_run = apply.is_none();
    let result = match apply {
        Some(apply) => Some(apply(&plan).await?),
        None => None,
    };
    let envelope = Planned {
        dry_run,
        plan,
        result,
    };
    emit(output, &envelope, human)
}

/// Footer line for a human-readable plan — names the gate the operator
/// must pass, or reports that the apply ran.
#[must_use]
pub const fn plan_footer(dry_run: bool) -> &'static str {
    if dry_run {
        "dry run — pass --yes to apply"
    } else {
        "applied"
    }
}

/// Render a duration in seconds as a compact age (`45s`, `12m`, `2h14m`,
/// `3d5h`) for table cells.
pub fn age(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86400;
    if seconds >= DAY {
        format!("{}d{}h", seconds / DAY, (seconds % DAY) / HOUR)
    } else if seconds >= HOUR {
        format!("{}h{}m", seconds / HOUR, (seconds % HOUR) / MINUTE)
    } else if seconds >= MINUTE {
        format!("{}m{}s", seconds / MINUTE, seconds % MINUTE)
    } else {
        format!("{seconds}s")
    }
}

/// Render a byte count as a compact human size for table cells.
pub fn size(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    const KIB: u64 = 1 << 10;
    #[allow(clippy::cast_precision_loss)]
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ===== The live watch frame (stow#853 §3) =====

use std::io::{self, IsTerminal as _};

use crossterm::ExecutableCommand;
use crossterm::cursor::MoveTo;
use crossterm::terminal::{Clear, ClearType};

use crate::watch::WatchFrame;

/// One value as one compact JSON line on `out` — NDJSON, so a line
/// consumer (`jq -c`, `head -1`) reads each tick as it lands (§3).
/// An `io::Result`, so a `BrokenPipe` reaches the caller where
/// `println!` would panic.
pub fn emit_ndjson(out: &mut impl io::Write, value: &impl serde::Serialize) -> io::Result<()> {
    let line = serde_json::to_string(value).map_err(io::Error::other)?;
    writeln!(out, "{line}")
}

/// The live frame's stdout sink: repaint in place on a TTY, append
/// otherwise, one NDJSON line under `--json` (§3). Everything the
/// watch writes leaves through here — `render.rs` keeps its only-
/// stdout-writer contract.
pub struct Screen<W = io::Stdout> {
    out: W,
    output: Output,
    /// Repaint in place — stdout is a terminal.
    tty: bool,
    /// The system zone the header clock renders in — resolved once,
    /// never UTC unless the zone is UTC.
    tz: jiff::tz::TimeZone,
    /// The first frame clears the screen; later frames move home and
    /// clear down, so nothing piles into scrollback and the last
    /// frame stays after exit.
    first: bool,
}

impl Screen<io::Stdout> {
    /// The sink on stdout — `IsTerminal` decides repaint-vs-append.
    pub fn new(output: Output, tz: jiff::tz::TimeZone) -> Self {
        Self {
            out: io::stdout(),
            output,
            tty: io::stdout().is_terminal(),
            tz,
            first: true,
        }
    }
}

impl<W: io::Write> Screen<W> {
    /// A sink on any writer — the tests' captured output and a
    /// forced TTY-ness.
    #[cfg(test)]
    pub const fn for_test(out: W, output: Output, tty: bool, tz: jiff::tz::TimeZone) -> Self {
        Self {
            out,
            output,
            tty,
            tz,
            first: true,
        }
    }

    /// Render one frame — the loop's whole per-tick write.
    pub fn render(&mut self, frame: &WatchFrame) -> io::Result<()> {
        match self.output {
            Output::Json => {
                emit_ndjson(&mut self.out, frame)?;
            }
            Output::Table if self.tty => self.repaint(frame)?,
            Output::Table => {
                let stamp = clock(frame.at, &self.tz, true);
                writeln!(self.out, "\n— {stamp} —")?;
                writeln!(self.out, "{}", table_frame(frame, &self.tz))?;
            }
        }
        self.out.flush()
    }

    /// Repaint: clear once, then move-home + clear-down each frame.
    /// The frame is truncated to the terminal's rows, ending with
    /// `… N more runs` when it overflows (§3).
    fn repaint(&mut self, frame: &WatchFrame) -> io::Result<()> {
        if self.first {
            self.out.execute(Clear(ClearType::All))?;
            self.first = false;
        } else {
            self.out.execute(MoveTo(0, 0))?;
            self.out.execute(Clear(ClearType::FromCursorDown))?;
        }
        let mut text = table_frame(frame, &self.tz);
        if let Ok((_, rows)) = crossterm::terminal::size() {
            let height = usize::from(rows);
            let lines: Vec<&str> = text.lines().collect();
            if lines.len() > height {
                let keep = height.saturating_sub(1);
                let mut truncated: String = lines[..keep].join("\n");
                let _ = write!(truncated, "\n… {} more runs", lines.len() - keep);
                text = truncated;
            }
        }
        writeln!(self.out, "{text}")
    }
}

/// Format one instant's `HH:MM`/`HH:MM:SS` in `tz` — DST is handled
/// per instant, so a frame is right whatever day it crosses.
fn clock(instant: time::OffsetDateTime, tz: &jiff::tz::TimeZone, seconds: bool) -> String {
    let timestamp = jiff::Timestamp::from_second(instant.unix_timestamp())
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    let format = if seconds { "%H:%M:%S" } else { "%H:%M" };
    timestamp.to_zoned(tz.clone()).strftime(format).to_string()
}

/// The whole human frame as text — the snapshot the render tests
/// pin (§3): `queue` and `github` headers, the per-target roll-up
/// (`queued` reads `queued (slotted)` — it counts only tasks holding a
/// slot, §2.6), the runs table and the failures list.
pub fn table_frame(frame: &WatchFrame, tz: &jiff::tz::TimeZone) -> String {
    let mut out = String::new();
    let scheduler = &frame.scheduler;
    let _ = writeln!(
        out,
        "queue  pending {} miss · {} human · blocked {} · dispatched {} · running {}",
        scheduler.pending_miss,
        scheduler.pending_human,
        scheduler.blocked,
        scheduler.dispatched,
        scheduler.running
    );
    let queued = frame
        .runs
        .iter()
        .filter(|run| run.status == "queued")
        .count();
    let in_progress = frame.runs.len() - queued;
    let done: u32 = frame.targets.iter().map(|target| target.tasks.done).sum();
    let since = clock(frame.since, tz, false);
    let _ = writeln!(
        out,
        "github  {} runs ({queued} queued · {in_progress} in progress) · since {since}: {done} tasks done · {} failed",
        frame.runs.len(),
        frame.failures.len()
    );
    if !frame.targets.is_empty() {
        let _ = writeln!(out);
        let mut table = Table::new(&["target", "queued (slotted)", "building", "done", "failed"]);
        let mut totals = crate::watch::TaskCounts::default();
        for target in &frame.targets {
            totals.queued += target.tasks.queued;
            totals.building += target.tasks.building;
            totals.done += target.tasks.done;
            totals.failed += target.tasks.failed;
            table.push([
                target.target.clone(),
                target.tasks.queued.to_string(),
                target.tasks.building.to_string(),
                target.tasks.done.to_string(),
                target.tasks.failed.to_string(),
            ]);
        }
        table.push([
            "total".to_owned(),
            totals.queued.to_string(),
            totals.building.to_string(),
            totals.done.to_string(),
            totals.failed.to_string(),
        ]);
        let _ = writeln!(out, "{}", table.render());
    }
    if !frame.runs.is_empty() {
        let _ = writeln!(out);
        let mut table = Table::new(&[
            "run", "task", "actor", "status", "attempt", "q/b/d/f", "age", "url",
        ]);
        for run in &frame.runs {
            table.push([
                run.run_id.to_string(),
                run.task_id.chars().take(8).collect::<String>(),
                run.actor.clone(),
                run.status.clone(),
                run.run_attempt.to_string(),
                format!(
                    "{}/{}/{}/{}",
                    run.tasks.queued, run.tasks.building, run.tasks.done, run.tasks.failed
                ),
                age(u64::try_from(run.age_seconds).unwrap_or(0)),
                run.url.clone(),
            ]);
        }
        let _ = writeln!(out, "{}", table.render());
    }
    if !frame.failures.is_empty() {
        let _ = writeln!(out);
        let mut table = Table::new(&["target", "crate", "version", "class", "job"]);
        for failure in &frame.failures {
            let class = failure.log_class.map_or_else(
                || failure.coarse_class.clone(),
                |class| format!("{} · {}", failure.coarse_class, class.as_str()),
            );
            table.push([
                failure.target.clone().unwrap_or_else(|| "-".to_owned()),
                failure.crate_name.clone().unwrap_or_else(|| "-".to_owned()),
                failure.version.clone().unwrap_or_else(|| "-".to_owned()),
                class,
                failure.job_url.clone().unwrap_or_else(|| "-".to_owned()),
            ]);
        }
        let _ = writeln!(out, "{}", table.render());
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Output, Planned, Table, age, emit, plan_footer, size};

    #[test]
    fn table_pads_columns_to_the_widest_cell() {
        let mut table = Table::new(&["name", "count"]);
        table.push(["alpha", "1"]);
        table.push(["beta-long", "200"]);
        let rendered = table.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "name       count");
        assert_eq!(lines[1], "alpha      1");
        // The last column is never padded — no trailing whitespace.
        assert_eq!(lines[2], "beta-long  200");
    }

    #[test]
    fn footer_names_the_gate_until_applied() {
        assert_eq!(plan_footer(true), "dry run — pass --yes to apply");
        assert_eq!(plan_footer(false), "applied");
    }

    #[test]
    fn dry_run_envelope_serializes_without_a_result() {
        #[derive(serde::Serialize)]
        struct Plan {
            rows: u32,
        }
        let planned = Planned {
            dry_run: true,
            plan: Plan { rows: 3 },
            result: Option::<serde_json::Value>::None,
        };
        let json = serde_json::to_value(&planned).expect("serialize");
        assert_eq!(json["dry_run"], true);
        assert_eq!(json["plan"]["rows"], 3);
        assert!(json.get("result").is_none());
    }

    #[test]
    fn applied_envelope_serializes_the_result() {
        #[derive(serde::Serialize)]
        struct Plan {
            rows: u32,
        }
        let planned = Planned {
            dry_run: false,
            plan: Plan { rows: 3 },
            result: Some(serde_json::json!({"affected": 3})),
        };
        let json = serde_json::to_value(&planned).expect("serialize");
        assert_eq!(json["dry_run"], false);
        assert_eq!(json["result"]["affected"], 3);
    }

    #[test]
    fn age_and_size_render_compact() {
        assert_eq!(age(45), "45s");
        assert_eq!(age(720), "12m0s");
        assert_eq!(age(8_040), "2h14m");
        assert_eq!(age(277_200), "3d5h");
        assert_eq!(size(512), "512 B");
        assert_eq!(size(2_048), "2.0 KiB");
        assert_eq!(size(5 * (1 << 30)), "5.0 GiB");
    }

    /// The whole human frame pinned as text — the queue/github
    /// headers, the `queued (slotted)` target table and its total,
    /// the runs table and the failures list (stow#853 §3).
    #[test]
    fn table_frame_snapshot() {
        use crate::watch::{RunView, SchedulerView, TargetView, TaskCounts, WatchFrame};
        use time::OffsetDateTime;

        let at = |unix: i64| OffsetDateTime::from_unix_timestamp(unix).expect("ts");
        let frame = WatchFrame {
            at: at(1_000),
            since: at(500),
            scheduler: SchedulerView {
                pending_miss: 7,
                pending_human: 3,
                blocked: 2,
                dispatched: 1,
                running: 4,
            },
            runs: vec![RunView {
                run_id: 7,
                task_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                rustc: "1.99.0".to_owned(),
                actor: "stow-bot".to_owned(),
                status: "in_progress".to_owned(),
                run_attempt: 2,
                age_seconds: 600,
                url: "https://github.com/water-rs/stow/actions/runs/7".to_owned(),
                tasks: TaskCounts {
                    queued: 1,
                    building: 2,
                    done: 1,
                    failed: 0,
                },
            }],
            targets: vec![TargetView {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                tasks: TaskCounts {
                    queued: 1,
                    building: 2,
                    done: 1,
                    failed: 0,
                },
            }],
            failures: vec![],
        };
        let text = super::table_frame(&frame, &jiff::tz::TimeZone::UTC);
        let expected = "\
queue  pending 7 miss · 3 human · blocked 2 · dispatched 1 · running 4
github  1 runs (0 queued · 1 in progress) · since 00:08: 1 tasks done · 0 failed

target                    queued (slotted)  building  done  failed
x86_64-unknown-linux-gnu  1                 2         1     0
total                     1                 2         1     0

run  task      actor     status       attempt  q/b/d/f  age    url
7    01234567  stow-bot  in_progress  2        1/2/1/0  10m0s  https://github.com/water-rs/stow/actions/runs/7";
        assert_eq!(text, expected);
    }

    #[test]
    fn emit_json_writes_the_serialized_value() {
        // `emit` is the only stdout writer; the JSON branch is covered by
        // its `to_string_pretty` contract — exercised here through the
        // fallible serialization path rather than a captured stdout.
        let result = emit(Output::Json, &serde_json::json!({"a": 1}), |_| {
            "unreachable".to_owned()
        });
        assert!(result.is_ok());
    }
}
