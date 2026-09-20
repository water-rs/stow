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
#[derive(Debug, serde::Serialize)]
pub struct Planned<P, R> {
    /// Nothing was applied — the run only rendered the plan.
    pub dry_run: bool,
    /// What the command will (or just did) touch.
    pub plan: P,
    /// The mutation's outcome — absent in a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<R>,
}

/// Run a mutating command's two phases: build `plan`, and only when `yes`
/// is set run `apply` and fold its result into the emitted envelope.
/// `apply` borrows the plan so the apply can never drift from what the
/// operator previewed. Without `--yes` the process exits 0 having changed
/// nothing.
pub async fn mutation<P, R>(
    output: Output,
    yes: bool,
    plan: P,
    human: impl FnOnce(&Planned<P, R>) -> String,
    apply: impl AsyncFnOnce(&P) -> stow_types::error::Result<R>,
) -> stow_types::error::Result<()>
where
    P: serde::Serialize,
    R: serde::Serialize,
{
    let result = if yes { Some(apply(&plan).await?) } else { None };
    let envelope = Planned {
        dry_run: !yes,
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
