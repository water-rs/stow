//! The operator's memory lines (stow#1501): the `memory_line` row the
//! `memory-line set` route writes, read once per isolate into the
//! graph cell. It lives outside the graph so it reads and sets while
//! the graph cannot wake — raising the small line is how an operator
//! wakes a graph the old line refused.

use skyzen_services::durable::DurableDb;
use stow_types::api::{MemoryLineSet, MemoryLineSetting};

use super::graph::GraphCell;
use crate::errors::QueueError;

/// What an isolate knows of the stored setting.
#[derive(Debug, Clone, Default)]
pub enum Cached {
    /// The row has not been read since the isolate started or the
    /// store was reset.
    #[default]
    Unread,
    /// The row as read or last written — `None` before the first set.
    Read(Option<MemoryLineSetting>),
}

#[derive(skyzen::FromRow)]
struct LineRow {
    normal_line_bytes: i64,
    small_line_bytes: i64,
    small_increment_bytes: i64,
    set_at: String,
    actor: String,
}

/// A stored byte count, which the set wrote from a `u64`.
fn bytes(column: &str, value: i64) -> Result<u64, QueueError> {
    u64::try_from(value)
        .map_err(|_| QueueError::Invariant(format!("memory_line.{column} is negative: {value}")))
}

/// A byte count as the column stores it.
fn column(value: u64) -> Result<i64, QueueError> {
    i64::try_from(value).map_err(|_| QueueError::Overflow {
        field: "memory_line",
        value,
    })
}

/// The setting in force: the cell's copy, or — once per isolate — the
/// stored row, which the cell then keeps.
///
/// # Errors
/// `QueueError::Sql` on a failed read, `QueueError::Invariant` on a
/// negative column.
pub async fn current(
    db: &DurableDb,
    cell: &GraphCell,
) -> Result<Option<MemoryLineSetting>, QueueError> {
    if let Cached::Read(known) = cell.memory_line() {
        return Ok(known);
    }
    let row = db
        .query(
            "SELECT normal_line_bytes, small_line_bytes, small_increment_bytes, set_at, actor \
             FROM memory_line WHERE id = 0",
        )
        .fetch_all::<LineRow>()
        .await
        .map_err(|error| QueueError::Sql(format!("memory line: {error}")))?
        .pop();
    let setting = row
        .map(|row| {
            Ok::<_, QueueError>(MemoryLineSetting {
                lines: MemoryLineSet {
                    normal_line_bytes: bytes("normal_line_bytes", row.normal_line_bytes)?,
                    small_line_bytes: bytes("small_line_bytes", row.small_line_bytes)?,
                    small_increment_bytes: bytes(
                        "small_increment_bytes",
                        row.small_increment_bytes,
                    )?,
                },
                set_at: row.set_at,
                actor: row.actor,
            })
        })
        .transpose()?;
    cell.set_memory_line(setting.clone());
    Ok(setting)
}

/// Store `setting` as the one row and put it in the cell.
///
/// # Errors
/// `QueueError::Sql` on a failed write, `QueueError::Overflow` on a
/// value past `i64`.
pub async fn store(
    db: &DurableDb,
    cell: &GraphCell,
    setting: MemoryLineSetting,
) -> Result<(), QueueError> {
    let MemoryLineSet {
        normal_line_bytes,
        small_line_bytes,
        small_increment_bytes,
    } = setting.lines;
    db.query(
        "INSERT INTO memory_line(id, normal_line_bytes, small_line_bytes, small_increment_bytes, \
         set_at, actor) VALUES (0, ?, ?, ?, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET normal_line_bytes = excluded.normal_line_bytes, \
         small_line_bytes = excluded.small_line_bytes, \
         small_increment_bytes = excluded.small_increment_bytes, \
         set_at = excluded.set_at, actor = excluded.actor",
    )
    .bind(column(normal_line_bytes)?)
    .bind(column(small_line_bytes)?)
    .bind(column(small_increment_bytes)?)
    .bind(setting.set_at.clone())
    .bind(setting.actor.clone())
    .execute()
    .await
    .map_err(|error| QueueError::Sql(format!("memory line set: {error}")))?;
    cell.set_memory_line(Some(setting));
    Ok(())
}
