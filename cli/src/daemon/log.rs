//! The daemon's size-bounded log.
//!
//! `tracing-appender`, which the lockfile carries, rotates by time only, so
//! it cannot bound a log's size. This is a small writer of its own: the
//! subscriber's writers send each record to a thread that owns the file,
//! counts its size and, once it has reached the bound, renames it to
//! `<name>.1` — replacing the previous one — and continues in a fresh
//! file. At most the log and one predecessor exist.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, channel};

use stow_types::error::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;

/// A log file that rotates when it reaches `bound` bytes.
#[derive(Debug)]
struct RotatingFile {
    path: PathBuf,
    predecessor: PathBuf,
    bound: u64,
    file: File,
    size: u64,
}

impl RotatingFile {
    fn open(path: &Path, bound: u64) -> Result<Self> {
        let file = open_append(path)?;
        let size = file
            .metadata()
            .wrap_err_with(|| format!("inspect the log {}", path.display()))?
            .len();
        let mut predecessor = path.as_os_str().to_owned();
        predecessor.push(".1");
        Ok(Self {
            path: path.to_owned(),
            predecessor: PathBuf::from(predecessor),
            bound,
            file,
            size,
        })
    }

    /// Append one record, rotating first when the file has reached the
    /// bound: a record is never split across files.
    fn write(&mut self, record: &[u8]) -> std::io::Result<()> {
        if self.size >= self.bound {
            std::fs::rename(&self.path, &self.predecessor)?;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.size = 0;
        }
        self.file.write_all(record)?;
        self.size += u64::try_from(record.len()).expect("a record's length fits a u64");
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .wrap_err_with(|| format!("open the daemon log {}", path.display()))
}

/// The subscriber's side: every writer it asks for sends its records to
/// the thread that owns the file.
#[derive(Debug, Clone)]
pub struct LogWriter {
    records: Sender<Vec<u8>>,
}

impl LogWriter {
    /// Open `path` and start the thread that writes it, rotating at
    /// `bound` bytes.
    ///
    /// # Errors
    ///
    /// The log cannot be opened or its thread cannot start.
    pub fn open(path: &Path, bound: u64) -> Result<Self> {
        let mut file = RotatingFile::open(path, bound)?;
        let (records, incoming) = channel::<Vec<u8>>();
        std::thread::Builder::new()
            .name("stow-daemon-log".to_owned())
            .spawn(move || {
                // A failed write ends the thread: the subscriber's sends
                // then fail and it drops its records, which is all a
                // daemon with no terminal can do about its own log.
                while let Ok(record) = incoming.recv() {
                    if file.write(&record).is_err() {
                        break;
                    }
                }
            })
            .wrap_err("spawn the daemon log thread")?;
        Ok(Self { records })
    }
}

impl std::io::Write for LogWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.records
            .send(buffer.to_vec())
            .map_err(|_| std::io::Error::other("the daemon log thread ended"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogWriter {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::RotatingFile;

    #[test]
    fn crossing_the_bound_rotates_and_keeps_exactly_one_predecessor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.log");
        let mut log = RotatingFile::open(&path, 10).expect("open");
        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).ok();

        log.write(b"first\n").expect("write");
        assert_eq!(read("daemon.log").as_deref(), Some("first\n"));
        assert_eq!(
            read("daemon.log.1"),
            None,
            "under the bound nothing rotates"
        );

        log.write(b"second\n").expect("write");
        assert_eq!(read("daemon.log").as_deref(), Some("first\nsecond\n"));
        assert_eq!(
            read("daemon.log.1"),
            None,
            "the record that crosses stays whole"
        );

        log.write(b"third\n").expect("write");
        assert_eq!(read("daemon.log").as_deref(), Some("third\n"));
        assert_eq!(read("daemon.log.1").as_deref(), Some("first\nsecond\n"));

        log.write(b"fourth-record\n").expect("write");
        log.write(b"fifth\n").expect("write");
        assert_eq!(read("daemon.log").as_deref(), Some("fifth\n"));
        assert_eq!(
            read("daemon.log.1").as_deref(),
            Some("third\nfourth-record\n"),
            "the previous predecessor is replaced"
        );
        let files = std::fs::read_dir(dir.path()).expect("list").count();
        assert_eq!(files, 2, "the log and one predecessor, nothing more");
    }

    #[test]
    fn a_log_reopened_over_a_full_file_rotates_at_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.log");
        std::fs::write(&path, "0123456789abc").expect("seed");
        let mut log = RotatingFile::open(&path, 10).expect("open");
        log.write(b"new\n").expect("write");
        assert_eq!(std::fs::read_to_string(&path).expect("log"), "new\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("daemon.log.1")).expect("predecessor"),
            "0123456789abc"
        );
    }
}
