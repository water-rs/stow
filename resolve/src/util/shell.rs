//! Terminal output, replacing `cargo-util-terminal/src/shell.rs`.
//!
//! The vendored resolver writes progress/diagnostic output through
//! `GlobalContext::shell()`. `cargo-util-terminal` is not published, so this
//! provides the same method surface with plain (non-TTY) rendering. On the
//! host the streams are real `stdout`/`stderr`; inside the worker they are
//! in-memory sinks. Either way, resolve output is unchanged because
//! `cargo metadata`'s JSON goes through `print_json` on `out`, uncolored.

use anyhow::Result;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use crate::util::report::{Group, Hyperlink, Verbosity};

pub struct Shell {
    verbosity: Verbosity,
    out: Box<dyn Write + Send>,
    err: Box<dyn Write + Send>,
    /// Whether stderr is a terminal — always false under VFS/worker use,
    /// matching `Shell::from_write`'s never-ANSI behavior.
    err_is_tty: bool,
}

impl Shell {
    /// Shell writing to the process' real stdio.
    pub fn new() -> Shell {
        Shell {
            verbosity: Verbosity::Normal,
            out: Box::new(io::stdout()),
            err: Box::new(io::stderr()),
            err_is_tty: false,
        }
    }

    /// Shell capturing both streams into the given writers.
    pub fn from_write(out: Box<dyn Write + Send>, err: Box<dyn Write + Send>) -> Shell {
        Shell {
            verbosity: Verbosity::Verbose,
            out,
            err,
            err_is_tty: false,
        }
    }

    /// Shell that drops all output (quiet service contexts).
    pub fn sink() -> Shell {
        Shell {
            verbosity: Verbosity::Quiet,
            out: Box::new(io::sink()),
            err: Box::new(io::sink()),
            err_is_tty: false,
        }
    }

    pub fn out(&mut self) -> &mut dyn Write {
        &mut *self.out
    }

    pub fn err(&mut self) -> &mut dyn Write {
        &mut *self.err
    }

    fn print(
        &mut self,
        status: &dyn fmt::Display,
        message: Option<&dyn fmt::Display>,
        justified: bool,
    ) -> Result<()> {
        if matches!(self.verbosity, Verbosity::Quiet) {
            return Ok(());
        }
        match message {
            Some(message) if justified => {
                writeln!(self.err(), "{status:>12} {message}")?;
            }
            Some(message) => {
                writeln!(self.err(), "{status}: {message}")?;
            }
            None => {
                writeln!(self.err(), "{status}")?;
            }
        }
        Ok(())
    }

    /// Prints a message, where `status` is justified.
    pub fn status<T: fmt::Display, U: fmt::Display>(
        &mut self,
        status: T,
        message: U,
    ) -> Result<()> {
        self.print(&status, Some(&message), false)
    }

    pub fn status_with_color<T: fmt::Display, U: fmt::Display>(
        &mut self,
        status: T,
        message: U,
        _color: &anstyle::Style,
    ) -> Result<()> {
        self.status(status, message)
    }

    /// Prints a red `error` message.
    pub fn error<T: fmt::Display>(&mut self, message: T) -> Result<()> {
        self.print(&"error", Some(&message), false)
    }

    /// Prints a yellow `warning` message.
    pub fn warn<T: fmt::Display>(&mut self, message: T) -> Result<()> {
        self.print(&"warning", Some(&message), false)
    }

    /// Prints a cyan `note` message.
    pub fn note<T: fmt::Display>(&mut self, message: T) -> Result<()> {
        self.print(&"note", Some(&message), false)
    }

    pub fn set_verbosity(&mut self, verbosity: Verbosity) {
        self.verbosity = verbosity;
    }

    /// Runs the callback only if we are in verbose mode.
    pub fn verbose<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(&mut Shell) -> Result<()>,
    {
        match self.verbosity {
            Verbosity::Verbose => callback(self),
            _ => Ok(()),
        }
    }

    pub fn verbosity(&self) -> Verbosity {
        self.verbosity
    }

    /// Whether stderr is a TTY that supports ANSI colors.
    pub fn is_err_tty(&self) -> bool {
        self.err_is_tty
    }

    /// Whether stdout is a TTY that supports ANSI colors.
    pub fn is_out_tty(&self) -> bool {
        false
    }

    /// Returns a hyperlink suitable for `stderr` — under our always
    /// non-TTY streams this is just the path text (same output cargo's
    /// `Hyperlink::default()` produces without hyperlink support).
    pub fn err_file_hyperlink(&mut self, _path: &Path) -> Hyperlink<String> {
        Hyperlink::default()
    }

    /// See [`Shell::err_file_hyperlink`].
    pub fn out_file_hyperlink(&mut self, _path: &Path) -> Hyperlink<String> {
        Hyperlink::default()
    }

    /// Prints the object as JSON to stdout.
    pub fn print_json<T: serde::Serialize>(&mut self, obj: &T) -> Result<()> {
        let encoded = serde_json::to_string(obj)?;
        drop(writeln!(self.out(), "{encoded}"));
        Ok(())
    }

    /// Prints the groups to stderr using `annotate_snippets`' plain renderer.
    pub fn print_report(&mut self, groups: &[Group<'_>], force: bool) -> Result<()> {
        if !force && matches!(self.verbosity, Verbosity::Quiet) {
            return Ok(());
        }
        let rendered = annotate_snippets::Renderer::plain().render(groups);
        writeln!(self.err(), "{rendered}")?;
        Ok(())
    }

    /// Raw write to stderr (used for already-rendered diagnostics).
    pub fn print_ansi_stderr(&mut self, message: &[u8]) -> Result<()> {
        self.err().write_all(message)?;
        Ok(())
    }

    /// Raw write to stdout.
    pub fn print_ansi_stdout(&mut self, message: &[u8]) -> Result<()> {
        self.out().write_all(message)?;
        Ok(())
    }
}
