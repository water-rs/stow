//! A progress bar, of sorts.
//!
//! Cargo's real `Progress` draws an interactive bar on a TTY. The resolve
//! runs on a worker (no TTY), so this keeps the vendored call sites' API —
//! [`Progress::with_style`], [`tick`], [`print_now`], throttling and the
//! quiet/CI gating — and renders updates as plain `shell.status` lines,
//! which is what a non-TTY `cargo` effectively emits as well.

use std::time::{Duration, Instant};

use crate::util::context::ProgressWhen;
use crate::util::errors::CargoResult;
use crate::util::report::Verbosity;
use crate::util::{GlobalContext, is_ci};

/// The `Progress` type ensures the progress bar is removed from the console
/// when dropped or [`Progress::clear`] is called.
pub struct Progress<'gctx> {
    gctx: &'gctx GlobalContext,
    state: Option<State>,
}

impl<'gctx> Progress<'gctx> {
    /// Creates a new `Progress` with the [`ProgressStyle::Percentage`] style.
    pub fn new(name: &str, gctx: &'gctx GlobalContext) -> Progress<'gctx> {
        Self::with_style(name, ProgressStyle::Percentage, gctx)
    }

    /// Creates a new progress bar.
    ///
    /// The progress bar may be created in a disabled state if the user has
    /// disabled progress display (such as with the `--quiet` option).
    pub fn with_style(
        name: &str,
        style: ProgressStyle,
        gctx: &'gctx GlobalContext,
    ) -> Progress<'gctx> {
        let dumb = matches!(gctx.get_env("TERM"), Ok(term) if term == "dumb");
        let progress_config = gctx.progress_config();
        match progress_config.when {
            ProgressWhen::Always => return Progress::new_priv(name, style, gctx),
            ProgressWhen::Never => return Progress { gctx, state: None },
            ProgressWhen::Auto => {}
        }
        if gctx.shell().verbosity() == Verbosity::Quiet || dumb || is_ci() {
            return Progress { gctx, state: None };
        }
        Progress::new_priv(name, style, gctx)
    }

    fn new_priv(name: &str, style: ProgressStyle, gctx: &'gctx GlobalContext) -> Progress<'gctx> {
        let _ = style;
        Progress {
            gctx,
            state: Some(State {
                name: name.to_string(),
                done: false,
                throttle: Throttle::new(),
            }),
        }
    }

    /// Disables the progress bar, ensuring it won't be displayed.
    pub fn disable(&mut self) {
        self.state = None;
    }

    /// Returns whether or not the progress bar is allowed to be displayed.
    pub fn is_enabled(&self) -> bool {
        self.state.is_some()
    }

    /// Updates the state of the progress bar.
    ///
    /// * `cur` should be how far along the progress is.
    /// * `max` is the maximum value for the progress bar.
    /// * `msg` is a small piece of text to display at the end of the progress
    ///   bar.
    pub fn tick(&mut self, cur: usize, max: usize, msg: &str) -> CargoResult<()> {
        let Some(s) = &mut self.state else {
            return Ok(());
        };
        if !s.throttle.allowed() {
            return Ok(());
        }
        if s.done {
            return Ok(());
        }
        if max > 0 && cur == max {
            s.done = true;
        }
        self.gctx
            .shell()
            .status(&s.name, format!("{cur}/{max} {msg}"))
    }

    /// Updates the state of the progress bar, ignoring rate throttling.
    pub fn tick_now(&mut self, cur: usize, max: usize, msg: &str) -> CargoResult<()> {
        self.tick(cur, max, msg)
    }

    /// Returns whether or not updates are currently being throttled.
    pub fn update_allowed(&mut self) -> bool {
        match &mut self.state {
            Some(s) => s.throttle.allowed(),
            None => false,
        }
    }

    /// Displays progress without a bar.
    ///
    /// This does not have any rate limit throttling, so be careful about
    /// calling it too often.
    pub fn print_now(&mut self, msg: &str) -> CargoResult<()> {
        match &mut self.state {
            Some(s) => self.gctx.shell().status(&s.name, msg),
            None => Ok(()),
        }
    }

    /// Clears the progress bar from the console.
    pub fn clear(&mut self) {
        // Plain status lines don't need clearing.
    }

    /// Sets the progress reporter to the error state.
    pub fn indicate_error(&mut self) {}
}

impl<'gctx> Drop for Progress<'gctx> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Indicates the style of information for displaying the amount of progress.
///
/// See also [`Progress::print_now`] for displaying progress without a bar.
pub enum ProgressStyle {
    /// Displays progress as a percentage.
    Percentage,
    /// Displays progress as a ratio.
    Ratio,
    /// Does not display an exact value of how far along it is.
    Indeterminate,
}

struct State {
    name: String,
    done: bool,
    throttle: Throttle,
}

struct Throttle {
    first: bool,
    last_update: Instant,
}

impl Throttle {
    fn new() -> Throttle {
        Throttle {
            first: true,
            last_update: Instant::now(),
        }
    }

    fn allowed(&mut self) -> bool {
        if self.first {
            let delay = Duration::from_millis(500);
            if self.last_update.elapsed() < delay {
                return false;
            }
        } else {
            let interval = Duration::from_millis(100);
            if self.last_update.elapsed() < interval {
                return false;
            }
        }
        self.update();
        true
    }

    fn update(&mut self) {
        self.first = false;
        self.last_update = Instant::now();
    }
}
