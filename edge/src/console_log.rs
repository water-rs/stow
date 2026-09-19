//! `tracing` → `console.*` bridge plus a panic hook.
//!
//! Nothing on wasm32 installs a `tracing` subscriber — skyzen only does
//! that in its native runtime — so every event this crate and the
//! framework emit (including `log_endpoint_error`, which carries the real
//! error chain behind the redacted 5xx body) went nowhere. `wrangler tail`
//! and the Workers Logs dashboard both render `console.*` calls.

use std::io::Write;
use std::sync::Once;

use skyzen_cloudflare::worker;
use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

/// Install the console subscriber and panic hook. Idempotent; call at the
/// top of every exported entry point (`fetch`, the Durable Object's
/// `fetch`) so whichever isolate handles first gets coverage.
pub fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            worker::console_error!("{info}");
        }));
        // `SystemTime::now` is unimplemented on this target, so the
        // formatter must not timestamp; the `ansi` feature is left out of
        // the dependency entirely since no terminal is involved.
        let _ = tracing_subscriber::fmt()
            .with_writer(ConsoleMakeWriter)
            .without_time()
            .with_max_level(Level::INFO)
            .try_init();
    });
}

struct ConsoleMakeWriter;

impl<'a> MakeWriter<'a> for ConsoleMakeWriter {
    type Writer = ConsoleWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleWriter::new(Level::INFO)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        ConsoleWriter::new(*meta.level())
    }
}

/// Accumulates one event's formatted bytes; `Drop` emits the finished
/// line to the `console` method matching the event's level, because the
/// formatter writes an event in several pieces.
struct ConsoleWriter {
    level: Level,
    buffer: Vec<u8>,
}

impl ConsoleWriter {
    const fn new(level: Level) -> Self {
        Self {
            level,
            buffer: Vec::new(),
        }
    }
}

impl Write for ConsoleWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ConsoleWriter {
    fn drop(&mut self) {
        let message = String::from_utf8_lossy(&self.buffer);
        let message = message.trim_end();
        if message.is_empty() {
            return;
        }
        if self.level == Level::ERROR {
            worker::console_error!("{message}");
        } else if self.level == Level::WARN {
            worker::console_warn!("{message}");
        } else if self.level == Level::INFO {
            worker::console_log!("{message}");
        } else {
            worker::console_debug!("{message}");
        }
    }
}
