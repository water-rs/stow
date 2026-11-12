//! What a session's tasks log, carried back to the driver that opened it.
//!
//! A build's decisions used to be logged by the driver process itself, so
//! `RUST_LOG` and `STOW_TRACE_FILE` covered them. They now run in the
//! daemon, whose log is its own file. Every event recorded under a
//! session's span is also sent over that session's control connection, and
//! the driver records it again in its own subscriber.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::protocol::Event;
use super::session::SessionId;

/// The name of the span every session task runs under; its `session`
/// field names the session.
pub const SESSION_SPAN: &str = "stow.session";

/// The prefix of the targets the driver's trace file records regardless of
/// `RUST_LOG`: stow's own crates.
const TRACE_TARGET_PREFIX: &str = "stow_";

/// A tracing level, in a form the wire carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// `ERROR`.
    Error,
    /// `WARN`.
    Warn,
    /// `INFO`.
    Info,
    /// `DEBUG`.
    Debug,
    /// `TRACE`.
    Trace,
}

impl From<tracing::Level> for LogLevel {
    fn from(level: tracing::Level) -> Self {
        match level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }
}

/// One event a session's task recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// The event's level.
    pub level: LogLevel,
    /// The module that recorded it.
    pub target: String,
    /// Its message followed by its fields, as `name=value` pairs.
    pub text: String,
}

/// A span a session's task opened, which the driver opens again so its
/// trace file shows the build's decisions where they were made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanRecord {
    /// Names the span in this session's events: the daemon's span id.
    pub id: u64,
    /// The closest enclosing span that is also carried, if any.
    pub parent: Option<u64>,
    /// The span's name.
    pub name: String,
    /// The module that opened it.
    pub target: String,
    /// Its fields, as `name=value` pairs.
    pub text: String,
}

/// Which events a session's driver wants back.
#[derive(Debug, Clone)]
pub struct LogInterest {
    /// The driver's `RUST_LOG`, or its default when unset.
    rust_log: Targets,
    /// The driver writes a trace file, which records stow's own crates at
    /// every level.
    trace_file: bool,
    /// Warnings and errors are wanted whatever `rust_log` says: the
    /// interest of a wrapper, which has no terminal of its own to tell
    /// otherwise.
    always_warn: bool,
}

impl LogInterest {
    /// The interest of a driver whose environment says `rust_log` and
    /// whether it traces to a file.
    ///
    /// # Errors
    ///
    /// `rust_log` is not a directive list.
    pub fn new(rust_log: Option<&str>, trace_file: bool) -> Result<Self, String> {
        // The driver's terminal default: what reaches it without
        // `RUST_LOG` is a once-per-condition warning.
        let rust_log = rust_log.unwrap_or("warn");
        Ok(Self {
            rust_log: rust_log
                .parse()
                .map_err(|error| format!("RUST_LOG `{rust_log}`: {error}"))?,
            trace_file,
            always_warn: false,
        })
    }

    /// The interest of a wrapper of a plain cargo build: every warning and
    /// error, and what `rust_log` selects besides when the wrapper traces.
    ///
    /// # Errors
    ///
    /// `rust_log` is not a directive list.
    pub fn of_wrapper(rust_log: Option<&str>) -> Result<Self, String> {
        // A wrapper that does not trace asks for nothing beyond the floor.
        let rust_log = rust_log.unwrap_or("off");
        Ok(Self {
            rust_log: rust_log
                .parse()
                .map_err(|error| format!("RUST_LOG `{rust_log}`: {error}"))?,
            trace_file: false,
            always_warn: true,
        })
    }

    fn wants(&self, target: &str, level: tracing::Level) -> bool {
        // `WARN` and `ERROR` order below the more verbose levels.
        (self.always_warn && level <= tracing::Level::WARN)
            || self.rust_log.would_enable(target, &level)
            || (self.trace_file && target.starts_with(TRACE_TARGET_PREFIX))
    }
}

struct Route {
    sender: UnboundedSender<Event>,
    interest: LogInterest,
}

/// The sessions whose events are being carried, shared by the layer that
/// records them and the table that opens and closes sessions.
#[derive(Clone, Default)]
pub struct SessionLogs {
    routes: Arc<Mutex<HashMap<SessionId, Route>>>,
}

impl std::fmt::Debug for SessionLogs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionLogs")
            .finish_non_exhaustive()
    }
}

impl SessionLogs {
    /// Start carrying `id`'s events that `interest` wants; the receiver is
    /// the stream the session's control connection forwards.
    pub fn register(&self, id: SessionId, interest: LogInterest) -> UnboundedReceiver<Event> {
        let (sender, receiver) = unbounded_channel();
        self.routes
            .lock()
            .expect("the session log routes' lock is never held across a panic")
            .insert(id, Route { sender, interest });
        receiver
    }

    /// Stop carrying `id`'s events.
    pub fn unregister(&self, id: SessionId) {
        self.routes
            .lock()
            .expect("the session log routes' lock is never held across a panic")
            .remove(&id);
    }

    /// The layer that records events into the routes.
    #[must_use]
    pub fn layer(&self) -> SessionLogLayer {
        SessionLogLayer { logs: self.clone() }
    }

    /// `id`'s route sender, when its driver wants a record at `level` from
    /// `target` (`None` asks for the sender whatever the interest).
    fn sender(
        &self,
        id: SessionId,
        wanted: Option<(&str, tracing::Level)>,
    ) -> Option<UnboundedSender<Event>> {
        self.routes
            .lock()
            .expect("the session log routes' lock is never held across a panic")
            .get(&id)
            .filter(|route| {
                wanted.is_none_or(|(target, level)| route.interest.wants(target, level))
            })
            .map(|route| route.sender.clone())
    }
}

/// The session an open span belongs to, kept in its extensions.
struct SpanSession(SessionId);

/// Marks a span that was sent to its session's driver, so its close is
/// sent too.
struct Carried(SessionId);

/// Records every event under a session span into that session's route.
#[derive(Debug)]
pub struct SessionLogLayer {
    logs: SessionLogs,
}

/// Reads the `session` field of a session span.
struct SessionField(Option<SessionId>);

impl Visit for SessionField {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "session" {
            self.0 = format!("{value:?}").parse().ok();
        }
    }
}

/// Renders an event as its message followed by `name=value` fields, the
/// shape the terminal formatter prints.
#[derive(Default)]
struct EventText {
    message: String,
    fields: String,
}

impl Visit for EventText {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // Writing to a `String` cannot fail.
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl<S> Layer<S> for SessionLogLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let Some(span) = context.span(id) else {
            return;
        };
        let metadata = attributes.metadata();
        if metadata.name() == SESSION_SPAN {
            let mut field = SessionField(None);
            attributes.record(&mut field);
            if let Some(session) = field.0 {
                span.extensions_mut().insert(SpanSession(session));
            }
            return;
        }
        // A span under a session's span is that session's decision span:
        // the driver's trace shows it where the build made it.
        let Some(session) = span.scope().skip(1).find_map(|ancestor| {
            ancestor
                .extensions()
                .get::<SpanSession>()
                .map(|found| found.0)
        }) else {
            return;
        };
        let Some(sender) = self
            .logs
            .sender(session, Some((metadata.target(), *metadata.level())))
        else {
            return;
        };
        let parent = span
            .scope()
            .skip(1)
            .find(|ancestor| ancestor.extensions().get::<Carried>().is_some())
            .map(|ancestor| ancestor.id().into_u64());
        let mut fields = EventText::default();
        attributes.record(&mut fields);
        span.extensions_mut().insert(Carried(session));
        // The receiver ends with the session's control connection; a
        // record after that has nowhere to go.
        let _ = sender.send(Event::SpanOpened(SpanRecord {
            id: id.into_u64(),
            parent,
            name: metadata.name().to_owned(),
            target: metadata.target().to_owned(),
            text: fields.fields.trim_start().to_owned(),
        }));
    }

    fn on_close(&self, id: Id, context: Context<'_, S>) {
        let Some(span) = context.span(&id) else {
            return;
        };
        let Some(session) = span.extensions().get::<Carried>().map(|carried| carried.0) else {
            return;
        };
        if let Some(sender) = self.logs.sender(session, None) {
            let _ = sender.send(Event::SpanClosed { id: id.into_u64() });
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, S>) {
        let Some(scope) = context.event_scope(event) else {
            return;
        };
        let Some(session) = scope
            .into_iter()
            .find_map(|span| span.extensions().get::<SpanSession>().map(|found| found.0))
        else {
            return;
        };
        let metadata = event.metadata();
        let Some(sender) = self
            .logs
            .sender(session, Some((metadata.target(), *metadata.level())))
        else {
            return;
        };
        let mut text = EventText::default();
        event.record(&mut text);
        // The receiver ends with the session's control connection; an
        // event after that has nowhere to go.
        let _ = sender.send(Event::Log(LogRecord {
            level: (*metadata.level()).into(),
            target: metadata.target().to_owned(),
            text: format!("{}{}", text.message, text.fields),
        }));
    }
}

/// The name of the span the driver opens for each [`SpanRecord`]; its
/// `mirrored` field carries the daemon span's own name.
pub const MIRRORED_SPAN: &str = "stow.daemon.span";

/// The daemon span name a mirrored span stands for, kept in its extensions
/// for the trace file to name it by.
pub struct MirroredName(pub String);

/// Reads the `mirrored` field of a mirrored span into [`MirroredName`].
#[derive(Debug, Default)]
pub struct MirroredNames;

struct MirroredField(Option<String>);

impl Visit for MirroredField {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "mirrored" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S> Layer<S> for MirroredNames
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        if attributes.metadata().name() != MIRRORED_SPAN {
            return;
        }
        let mut field = MirroredField(None);
        attributes.record(&mut field);
        if let (Some(name), Some(span)) = (field.0, context.span(id)) {
            span.extensions_mut().insert(MirroredName(name));
        }
    }
}

/// The driver's copy of a session's spans: each [`SpanRecord`] opens a
/// span in the driver's subscriber under the copy of its parent, and the
/// matching close ends it, so the driver's trace file shows the decisions
/// the daemon made while the build ran.
#[derive(Debug)]
pub struct SpanMirror {
    /// The span the copies hang under when the daemon span has no carried
    /// parent: the one the session was opened in.
    root: tracing::Span,
    open: HashMap<u64, tracing::Span>,
}

impl SpanMirror {
    /// A mirror whose top-level spans open under `root`.
    #[must_use]
    pub fn under(root: tracing::Span) -> Self {
        Self {
            root,
            open: HashMap::new(),
        }
    }

    /// Open the copy of `record`.
    pub fn opened(&mut self, record: &SpanRecord) {
        let parent = record
            .parent
            .and_then(|parent| self.open.get(&parent))
            .unwrap_or(&self.root);
        let span = tracing::debug_span!(
            parent: parent,
            "stow.daemon.span",
            mirrored = %record.name,
            daemon_target = %record.target,
            fields = %record.text,
        );
        self.open.insert(record.id, span);
    }

    /// End the copy of span `id`.
    pub fn closed(&mut self, id: u64) {
        self.open.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{LogInterest, LogLevel, SESSION_SPAN, SessionLogs};
    use crate::daemon::protocol::Event;
    use crate::daemon::session::SessionId;

    /// Events under a session's span reach that session's route when its
    /// driver asked for their level, and nobody else's.
    #[test]
    fn events_under_a_session_span_reach_only_that_sessions_route() {
        let logs = SessionLogs::default();
        let mine = SessionId::mint();
        let other = SessionId::mint();
        let mut mine_receiver = logs.register(
            mine,
            LogInterest::new(Some("stow_cli=debug"), false).expect("filter"),
        );
        let mut other_receiver = logs.register(
            other,
            LogInterest::new(Some("warn"), false).expect("filter"),
        );
        let subscriber = tracing_subscriber::registry().with(logs.layer());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(SESSION_SPAN, session = %mine);
            let _entered = span.enter();
            tracing::debug!(target: "stow_cli::lib", crate_name = "demo", "decided a unit");
        });
        let Event::Log(record) = mine_receiver.try_recv().expect("the session's own event") else {
            panic!("an event was recorded");
        };
        assert_eq!(record.level, LogLevel::Debug);
        assert_eq!(record.target, "stow_cli::lib");
        assert_eq!(record.text, r#"decided a unit crate_name="demo""#);
        assert!(other_receiver.try_recv().is_err());
    }

    /// A level the driver did not ask for stays in the daemon.
    #[test]
    fn an_event_below_the_drivers_filter_is_not_carried() {
        let logs = SessionLogs::default();
        let id = SessionId::mint();
        let mut receiver = logs.register(id, LogInterest::new(None, false).expect("filter"));
        let subscriber = tracing_subscriber::registry().with(logs.layer());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(SESSION_SPAN, session = %id);
            let _entered = span.enter();
            tracing::debug!(target: "stow_cli::lib", "quiet");
            tracing::warn!(target: "stow_cli::lib", "loud");
        });
        let Event::Log(record) = receiver.try_recv().expect("the warning") else {
            panic!("an event was recorded");
        };
        assert_eq!(record.text, "loud");
        assert!(receiver.try_recv().is_err());
    }

    /// A span under a session's span is carried with its parent link and
    /// its close, and a span outside every session is not.
    #[test]
    fn spans_under_a_session_span_are_carried_with_their_parents() {
        let logs = SessionLogs::default();
        let id = SessionId::mint();
        let mut receiver = logs.register(id, LogInterest::new(None, true).expect("filter"));
        let subscriber = tracing_subscriber::registry().with(logs.layer());
        tracing::subscriber::with_default(subscriber, || {
            drop(tracing::debug_span!(target: "stow_cli::lib", "stow.outside").entered());
            let session = tracing::info_span!(SESSION_SPAN, session = %id);
            let _session = session.enter();
            let outer =
                tracing::debug_span!(target: "stow_cli::lib", "stow.decide", crate_name = "demo");
            let _outer = outer.enter();
            drop(tracing::debug_span!(target: "stow_cli::lib", "stow.serve").entered());
        });
        let mut opened = Vec::new();
        let mut closed = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            match event {
                Event::SpanOpened(record) => opened.push(record),
                Event::SpanClosed { id } => closed.push(id),
                Event::Log(_) | Event::ResolutionDone => {}
            }
        }
        let names: Vec<&str> = opened.iter().map(|record| record.name.as_str()).collect();
        assert_eq!(names, ["stow.decide", "stow.serve"]);
        assert_eq!(opened[0].parent, None);
        assert_eq!(opened[0].text, r#"crate_name="demo""#);
        assert_eq!(opened[1].parent, Some(opened[0].id));
        // The inner span closes first.
        assert_eq!(closed, [opened[1].id, opened[0].id]);
    }

    /// A span nested in a session's, with a session name of its own, takes
    /// the events recorded under it: how one wrapper of a plain build gets
    /// its request's events while the build's session has no route. A
    /// wrapper that does not trace gets the warnings and nothing more.
    #[test]
    fn a_wrappers_nested_span_takes_its_warnings_and_not_the_debug_detail() {
        let logs = SessionLogs::default();
        let build = SessionId::mint();
        let wrapper = SessionId::mint();
        let mut wrapper_receiver =
            logs.register(wrapper, LogInterest::of_wrapper(None).expect("filter"));
        let subscriber = tracing_subscriber::registry().with(logs.layer());
        tracing::subscriber::with_default(subscriber, || {
            let session = tracing::info_span!(SESSION_SPAN, session = %build);
            let _session = session.enter();
            // Bookkeeping that runs under the session's own span has no route.
            tracing::warn!("recorded under the build's span");
            let nested = tracing::info_span!(parent: &session, SESSION_SPAN, session = %wrapper);
            let _nested = nested.enter();
            tracing::debug!("debug detail");
            tracing::warn!("a warning");
            tracing::error!("an error");
        });
        let mut texts = Vec::new();
        while let Ok(Event::Log(record)) = wrapper_receiver.try_recv() {
            texts.push((record.level, record.text));
        }
        assert_eq!(
            texts,
            [
                (LogLevel::Warn, "a warning".to_owned()),
                (LogLevel::Error, "an error".to_owned())
            ]
        );
    }

    #[test]
    fn a_tracing_wrapper_gets_its_directives_besides_the_warnings() {
        let interest = LogInterest::of_wrapper(Some("stow_cli=debug,off")).expect("filter");
        assert!(interest.wants("stow_cli::lib", tracing::Level::DEBUG));
        assert!(interest.wants("anything", tracing::Level::WARN));
        assert!(!interest.wants("anything", tracing::Level::INFO));
        assert!(LogInterest::of_wrapper(Some("stow_cli=nonsense")).is_err());
    }
}
