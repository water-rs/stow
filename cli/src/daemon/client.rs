//! The async side of the daemon connection: a driver's control connection
//! and a wrapper's conversation.
//!
//! Reaching the daemon is [`super::start`]'s job; what is here speaks the
//! session protocol over a stream that path made sure exists.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use stow_types::error::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, WriteHalf};
use tokio::sync::{oneshot, watch};

use super::events::SpanMirror;
use super::protocol::{
    ControlRequest, Event, Hello, PROTOCOL, PROTOCOL_FLOOR, Response, Role, SessionRef,
    WrapperRequest, encode, read_frame_async, speaks,
};
use super::relay::{RELAY_METHOD, RelayBody, RelayCall, mint_connection_id};
use super::session::{SessionEnd, SessionFacts, SessionId};
use super::start::{connect_or_start, describe_daemon};
use super::{RunDir, Settings};
use crate::daemon::session::handler::CONNECTION_DRAIN_BUDGET;
use crate::daemon::session::os_bytes;
use crate::daemon::wrapper::{
    Answer, ArtifactNotifications, BuildEnvironment, CcCompiled, CcLookup, Compiled, Plan,
};

/// The variable a build's driver exports so its wrappers find the build's
/// session.
pub const STOW_SESSION_ENV: &str = "STOW_SESSION";

/// The spelling of [`STOW_SESSION_ENV`] a sandboxed build's wrappers read:
/// the relay's IPC socket follows it.
const RELAY_PREFIX: &str = "relay:";

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// How a wrapper reaches its build's session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLink {
    /// Straight to the daemon, naming the session the driver opened.
    Direct(SessionId),
    /// Through the driver's relay at this IPC socket: a sandboxed wrapper
    /// holds neither the daemon's endpoint nor a session id.
    Relay(PathBuf),
    /// Straight to the daemon, which finds the cargo that started this
    /// wrapper and serves it a session of its own: no driver opened one.
    Cargo,
}

impl SessionLink {
    /// The link this process's environment names. Unset or empty means the
    /// wrapper runs under no driver, so its cargo owns the session.
    ///
    /// # Errors
    ///
    /// The variable is set but is neither a session id nor a relay.
    pub fn from_env() -> std::result::Result<Self, String> {
        let Some(raw) = std::env::var_os(STOW_SESSION_ENV) else {
            return Ok(Self::Cargo);
        };
        let raw = raw
            .to_str()
            .ok_or_else(|| format!("{STOW_SESSION_ENV} is not valid Unicode"))?;
        Self::parse(raw)
    }

    fn parse(raw: &str) -> std::result::Result<Self, String> {
        if raw.is_empty() {
            return Ok(Self::Cargo);
        }
        match raw.strip_prefix(RELAY_PREFIX) {
            Some(path) if !path.is_empty() => Ok(Self::Relay(PathBuf::from(path))),
            Some(_) => Err(format!("{STOW_SESSION_ENV} names a relay without a socket")),
            None => raw
                .parse()
                .map(Self::Direct)
                .map_err(|error| format!("{STOW_SESSION_ENV}: {error}")),
        }
    }

    /// The spelling [`Self::from_env`] reads.
    #[must_use]
    pub fn encode(&self) -> OsString {
        match self {
            Self::Cargo => OsString::new(),
            Self::Direct(id) => OsString::from(id.to_string()),
            Self::Relay(path) => {
                let mut value = OsString::from(RELAY_PREFIX);
                value.push(path);
                value
            }
        }
    }
}

/// Connect once. A missing endpoint or a refused connection means the
/// daemon is down: `None`.
#[cfg(unix)]
async fn try_open(endpoint: &Path, _answer: Duration) -> Result<Option<Stream>> {
    use std::io::ErrorKind;
    match Stream::connect(endpoint).await {
        Ok(stream) => Ok(Some(stream)),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error)
            .wrap_err_with(|| format!("connect to the stow daemon at {}", endpoint.display())),
    }
}

/// Connect once. A missing pipe means the daemon is down; a pipe whose
/// instances are all busy is retried within the answer bound.
#[cfg(windows)]
async fn try_open(endpoint: &Path, answer: Duration) -> Result<Option<Stream>> {
    use tokio::net::windows::named_pipe::ClientOptions;
    /// `ERROR_PIPE_BUSY`: every instance of the pipe is serving a client.
    const PIPE_BUSY: i32 = 231;
    /// The pause before asking a busy pipe again.
    const BUSY_PAUSE: Duration = Duration::from_millis(10);
    let deadline = tokio::time::Instant::now() + answer;
    loop {
        match ClientOptions::new().open(endpoint) {
            Ok(pipe) => return Ok(Some(pipe)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error)
                if error.raw_os_error() == Some(PIPE_BUSY)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(BUSY_PAUSE).await;
            }
            Err(error) => {
                return Err(error).wrap_err_with(|| {
                    format!("connect to the stow daemon at {}", endpoint.display())
                });
            }
        }
    }
}

async fn run_dir() -> Result<RunDir> {
    smol::unblock(|| RunDir::prepare(RunDir::locate()?)).await
}

/// Reach the daemon and connect, starting it when it is down: a live
/// daemon is one connect, and only a down one pays the start path.
///
/// # Errors
///
/// The daemon cannot be started, does not answer, or speaks a protocol
/// this stow does not.
pub async fn connect(exe: PathBuf, settings: Settings) -> Result<Stream> {
    let run_dir = run_dir().await?;
    if let Some(stream) = try_open(&run_dir.endpoint(), settings.answer).await? {
        return Ok(stream);
    }
    connect_starting(exe, settings).await
}

/// Reach the daemon through the start path — which verifies it answers and
/// speaks a protocol this stow reads — and connect.
///
/// # Errors
///
/// The daemon cannot be started, does not answer, or speaks a protocol
/// this stow does not.
pub async fn connect_starting(exe: PathBuf, settings: Settings) -> Result<Stream> {
    let run_dir = run_dir().await?;
    let status = smol::unblock(move || connect_or_start(&exe, settings)?.status()).await?;
    if !speaks(status.protocol) {
        return Err(stow_types::stow_error!(
            "the running stow daemon ({}) speaks protocol {}, this stow speaks {PROTOCOL_FLOOR} through {PROTOCOL}",
            describe_daemon(&run_dir.log()),
            status.protocol
        ));
    }
    try_open(&run_dir.endpoint(), settings.answer)
        .await?
        .ok_or_else(|| {
            stow_types::stow_error!(
                "the stow daemon answered a status request but nothing listens at {}",
                run_dir.endpoint().display()
            )
        })
}

/// A wrapper's conversation with its session: its first request carries
/// the `Hello`, and every request is answered with one answer, however
/// long the decision takes — the daemon says it is still working.
#[derive(Debug)]
pub struct WrapperStream<S> {
    stream: S,
    greeting: Option<Hello>,
    answer: Duration,
    reach: Option<Reach>,
}

/// Where the daemon a wrapper talks to lives: what every failure to get an
/// answer from it names, so one message serves every way the daemon can be
/// out of reach.
#[derive(Debug, Clone)]
pub struct Reach {
    endpoint: PathBuf,
    run_dir: PathBuf,
    log: PathBuf,
}

/// What every failure to reach the daemon says about the build: no wrapper
/// decides anything on its own.
const NO_BUILD_WITHOUT_DAEMON: &str = "every compile of a cargo build through stow's wrapper is answered by the stow daemon, so the build cannot run where the daemon cannot be reached";

impl Reach {
    /// The daemon of this user's run directory.
    ///
    /// # Errors
    ///
    /// The run directory cannot be located or created.
    pub async fn locate() -> Result<Self> {
        let run_dir = run_dir().await?;
        Ok(Self {
            endpoint: run_dir.endpoint(),
            run_dir: run_dir.path().to_owned(),
            log: run_dir.log(),
        })
    }

    /// `failure` with what a person needs to find the daemon: the endpoint
    /// and run directory it serves from, its pid and its log, and that no
    /// compile of the build runs without it.
    #[must_use]
    pub fn explain(&self, failure: &str) -> String {
        format!(
            "{failure} ({NO_BUILD_WITHOUT_DAEMON}; endpoint {}, run directory {}, daemon {})",
            self.endpoint.display(),
            self.run_dir.display(),
            describe_daemon(&self.log)
        )
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> WrapperStream<S> {
    /// A conversation over `stream` for `session`, whose daemon answers
    /// within `answer` or says it is working.
    pub fn new(stream: S, session: SessionRef, answer: Duration) -> Self {
        Self {
            stream,
            greeting: Some(Hello::new(Role::Wrapper { session })),
            answer,
            reach: None,
        }
    }

    /// Name the daemon in every failure of this conversation.
    #[must_use]
    pub fn reaching(mut self, reach: Reach) -> Self {
        self.reach = Some(reach);
        self
    }

    /// Send `request` and read its answer. A daemon that has no session
    /// for the wrapper's cargo asks for the wrapper's environment, which is
    /// sent before the answer is waited for.
    ///
    /// # Errors
    ///
    /// The daemon closes the connection, goes quiet for longer than the
    /// answer bound, or refuses the request.
    pub async fn exchange(
        &mut self,
        request: &WrapperRequest,
    ) -> std::result::Result<Answer, String> {
        self.converse(request)
            .await
            .map_err(|failure| match &self.reach {
                Some(reach) => reach.explain(&failure),
                None => failure,
            })
    }

    async fn send(&mut self, request: &WrapperRequest) -> std::result::Result<(), String> {
        // The `Hello` and the first request go out in one write.
        let mut bytes = match self.greeting.take() {
            Some(hello) => encode(&hello).map_err(|error| error.to_string())?,
            None => Vec::new(),
        };
        bytes.extend(encode(request).map_err(|error| error.to_string())?);
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|error| format!("send a request to the stow daemon: {error}"))?;
        self.stream
            .flush()
            .await
            .map_err(|error| format!("send a request to the stow daemon: {error}"))
    }

    async fn converse(&mut self, request: &WrapperRequest) -> std::result::Result<Answer, String> {
        self.send(request).await?;
        loop {
            let frame = tokio::time::timeout(self.answer, read_frame_async(&mut self.stream))
                .await
                .map_err(|_| {
                    format!(
                        "the stow daemon did not answer or report progress within {} s",
                        self.answer.as_secs()
                    )
                })?
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    "the stow daemon closed the connection without answering".to_owned()
                })?;
            if !speaks(frame.protocol) {
                return Err(format!(
                    "the stow daemon speaks protocol {}, this stow speaks {PROTOCOL_FLOOR} through {PROTOCOL}",
                    frame.protocol
                ));
            }
            match frame
                .decode::<Response>()
                .map_err(|error| error.to_string())?
            {
                // What the daemon logged while deciding this wrapper's
                // request, which it carries ahead of the answer.
                Response::Event(Event::Log(record)) => record_log(&record),
                // A wrapper keeps no spans of the daemon's and waits on no
                // resolution.
                Response::Working | Response::Event(_) => {}
                Response::Answer(Answer::Describe) => {
                    let environment = BuildEnvironment::current()?;
                    self.send(&WrapperRequest::Describe(environment)).await?;
                }
                Response::Answer(answer) => return Ok(answer),
                Response::Rejected { reason } => {
                    return Err(format!("the stow daemon refused the request: {reason}"));
                }
                other => {
                    return Err(format!("the stow daemon answered a request with {other:?}"));
                }
            }
        }
    }

    /// End the conversation: the daemon reads the stream's end and ends
    /// the connection's flight.
    ///
    /// # Errors
    ///
    /// The stream cannot be shut down.
    pub async fn close(mut self) -> std::result::Result<(), String> {
        self.stream
            .shutdown()
            .await
            .map_err(|error| format!("close the stow daemon connection: {error}"))
    }
}

/// What the daemon decided for a keyed C/C++ invocation.
#[derive(Debug)]
pub enum CcDecision {
    /// The cache holds the object at this path: clone it to the output.
    Hit(PathBuf),
    /// Run the compiler, then call [`WrapperConnection::cc_report`].
    Miss,
    /// The daemon could not consult the cache (the message says why): run
    /// the compiler and report nothing.
    Bypass(String),
}

/// What the daemon decided for a rustc invocation.
#[derive(Debug)]
pub enum Decision {
    /// The outputs are already in place; exit 0 after writing the
    /// artifact-notification lines cargo is owed to this process's stderr
    /// (stow#633).
    Served(ArtifactNotifications),
    /// Run exactly this command — the build's own arguments are already in
    /// it — then call [`WrapperConnection::report`] with its outcome on
    /// this connection.
    Compile {
        /// The executable to run.
        executable: OsString,
        /// Its arguments.
        args: Vec<OsString>,
    },
}

/// A wrapper's connection to its build's session, kept open across the
/// plan and the report so the compile's outcome reaches the same
/// conversation.
pub enum WrapperConnection {
    /// Straight to the daemon.
    Direct(WrapperStream<Stream>),
    /// Through the driver's relay inside a sandbox. The client leaves its
    /// slot while a call blocks on the worker thread and is always put
    /// back, so a call never finds it gone.
    Relay {
        client: Option<heel::IpcClient>,
        connection: u64,
    },
}

impl WrapperConnection {
    /// Connect to the session `link` names.
    ///
    /// # Errors
    ///
    /// Any connection failure. The caller fails the build: a session the
    /// environment names that cannot be reached means the daemon is gone,
    /// and a build that quietly stops using the cache is the failure that
    /// hides.
    pub async fn open(link: &SessionLink) -> std::result::Result<Self, String> {
        match link {
            SessionLink::Direct(id) => Self::open_direct(SessionRef::Id(*id)).await,
            SessionLink::Cargo => {
                Self::open_direct(SessionRef::Cargo {
                    cargo: std::env::var_os("CARGO").map(|cargo| os_bytes::encode(&cargo)),
                    // A wrapper that does not trace takes the warnings the
                    // daemon returns to it and nothing more.
                    rust_log: crate::wrapper_tracing_requested(
                        std::env::var_os(crate::STOW_TRACE_WRAPPED_COMPILERS_ENV).as_deref(),
                    )
                    .then(|| std::env::var("RUST_LOG").ok())
                    .flatten(),
                })
                .await
            }
            SessionLink::Relay(path) => {
                let path = path.clone();
                let client = smol::unblock(move || heel::IpcClient::connect(path))
                    .await
                    .map_err(|error| {
                        format!("connect to the build's relay over heel IPC: {error}")
                    })?;
                Ok(Self::Relay {
                    client: Some(client),
                    connection: mint_connection_id(),
                })
            }
        }
    }

    /// A conversation with the daemon, started from the runtime executable
    /// when it is down.
    async fn open_direct(session: SessionRef) -> std::result::Result<Self, String> {
        let exe = runtime_executable()?;
        let settings = Settings::from_env().map_err(|error| error.to_string())?;
        // With no run directory there is no endpoint, log or pid to name.
        let reach = Reach::locate()
            .await
            .map_err(|error| format!("{error:#} ({NO_BUILD_WITHOUT_DAEMON})"))?;
        let stream = connect(exe, settings)
            .await
            .map_err(|error| reach.explain(&format!("{error:#}")))?;
        Ok(Self::Direct(
            WrapperStream::new(stream, session, settings.answer).reaching(reach),
        ))
    }

    /// Whether the build's C/C++ object cache is on.
    ///
    /// # Errors
    ///
    /// Transport failures and an answer that is not a policy.
    pub async fn cc_enabled(&mut self) -> std::result::Result<bool, String> {
        match self
            .exchange(&WrapperRequest::CcPolicy)
            .await?
            .ok_or_else(no_answer)?
        {
            Answer::CcPolicy { enabled } => Ok(enabled),
            Answer::Failed { message } => Err(message),
            other => Err(format!(
                "the daemon answered a C/C++ policy request with {other:?}"
            )),
        }
    }

    /// Ask whether the object cache holds the object a keyed C/C++
    /// invocation would produce. A hit's records are written after the
    /// answer, so the wrapper clones the object without waiting for them.
    ///
    /// # Errors
    ///
    /// Transport failures and an answer that is not a cache decision. A
    /// daemon that cannot look the key up is [`CcDecision::Bypass`]: the
    /// cache failing is not the build failing.
    pub async fn cc_lookup(&mut self, cache_key: &str) -> std::result::Result<CcDecision, String> {
        let lookup = CcLookup {
            cache_key: cache_key.to_owned(),
        };
        match self
            .exchange(&WrapperRequest::CcLookup(lookup))
            .await?
            .ok_or_else(no_answer)?
        {
            Answer::CcHit { object } => os_bytes::decode(&object)
                .map(|object| CcDecision::Hit(PathBuf::from(object)))
                .map_err(|error| format!("the daemon named an undecodable object path: {error}")),
            Answer::CcMiss => Ok(CcDecision::Miss),
            Answer::Failed { message } => Ok(CcDecision::Bypass(message)),
            other => Err(format!(
                "the daemon answered a C/C++ lookup with {other:?}, which is not a cache decision"
            )),
        }
    }

    /// Report the compile a [`CcDecision::Miss`] sent the wrapper to run and
    /// wait for the receipt. The receipt follows the object's snapshot and
    /// precedes its store, so the wrapper exits with the compiler.
    ///
    /// # Errors
    ///
    /// Transport failures and an answer that is not a receipt. A report the
    /// daemon refuses — an output outside the build's target directory — is
    /// `Ok(Some(reason))`: the compile succeeded and only the cache did not
    /// take it.
    pub async fn cc_report(
        &mut self,
        cache_key: &str,
        output_path: &Path,
        success: bool,
    ) -> std::result::Result<Option<String>, String> {
        let report = CcCompiled::new(cache_key.to_owned(), output_path, success);
        match self
            .exchange(&WrapperRequest::CcCompiled(report))
            .await?
            .ok_or_else(no_answer)?
        {
            Answer::Received => Ok(None),
            Answer::Failed { message } => Ok(Some(message)),
            other => Err(format!("the daemon answered a C/C++ report with {other:?}")),
        }
    }

    /// End the conversation, which ends the connection's flight on the
    /// daemon. No wrapper leaves through `std::process::exit` with a
    /// connection in hand (stow#682), so a drop releases it too; the close
    /// stays explicit because it ends the stream in order and reports a
    /// shutdown that fails, where a drop reports nothing.
    ///
    /// # Errors
    ///
    /// A stream that cannot be shut down, or a close the relay could not
    /// deliver — the conversation's flight then stays until the build ends
    /// instead of completing now.
    pub async fn close(self) -> std::result::Result<(), String> {
        match self {
            Self::Direct(stream) => stream.close().await,
            Self::Relay { client, connection } => {
                let Some(mut client) = client else {
                    return Ok(());
                };
                let call = RelayCall {
                    connection,
                    body: RelayBody::Close,
                };
                smol::unblock(move || {
                    client
                        .call::<_, Option<Answer>>(RELAY_METHOD, &call)
                        .map(|_| ())
                        .map_err(|error| format!("close the relay conversation: {error}"))
                })
                .await
            }
        }
    }

    async fn exchange(
        &mut self,
        request: &WrapperRequest,
    ) -> std::result::Result<Option<Answer>, String> {
        match self {
            Self::Direct(stream) => stream.exchange(request).await.map(Some),
            Self::Relay { client, connection } => {
                let mut ipc = client
                    .take()
                    .expect("the IPC client is restored after every call");
                let call = RelayCall {
                    connection: *connection,
                    body: RelayBody::Request(request.clone()),
                };
                let (ipc, answer) = smol::unblock(move || {
                    let answer = ipc
                        .call::<_, Option<Answer>>(RELAY_METHOD, &call)
                        .map_err(|error| format!("relay IPC call: {error}"));
                    (ipc, answer)
                })
                .await;
                *client = Some(ipc);
                answer
            }
        }
    }
}

/// A wrapper's conversation with its session on the daemon, as a rustc
/// wrapper has it: ask what to do with an invocation, and report the
/// compile the answer sent it to run. A wrapper's own code is written
/// against this, so a test can run it over a stream it holds both ends of.
pub trait Conversation {
    /// Send `request` and wait for the daemon's answer.
    ///
    /// # Errors
    ///
    /// The daemon closes the connection, goes quiet for longer than the
    /// answer bound, or refuses the request.
    async fn exchange(&mut self, request: &WrapperRequest) -> std::result::Result<Answer, String>;

    /// Ask what to do with one rustc invocation.
    ///
    /// # Errors
    ///
    /// Transport failures, and a daemon that answers with a failure of its
    /// own.
    async fn plan(
        &mut self,
        executable: &std::ffi::OsStr,
        args: &[OsString],
    ) -> std::result::Result<Decision, String> {
        let plan = Plan::new(
            executable,
            args,
            crate::daemon::wrapper::InvocationEnv::current(),
        );
        match Conversation::exchange(self, &WrapperRequest::Plan(plan)).await? {
            Answer::Served(notifications) => Ok(Decision::Served(notifications)),
            Answer::Compile(command) => Ok(Decision::Compile {
                executable: command.executable()?,
                args: command.args()?,
            }),
            Answer::Failed { message } => Err(message),
            other => Err(format!(
                "the daemon answered a plan with {other:?}, which is not a decision"
            )),
        }
    }

    /// Report the compile the daemon asked for and wait for its receipt.
    /// The receipt precedes the daemon's bookkeeping, so the wrapper exits
    /// as soon as rustc has and its unit is already recorded as exited
    /// (stow#1431).
    ///
    /// # Errors
    ///
    /// Transport failures, and a daemon that refuses the report.
    async fn report(
        &mut self,
        success: bool,
        compile_time: Duration,
    ) -> std::result::Result<(), String> {
        let report = Compiled {
            success,
            compile_millis: crate::duration_millis(compile_time),
        };
        match Conversation::exchange(self, &WrapperRequest::Compiled(report)).await? {
            Answer::Received => Ok(()),
            Answer::Failed { message } => Err(message),
            other => Err(format!("the daemon answered a report with {other:?}")),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Conversation for WrapperStream<S> {
    async fn exchange(&mut self, request: &WrapperRequest) -> std::result::Result<Answer, String> {
        Self::exchange(self, request).await
    }
}

impl Conversation for WrapperConnection {
    async fn exchange(&mut self, request: &WrapperRequest) -> std::result::Result<Answer, String> {
        Self::exchange(self, request).await?.ok_or_else(no_answer)
    }
}

/// The executable that starts the daemon: the runtime. A wrapper is the
/// runtime under a wrapper's name, which would play that wrapper's role
/// again, so the `stow-runtime` link beside it is used instead.
fn runtime_executable() -> std::result::Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("resolve this wrapper's own executable: {error}"))?;
    Ok(if stow_shim::WrapperRole::from_program(&exe).is_some() {
        stow_shim::runtime_executable_beside(&exe)
    } else {
        exe
    })
}

fn no_answer() -> String {
    "the relay answered a two-way request with nothing".to_owned()
}

/// A build's session on the daemon, as its driver holds it.
///
/// The control connection's lifetime is the session's: dropping this
/// closes it, and the daemon ends the session without journaling.
#[derive(Debug)]
pub struct DaemonSession {
    id: SessionId,
    writer: WriteHalf<Stream>,
    resolution_done: crate::ResolutionDone,
    ended: oneshot::Receiver<SessionEnd>,
    lost: watch::Receiver<Option<String>>,
    reader: tokio::task::JoinHandle<()>,
    settings: Settings,
    log: PathBuf,
}

impl DaemonSession {
    /// Open the session `facts` describe on the daemon, starting the
    /// daemon from `exe` when it is down.
    ///
    /// # Errors
    ///
    /// The daemon cannot be reached, refuses the session or does not
    /// answer within the answer bound.
    pub async fn open(exe: PathBuf, facts: SessionFacts, settings: Settings) -> Result<Self> {
        let run_dir = run_dir().await?;
        let log = run_dir.log();
        let mut stream = connect_starting(exe, settings).await?;
        let mut bytes = encode(&Hello::new(Role::Control))?;
        bytes.extend(encode(&ControlRequest::OpenSession(Box::new(facts)))?);
        let opened = async {
            stream
                .write_all(&bytes)
                .await
                .wrap_err("send the session's facts to the daemon")?;
            stream.flush().await.wrap_err("send the session's facts")?;
            tokio::time::timeout(settings.answer, read_frame_async(&mut stream))
                .await
                .map_err(|_| {
                    stow_types::stow_error!("no answer within {} s", settings.answer.as_secs())
                })?
        }
        .await
        .wrap_err_with(|| {
            format!(
                "open a session on the stow daemon ({})",
                describe_daemon(&log)
            )
        })?
        .ok_or_else(|| {
            stow_types::stow_error!(
                "the stow daemon ({}) closed the connection while opening the session",
                describe_daemon(&log)
            )
        })?;
        let id = match opened.decode::<Response>()? {
            Response::SessionOpened { session } => session,
            Response::Rejected { reason } => {
                return Err(stow_types::stow_error!(
                    "the stow daemon ({}) refused the session: {reason}",
                    describe_daemon(&log)
                ));
            }
            other => {
                return Err(stow_types::stow_error!(
                    "the stow daemon ({}) answered OpenSession with {other:?}",
                    describe_daemon(&log)
                ));
            }
        };
        let (read, writer) = tokio::io::split(stream);
        let resolution_done = crate::ResolutionDone::pending();
        let (ended_sender, ended) = oneshot::channel();
        let (lost_sender, lost) = watch::channel(None);
        let reader = tokio::spawn(read_events(
            read,
            resolution_done.clone(),
            ended_sender,
            lost_sender,
            log.clone(),
            // The session's spans hang under the span the driver opened
            // it in.
            SpanMirror::under(tracing::Span::current()),
        ));
        Ok(Self {
            id,
            writer,
            resolution_done,
            ended,
            lost,
            reader,
            settings,
            log,
        })
    }

    /// The session's id, which every wrapper of the build names.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// The signal that cargo's resolution is over.
    #[must_use]
    pub fn resolution_done(&self) -> crate::ResolutionDone {
        self.resolution_done.clone()
    }

    /// Resolves, with why, if the control connection ends before the
    /// session was ended: the daemon died or dropped the session. Never
    /// resolves otherwise.
    pub async fn lost(&self) -> String {
        let mut lost = self.lost.clone();
        // The borrow the wait returns is not `Send`: the verdict is copied
        // out before anything else is awaited.
        let verdict = lost
            .wait_for(Option::is_some)
            .await
            .map(|reason| reason.clone().unwrap_or_default());
        match verdict {
            Ok(reason) => reason,
            // The reader ended without a verdict only after the session
            // ended, which `lost`'s callers have stopped listening for.
            Err(_) => std::future::pending().await,
        }
    }

    /// End the session: the daemon drains the build's bookkeeping, writes
    /// its miss journal and answers with what it found.
    ///
    /// # Errors
    ///
    /// The daemon is gone, or does not answer within the drain budget and
    /// the answer bound.
    pub async fn end(mut self) -> Result<SessionEnd> {
        let outcome = async {
            let frame = encode(&ControlRequest::EndSession)?;
            self.writer
                .write_all(&frame)
                .await
                .wrap_err("send EndSession to the daemon")?;
            self.writer.flush().await.wrap_err("send EndSession")?;
            let bound = CONNECTION_DRAIN_BUDGET + self.settings.answer;
            match tokio::time::timeout(bound, &mut self.ended).await {
                Ok(Ok(end)) => Ok(end),
                Ok(Err(_)) => Err(stow_types::stow_error!(
                    "the connection closed before the session ended: {}",
                    self.lost.borrow().clone().unwrap_or_default()
                )),
                Err(_) => Err(stow_types::stow_error!(
                    "no answer within {} s",
                    bound.as_secs()
                )),
            }
        }
        .await
        .wrap_err_with(|| {
            format!(
                "end the build's session on the stow daemon ({})",
                describe_daemon(&self.log)
            )
        });
        self.reader.abort();
        outcome
    }
}

impl Drop for DaemonSession {
    fn drop(&mut self) {
        // The reader owns the read half: stopping it and dropping the
        // write half closes the connection, which ends the session.
        self.reader.abort();
    }
}

/// Read the control connection until it ends: complete the resolution
/// latch, record the session's events and hand the end over.
async fn read_events(
    mut read: tokio::io::ReadHalf<Stream>,
    resolution_done: crate::ResolutionDone,
    ended: oneshot::Sender<SessionEnd>,
    lost: watch::Sender<Option<String>>,
    log: PathBuf,
    mut spans: SpanMirror,
) {
    let reason = loop {
        let frame = match read_frame_async(&mut read).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break "the daemon closed the control connection".to_owned(),
            Err(error) => break format!("the control connection failed: {error}"),
        };
        match frame.decode::<Response>() {
            Ok(Response::Event(Event::ResolutionDone)) => resolution_done.complete(),
            Ok(Response::Event(Event::Log(record))) => record_log(&record),
            Ok(Response::Event(Event::SpanOpened(record))) => spans.opened(&record),
            Ok(Response::Event(Event::SpanClosed { id })) => spans.closed(id),
            Ok(Response::SessionEnded(end)) => {
                // `end` is waiting; a driver that dropped the session has
                // no one to tell.
                let _ = ended.send(end);
                return;
            }
            Ok(Response::Rejected { reason }) => break format!("the daemon refused: {reason}"),
            Ok(other) => break format!("the daemon sent an unexpected {other:?}"),
            Err(error) => break format!("an undecodable control frame: {error}"),
        }
    };
    let _ = lost.send(Some(format!(
        "the stow daemon ({}) ended this build's session: {reason}",
        describe_daemon(&log)
    )));
}

/// Record an event the daemon's session task logged, at the level it was
/// logged at. The module that logged it rides as a field: a target is a
/// compile-time constant of the call site.
fn record_log(record: &super::events::LogRecord) {
    use super::events::LogLevel;
    let (target, text) = (&record.target, &record.text);
    match record.level {
        LogLevel::Error => tracing::error!(daemon_target = %target, "{text}"),
        LogLevel::Warn => tracing::warn!(daemon_target = %target, "{text}"),
        LogLevel::Info => tracing::info!(daemon_target = %target, "{text}"),
        LogLevel::Debug => tracing::debug!(daemon_target = %target, "{text}"),
        LogLevel::Trace => tracing::trace!(daemon_target = %target, "{text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{STOW_SESSION_ENV, SessionLink};
    use crate::daemon::session::SessionId;

    #[test]
    fn a_session_link_round_trips_through_its_spelling() {
        let id = SessionId::mint();
        for link in [
            SessionLink::Direct(id),
            SessionLink::Relay("/tmp/heel/ipc.sock".into()),
            SessionLink::Cargo,
        ] {
            let spelled = link.encode();
            assert_eq!(
                SessionLink::parse(spelled.to_str().expect("utf8")),
                Ok(link)
            );
        }
    }

    fn reach(dir: &std::path::Path) -> super::Reach {
        let log = dir.join("daemon.log");
        std::fs::write(&log, "INFO stow daemon serving pid=4242 endpoint=x\n").expect("log");
        super::Reach {
            endpoint: dir.join("daemon.sock"),
            run_dir: dir.to_owned(),
            log,
        }
    }

    #[test]
    fn an_unreachable_daemon_is_named_by_endpoint_run_directory_pid_and_log() {
        let dir = tempfile::tempdir().expect("dir");
        let message = reach(dir.path()).explain("connect failed");
        for part in [
            "connect failed",
            "daemon.sock",
            "pid 4242",
            "daemon.log",
            &dir.path().display().to_string(),
            "cannot run where the daemon cannot be reached",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }

    #[tokio::test]
    async fn a_refused_request_names_the_daemon() {
        let dir = tempfile::tempdir().expect("dir");
        let (client, mut daemon_end) = tokio::io::duplex(1 << 16);
        let mut stream = super::WrapperStream::new(
            client,
            super::SessionRef::Cargo {
                cargo: None,
                rust_log: None,
            },
            std::time::Duration::from_secs(5),
        )
        .reaching(reach(dir.path()));
        let refusal = super::encode(&super::Response::Rejected {
            reason: "no such cargo".to_owned(),
        })
        .expect("encode");
        tokio::io::AsyncWriteExt::write_all(&mut daemon_end, &refusal)
            .await
            .expect("write");
        let error = stream
            .exchange(&super::WrapperRequest::CcPolicy)
            .await
            .expect_err("refused");
        assert!(
            error.contains("no such cargo") && error.contains("pid 4242"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_daemon_that_asks_for_the_environment_is_sent_it_before_the_answer() {
        let (client, mut daemon_end) = tokio::io::duplex(1 << 20);
        let mut stream = super::WrapperStream::new(
            client,
            super::SessionRef::Cargo {
                cargo: None,
                rust_log: None,
            },
            std::time::Duration::from_secs(5),
        );
        let daemon = async move {
            // The hello and the held request arrive together.
            for _ in 0..2 {
                super::read_frame_async(&mut daemon_end)
                    .await
                    .expect("read")
                    .expect("a frame");
            }
            let describe =
                super::encode(&super::Response::Answer(super::Answer::Describe)).expect("encode");
            tokio::io::AsyncWriteExt::write_all(&mut daemon_end, &describe)
                .await
                .expect("write");
            let environment = super::read_frame_async(&mut daemon_end)
                .await
                .expect("read")
                .expect("the environment")
                .decode::<super::WrapperRequest>()
                .expect("request");
            assert!(
                matches!(environment, super::WrapperRequest::Describe(_)),
                "{environment:?}"
            );
            let answer =
                super::encode(&super::Response::Answer(super::Answer::CcMiss)).expect("encode");
            tokio::io::AsyncWriteExt::write_all(&mut daemon_end, &answer)
                .await
                .expect("write");
        };
        let (answer, ()) = tokio::join!(stream.exchange(&super::WrapperRequest::CcPolicy), daemon);
        assert_eq!(answer, Ok(super::Answer::CcMiss));
    }

    #[test]
    fn text_that_names_no_session_is_refused() {
        for bad in ["relay:", "nonsense", "ABCDEF"] {
            let error = SessionLink::parse(bad).expect_err("refused");
            assert!(
                error.contains(STOW_SESSION_ENV) || error.contains("hex"),
                "{error}"
            );
        }
    }
}
