//! What answers a wrapper: the handler a build's session implements, the
//! in-flight registry its bookkeeping orders dependents by, and the
//! request-to-answer step every transport shares.
//!
//! Transports are not here. A wrapper's conversation reaches a session
//! over the daemon's socket (see [`crate::daemon`]), directly or, for a
//! sandboxed build, through the driver's relay. The handler owns two
//! pieces of mutable state: the
//! units whose post-compile bookkeeping is still running — the in-flight
//! registry a dependent's bookkeeping waits on (stow#618) — and the
//! bookkeeping tasks themselves ([`Reports`]).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use stow_types::rustc::ParsedRustcArgs;
use tracing::Instrument as _;

use super::invocation::{Refusal, RefusalPolicy, VerifiedInvocation};
use crate::daemon::wrapper::{
    Answer, ArtifactNotifications, CcCompiled, CcLookup, CompileCommand, Compiled, Plan, Request,
};
use crate::toolchain::BuildToolchain;

/// What a session does with the invocations its wrappers send.
///
/// Implemented by the build's own state, which owns the config, the index
/// slice, the local cache and the one edge connection the whole build
/// shares.
pub trait Handler: Send + Sync + 'static {
    /// Decide one invocation.
    fn plan(
        self: &Arc<Self>,
        invocation: VerifiedInvocation,
        env: crate::daemon::wrapper::InvocationEnv,
    ) -> impl Future<Output = Decision<Self::Pending>> + Send;

    /// Finish the work that only exists after a real compile.
    fn compiled(
        self: &Arc<Self>,
        pending: Self::Pending,
        success: bool,
        compile_time: Duration,
    ) -> impl Future<Output = ()> + Send;

    /// The toolchain this build compiles with, resolved by the driver
    /// before cargo started: the only source of every rustc fact the
    /// session uses, and what a request's executable is checked against.
    fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain>;

    /// What this build does with a refused request, fixed when the
    /// handler was built.
    fn refusal_policy(self: &Arc<Self>) -> RefusalPolicy;

    /// Record a request the session refused under
    /// [`RefusalPolicy::FailBuild`], so the build fails naming the field
    /// once cargo has exited — a one-way report has no answer to carry
    /// the refusal. Never called under [`RefusalPolicy::CompileUncached`].
    fn refused(self: &Arc<Self>, refusal: Refusal);

    /// The config whose C/C++ object cache and state database answer the
    /// C compiler wrapper — the build's own, so the wrappers never open
    /// the database themselves. `None` — the default — when the handler
    /// has no C/C++ cache to answer from.
    fn cc_config(self: &Arc<Self>) -> Option<&crate::config::StowConfig> {
        None
    }

    /// The build's output roots: the only places a compiler output a
    /// wrapper reports, or an `--out-dir` it names, may live. `None` — the
    /// default — when the handler does not know them, which refuses every
    /// report and every request that names an output directory.
    fn output_roots(self: &Arc<Self>) -> Option<&super::invocation::OutputRoots> {
        None
    }

    /// The arguments a request is decided and compiled with: the request's
    /// own, plus whatever the build adds to every unit. The default adds
    /// nothing.
    ///
    /// # Errors
    ///
    /// The request's environment cannot be decoded.
    fn plan_args(
        self: &Arc<Self>,
        args: Vec<std::ffi::OsString>,
        _env: &crate::daemon::wrapper::InvocationEnv,
    ) -> Result<Vec<std::ffi::OsString>, String> {
        Ok(args)
    }

    /// What the handler needs to remember between asking for a compile and
    /// hearing that it finished. Its default is the pending of a compile
    /// with no bookkeeping: what a refused plan is answered with under
    /// [`RefusalPolicy::CompileUncached`].
    type Pending: Default + Send + 'static;
}

/// A handler's decision about one invocation.
pub enum Decision<P> {
    /// The outputs are in place; the wrapper exits 0. The payload is the
    /// artifact-notification lines the wrapper owes cargo's stderr first
    /// (stow#633).
    Served(ArtifactNotifications),
    /// The wrapper runs rustc and reports back with `pending` restored.
    Compile(P),
}

/// How long a session's end waits for the bookkeeping its wrappers' reports
/// queued (stow#618). Every wrapper has exited by then, so only the
/// bookkeeping remains — sqlite writes and file copies that take
/// milliseconds. The bound exists for the bookkeeping that hangs instead:
/// a wedged store must not hang a build that is already over.
pub const CONNECTION_DRAIN_BUDGET: Duration = Duration::from_secs(30);

/// The bookkeeping tasks a session's reports spawned.
///
/// A report's receipt goes out before its bookkeeping runs, so the
/// bookkeeping outlives the exchange that carried it and the session's end
/// is what waits for it (stow#618, stow#1431).
#[derive(Debug, Default, Clone)]
pub struct Reports {
    tasks: Arc<std::sync::Mutex<tokio::task::JoinSet<()>>>,
}

impl Reports {
    /// Run `work` as bookkeeping of the session, on the current runtime.
    pub fn spawn(&self, work: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().expect("reports mutex");
        // Reap the bookkeeping that already ended so the set holds only
        // what still runs.
        while tasks.try_join_next().is_some() {}
        tasks.spawn(work);
    }

    /// Wait for the bookkeeping still running, at most `budget`. Returns
    /// how many tasks were abandoned (and aborted) at the bound — `0` is a
    /// clean drain.
    pub async fn drain(&self, budget: Duration) -> usize {
        let mut tasks = std::mem::take(&mut *self.tasks.lock().expect("reports mutex"));
        let drained = tokio::time::timeout(budget, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "report bookkeeping task failed");
                }
            }
        })
        .await;
        if drained.is_err() {
            let abandoned = tasks.len();
            tracing::warn!(
                abandoned,
                "the session's end abandoned in-flight report bookkeeping"
            );
            return abandoned;
        }
        0
    }
}

/// The locally-compiled units of this build whose post-compile
/// bookkeeping has not finished, keyed by the output paths a dependent's
/// `--extern` arguments can name (stow#618).
///
/// A unit is in flight from the moment the session learns cargo is
/// compiling it — the `Compile` answer on the plan path — until its
/// bookkeeping ends one way or another: the report's store finished, the
/// report errored or skipped, or the wrapper's connection ended without a
/// report at all. A dependent's identity resolution reads the
/// `materialized_outputs` rows that bookkeeping writes, so its
/// post-compile waits on every in-flight unit its `--extern` set names
/// instead of racing the write.
///
/// The flight has two legs and the report frame's arrival is the boundary
/// between them. Until the frame arrives rustc is running; the wrapper
/// exits once the receipt for its report arrives — sent as soon as this
/// latch has fired, before the bookkeeping — so from the frame on only
/// the session's bookkeeping is left, and a dependent cargo starts
/// after the wrapper's exit always finds the latch fired (stow#1431). A
/// dependent's plan waits for a unit in its second leg — cargo starts a
/// dependent after a proc macro or a build script has fully finished, and
/// that dependent plans against the unit's rows — and never for one in
/// its first, which a pipelined dependent legitimately plans against
/// while it compiles.
///
/// `std::sync::Mutex` around a map rather than another actor: completing a
/// unit has to happen in `Drop` — an early return, an error and a dead
/// connection all end the flight the same way — and a drop cannot await a
/// channel send. Every critical section is a handful of map operations;
/// nothing awaits inside one.
#[derive(Debug, Default, Clone)]
pub struct InFlightUnits {
    units: Arc<std::sync::Mutex<HashMap<String, Arc<InFlightUnit>>>>,
}

impl InFlightUnits {
    /// Put the unit owning `paths` in flight; the returned guard is the
    /// flight's lifetime — dropping it completes the unit.
    fn register(&self, paths: Vec<String>) -> Completion {
        let unit = Arc::new(InFlightUnit {
            paths,
            exited: crate::Latch::pending(),
            done: crate::Latch::pending(),
        });
        {
            let mut units = self.units.lock().expect("in-flight units mutex");
            for path in &unit.paths {
                units.insert(path.clone(), Arc::clone(&unit));
            }
        }
        Completion {
            registry: self.clone(),
            unit,
        }
    }

    /// Resolve once `waits` dependents have parked on the in-flight unit
    /// registered under `path` — the test observation
    /// [`crate::Latch::parked`] carries, reached by an `--extern` path
    /// (stow#810).
    #[cfg(test)]
    pub(crate) async fn parked_on(&self, path: &str, waits: usize) {
        self.flight(path).done.parked(waits).await;
    }

    /// The unit in flight under `path`, for a test that observes its
    /// flight directly.
    #[cfg(test)]
    fn flight(&self, path: &str) -> Arc<InFlightUnit> {
        Arc::clone(
            self.units
                .lock()
                .expect("in-flight units mutex")
                .get(path)
                .unwrap_or_else(|| panic!("no unit in flight under {path}")),
        )
    }

    /// The in-flight units one of `parsed`'s `--extern` dependencies could
    /// be, deduplicated, that satisfy `keep`. The paths come from the same
    /// `extern_output_paths` derivation the identity resolution uses, so
    /// the set covers exactly the units whose `materialized_outputs` rows
    /// it reads (stow#618).
    fn externs_in_flight(
        &self,
        parsed: &ParsedRustcArgs,
        keep: impl Fn(&InFlightUnit) -> bool,
    ) -> Vec<Arc<InFlightUnit>> {
        let externs = crate::artifact_cache::extern_output_paths(parsed).unwrap_or_default();
        let units = self.units.lock().expect("in-flight units mutex");
        // One unit registers several paths and a dependent can name
        // more than one of them — dedupe on the unit itself.
        let mut seen = HashSet::new();
        externs
            .iter()
            .filter_map(|(_, path)| units.get(path))
            .filter(|unit| keep(unit))
            .filter(|unit| seen.insert(Arc::as_ptr(unit)))
            .cloned()
            .collect()
    }

    /// Wait for the bookkeeping of every in-flight unit one of `parsed`'s
    /// `--extern` dependencies could be, whichever leg it is in: the
    /// dependent's post-compile reads their rows once its own rustc has
    /// finished (stow#618).
    pub async fn wait_for_externs(&self, parsed: &ParsedRustcArgs) {
        for unit in self.externs_in_flight(parsed, |_| true) {
            unit.wait().await;
        }
    }

    /// Wait for the bookkeeping of every in-flight unit one of `parsed`'s
    /// `--extern` dependencies could be whose rustc has exited — the
    /// units whose rows are about to land. A dependency still compiling
    /// is not waited for: nothing recorded it yet and nothing will until
    /// it exits, so a pipelined dependent plans against it as it always
    /// did (stow#1431).
    pub async fn wait_for_exited_externs(&self, parsed: &ParsedRustcArgs) {
        for unit in self.externs_in_flight(parsed, |unit| unit.exited.has_completed()) {
            unit.wait().await;
        }
    }

    /// End a flight: lift the unit's registrations and release its
    /// waiters. A registration a different unit has since taken is left
    /// alone — the pointer check keeps one flight from completing
    /// another's.
    fn complete(&self, unit: &Arc<InFlightUnit>) {
        {
            let mut units = self.units.lock().expect("in-flight units mutex");
            for path in &unit.paths {
                if units
                    .get(path)
                    .is_some_and(|registered| Arc::ptr_eq(registered, unit))
                {
                    units.remove(path);
                }
            }
        }
        // A dependent waits on its dependencies one at a time, so this
        // flight can end before the dependent has subscribed to it: the
        // latch stores the end either way (stow#642). A flight that ends
        // without a report ends its first leg with it.
        unit.exited.complete();
        unit.done.complete();
    }
}

/// One in-flight unit: the paths it registered under and the signal its
/// bookkeeping's end sends.
#[derive(Debug)]
struct InFlightUnit {
    /// Every `--extern`-addressable output path this unit's bookkeeping
    /// records — normalized by the same `path_to_string` the
    /// `materialized_outputs` rows and the extern lookup use.
    paths: Vec<String>,
    /// Fired when the report frame arrives: rustc has exited and only the
    /// session's bookkeeping is left (stow#1431).
    exited: crate::Latch,
    /// Fired once the flight ends; a waiter that arrives late resolves
    /// at once.
    done: crate::Latch,
}

impl InFlightUnit {
    /// Resolve once this unit's bookkeeping has finished — immediately
    /// when it already has.
    async fn wait(&self) {
        self.done.wait().await;
    }
}

/// The guard a connection holds on one registered flight. Dropping it —
/// at the end of the report's bookkeeping, on an early return or an error
/// inside it, or with the connection's flight when the wrapper goes away
/// mid-flight — completes the unit (stow#618).
struct Completion {
    registry: InFlightUnits,
    unit: Arc<InFlightUnit>,
}

impl Completion {
    /// The report frame arrived: rustc has exited, the flight's second
    /// leg — the bookkeeping — begins (stow#1431).
    fn rustc_exited(&self) {
        self.unit.exited.complete();
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.registry.complete(&self.unit);
    }
}

/// The compile one connection was told to run and has not yet reported:
/// what the handler remembered for the report, and the guard that keeps
/// the unit in flight until the report's bookkeeping ends. A connection
/// that ends first drops it, completing the unit, so no dependent waits
/// on bookkeeping that will never run (stow#618).
pub struct Flight<P> {
    pending: P,
    /// `None` for a compile that records nothing — a refused request
    /// compiled uncached, or an invocation whose outputs cannot be named.
    completion: Option<Completion>,
}

/// The output paths a locally-compiled unit's bookkeeping records in
/// `materialized_outputs` — the paths a dependent's `--extern` names,
/// whose platform naming follows `host`. `None` only when the paths
/// themselves cannot be derived: nothing records them, so nothing waits
/// on them.
fn recordable_output_paths(parsed: &ParsedRustcArgs, host: &str) -> Option<Vec<String>> {
    let paths = crate::artifact_cache::materialized_output_paths(parsed, host).ok()?;
    paths
        .iter()
        .map(|path| crate::artifact_cache::path_to_string(path))
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

/// What a request earns: the answer the wrapper reads and the
/// bookkeeping the answer precedes.
pub struct Reply<P> {
    answer: Answer,
    /// The post-compile bookkeeping of a report, to run once the answer
    /// is out — the wrapper's wait ends at the receipt, never at this.
    work: Option<ReportWork<P>>,
}

impl<P> Reply<P> {
    const fn answer(answer: Answer) -> Self {
        Self { answer, work: None }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self::answer(Answer::Failed {
            message: message.into(),
        })
    }

    /// The answer to write and the bookkeeping to run after it, for a
    /// transport that schedules the two itself.
    pub fn split(self) -> (Answer, Option<ReportWork<P>>) {
        (self.answer, self.work)
    }
}

/// A report's post-compile bookkeeping, with the guard that ends the
/// unit's flight: dropping it — when the bookkeeping ends, or unrun —
/// completes the unit (stow#618).
pub struct ReportWork<P> {
    completion: Option<Completion>,
    kind: ReportKind<P>,
}

enum ReportKind<P> {
    /// A `Compiled` report with the pending its plan left.
    Compiled {
        pending: P,
        success: bool,
        compile_time: Duration,
    },
    /// The records a C compiler wrapper's answer precedes.
    Cc(crate::cc::CcRecord),
}

/// Run a report's bookkeeping; the flight ends when it does, succeeded
/// or not.
pub async fn finish_report<H: Handler>(handler: &Arc<H>, work: ReportWork<H::Pending>) {
    let ReportWork { completion, kind } = work;
    match kind {
        ReportKind::Compiled {
            pending,
            success,
            compile_time,
        } => handler.compiled(pending, success, compile_time).await,
        ReportKind::Cc(record) => {
            if let Some(config) = handler.cc_config() {
                crate::cc::write_record(config, record).await;
            }
        }
    }
    drop(completion);
}

/// Answer one request and hand its bookkeeping to `reports`. The answer is
/// returned as soon as the bookkeeping is spawned: the wrapper's wait ends
/// at the receipt, never at the bookkeeping (stow#1431).
pub async fn answer_and_book<H: Handler>(
    handler: &Arc<H>,
    in_flight: &InFlightUnits,
    reports: &Reports,
    flight: &mut Option<Flight<H::Pending>>,
    request: Request,
) -> Answer {
    let (answer, work) = answer_request(handler, in_flight, flight, request)
        .await
        .split();
    if let Some(work) = work {
        let handler = Arc::clone(handler);
        // The bookkeeping is the session's work like the request that
        // earned it: it keeps the span the request ran under.
        reports.spawn(
            async move { finish_report(&handler, work).await }.instrument(tracing::Span::current()),
        );
    }
    answer
}

/// Answer the request. A report is answered with a receipt as soon as the
/// unit's `exited` latch has fired — before any bookkeeping is awaited,
/// which the reply carries for the transport to run after the answer is
/// out (stow#1431). `flight` is the connection's own: a plan answered
/// with a compile fills it and the report empties it.
pub async fn answer_request<H: Handler>(
    handler: &Arc<H>,
    in_flight: &InFlightUnits,
    flight: &mut Option<Flight<H::Pending>>,
    request: Request,
) -> Reply<H::Pending> {
    match request {
        Request::Plan(plan) => Reply::answer(answer_plan(handler, in_flight, flight, plan).await),
        Request::Compiled(report) => accept_report(flight, &report),
        Request::CcPolicy => Reply::answer(Answer::CcPolicy {
            enabled: handler
                .cc_config()
                .is_some_and(|config| config.cache.uses_cc_cache()),
        }),
        Request::CcLookup(lookup) => answer_cc_lookup(handler, lookup).await,
        Request::CcCompiled(report) => answer_cc_compiled(handler, report).await,
    }
}

/// Look the object up in the build's C/C++ cache. A hit is answered at
/// once — the wrapper clones the object while the LRU stamp and the hit
/// statistic are written after the answer, like a rustc report's
/// bookkeeping (stow#1431).
async fn answer_cc_lookup<H: Handler>(handler: &Arc<H>, lookup: CcLookup) -> Reply<H::Pending> {
    let Some(config) = handler.cc_config() else {
        return Reply::failed("the build has no config for the C/C++ cache");
    };
    if !config.cache.uses_cc_cache() {
        return Reply::failed("the C/C++ cache layer is off for this build");
    }
    if !crate::cc::is_cache_key(&lookup.cache_key) {
        return Reply::failed("malformed C/C++ cache key");
    }
    match crate::cc::locate_cached_object(config, &lookup.cache_key).await {
        Ok(Some(object)) => Reply {
            answer: Answer::CcHit {
                object: super::os_bytes::encode(object.as_os_str()),
            },
            work: Some(ReportWork {
                completion: None,
                kind: ReportKind::Cc(crate::cc::CcRecord::Hit {
                    cache_key: lookup.cache_key,
                }),
            }),
        },
        Ok(None) => Reply::answer(Answer::CcMiss),
        Err(error) => Reply::failed(format!("C/C++ cache lookup failed: {error}")),
    }
}

/// Accept the report of a C compile a miss sent the wrapper to run. The
/// object is snapshotted into the cache directory before the receipt —
/// the wrapper's output file may be rewritten as soon as the compiler's
/// caller moves on — and the publish, the LRU row, the eviction pass and
/// the statistic follow it.
async fn answer_cc_compiled<H: Handler>(handler: &Arc<H>, report: CcCompiled) -> Reply<H::Pending> {
    let Some(config) = handler.cc_config() else {
        return Reply::failed("the build has no config for the C/C++ cache");
    };
    if !crate::cc::is_cache_key(&report.cache_key) {
        return Reply::failed("malformed C/C++ cache key");
    }
    let output_path = match report.output_path() {
        Ok(path) => path,
        Err(error) => return Reply::failed(error),
    };
    let record = if report.success {
        // The path is the wrapper's word and this process is not
        // sandboxed: the file is opened and checked as one descriptor,
        // and staged from it, so a refused path is never read.
        let Some(roots) = handler.output_roots().map(|roots| roots.dirs().to_vec()) else {
            return refuse_cc_output(&output_path, "the build's target directory is unknown");
        };
        let opened = {
            let output_path = output_path.clone();
            smol::unblock(move || crate::cc::open_reported_output(&output_path, &roots)).await
        };
        let source = match opened {
            Ok(source) => source,
            Err(message) => return refuse_cc_output(&output_path, &message),
        };
        let cache_path = crate::cc::cached_object_path(config, &report.cache_key);
        let staged = match crate::cc::stage_opened_object(&cache_path, source, &output_path).await {
            Ok(staged) => Some(staged),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    cache_key = %report.cache_key,
                    output_path = %output_path.display(),
                    "failed to stage C/C++ compilation for the local stow cache"
                );
                None
            }
        };
        crate::cc::CcRecord::Compiled {
            cache_key: report.cache_key,
            staged,
        }
    } else {
        crate::cc::CcRecord::Failed {
            cache_key: report.cache_key,
        }
    };
    Reply {
        answer: Answer::Received,
        work: Some(ReportWork {
            completion: None,
            kind: ReportKind::Cc(record),
        }),
    }
}

/// Refuse a reported C/C++ output: logged, answered `Failed`, nothing
/// staged. `message` already names the path unless the refusal is about
/// the build, so the path is named here too.
fn refuse_cc_output<P>(output_path: &std::path::Path, message: &str) -> Reply<P> {
    tracing::warn!(output_path = %output_path.display(), reason = %message, "refused a reported C/C++ output");
    Reply::failed(format!(
        "refused the C/C++ output {}: {message}",
        output_path.display()
    ))
}

async fn answer_plan<H: Handler>(
    handler: &Arc<H>,
    in_flight: &InFlightUnits,
    flight: &mut Option<Flight<H::Pending>>,
    plan: Plan,
) -> Answer {
    // A wrapper plans once and reports once per connection: a second plan
    // while the first compile is unreported is a wiring defect, refused
    // rather than left to overwrite the flight the report belongs to.
    if flight.is_some() {
        return Answer::Failed {
            message: "a plan arrived on a connection whose compile is unreported".to_owned(),
        };
    }
    let (executable, args) = match (plan.executable(), plan.args()) {
        (Ok(executable), Ok(args)) => (executable, args),
        (Err(error), _) | (_, Err(error)) => {
            return Answer::Failed { message: error };
        }
    };
    // A refused request compiles as cargo asked, with nothing the build
    // adds to the arguments.
    let as_requested = CompileCommand::new(&executable, &args);
    let args = match handler.plan_args(args, &plan.env) {
        Ok(args) => args,
        Err(message) => return Answer::Failed { message },
    };
    let command = CompileCommand::new(&executable, &args);
    let invocation = match VerifiedInvocation::verify(
        handler.toolchain(),
        handler.output_roots(),
        executable,
        args,
        &plan.env,
    )
    .await
    {
        Ok(invocation) => invocation,
        Err(refusal) => {
            return match settle_refusal(handler, refusal, "plan request") {
                Settled::Fail(message) => Answer::Failed { message },
                // The wrapper compiles and reports back: the report finds
                // a pending that does no bookkeeping, and no unit is
                // registered for a compile nothing recorded.
                Settled::CompileUncached => {
                    *flight = Some(Flight {
                        pending: H::Pending::default(),
                        completion: None,
                    });
                    Answer::Compile(as_requested)
                }
            };
        }
    };
    // The build's host names the unit's recordable outputs; an
    // invocation the parser cannot model records nothing (stow#618).
    let recordable_paths = ParsedRustcArgs::parse(invocation.args())
        .ok()
        .and_then(|parsed| recordable_output_paths(&parsed, handler.toolchain().host_target()));
    match handler.plan(invocation, plan.env).await {
        Decision::Served(notifications) => Answer::Served(notifications),
        Decision::Compile(pending) => {
            // The wrapper was told to compile: the unit is in flight
            // until the `Compiled` report's bookkeeping — or this
            // connection's end — completes it (stow#618).
            *flight = Some(Flight {
                pending,
                completion: recordable_paths.map(|paths| in_flight.register(paths)),
            });
            Answer::Compile(command)
        }
    }
}

/// What a refused request earns, decided in one place by the handler's
/// [`RefusalPolicy`].
enum Settled {
    /// Answer the request with this failure.
    Fail(String),
    /// Take no cache action: compile uncached, or drop a one-way frame.
    CompileUncached,
}

/// The one place a refusal is acted on: logged once at `warn` naming the
/// field and reason, then either recorded for the build to fail on or
/// left with no effect at all, per the handler's policy.
fn settle_refusal<H: Handler>(handler: &Arc<H>, refusal: Refusal, request: &str) -> Settled {
    let message = refusal.to_string();
    tracing::warn!(%message, "refused a {request}");
    match handler.refusal_policy() {
        RefusalPolicy::FailBuild => {
            handler.refused(refusal);
            Settled::Fail(message)
        }
        RefusalPolicy::CompileUncached => Settled::CompileUncached,
    }
}

/// Accept the report of the compile the connection was told to run: fire
/// the unit's `exited` latch and answer with a receipt, carrying the
/// bookkeeping for the transport to run after it (stow#1431). A report
/// the session cannot use is refused — the wrapper is listening for the
/// receipt.
fn accept_report<P>(flight: &mut Option<Flight<P>>, report: &Compiled) -> Reply<P> {
    let Some(Flight {
        pending,
        completion,
    }) = flight.take()
    else {
        return Reply::failed("the connection has no compile awaiting a report");
    };
    if let Some(completion) = &completion {
        completion.rustc_exited();
    }
    Reply {
        answer: Answer::Received,
        work: Some(ReportWork {
            completion,
            kind: ReportKind::Compiled {
                pending,
                success: report.success,
                compile_time: Duration::from_millis(report.compile_millis),
            },
        }),
    }
}
