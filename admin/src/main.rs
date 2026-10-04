//! `stow-admin`: the operations CLI for the stow edge — queue inspection
//! and mutation, coverage and artifact catalog reads, cache-warming
//! submissions, run failure triage, and GitHub Actions cache management.
//!
//! One binary, nouns then verbs. Every command answers `--json` with
//! machine-readable stdout and otherwise prints a human table; every
//! mutating command prints its plan and exits 0 without acting unless
//! `--yes` is given. Diagnostics go through `tracing` on stderr; the only
//! stdout writers are the final renderers in `render.rs`.

mod artifacts;
mod cache;
mod cloudflare;
mod coverage;
mod crates_io;
mod deploy;
mod github;
mod index_cmd;
mod launch_gate;
mod launch_load;
mod launch_model;
mod maintenance;
mod manual;
mod preheat;
mod projects;
mod queue;
mod render;
mod request;
mod resolve;
mod runs;
mod rust_channel;
mod scheduler;
#[cfg(test)]
mod test_server;
mod watchdog;

use std::fmt::Write as _;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use stow_types::api::{
    AdminStatus, ChannelOutcome, DispatchFreeze, DispatchFreezeTrigger, EnqueueRequest,
    FreezeTransitionEvent, SchedulerSubmitResponse,
};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;
use tracing_subscriber::EnvFilter;
use zenwave::{Client, ResponseExt};

use render::{Output, Table};

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
/// `aud` the Actions OIDC mint requests — must equal the edge's own
/// `STOW_OIDC_AUDIENCE` binding.
const STOW_OIDC_AUDIENCE_ENV: &str = "STOW_OIDC_AUDIENCE";
/// The OIDC endpoint and request credential the Actions runtime injects
/// per job when `id-token: write` is granted.
const ACTIONS_ID_TOKEN_REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
/// Pinned verbatim onto every edge call as the
/// `Cloudflare-Workers-Version-Overrides` header when set — the deploy
/// workflow uses it to aim `scheduler migrate` (and any other trusted
/// call) at the uploaded candidate version before traffic shifts.
const STOW_EDGE_VERSION_OVERRIDE_ENV: &str = "STOW_EDGE_VERSION_OVERRIDE";
/// The header `STOW_EDGE_VERSION_OVERRIDE` fills.
const VERSION_OVERRIDES_HEADER: &str = "Cloudflare-Workers-Version-Overrides";
/// Every edge call the admin client makes is bounded — an unanswered
/// request (a wedged dev-runtime stub, a vanished connection) must fail
/// the command, not hang it. Same 45 s the `cloudflare.rs` client uses.
/// The scheduler budget probe carries its own, larger bound.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Parser)]
#[command(name = "stow-admin", about = "Operations CLI for the stow build fleet")]
struct Cli {
    /// Machine-readable JSON on stdout instead of the human table.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scheduler overview: lane depths, oldest pending age, in-flight
    /// runs with their GitHub URLs, and per-target outcomes over the
    /// trailing 24 hours.
    Status,
    /// Inspect and mutate scheduler queue rows.
    Queue(queue::QueueArgs),
    /// Scheduler operations — the schema migration route and anything
    /// else that runs on operator cadence, not per request.
    Scheduler(scheduler::SchedulerArgs),
    /// Per-target servable identities for one crate.
    Coverage(coverage::CoverageArgs),
    /// Enqueue cache-warming task batches.
    Preheat(preheat::PreheatArgs),
    /// Inspect GitHub Actions build runs.
    Runs(runs::RunsArgs),
    /// Inspect and prune the artifact catalog.
    Artifacts(artifacts::ArtifactsArgs),
    /// GitHub Actions cache usage and eviction.
    Cache(cache::CacheArgs),
    /// Ensure or toggle the zone's WAF maintenance rules — the breaker
    /// that stops traffic before it reaches the Worker.
    Maintenance(maintenance::MaintenanceArgs),
    /// External watchdog: evaluate the incident signals, trip the
    /// breaker on a breach, keep the incident issue and the alert mail
    /// current. `watchdog clear` is the manual recovery.
    Watchdog(watchdog::WatchdogArgs),
    /// Read or clear the scheduler's dispatch freeze — the manual
    /// recovery path after a systematic-failure or cost trip.
    DispatchFreeze(DispatchFreezeArgs),
    /// Publish the signed artifact index.
    Index(index_cmd::IndexArgs),
    /// Regenerate the checked-in launch traffic model from production
    /// analytics (stow#452).
    LaunchModel(launch_model::LaunchModelArgs),
    /// The launch-cost gate: project the measured scheduler-budget
    /// report against the launch model and fail on an over-allowance
    /// dimension (stow#452).
    LaunchGate(launch_gate::LaunchGateArgs),
    /// The stow#452 mock-stack load test: drive a running edge at the
    /// launch model's peak rates and report per-lane p50/p99, error
    /// and overload signals.
    LaunchLoad(launch_load::LaunchLoadArgs),
    /// The human request lane's Actions leg: `request resolve` turns an
    /// admitted request's dispatch input into its outcome report.
    Request(request::RequestArgs),
    /// Submit one build task batch to the scheduler.
    Submit(SubmitArgs),
    /// Canary deployment verdicts for the edge Worker.
    Deploy(deploy::DeployArgs),
}

#[derive(Args)]
struct DispatchFreezeArgs {
    /// `status` reads the freeze; `clear` lifts it, resuming dispatch of
    /// everything that queued during it. Engagement is automatic — a
    /// systematic-failure or cost trip — or the dispatch-freeze POST.
    #[arg(value_enum)]
    action: DispatchFreezeAction,
    /// Apply the clear. `status` never mutates; `clear` without `--yes`
    /// prints the plan and exits 0.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DispatchFreezeAction {
    Status,
    Clear,
}

#[derive(Args)]
struct SubmitArgs {
    #[arg(long)]
    crate_name: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    features_json: String,
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long, default_value_t = 0)]
    downloads: u64,
    /// When true, the trusted CI runner keeps the bundled `Cargo.lock`
    /// from the crates.io tarball — an operator escape hatch on
    /// hand-submitted tasks; every resolver-emitted task carries false.
    #[arg(long, default_value_t = false)]
    preserve_lockfile: bool,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

fn main() -> stow_types::error::Result<()> {
    // Multi-call binary: a copy of this executable named
    // `rustc-shim-<host>` is cargo's `build.rustc-wrapper` for the
    // resolver's host probing — dispatch before clap sees its args.
    if std::env::args_os()
        .next()
        .and_then(|arg0| {
            std::path::Path::new(&arg0)
                .file_stem()
                .map(std::ffi::OsStr::to_os_string)
        })
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|stem| stem.starts_with(stow_resolver::shim::STEM_PREFIX))
    {
        stow_resolver::shim::run();
    }
    install_tracing();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| stow_error!("install ring CryptoProvider"))?;
    let cli = Cli::parse();
    let output = if cli.json {
        Output::Json
    } else {
        Output::Table
    };
    run(dispatch(cli.command, output))?
}

/// Drive `future` on the binary's single executor — one multi-thread
/// Tokio runtime every command dispatches onto. `stow-oci`'s reqwest
/// session, the sigstore trust root (`tough` reads through
/// `tokio::fs`), and every `tokio::{fs,process,time}` call need that
/// reactor; issue #530 was the watchdog panicking "there is no reactor
/// running" when dispatch ran under `smol::block_on`. Tests share this
/// entry so a mixed-executor regression fails `cargo test`, not
/// production.
fn run<F: std::future::Future>(future: F) -> stow_types::error::Result<F::Output> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| stow_error!("build tokio runtime: {error}"))?;
    Ok(runtime.block_on(future))
}

async fn dispatch(command: Command, output: Output) -> stow_types::error::Result<()> {
    match command {
        Command::Status => status(&Edge::connect().await?, output).await,
        Command::Queue(args) => queue::run(&Edge::connect().await?, args, output).await,
        Command::Scheduler(args) => scheduler::run(&Edge::connect().await?, args, output).await,
        Command::Coverage(args) => coverage::run(&Edge::connect().await?, args, output).await,
        Command::Preheat(args) => preheat::run(args, output).await,
        Command::Runs(args) => runs::run(&github_token().await?, args, output).await,
        Command::Artifacts(args) => artifacts::run(&Edge::connect().await?, args, output).await,
        Command::Cache(args) => cache::run(&github_token().await?, args, output).await,
        Command::Maintenance(args) => maintenance::run(args, output).await,
        Command::Watchdog(args) => watchdog::run(&Edge::connect().await?, args, output).await,
        Command::DispatchFreeze(args) => {
            dispatch_freeze_switch(&Edge::connect().await?, args, output).await
        }
        Command::Index(args) => index_cmd::run(args).await,
        Command::LaunchModel(args) => launch_model::run(args, output).await,
        Command::LaunchGate(args) => launch_gate::run(&args, output).await,
        Command::LaunchLoad(args) => launch_load::run(&Edge::connect().await?, &args, output).await,
        Command::Request(args) => request::run(args, output).await,
        Command::Submit(args) => submit_command(&Edge::connect().await?, args, output).await,
        Command::Deploy(args) => deploy::run(args, output).await,
    }
}

/// Authenticated access to the edge's `/api/v1/admin/*` and
/// `/api/v1/scheduler/*` endpoints — the base URL plus a bearer every
/// call mints or reuses.
pub(crate) struct Edge {
    base: String,
    /// Outside GitHub Actions: the operator credential captured once at
    /// connect. Inside Actions: `None` — every request mints a fresh
    /// OIDC JWT, because the Actions runtime expires a minted token
    /// (~10 min) well inside a lane that resolves a few hundred
    /// repositories; the JWT shape is how the edge tells the OIDC
    /// caller apart, so a per-request mint is also what keeps the run
    /// under its own identity rather than a staged `GH_TOKEN`.
    token: Option<String>,
    /// `STOW_EDGE_VERSION_OVERRIDE` verbatim — a Dictionary Structured
    /// Header entry such as `stow-edge="<version-id>"`, pinned onto every
    /// request so the call runs against that deployed version.
    version_override: Option<String>,
}

impl Edge {
    /// Resolve `STOW_EDGE_URL` and the credential source: Actions OIDC
    /// when the runtime advertises it, else the operator's GitHub token.
    pub(crate) async fn connect() -> stow_types::error::Result<Self> {
        let base = std::env::var(STOW_EDGE_URL_ENV)
            .map_err(|_| stow_error!("missing {STOW_EDGE_URL_ENV}"))?;
        let token = if actions_oidc_available() {
            None
        } else {
            Some(github_token().await?)
        };
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            token,
            version_override: std::env::var(STOW_EDGE_VERSION_OVERRIDE_ENV)
                .ok()
                .filter(|value| !value.is_empty()),
        })
    }

    /// The trimmed base URL — `index export` builds paged URLs off it.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// The bearer for the next request: the stored operator token, or a
    /// freshly minted Actions OIDC JWT. Callers that build their own
    /// requests (`index export`'s paged reads) await this per request,
    /// which is what keeps a long pagination inside the JWT's lifetime.
    pub(crate) async fn bearer(&self) -> stow_types::error::Result<String> {
        match &self.token {
            Some(token) => Ok(token.clone()),
            None => mint_actions_oidc().await,
        }
    }

    /// `GET` an edge path and decode its JSON body.
    pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> stow_types::error::Result<T> {
        let url = format!("{}{path}", self.base);
        let bearer = self.bearer().await?;
        let mut client = zenwave::client().timeout(REQUEST_TIMEOUT);
        let request = client
            .get(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {bearer}")))
            .and_then(|request| match &self.version_override {
                Some(value) => request.header(VERSION_OVERRIDES_HEADER, value.clone()),
                None => Ok(request),
            })
            .map_err(|error| stow_error!("GET {url}: {error}"))?;
        let response = request
            .await
            .map_err(|error| stow_error!("GET {url}: {error}"))?;
        response
            .error_for_status()
            .await
            .map_err(|error| stow_error!("GET {url}: {error}"))?
            .into_json()
            .await
            .map_err(|error| stow_error!("decode {url}: {error}"))
    }

    /// `POST` a JSON body to an edge path and decode its JSON answer.
    pub(crate) async fn post_json<B: serde::Serialize + Sync, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> stow_types::error::Result<T> {
        self.post_json_with_timeout(path, body, REQUEST_TIMEOUT)
            .await
    }

    /// `POST` a JSON body to an edge path — the one transport every
    /// JSON/unit/stream caller shares: bearer + version header +
    /// timeout + status guard. The caller owns the 2xx response's
    /// decode, drain, or unbuffered stream.
    async fn post_response<B: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> stow_types::error::Result<zenwave::Response> {
        let url = format!("{}{path}", self.base);
        let bearer = self.bearer().await?;
        let mut client = zenwave::client().timeout(timeout);
        let request = client
            .post(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {bearer}")))
            .and_then(|request| match &self.version_override {
                Some(value) => request.header(VERSION_OVERRIDES_HEADER, value.clone()),
                None => Ok(request),
            })
            .and_then(|request| request.json_body(body))
            .map_err(|error| stow_error!("POST {url}: {error}"))?;
        let response = request
            .await
            .map_err(|error| stow_error!("POST {url}: {error}"))?;
        response
            .error_for_status()
            .await
            .map_err(|error| stow_error!("POST {url}: {error}"))
    }

    /// [`post_json`](Self::post_json) at an explicit bound — for the
    /// routes that legitimately outlive the default, like the scheduler
    /// budget probe replaying every drive on a seeded fixture.
    pub(crate) async fn post_json_with_timeout<
        B: serde::Serialize + Sync,
        T: serde::de::DeserializeOwned,
    >(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> stow_types::error::Result<T> {
        let url = format!("{}{path}", self.base);
        self.post_response(path, body, timeout)
            .await?
            .into_json()
            .await
            .map_err(|error| stow_error!("decode {url}: {error}"))
    }

    /// `POST` a JSON body whose answer carries nothing the caller
    /// reads — the response body is still drained so the connection
    /// returns to the pool rather than stalling in it.
    pub(crate) async fn post_unit<B: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> stow_types::error::Result<()> {
        let url = format!("{}{path}", self.base);
        self.post_response(path, body, REQUEST_TIMEOUT)
            .await?
            .into_bytes()
            .await
            .map(|_| ())
            .map_err(|error| stow_error!("drain {url}: {error}"))
    }

    /// `POST` a JSON body and hand the 2xx response back with its body
    /// unbuffered — the demand feed's hour document is larger than
    /// anything this process should hold (stow#523), so the caller
    /// streams it to disk itself.
    pub(crate) async fn post_stream<B: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> stow_types::error::Result<zenwave::Response> {
        self.post_response(path, body, REQUEST_TIMEOUT).await
    }
}

/// Whether the Actions OIDC mint endpoint is advertised — both env vars
/// present means the job runs under `id-token: write`.
fn actions_oidc_available() -> bool {
    std::env::var_os(ACTIONS_ID_TOKEN_REQUEST_URL_ENV).is_some()
        && std::env::var_os(ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV).is_some()
}

#[derive(serde::Deserialize)]
struct OidcResponse {
    value: String,
}

/// Mint a fresh Actions OIDC JWT for the edge audience.
///
/// `GET {ACTIONS_ID_TOKEN_REQUEST_URL}&audience={STOW_OIDC_AUDIENCE}`
/// with the request token as bearer answers `{"value": "<jwt>"}` — the
/// same endpoint the workflow used to call once per run; calling it per
/// request is what the lane needs to outlive the ~10-minute JWT
/// lifetime.
async fn mint_actions_oidc() -> stow_types::error::Result<String> {
    let request_url = std::env::var(ACTIONS_ID_TOKEN_REQUEST_URL_ENV)
        .map_err(|_| stow_error!("missing {ACTIONS_ID_TOKEN_REQUEST_URL_ENV}"))?;
    let request_token = std::env::var(ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV}"))?;
    let audience = std::env::var(STOW_OIDC_AUDIENCE_ENV)
        .map_err(|_| stow_error!("missing {STOW_OIDC_AUDIENCE_ENV}"))?;
    let separator = if request_url.contains('?') { "&" } else { "?" };
    let url = format!(
        "{request_url}{separator}audience={}",
        encode_uri_component(&audience)
    );
    let mut client = zenwave::client();
    let response = client
        .get(&url)
        .and_then(|request| request.header("Authorization", format!("bearer {request_token}")))
        .and_then(|request| request.header("Accept", "application/json"))
        .map_err(|error| stow_error!("mint Actions OIDC token: {error}"))?
        .await
        .map_err(|error| stow_error!("mint Actions OIDC token: {error}"))?;
    let body: OidcResponse = response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("mint Actions OIDC token: {error}"))?
        .into_json()
        .await
        .map_err(|error| stow_error!("decode Actions OIDC response: {error}"))?;
    Ok(body.value)
}

/// The RFC 3986 unreserved set — what `jq -rn --arg a \"$A\" '$a|@uri'`
/// emits, which is the encoding the Actions OIDC endpoint's `audience`
/// parameter expects.
fn encode_uri_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `GET /api/v1/admin/status` rendered for the operator.
async fn status(edge: &Edge, output: Output) -> stow_types::error::Result<()> {
    let status: AdminStatus = edge.get_json("/api/v1/admin/status").await?;
    render::emit(output, &status, |status| {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "freeze       {}",
            if status.dispatch_frozen { "on" } else { "off" }
        );
        let _ = writeln!(
            out,
            "pending      {} miss, {} human",
            status.pending_miss, status.pending_human
        );
        let _ = writeln!(out, "blocked      {}", status.blocked);
        let _ = writeln!(
            out,
            "oldest       {}",
            status
                .oldest_pending_seconds
                .map_or_else(|| "—".to_owned(), render::age)
        );
        if status.in_flight.is_empty() {
            let _ = writeln!(out, "in flight    none");
        } else {
            let _ = writeln!(out, "in flight");
            let mut table = Table::new(&["task", "crate", "version", "target", "status", "run"]);
            for task in &status.in_flight {
                table.push([
                    task.task_id.chars().take(12).collect(),
                    task.crate_name.as_str().to_owned(),
                    task.version.to_string(),
                    task.target.as_str().to_owned(),
                    task.status.as_str().to_owned(),
                    task.github_run_id.as_ref().map_or_else(
                        || "—".to_owned(),
                        |run_id| {
                            format!("https://github.com/{}/actions/runs/{run_id}", github::REPO)
                        },
                    ),
                ]);
            }
            let _ = writeln!(out, "{}", table.render());
        }
        let _ = writeln!(out, "24h outcomes");
        if status.targets.is_empty() {
            let _ = write!(out, "  none");
        } else {
            let mut table = Table::new(&["target", "completed", "failed", "success"]);
            for target in &status.targets {
                let total = target.completed_24h + target.failed_24h;
                #[allow(clippy::cast_precision_loss)]
                let rate = if total == 0 {
                    "—".to_owned()
                } else {
                    format!(
                        "{:.0}%",
                        f64::from(target.completed_24h) / f64::from(total) * 100.0
                    )
                };
                table.push([
                    target.target.as_str().to_owned(),
                    target.completed_24h.to_string(),
                    target.failed_24h.to_string(),
                    rate,
                ]);
            }
            let _ = write!(out, "{}", table.render());
        }
        out.trim_end().to_owned()
    })
}

/// `stow-admin dispatch-freeze status|clear` — read the dispatch
/// freeze or drive the manual transition that is its only recovery
/// path. `status` shows the whole record — the trigger, and the alert
/// outcome so a freeze nobody was emailed about is visible. `clear` is
/// a mutation: it prints the plan and only applies under `--yes`.
async fn dispatch_freeze_switch(
    edge: &Edge,
    args: DispatchFreezeArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    if args.action == DispatchFreezeAction::Status {
        let switch: DispatchFreeze = edge.get_json("/api/v1/admin/dispatch-freeze").await?;
        return render::emit(output, &switch, render_freeze);
    }
    let plan = DispatchFreeze {
        enabled: false,
        record: None,
        transitions: Vec::new(),
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<DispatchFreeze, DispatchFreeze>| {
            let mut out = "clear dispatch freeze\n".to_owned();
            if let Some(result) = &envelope.result {
                let _ = writeln!(out, "{}", render_freeze(result));
            }
            let _ = write!(out, "{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |plan: &DispatchFreeze| {
            edge.post_json("/api/v1/admin/dispatch-freeze", plan).await
        },
    )
    .await
}

/// Human rendering of the freeze state — the flag line, the stored
/// record's trigger and alert outcome, and the transition log the
/// incident record is written from.
fn render_freeze(switch: &DispatchFreeze) -> String {
    let mut out = format!("freeze {}", if switch.enabled { "on" } else { "off" });
    if let Some(record) = &switch.record {
        let _ = write!(out, "\n  frozen at  {}", record.frozen_at);
        let _ = write!(out, "\n  trigger    {}", summarize_trigger(&record.trigger));
        let _ = write!(out, "\n  alert      {}", summarize_notify(&record.notify));
    }
    if !switch.transitions.is_empty() {
        out.push_str("\n  transitions (newest first):");
        for transition in &switch.transitions {
            let event = match transition.event {
                FreezeTransitionEvent::Engaged => "engaged",
                FreezeTransitionEvent::Cleared => "cleared",
            };
            let _ = write!(out, "\n    {} {}", transition.at, event);
            if let Some(trigger) = &transition.trigger {
                let _ = write!(out, " — {}", summarize_trigger(trigger));
            }
        }
    }
    out
}

/// One-line summary of a stored trigger — the same wording the
/// cleared-transition email carries.
fn summarize_trigger(trigger: &DispatchFreezeTrigger) -> String {
    match trigger {
        DispatchFreezeTrigger::Manual => "manual (dispatch-freeze POST)".to_owned(),
        DispatchFreezeTrigger::Tripped(trip) => {
            let tripped: Vec<&str> = trip
                .targets
                .iter()
                .filter(|target| target.tripped)
                .map(|target| target.target.as_str())
                .collect();
            let streams = if trip.fleet_tripped {
                if tripped.is_empty() {
                    "fleet".to_owned()
                } else {
                    format!("fleet + {}", tripped.join(", "))
                }
            } else {
                tripped.join(", ")
            };
            format!(
                "tripped: {}/{} outcomes failed ({}%) over {}m — {}",
                trip.failures, trip.outcomes, trip.failure_percent, trip.window_minutes, streams
            )
        }
        DispatchFreezeTrigger::Cost(cost) => {
            format!(
                "cost trip: {:?} used {:.0} of a {:.0} daily budget",
                cost.metric, cost.used, cost.budget
            )
        }
    }
}

/// One-line summary of the stored alert outcome — a failure is
/// shouted, not summarized away.
fn summarize_notify(notify: &ChannelOutcome) -> String {
    match notify {
        ChannelOutcome::Sent { message_id } => message_id
            .as_ref()
            .map_or_else(|| "sent".to_owned(), |id| format!("sent (messageId {id})")),
        ChannelOutcome::Opened { url } => format!("opened {url}"),
        ChannelOutcome::Commented { url } => format!("commented {url}"),
        ChannelOutcome::Resolved { url } => format!("resolved {url}"),
        ChannelOutcome::Failed { message, hint } => hint.as_ref().map_or_else(
            || format!("FAILED: {message}"),
            |hint| format!("FAILED: {message} — {hint}"),
        ),
        ChannelOutcome::Disabled { reason } => format!("disabled: {reason}"),
    }
}

/// `stow-admin submit` — one `EnqueueRequest` batch, one POST. The
/// endpoint takes the whole `Vec<EnqueueRequest>`; there is no
/// per-request loop and no local retry — the response reports what the
/// batch became.
async fn submit_command(
    edge: &Edge,
    args: SubmitArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let crate_name = CrateName::parse(args.crate_name)
        .map_err(|error| stow_error!("submit crate_name: {error}"))?;
    let version = TypedCrateVersion::new(semver::Version::parse(&args.version)?);
    let features: Vec<String> = serde_json::from_str(&args.features_json)
        .map_err(|error| stow_error!("submit features_json: {error}"))?;
    let features_json = FeaturesJson::canonicalize(features)
        .map_err(|error| stow_error!("submit features_json: {error}"))?;
    let target =
        TargetTriple::parse(args.target).map_err(|error| stow_error!("submit target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version)
        .map_err(|error| stow_error!("submit rustc_version: {error}"))?;
    // The submit lane posts exactly the identity the operator names — it
    // never inspects targets, so an operator can name a crate publishing
    // no library target and the request lands as a task the generated
    // wrapper package declares as a dependency. Cargo ignores a bin-only
    // dependency, so nothing compiles and the publish stage's closure
    // resolution fails the task — an operator's mistake, reported as one,
    // rather than designed around. The ranked and resolved lanes filter
    // bin-only crates; this one reports what it was told.
    let requests = vec![EnqueueRequest {
        crate_name,
        version,
        features_json,
        target,
        rustc_version,
        downloads: args.downloads,
        source: stow_types::api::EnqueueSource::CacheMiss,
        depends_on: Vec::new(),
        preserve_lockfile: args.preserve_lockfile,
        host_side: false,
    }];
    render::mutation(
        output,
        args.yes,
        requests,
        |envelope: &render::Planned<Vec<EnqueueRequest>, SchedulerSubmitResponse>| {
            let mut out = format!("{} task(s)\n", envelope.plan.len());
            for request in &envelope.plan {
                let _ = writeln!(
                    out,
                    "  {} {} {} {} rustc={}",
                    request.crate_name,
                    request.version,
                    request.target,
                    request.features_json.raw(),
                    request.rustc_version,
                );
            }
            if let Some(result) = &envelope.result {
                let _ = writeln!(
                    out,
                    "submitted {}, inserted {}, dropped {}",
                    result.submitted, result.inserted, result.dropped
                );
            }
            let _ = write!(out, "{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |requests: &Vec<EnqueueRequest>| submit(edge, requests).await,
    )
    .await
}

/// POST one `Vec<EnqueueRequest>` batch to the scheduler submit endpoint —
/// the single shared submit path every preheat lane and `submit` itself
/// uses.
pub(crate) async fn submit(
    edge: &Edge,
    requests: &[EnqueueRequest],
) -> stow_types::error::Result<SchedulerSubmitResponse> {
    let response: SchedulerSubmitResponse = edge
        .post_json("/api/v1/scheduler/tasks/submit", &requests)
        .await?;
    tracing::info!(
        submitted = response.submitted,
        inserted = response.inserted,
        dropped = response.dropped,
        "submitted scheduler task batch"
    );
    Ok(response)
}

/// The operator's GitHub credential for the edge's trusted endpoints and
/// the GitHub REST calls (`runs`, `cache`): `GH_TOKEN`/`GITHUB_TOKEN`
/// when set — the precedence `gh` itself follows — else `gh auth token`.
pub(crate) async fn github_token() -> stow_types::error::Result<String> {
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(token) = std::env::var(name)
            && !token.is_empty()
        {
            return Ok(token);
        }
    }
    let output = tokio::process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .await
        .map_err(|error| {
            stow_error!(
                "run `gh auth token` — install gh and `gh auth login`, or set GH_TOKEN: {error}"
            )
        })?;
    if !output.status.success() {
        return Err(stow_error!(
            "`gh auth token` failed ({}): {} — run `gh auth login` or set GH_TOKEN",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let token = String::from_utf8(output.stdout)
        .map_err(|error| stow_error!("`gh auth token` output is not UTF-8: {error}"))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(stow_error!(
            "`gh auth token` printed nothing — run `gh auth login` or set GH_TOKEN"
        ));
    }
    Ok(token.to_owned())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: keep diagnostics off the data stream.
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    /// #510 made `run` the one executor entry; #530 was the watchdog
    /// panicking "there is no reactor running" the moment a dispatched
    /// future touched Tokio machinery (`tokio::fs`, `tokio::spawn` —
    /// what reqwest and the sigstore trust root call). Drive the same
    /// entry the binary does so a non-Tokio executor fails here.
    #[test]
    fn run_provides_the_tokio_reactor() {
        let path = std::env::temp_dir().join(format!("stow-admin-run-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("write probe file");
        super::run(async {
            let bytes = tokio::fs::read(&path).await.expect("tokio::fs::read");
            assert_eq!(bytes, b"x");
            tokio::spawn(async {}).await.expect("tokio::spawn join");
        })
        .expect("run drives the future");
        std::fs::remove_file(&path).expect("remove probe file");
    }
}
