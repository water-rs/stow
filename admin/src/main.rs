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
mod coverage;
mod crates_io;
mod github;
mod index_cmd;
mod preheat;
mod projects;
mod queue;
mod render;
mod runs;

use std::fmt::Write as _;

use clap::{Args, Parser, Subcommand, ValueEnum};
use stow_types::api::{AdminStatus, EnqueueRequest, PanicSwitch, SchedulerSubmitResponse};
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
    /// Read or flip the edge's anonymous-traffic circuit breaker.
    Panic(PanicArgs),
    /// Publish the signed artifact index.
    Index(index_cmd::IndexArgs),
    /// Submit one build task batch to the scheduler.
    Submit(SubmitArgs),
}

#[derive(Args)]
struct PanicArgs {
    /// `on`/`off` write the flag; `status` reads it.
    #[arg(value_enum)]
    action: PanicAction,
    /// Apply the flip. `status` never mutates; `on`/`off` without `--yes`
    /// print the plan and exit 0.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PanicAction {
    On,
    Off,
    Status,
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
    /// from the crates.io tarball. Required for the top-binaries
    /// resolver path: a binary's preheat closure must resolve transitive
    /// deps the same way `cargo install --locked <bin>` would.
    #[arg(long, default_value_t = false)]
    preserve_lockfile: bool,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

fn main() -> stow_types::error::Result<()> {
    install_tracing();
    let cli = Cli::parse();
    let output = if cli.json {
        Output::Json
    } else {
        Output::Table
    };
    match cli.command {
        Command::Status => with_edge(|edge| async move { status(&edge, output).await }),
        Command::Queue(args) => {
            with_edge(|edge| async move { queue::run(&edge, args, output).await })
        }
        Command::Coverage(args) => {
            with_edge(|edge| async move { coverage::run(&edge, args, output).await })
        }
        // `preheat` picks its own executor like `index` does: the
        // projects lane needs GitHub for `generate` and the edge for
        // `submit`; the other lanes run against the edge.
        Command::Preheat(args) => preheat::run(args, output),
        Command::Runs(args) => {
            with_github(|token| async move { runs::run(&token, args, output).await })
        }
        Command::Artifacts(args) => {
            with_edge(|edge| async move { artifacts::run(&edge, args, output).await })
        }
        Command::Cache(args) => {
            with_github(|token| async move { cache::run(&token, args, output).await })
        }
        Command::Panic(args) => {
            with_edge(|edge| async move { panic_switch(&edge, args, output).await })
        }
        // The index commands pick their own executor: `publish` drives
        // `oci-client` (hyper, so a Tokio reactor), the rest run on smol
        // like every other command.
        Command::Index(args) => index_cmd::run(args),
        Command::Submit(args) => {
            with_edge(|edge| async move { submit_command(&edge, args, output).await })
        }
    }
}

/// Run one edge-backed command on the smol executor: connect, then hand
/// the connection to the command.
fn with_edge<F, Fut>(command: F) -> stow_types::error::Result<()>
where
    F: FnOnce(Edge) -> Fut,
    Fut: std::future::Future<Output = stow_types::error::Result<()>>,
{
    smol::block_on(async move { command(Edge::connect().await?).await })
}

/// Run one GitHub-backed command on the smol executor with the operator
/// token.
fn with_github<F, Fut>(command: F) -> stow_types::error::Result<()>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = stow_types::error::Result<()>>,
{
    smol::block_on(async move { command(github_token().await?).await })
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
        let mut client = zenwave::client();
        let response = client
            .get(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {bearer}")))
            .map_err(|error| stow_error!("GET {url}: {error}"))?
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
        let url = format!("{}{path}", self.base);
        let bearer = self.bearer().await?;
        let mut client = zenwave::client();
        let response = client
            .post(&url)
            .and_then(|request| request.header("Authorization", format!("Bearer {bearer}")))
            .and_then(|request| request.json_body(body))
            .map_err(|error| stow_error!("POST {url}: {error}"))?
            .await
            .map_err(|error| stow_error!("POST {url}: {error}"))?;
        response
            .error_for_status()
            .await
            .map_err(|error| stow_error!("POST {url}: {error}"))?
            .into_json()
            .await
            .map_err(|error| stow_error!("decode {url}: {error}"))
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
            "panic        {}",
            if status.panic_enabled { "on" } else { "off" }
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
            let mut table = Table::new(&["target", "completed", "failed", "partial", "success"]);
            for target in &status.targets {
                let total = target.completed_24h + target.failed_24h + target.partial_24h;
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
                    target.partial_24h.to_string(),
                    rate,
                ]);
            }
            let _ = write!(out, "{}", table.render());
        }
        out.trim_end().to_owned()
    })
}

/// `stow-admin panic on|off|status` — read or flip the circuit breaker.
/// `on`/`off` are mutations: they print the target state and only apply
/// under `--yes`.
async fn panic_switch(
    edge: &Edge,
    args: PanicArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    if args.action == PanicAction::Status {
        let switch: PanicSwitch = edge.get_json("/api/v1/admin/panic").await?;
        return render::emit(output, &switch, |switch| {
            format!("panic {}", if switch.enabled { "on" } else { "off" })
        });
    }
    let target_enabled = matches!(args.action, PanicAction::On);
    let plan = PanicSwitch {
        enabled: target_enabled,
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<PanicSwitch, PanicSwitch>| {
            let mut out = format!(
                "set panic {}\n",
                if envelope.plan.enabled { "on" } else { "off" }
            );
            if let Some(result) = &envelope.result {
                let _ = writeln!(
                    out,
                    "panic is now {}",
                    if result.enabled { "on" } else { "off" }
                );
            }
            let _ = write!(out, "{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |plan: &PanicSwitch| edge.post_json("/api/v1/admin/panic", plan).await,
    )
    .await
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
async fn github_token() -> stow_types::error::Result<String> {
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(token) = std::env::var(name)
            && !token.is_empty()
        {
            return Ok(token);
        }
    }
    let output = smol::process::Command::new("gh")
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
