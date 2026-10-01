//! `stow-admin launch-load` — the stow#452 mock-stack load test driver.
//!
//! The driver reads `launch-model.toml` and fires each lane at its
//! peak-hour rate for `--duration-secs` (the issue's thirty minutes by
//! default). The public lanes need no credential; `--scheduler` adds
//! the trusted lanes on the operator bearer, `--webhook-secret` adds
//! the `workflow_run` callback lane signed under the mock's
//! `STOW_GITHUB_WEBHOOK_SECRET`, and `--pow-secret` adds the untrusted
//! miss lanes — real `POST /api/v1/admissions` calls, and `POST
//! /api/v1/enqueue` redemptions on tickets the driver mints itself
//! under the mock's `STOW_POW_CHALLENGE_SECRET`. Alarm passes are
//! never fired directly — the submits, mutations and completions the
//! lanes drive arm the dispatch alarm, which is exactly how production
//! earns them.
//!
//! Per lane it reports request count, the effective rate, p50/p99
//! latency and the status mix, and the run exits nonzero on a breach:
//! any `overload` signal (a 429/503 or an `overload` marker in the
//! body), a lane's error share over 1%, or a lane p99 over its bound.
//! The per-route row counts under load come from the
//! `scheduler-budget` probe — `scripts/launch-load.sh` runs it before
//! and after the driver and gates on both reports.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Args;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stow_types::admission::{DEFAULT_POW_MIN_BITS, difficulty, issue_challenge};
use stow_types::api::{
    AdmissionRequest, DependencyGraphEntry, EnqueueRequest, EnqueueSource, EnqueueTicket,
    QueueSelector, ResolvedDependencyGraphEntry,
};
use stow_types::fixture::{FixtureShape, task_hex_id};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::pow::enqueue_pow_zero_bits;
use stow_types::stow_error;

use zenwave::Client;

use crate::Edge;
use crate::render::{Output, Table, emit};

/// The load driver — `stow-admin launch-load`.
#[derive(Debug, Args)]
pub struct LaunchLoadArgs {
    /// The checked-in launch model.
    #[arg(long, default_value = "launch-model.toml")]
    pub model: PathBuf,
    /// Seconds the run lasts — stow#452's thirty minutes by default.
    #[arg(long, default_value_t = 1800)]
    pub duration_secs: u64,
    /// Multiplier over the model's peak-hour rate — `--rate-scale 0.1`
    /// for a smoke run, `1.0` for the launch rate.
    #[arg(long, default_value_t = 1.0)]
    pub rate_scale: f64,
    /// Also drive the trusted scheduler lanes (`/api/v1/admin/*`,
    /// `/api/v1/scheduler/tasks/submit`) on the operator bearer —
    /// requires the push-capable credential CI carries.
    #[arg(long)]
    pub scheduler: bool,
    /// Sign `workflow_run` callback deliveries under this secret — the
    /// mock manifest's `STOW_GITHUB_WEBHOOK_SECRET`
    /// (`mock-github-webhook-secret`).
    #[arg(long)]
    pub webhook_secret: Option<String>,
    /// Queue rows the seeded fixture holds — picks the task ids the
    /// mutation and callback lanes name. The harness seeds 100k.
    #[arg(long, default_value_t = 100_000)]
    pub queue_rows: u64,
    /// The rustc the seeded rows and synthetic tasks name.
    #[arg(long, default_value = "1.85.0")]
    pub rustc: String,
    /// Per-lane p99 bound in milliseconds — the serialization sanity
    /// check, not a latency SLO.
    #[arg(long, default_value_t = 10_000.0)]
    pub p99_bound_ms: f64,
    /// Comma-separated lane names to run instead of the full set — a
    /// debugging aid; the harness runs them all.
    #[arg(long, value_delimiter = ',')]
    pub lanes: Vec<String>,
    /// Mint the redemption lane's tickets under this challenge secret —
    /// the mock manifest's `STOW_POW_CHALLENGE_SECRET`
    /// (`mock-pow-challenge-secret`). With it the driver fires the
    /// untrusted `admissions` and `enqueue` lanes; without it they stay
    /// off.
    #[arg(long)]
    pub pow_secret: Option<String>,
    /// Leading-zero bits the redemption lane's tickets solve to — the
    /// mock manifest's `STOW_POW_MIN_BITS` (default 12).
    #[arg(long, default_value_t = DEFAULT_POW_MIN_BITS)]
    pub pow_min_bits: u32,
}

/// Lane error share the run tolerates before it fails — one percent.
const ERROR_RATE_BOUND: f64 = 0.01;

/// A response that takes this long under the mock stack is a stall,
/// not slowness: an unanswered request would otherwise freeze its lane
/// forever — `run_lane` only checks the deadline between fires — and
/// `join_all` would sit until the CI job's timeout kills the whole
/// load run. The lane scores a stall as a transport error, the same
/// signal any other failed request leaves.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// What one lane event is.
#[derive(Debug)]
enum Fire {
    /// Round-robin `GET`s over public paths.
    PublicGet(Vec<String>),
    /// `GET /api/v1/index/{target}/{rustc}` then the digest-addressed
    /// slice when a pointer answers — the pull's two requests.
    IndexPull { target: String, rustc: String },
    /// `GET /api/v1/bundles/sha256:{counter}` — rotating synthetic
    /// digests; the 404 is the miss the launch fleet sees on an
    /// uncovered unit, and it still costs the full route.
    BundleFetch,
    /// `GET /api/v1/requests/{task_id}` over seeded pending ids —
    /// reaches the DO status batch on a real row.
    StatusRead { queue_rows: u64 },
    /// Bearer `GET` on a trusted path.
    TrustedGet(String),
    /// `POST /api/v1/admin/queue/{verb}` over seeded failed ids.
    QueueMutate { verb: &'static str, queue_rows: u64 },
    /// `POST /api/v1/scheduler/tasks/submit` — one synthetic task over
    /// a rotating pool of real crates.
    TrustedSubmit { rustc: String },
    /// HMAC-signed `POST /api/v1/github/workflow_run` completing a
    /// seeded dispatched row.
    WorkflowRun {
        secret: String,
        rustc: String,
        queue_rows: u64,
    },
    /// `POST /api/v1/admissions` — one miss entry whose resolved graph
    /// rides in the body, so the lane pays the real mint path without
    /// a crates.io hop.
    Admission { target: String, rustc: String },
    /// `POST /api/v1/enqueue` — a ticket the driver mints itself under
    /// the mock's challenge secret, nonce solved to `min_bits`.
    EnqueueRedeem {
        secret: String,
        min_bits: u32,
        rustc: String,
    },
}

/// One lane: what to fire, at what peak rate, and which statuses are
/// the route working as designed (a bundle 404 is the miss path).
struct Lane {
    /// Report label.
    name: &'static str,
    /// Events per second at the peak rate the run drives.
    eps: f64,
    /// What one event does.
    fire: Fire,
    /// Statuses the lane accepts as designed work.
    expected: fn(u16) -> bool,
}

/// Per-lane measurements over the run.
#[derive(Debug, Default, serde::Serialize)]
struct LaneStats {
    /// Requests the lane fired.
    requests: u64,
    /// The rate it actually drove.
    effective_eps: f64,
    /// Median latency in milliseconds.
    p50_ms: f64,
    /// 99th-percentile latency.
    p99_ms: f64,
    /// Transport failures (connect, timeout, stream).
    transport_errors: u64,
    /// 5xx responses.
    server_errors: u64,
    /// Responses outside the lane's expected status set.
    unexpected_statuses: u64,
    /// `overload` signals — a 429/503 or the marker string in a body.
    overloaded: u64,
    /// Status histogram.
    statuses: BTreeMap<u16, u64>,
    /// Raw per-request latencies — the percentiles summarize it; kept
    /// out of the emitted JSON.
    #[serde(skip)]
    latencies_ms: Vec<f64>,
}

/// One fired request's outcome.
enum Outcome {
    /// A response arrived: its status and whether the body or the
    /// status itself signalled overload.
    Response { status: u16, overloaded: bool },
    /// The request never completed — connect, timeout, stream error.
    Transport(String),
}

/// The driver's report — one entry per lane plus the verdict.
#[derive(Debug, serde::Serialize)]
struct LoadReport {
    /// Seconds the run lasted.
    duration_secs: u64,
    /// `rate_scale` the lanes ran at.
    rate_scale: f64,
    /// Per-lane stats keyed by lane name.
    lanes: BTreeMap<&'static str, LaneStats>,
    /// Every breach the verdict names; empty on a pass.
    breaches: Vec<String>,
}

/// The queue-order shape the seeded ids come from —
/// `stow_types::fixture` owns the math so the lanes and the seeders
/// cannot drift (stow#452 F11).
fn shape(queue_rows: u64) -> FixtureShape {
    FixtureShape {
        queue_rows: u32::try_from(queue_rows).unwrap_or(u32::MAX),
    }
}

/// The k-th dispatched row's task id — the fixture's in-flight range,
/// even `n` only.
fn dispatched_task_id(k: u64, queue_rows: u64) -> String {
    let shape = shape(queue_rows);
    let index = u32::try_from(k % u64::from(FixtureShape::IN_FLIGHT_ROWS / 2)).unwrap_or_default();
    task_hex_id(u64::from(shape.dispatched_row(index)))
}

/// The k-th failed row's task id — `completed_end < n <= failed_end`.
fn failed_task_id(k: u64, queue_rows: u64) -> String {
    let shape = shape(queue_rows);
    let span = shape
        .failed_end()
        .saturating_sub(shape.completed_end())
        .max(1);
    let index = u32::try_from(k % u64::from(span)).unwrap_or_default();
    task_hex_id(u64::from(shape.failed_row(index)))
}

/// The k-th pending row — `1..=pending_end`.
fn pending_task_id(k: u64, queue_rows: u64) -> String {
    let pending_end = u64::from(shape(queue_rows).pending_end()).max(1);
    task_hex_id(1 + (k % pending_end))
}

/// Real crates the submit lane rotates through — each resolves for
/// real through the canonicalize step so the enqueue is the genuine
/// trusted path. The pool is fixed, so every submission dedupes onto
/// the same eight task ids — the lane exercises the resubmit path;
/// the fresh-row inserts come from the miss lanes' per-counter
/// features.
const SUBMIT_POOL: &[(&str, &str)] = &[
    ("cfg-if", "1.0.0"),
    ("scopeguard", "1.2.0"),
    ("unicode-xid", "0.2.4"),
    ("stable_deref_trait", "1.2.0"),
    ("memchr", "2.7.1"),
    ("either", "1.9.0"),
    ("bitflags", "2.4.1"),
    ("log", "0.4.21"),
];

/// `POST /api/v1/github/workflow_run`'s `sha256=<hex>` HMAC-SHA256 over
/// the raw body.
fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// The signed `workflow_run` delivery for one seeded dispatched task —
/// the pinned fields `authorized_run` checks: the trusted repo, the
/// build workflow's path, `main`, `workflow_dispatch`, and a
/// `<rustc>-<task_id>` title.
fn workflow_run_body(task_id: &str, rustc: &str, run_id: u64) -> String {
    serde_json::json!({
        "action": "completed",
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "display_title": format!("{rustc}-{task_id}"),
            "event": "workflow_dispatch",
            "head_branch": stow_types::trusted_builder::BRANCH,
            "path": format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::WORKFLOW_FILE
            ),
            "conclusion": "success",
            "id": run_id,
            "html_url": null,
            "head_repository": {
                "full_name": stow_types::trusted_builder::REPOSITORY
            },
        },
    })
    .to_string()
}

/// A lane event resolved into an HTTP request — `fire_once` turns the
/// plan into a zenwave call.
enum Plan {
    /// `GET url`, optionally on the operator bearer.
    Get { url: String, bearer: Option<String> },
    /// `POST url` with a JSON body, optionally on the bearer.
    PostJson {
        url: String,
        bearer: Option<String>,
        body: serde_json::Value,
    },
    /// `POST url` with raw bytes and fixed headers — the webhook lane.
    PostBytes {
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// The event resolved to an outcome already — the index pull's
    /// pointer hop answers the pull when no slice is published.
    Done(Outcome),
}

/// A pull is the pointer GET plus the slice GET when one is published —
/// the second hop reads the pointer's digest. A miss answers 404 and is
/// the pull's outcome.
async fn plan_index_pull(
    base: &str,
    target: &str,
    rustc: &str,
    client: &mut zenwave::DefaultClient,
) -> Result<Plan, String> {
    let pointer = client
        .get(format!("{base}/api/v1/index/{target}/{rustc}"))
        .map_err(|error| error.to_string())?
        .await;
    let pointer = match pointer {
        Ok(pointer) => pointer,
        Err(zenwave::Error::Http { status, .. }) => {
            return Ok(Plan::Done(Outcome::Response {
                status: status.as_u16(),
                overloaded: matches!(status.as_u16(), 429 | 503),
            }));
        }
        Err(error) => return Ok(Plan::Done(Outcome::Transport(error.to_string()))),
    };
    let pointer_status = pointer.status().as_u16();
    let digest = if (200..300).contains(&pointer_status) {
        let body = pointer
            .into_body()
            .into_string()
            .await
            .map_err(|error| error.to_string())?;
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("digest").and_then(|d| d.as_str()).map(str::to_owned))
    } else {
        None
    };
    let Some(digest) = digest else {
        return Ok(Plan::Done(Outcome::Response {
            status: pointer_status,
            overloaded: false,
        }));
    };
    Ok(Plan::Get {
        url: format!("{base}/api/v1/index/{target}/{rustc}/{digest}"),
        bearer: None,
    })
}

/// The crate task a submit lane posts — a real crates.io crate at the
/// run's rustc, round-robined over the pool.
fn submit_task(rustc: &str, counter: u64) -> Result<EnqueueRequest, String> {
    let index = usize::try_from(counter).unwrap_or_default() % SUBMIT_POOL.len();
    let (crate_name, version) = SUBMIT_POOL[index];
    Ok(EnqueueRequest {
        crate_name: crate_name
            .parse::<CrateName>()
            .map_err(|error| format!("crate name: {error}"))?,
        version: version
            .parse::<CrateVersion>()
            .map_err(|error| format!("version: {error}"))?,
        features_json: FeaturesJson::default(),
        target: "x86_64-unknown-linux-gnu"
            .parse::<TargetTriple>()
            .map_err(|error| format!("target: {error}"))?,
        rustc_version: rustc
            .parse::<WireRustcVersion>()
            .map_err(|error| format!("rustc: {error}"))?,
        downloads: 0,
        source: EnqueueSource::CrateUpdate,
        depends_on: Vec::new(),
        host_side: false,
        preserve_lockfile: false,
    })
}

/// The miss-lane task — same pool crates but a per-counter feature, so
/// every admission mint and every redemption inserts a task the queue
/// has not seen instead of measuring the dedup path (stow#452 F7/F9).
fn miss_task(rustc: &str, counter: u64) -> Result<EnqueueRequest, String> {
    let mut task = submit_task(rustc, counter)?;
    task.source = EnqueueSource::CacheMiss;
    task.features_json = FeaturesJson::canonicalize(vec![format!("stow-load-{counter}")])
        .map_err(|error| format!("features: {error}"))?;
    Ok(task)
}

/// The admission's request body: one miss entry whose resolved graph
/// rides in `expanded_entries` — the edge's expansion consumes the
/// supplied graph and never calls crates.io.
fn admission_body(target: &str, rustc: &str, counter: u64) -> Result<serde_json::Value, String> {
    let task = miss_task(rustc, counter)?;
    let crate_name = task.crate_name.clone();
    let version = semver::Version::parse(&task.version.to_string())
        .map_err(|error| format!("version: {error}"))?;
    let features = vec![format!("stow-load-{counter}")];
    serde_json::to_value(AdmissionRequest {
        target: target
            .parse::<TargetTriple>()
            .map_err(|error| format!("target: {error}"))?,
        rustc_version: task.rustc_version,
        entries: vec![DependencyGraphEntry {
            crate_name: crate_name.clone(),
            version: version.clone(),
            features: features.clone(),
        }],
        expanded_entries: vec![ResolvedDependencyGraphEntry {
            crate_name,
            version,
            features,
            host_side: false,
            dependencies: Vec::new(),
        }],
    })
    .map_err(|error| error.to_string())
}

/// Wall-clock minute the admission protocol stamps challenges with —
/// the host twin of the edge handler's `now_minute()`.
fn now_minute() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60
}

/// Mint a redeemable ticket for `request` under `secret` — the same
/// `issue_challenge` the edge runs, then a nonce scanned to the
/// configured difficulty. A ticket exactly like what `POST
/// /api/v1/admissions` would have returned, minus the round trip.
fn mint_ticket(
    secret: &str,
    min_bits: u32,
    request: &EnqueueRequest,
) -> Result<EnqueueTicket, String> {
    let task_id = stow_types::api::task_id(
        request.crate_name.as_str(),
        &request.version.to_string(),
        request.features_json.raw().as_str(),
        request.target.as_str(),
        request.rustc_version.as_str(),
        request.host_side,
    );
    let request_json = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let challenge = issue_challenge(secret, &task_id, &request_json, now_minute());
    let required = difficulty(min_bits);
    // The scan bound is 2^(bits+14) — at the default 12 that is ~16M
    // hashes against an expected 4k, so `None` means the configured
    // difficulty, not the search.
    let bound = 1u64
        .checked_shl(required.saturating_add(14).min(63))
        .unwrap_or(u64::MAX);
    let nonce = (0u64..bound)
        .find(|nonce| enqueue_pow_zero_bits(&task_id, &challenge, *nonce) >= required)
        .ok_or_else(|| format!("no PoW nonce below {bound} for {required} bits"))?;
    Ok(EnqueueTicket {
        task_id,
        challenge,
        nonce,
        request: request.clone(),
    })
}

/// Resolve one lane event into its request — the index pull's pointer
/// hop and the bearer fetches happen here.
async fn plan(
    fire: &Fire,
    edge: &Edge,
    client: &mut zenwave::DefaultClient,
    counter: u64,
) -> Result<Plan, String> {
    let base = edge.base();
    let bearer = || async { edge.bearer().await.map_err(|error| error.to_string()) };
    match fire {
        Fire::PublicGet(paths) => {
            let index = usize::try_from(counter).unwrap_or_default() % paths.len();
            Ok(Plan::Get {
                url: format!("{base}{}", paths[index]),
                bearer: None,
            })
        }
        Fire::IndexPull { target, rustc } => plan_index_pull(base, target, rustc, client).await,
        Fire::BundleFetch => {
            let digest = format!("{:064x}", counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            Ok(Plan::Get {
                url: format!("{base}/api/v1/bundles/sha256:{digest}"),
                bearer: None,
            })
        }
        Fire::StatusRead { queue_rows } => {
            // Alternate the per-task read with the fleet-wide status —
            // both are DO reads the model's status rate pays for.
            let path = if counter.is_multiple_of(2) {
                "/api/v1/scheduler/status".to_owned()
            } else {
                let id = pending_task_id(counter / 2, *queue_rows);
                format!("/api/v1/requests/{id}")
            };
            Ok(Plan::Get {
                url: format!("{base}{path}"),
                bearer: None,
            })
        }
        Fire::TrustedGet(path) => Ok(Plan::Get {
            url: format!("{base}{path}"),
            bearer: Some(bearer().await?),
        }),
        Fire::QueueMutate { verb, queue_rows } => Ok(Plan::PostJson {
            url: format!("{base}/api/v1/admin/queue/{verb}"),
            bearer: Some(bearer().await?),
            body: serde_json::to_value(QueueSelector {
                task_ids: vec![failed_task_id(counter, *queue_rows)],
                ..QueueSelector::default()
            })
            .map_err(|error| error.to_string())?,
        }),
        Fire::TrustedSubmit { rustc } => Ok(Plan::PostJson {
            url: format!("{base}/api/v1/scheduler/tasks/submit"),
            bearer: Some(bearer().await?),
            body: serde_json::to_value(vec![submit_task(rustc, counter)?])
                .map_err(|error| error.to_string())?,
        }),
        Fire::WorkflowRun {
            secret,
            rustc,
            queue_rows,
        } => {
            let body = workflow_run_body(&dispatched_task_id(counter, *queue_rows), rustc, counter);
            let signature = sign_body(secret, body.as_bytes());
            Ok(Plan::PostBytes {
                url: format!("{base}/api/v1/github/workflow-run"),
                headers: vec![
                    ("X-GitHub-Event".to_owned(), "workflow_run".to_owned()),
                    ("X-Hub-Signature-256".to_owned(), signature),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                ],
                body: body.into_bytes(),
            })
        }
        Fire::Admission { target, rustc } => Ok(Plan::PostJson {
            url: format!("{base}/api/v1/admissions"),
            bearer: None,
            body: admission_body(target, rustc, counter)?,
        }),
        Fire::EnqueueRedeem {
            secret,
            min_bits,
            rustc,
        } => {
            let request = miss_task(rustc, counter)?;
            let ticket = mint_ticket(secret, *min_bits, &request)?;
            Ok(Plan::PostJson {
                url: format!("{base}/api/v1/enqueue"),
                bearer: None,
                body: serde_json::to_value(&ticket).map_err(|error| error.to_string())?,
            })
        }
    }
}

/// Fire one lane event; returns the response outcome.
async fn fire_once(
    fire: &Fire,
    edge: &Edge,
    client: &mut zenwave::DefaultClient,
    counter: u64,
) -> Result<Outcome, String> {
    let request = match plan(fire, edge, client, counter).await? {
        Plan::Done(outcome) => return Ok(outcome),
        Plan::Get { url, bearer } => {
            let request = client.get(url).map_err(|error| error.to_string())?;
            match bearer {
                Some(token) => request
                    .header("Authorization", format!("Bearer {token}"))
                    .map_err(|error| error.to_string())?,
                None => request,
            }
        }
        Plan::PostJson { url, bearer, body } => {
            let request = client.post(url).map_err(|error| error.to_string())?;
            let request = match bearer {
                Some(token) => request
                    .header("Authorization", format!("Bearer {token}"))
                    .map_err(|error| error.to_string())?,
                None => request,
            };
            request
                .json_body(&body)
                .map_err(|error| error.to_string())?
        }
        Plan::PostBytes { url, headers, body } => {
            let mut request = client.post(url).map_err(|error| error.to_string())?;
            for (name, value) in headers {
                request = request
                    .header(name, value)
                    .map_err(|error| error.to_string())?;
            }
            request.bytes_body(body)
        }
    };
    // Per-request work: await, read the body, scan for the overload
    // marker. zenwave lifts non-2xx statuses into `Error::Http` — they
    // are lane responses all the same (a 404 is the designed miss), so
    // they rejoin the status path while transport failures stay `Err`.
    match request.await {
        Err(error) => match error {
            zenwave::Error::Http {
                status, response, ..
            } => {
                let overloaded = matches!(status.as_u16(), 429 | 503)
                    || response
                        .body_text
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains("overload");
                Ok(Outcome::Response {
                    status: status.as_u16(),
                    overloaded,
                })
            }
            error => Ok(Outcome::Transport(error.to_string())),
        },
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .into_bytes()
                .await
                .map_err(|error| error.to_string())
                .unwrap_or_default();
            let scan = &body[..body.len().min(8 * 1024)];
            let text = String::from_utf8_lossy(scan).to_lowercase();
            let overloaded = matches!(status, 429 | 503) || text.contains("overload");
            Ok(Outcome::Response { status, overloaded })
        }
    }
}

/// Whether a status is a 2xx.
fn ok2xx(status: u16) -> bool {
    (200..300).contains(&status)
}

/// The index/bundle miss path answers 404 as designed — a request the
/// launch fleet pays for either way.
fn ok_or_404(status: u16) -> bool {
    ok2xx(status) || status == 404
}

/// Run one lane to the deadline, pacing at `eps`.
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "request counts and percentile indices are tiny"
)]
async fn run_lane(lane: &Lane, edge: &Edge, duration: Duration) -> LaneStats {
    let mut client = zenwave::client();
    let mut stats = LaneStats::default();
    let interval = Duration::from_secs_f64(1.0 / lane.eps.max(1e-4));
    let deadline = Instant::now() + duration;
    let mut counter = 0u64;
    loop {
        let fired = Instant::now();
        // A response the edge never sends cannot stall the run: the
        // deadline check happens between fires, so bound each one.
        let outcome = tokio::time::timeout(
            REQUEST_TIMEOUT,
            fire_once(&lane.fire, edge, &mut client, counter),
        )
        .await
        .unwrap_or_else(|_| {
            Ok(Outcome::Transport(format!(
                "lane request exceeded {}s",
                REQUEST_TIMEOUT.as_secs()
            )))
        });
        match outcome {
            Ok(Outcome::Response { status, overloaded }) => {
                *stats.statuses.entry(status).or_default() += 1;
                if (500..600).contains(&status) {
                    stats.server_errors += 1;
                }
                if !(lane.expected)(status) {
                    stats.unexpected_statuses += 1;
                }
                if overloaded {
                    stats.overloaded += 1;
                }
            }
            Ok(Outcome::Transport(error)) => {
                stats.transport_errors += 1;
                tracing::debug!(lane = lane.name, %error, "request failed");
            }
            Err(error) => {
                stats.transport_errors += 1;
                tracing::warn!(lane = lane.name, %error, "lane request build failed");
            }
        }
        stats
            .latencies_ms
            .push(fired.elapsed().as_secs_f64() * 1000.0);
        stats.requests += 1;
        counter += 1;
        let elapsed = fired.elapsed();
        if Instant::now() >= deadline {
            break;
        }
        let wait = interval.saturating_sub(elapsed);
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let mut sorted = std::mem::take(&mut stats.latencies_ms);
    sorted.sort_by(f64::total_cmp);
    let percentile = |p: f64| -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let index = (((sorted.len() - 1) as f64) * p).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    };
    stats.p50_ms = percentile(0.5);
    stats.p99_ms = percentile(0.99);
    stats.latencies_ms = sorted;
    stats.effective_eps = stats.requests as f64 / duration.as_secs_f64();
    stats
}

/// Build this run's lane set — the public lanes always, the trusted
/// scheduler lanes behind `--scheduler`, the signed callback lane
/// behind `--webhook-secret`.
fn build_lanes(args: &LaunchLoadArgs, model: &LaunchModel) -> Vec<Lane> {
    let scale = args.rate_scale;
    let eps = |kind: EventKind| model.peak_events_per_second(kind) * scale;

    let mut lanes = vec![
        Lane {
            name: "site",
            eps: eps(EventKind::SiteView),
            fire: Fire::PublicGet(vec![
                "/".to_owned(),
                "/install.sh".to_owned(),
                "/install.ps1".to_owned(),
            ]),
            expected: ok2xx,
        },
        Lane {
            name: "stats",
            eps: eps(EventKind::StatsView),
            fire: Fire::PublicGet(vec!["/stats".to_owned(), "/api/v1/stats".to_owned()]),
            expected: ok2xx,
        },
        Lane {
            name: "index-pull",
            eps: eps(EventKind::IndexPull),
            fire: Fire::IndexPull {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                rustc: args.rustc.clone(),
            },
            expected: ok_or_404,
        },
        Lane {
            name: "bundle-fetch",
            eps: eps(EventKind::CliBytePathFetch),
            fire: Fire::BundleFetch,
            expected: ok_or_404,
        },
        Lane {
            name: "status-read",
            eps: eps(EventKind::RequestStatusRead),
            fire: Fire::StatusRead {
                queue_rows: args.queue_rows,
            },
            expected: ok2xx,
        },
    ];
    if args.scheduler {
        lanes.extend(scheduler_lanes(args, model));
    }
    if let Some(secret) = &args.pow_secret {
        lanes.extend([
            Lane {
                name: "admission",
                eps: eps(EventKind::Admission),
                fire: Fire::Admission {
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    rustc: args.rustc.clone(),
                },
                expected: ok2xx,
            },
            Lane {
                name: "enqueue-redeem",
                eps: eps(EventKind::EnqueueRedemption),
                fire: Fire::EnqueueRedeem {
                    secret: secret.clone(),
                    min_bits: args.pow_min_bits,
                    rustc: args.rustc.clone(),
                },
                expected: ok2xx,
            },
        ]);
    }
    if let Some(secret) = &args.webhook_secret {
        lanes.push(Lane {
            name: "workflow-callback",
            eps: eps(EventKind::BuildCallback),
            fire: Fire::WorkflowRun {
                secret: secret.clone(),
                rustc: args.rustc.clone(),
                queue_rows: args.queue_rows,
            },
            expected: ok2xx,
        });
    }

    lanes
}

/// The `--scheduler` lanes — the trusted surface's admin reads, a queue
/// mutation, and the human-lane submits (the miss lanes' enqueues fire
/// on their own routes, so `trusted-submit` carries only the model's
/// human traffic).
fn scheduler_lanes(args: &LaunchLoadArgs, model: &LaunchModel) -> Vec<Lane> {
    let scale = args.rate_scale;
    let eps = |kind: EventKind| model.peak_events_per_second(kind) * scale;
    vec![
        Lane {
            name: "admin-status",
            eps: eps(EventKind::AdminOperation).max(0.005),
            fire: Fire::TrustedGet("/api/v1/admin/status".to_owned()),
            expected: ok2xx,
        },
        Lane {
            name: "queue-read",
            eps: eps(EventKind::AdminOperation).max(0.005),
            fire: Fire::TrustedGet("/api/v1/admin/queue?status=failed&limit=50".to_owned()),
            expected: ok2xx,
        },
        Lane {
            name: "queue-mutate",
            eps: eps(EventKind::AdminOperation).max(0.005),
            fire: Fire::QueueMutate {
                verb: "retry",
                queue_rows: args.queue_rows,
            },
            expected: ok2xx,
        },
        Lane {
            name: "trusted-submit",
            eps: eps(EventKind::HumanRequest).max(0.005),
            fire: Fire::TrustedSubmit {
                rustc: args.rustc.clone(),
            },
            expected: ok2xx,
        },
    ]
}

/// `stow-admin launch-load` — fire the lanes, then emit the report and
/// exit nonzero on a breach.
#[expect(
    clippy::cast_precision_loss,
    reason = "request counts are tiny next to f64's mantissa"
)]
pub async fn run(
    edge: &Edge,
    args: &LaunchLoadArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let model_text = tokio::fs::read_to_string(&args.model)
        .await
        .map_err(|error| stow_error!("read launch model {}: {error}", args.model.display()))?;
    let model = LaunchModel::from_toml(&model_text)
        .map_err(|error| stow_error!("load launch model {}: {error}", args.model.display()))?;
    let mut lanes = build_lanes(args, &model);
    if !args.lanes.is_empty() {
        lanes.retain(|lane| args.lanes.iter().any(|name| name == lane.name));
        if lanes.is_empty() {
            return Err(stow_error!(
                "no launch-load lane matches --lanes {}",
                args.lanes.join(",")
            ));
        }
    }

    let duration = Duration::from_secs(args.duration_secs);
    let results =
        futures_util::future::join_all(lanes.iter().map(|lane| run_lane(lane, edge, duration)))
            .await;

    let mut lanes_map = BTreeMap::new();
    let mut breaches = Vec::new();
    for (lane, stats) in lanes.iter().zip(results) {
        let total = stats.requests.max(1) as f64;
        let error_share = (stats.transport_errors + stats.server_errors) as f64 / total;
        if error_share > ERROR_RATE_BOUND {
            breaches.push(format!(
                "{}: error share {:.1}% over {:.0}%",
                lane.name,
                error_share * 100.0,
                ERROR_RATE_BOUND * 100.0
            ));
        }
        if stats.unexpected_statuses > 0 {
            breaches.push(format!(
                "{}: {} unexpected statuses",
                lane.name, stats.unexpected_statuses
            ));
        }
        if stats.overloaded > 0 {
            breaches.push(format!(
                "{}: {} overload signal(s) — the DO serialization bound",
                lane.name, stats.overloaded
            ));
        }
        if stats.p99_ms > args.p99_bound_ms {
            breaches.push(format!(
                "{}: p99 {:.0}ms over the {:.0}ms bound",
                lane.name, stats.p99_ms, args.p99_bound_ms
            ));
        }
        lanes_map.insert(lane.name, stats);
    }
    let report = LoadReport {
        duration_secs: args.duration_secs,
        rate_scale: args.rate_scale,
        lanes: lanes_map,
        breaches,
    };
    emit(output, &report, render_report)?;
    if report.breaches.is_empty() {
        Ok(())
    } else {
        Err(stow_error!(
            "launch-load: {} breach(es)",
            report.breaches.len()
        ))
    }
}

/// Human rendering — per-lane rate/latency/status table plus the
/// verdict lines.
fn render_report(report: &LoadReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut table = Table::new(&[
        "lane",
        "reqs",
        "eff eps",
        "p50 ms",
        "p99 ms",
        "errs",
        "unexpected",
        "overload",
        "statuses",
    ]);
    for (name, stats) in &report.lanes {
        let statuses = stats
            .statuses
            .iter()
            .map(|(status, count)| format!("{status}×{count}"))
            .collect::<Vec<_>>()
            .join(" ");
        table.push([
            (*name).to_owned(),
            stats.requests.to_string(),
            format!("{:.3}", stats.effective_eps),
            format!("{:.0}", stats.p50_ms),
            format!("{:.0}", stats.p99_ms),
            (stats.transport_errors + stats.server_errors).to_string(),
            stats.unexpected_statuses.to_string(),
            stats.overloaded.to_string(),
            statuses,
        ]);
    }
    let _ = writeln!(out, "{}", table.render());
    if report.breaches.is_empty() {
        let _ = writeln!(out, "\nlaunch-load: PASS");
    } else {
        let _ = writeln!(out, "\nlaunch-load: FAIL");
        for breach in &report.breaches {
            let _ = writeln!(out, "  {breach}");
        }
    }
    out
}
