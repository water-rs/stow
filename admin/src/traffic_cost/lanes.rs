//! The traffic lanes the Traffic cost test fires — one lane per kind
//! of user or operator request the launch model counts. The peak drive
//! (`peak.rs`) paces every lane at the model's peak rate; the Worker CPU
//! measurement (`cpu.rs`) fires each lane alone under the isolate's CPU
//! profiler. Both build their lanes here, so the request a CPU number
//! prices is the request the peak drive sends.
//!
//! The public lanes need no credential; `--scheduler` adds the trusted
//! lanes on the operator bearer, `--webhook-secret` adds the
//! `workflow_run` callback lane — a `build-crate.yml` run's `completed`
//! delivery for a seeded in-flight task, re-armed on the operator
//! bearer outside its counted events so each delivery is a first one —
//! signed under the mock's `STOW_GITHUB_WEBHOOK_SECRET`, and
//! `--pow-secret` adds the untrusted
//! miss lanes — real `POST /api/v1/admissions` calls, and `POST
//! /api/v1/enqueue` redemptions on tickets minted under the mock's
//! `STOW_POW_CHALLENGE_SECRET`. Alarm passes are never fired directly —
//! the submits, mutations and completions the lanes drive arm the
//! dispatch alarm, which is exactly how production earns them.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use clap::Args;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stow_types::admission::{DEFAULT_POW_MIN_BITS, difficulty, issue_challenge};
use stow_types::api::{
    AdmissionRequest, DependencyGraphEntry, EnqueueRequest, EnqueueSource, EnqueueTicket,
    PublishedRunReport, PublishedSlice, PublishedSliceRow, QueueSelector,
    ResolvedDependencyGraphEntry, SchedulerRearmReport, SchedulerRearmRequest,
};
use stow_types::fixture::{
    FixtureShape, InFlightRun, REQUEST_FIXTURE_ENQUEUED, REQUEST_FIXTURE_FAILED, fixture_task_id,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::launch_model::{EventKind, LaunchModel};
use stow_types::node_profile::NodeProfile;
use stow_types::pow::enqueue_pow_zero_bits;
use stow_types::records::run_title;
use stow_types::runs::run_url;

use zenwave::Client;

use crate::Edge;

/// Which lanes run and what they name — shared by the peak drive and
/// the CPU measurement.
#[derive(Debug, Args)]
pub struct LaneArgs {
    /// The checked-in launch model.
    #[arg(long, default_value = "launch-model.toml")]
    pub model: PathBuf,
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
    /// Mock newreleases signing secret; enables fixed preheat CPU lanes.
    #[arg(long, requires = "preheat_cron")]
    pub newreleases_secret: Option<String>,
    /// Native Miniflare scheduled event's configured daily preheat cron.
    #[arg(long, requires = "newreleases_secret")]
    pub preheat_cron: Option<String>,
    /// Queue rows the seeded fixture holds — picks the task ids the
    /// mutation and callback lanes name.
    #[arg(long, default_value_t = 100_000)]
    pub queue_rows: u64,
    /// The rustc the seeded rows and synthetic tasks name.
    #[arg(long, default_value = "1.85.0")]
    pub rustc: String,
    /// Comma-separated lane names to run instead of the full set — a
    /// debugging aid; the test runs them all.
    #[arg(long, value_delimiter = ',')]
    pub lanes: Vec<String>,
    /// Mint the redemption lane's tickets under this challenge secret —
    /// the mock manifest's `STOW_POW_CHALLENGE_SECRET`
    /// (`mock-pow-challenge-secret`). With it the `admissions` and
    /// `enqueue` lanes run; without it they stay off.
    #[arg(long)]
    pub pow_secret: Option<String>,
    /// Leading-zero bits the redemption lane's tickets solve to — the
    /// mock manifest's `STOW_POW_MIN_BITS` (default 12).
    #[arg(long, default_value_t = DEFAULT_POW_MIN_BITS)]
    pub pow_min_bits: u32,
    /// A bundle digest the mock registry holds (`stow-mock-registry
    /// put-blob`): the bundle lane streams it instead of asking for
    /// rotating absent digests, so it pays the covered-fetch path a
    /// CLI byte-path fetch pays.
    #[arg(long)]
    pub bundle_digest: Option<String>,
    /// File containing the mock issuer token for index-publish.yml.
    #[arg(long, requires = "index_publish_rustc")]
    pub index_publish_token_file: Option<PathBuf>,
    /// Actual toolchain for the index-report slice; must differ from seeded toolchains.
    #[arg(long, requires = "index_publish_token_file")]
    pub index_publish_rustc: Option<String>,
    /// Mock resolve-request.yml OIDC token for the complete human lifecycle lane.
    #[arg(long, requires_all = ["webhook_secret", "index_publish_rustc"])]
    pub resolve_token_file: Option<PathBuf>,
}

/// A response that takes this long under the mock stack is a stall,
/// not slowness: an unanswered request would otherwise freeze its lane
/// forever — `run_lane` only checks the deadline between fires — and
/// `join_all` would sit until the CI job's timeout kills the whole
/// load run. The lane scores a stall as a transport error, the same
/// signal any other failed request leaves.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// What one lane event is.
#[derive(Debug)]
pub enum Fire {
    /// Admission, resolve workflow deliveries and nonempty outcome reporting.
    HumanLifecycle(super::human::HumanLane),
    /// Round-robin `GET`s over public paths.
    PublicGet(Vec<String>),
    /// `GET /api/v1/index/{target}/{rustc}` then the digest-addressed
    /// slice when a pointer answers — the pull's two requests.
    IndexPull { target: String, rustc: String },
    /// `GET /api/v1/bundles/{rustc}/{digest}` — the stored `digest`
    /// when one is given (the covered fetch), else rotating synthetic
    /// digests under the run's rustc, whose 404 is the miss the launch
    /// fleet sees on an uncovered unit and still costs the full route.
    BundleFetch {
        rustc: String,
        digest: Option<String>,
    },
    /// `GET /api/v1/requests/{request_id}` over the seeded request
    /// records — alternates the `enqueued` record (whose read re-probes
    /// its stored roots into live queue rows) with the `failed` record.
    StatusRead,
    /// Bearer `GET` on a trusted path.
    TrustedGet(String),
    /// `POST /api/v1/admin/queue/{verb}` over seeded failed ids.
    QueueMutate { verb: &'static str, queue_rows: u64 },
    /// `POST /api/v1/scheduler/tasks/submit` — one synthetic task over
    /// a rotating pool of real crates.
    TrustedSubmit { rustc: String },
    /// HMAC-signed `POST /api/v1/github/workflow_run` reporting a
    /// seeded in-flight task's `build-crate.yml` run `completed` — each
    /// event the first delivery for an armed run.
    WorkflowRun(CallbackLane),
    /// A nonempty signed-index membership report on its own workflow identity.
    IndexReport { token_file: PathBuf, rustc: String },
    /// A signed stable Rust release notification.
    PreheatRelease { secret: String, rustc: String },
    /// One signed lifecycle delivery under the named workflow identity.
    WorkflowDelivery {
        secret: String,
        action: &'static str,
        workflow: &'static str,
        title: &'static str,
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

/// The callback lane's supply of first deliveries.
///
/// Production's per-event cost is a run's *first* `completed`
/// delivery: the completion write, the alarm arm, then one alarm pass
/// that resolves the batch and deletes its row. A second delivery for
/// the same batch is a cheaper duplicate, and one after the resolution a
/// cheaper 404, so a lane that cycled the fixture's
/// [`FixtureShape::IN_FLIGHT_ROWS`] bound batches would price the cheap
/// paths once it went round. The lane instead delivers only armed
/// batches — bound, with no completion recorded — and refills from the
/// probe's `POST /api/v1/admin/scheduler/budget/rearm`, which re-arms
/// the batches its earlier deliveries resolved. The refill is harness
/// work: it runs before an event is timed or profiled, never inside one.
#[derive(Debug)]
pub struct CallbackLane {
    secret: String,
    queue_rows: u32,
    /// Armed, undelivered in-flight indexes `k`, in delivery order.
    armed: Mutex<VecDeque<u32>>,
}

impl CallbackLane {
    /// A lane over the `queue_rows` fixture, nothing armed yet.
    ///
    /// # Errors
    /// `queue_rows` does not fit the fixture's `u32` row space.
    pub(super) fn new(secret: String, queue_rows: u64) -> Result<Self, String> {
        Ok(Self {
            secret,
            queue_rows: u32::try_from(queue_rows).map_err(|_| {
                format!("--queue-rows {queue_rows} exceeds the fixture's row space")
            })?,
            armed: Mutex::new(VecDeque::new()),
        })
    }

    /// Deliver exactly `armed` next — the edge's whole armed set, which
    /// already holds every run this lane has queued and not delivered.
    fn replace(&self, armed: impl IntoIterator<Item = u32>) {
        *self.armed.lock().expect("armed runs") = armed.into_iter().collect();
    }

    /// Armed runs not yet delivered.
    fn len(&self) -> usize {
        self.armed.lock().expect("armed runs").len()
    }

    /// The next armed run to deliver.
    ///
    /// # Errors
    /// Nothing is armed — the caller fired without [`Fire::ready`].
    fn take(&self) -> Result<InFlightRun, String> {
        let k = self
            .armed
            .lock()
            .expect("armed runs")
            .pop_front()
            .ok_or_else(|| "the callback lane fired with no armed run".to_owned())?;
        Ok(shape(u64::from(self.queue_rows)).in_flight_run(k))
    }

    /// Re-arm until at least `needed` runs are armed. A delivered
    /// run is re-armable once the alarm pass its delivery armed has
    /// resolved it, which is the delivery's own aftermath and takes no
    /// longer than a request; the wait is bounded by
    /// [`REQUEST_TIMEOUT`], past which the lane fails rather than
    /// deliver a duplicate.
    async fn ready(&self, edge: &Edge, needed: usize) -> Result<(), String> {
        if needed > FixtureShape::IN_FLIGHT_ROWS as usize {
            return Err(format!(
                "the callback lane needs {needed} armed runs at once, but the fixture holds \
                 {} in flight",
                FixtureShape::IN_FLIGHT_ROWS
            ));
        }
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        while self.len() < needed {
            let report: SchedulerRearmReport = edge
                .post_json(
                    "/api/v1/admin/scheduler/budget/rearm",
                    &SchedulerRearmRequest {
                        queue_rows: self.queue_rows,
                    },
                )
                .await
                .map_err(|error| format!("re-arm the fixture's in-flight runs: {error}"))?;
            self.replace(report.armed);
            if self.len() >= needed {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "{} of the {needed} runs the callback lane needs are armed after \
                     {REQUEST_TIMEOUT:?} — the rest were never resolved after their delivery",
                    self.len()
                ));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }
}

impl Fire {
    /// Make the next `needed` events fireable, outside any timed or
    /// profiled window — the callback lane's re-arm; every other lane
    /// needs nothing.
    ///
    /// # Errors
    /// The re-arm failed or could not arm `needed` runs in time.
    pub async fn ready(&self, edge: &Edge, needed: usize) -> Result<(), String> {
        match self {
            Self::WorkflowRun(lane) => lane.ready(edge, needed).await,
            Self::HumanLifecycle(lane) => {
                tokio::time::timeout(REQUEST_TIMEOUT, lane.ready(edge, needed))
                    .await
                    .map_err(|_| {
                        "human lifecycle preparation exceeded its request deadline".to_owned()
                    })?
            }
            _ => Ok(()),
        }
    }
}

/// One lane: what to fire, at what peak rate, and which statuses are
/// the route working as designed (a bundle 404 is the miss path).
pub struct Lane {
    /// Report label — also the key of the lane's Worker CPU budget.
    pub name: &'static str,
    /// Events per second at the peak rate the run drives.
    pub eps: f64,
    /// What one event does.
    pub fire: Fire,
    /// Statuses the lane accepts as designed work.
    pub expected: fn(u16) -> bool,
}

/// One fired request's outcome.
pub enum Outcome {
    /// A response arrived: its status and whether the body or the
    /// status itself signalled overload.
    Response { status: u16, overloaded: bool },
    /// The request never completed — connect, timeout, stream error.
    Transport(String),
}

/// The queue-order shape the seeded ids come from —
/// `stow_types::fixture` owns the math so the lanes and the seeders
/// cannot drift (stow#452 F11).
fn shape(queue_rows: u64) -> FixtureShape {
    FixtureShape {
        queue_rows: u32::try_from(queue_rows).unwrap_or(u32::MAX),
    }
}

/// The k-th failed row's task id — `completed_end < n <= failed_end`.
fn failed_task_id(k: u64, queue_rows: u64) -> String {
    let shape = shape(queue_rows);
    let span = shape
        .failed_end()
        .saturating_sub(shape.completed_end())
        .max(1);
    let index = u32::try_from(k % u64::from(span)).unwrap_or_default();
    fixture_task_id(u64::from(shape.failed_row(index)))
}

/// Real crates the submit lane rotates through — each posts a pinned
/// `(crate, version)` that lands verbatim through the trusted submit
/// path. The pool is fixed, so every submission dedupes onto
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
pub(super) fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// The signed `completed` delivery GitHub sends when `task`'s
/// `build-crate.yml` run finishes — the pinned fields `authorized_run`
/// checks (the trusted repo, the build workflow's path, `main`,
/// `workflow_dispatch`) and the `<rustc>-<task_id>` title the
/// webhook decodes into the completion route's task. The `id` is the
/// run the fixture bound the task to: the scheduler records the
/// completion only for that run, and the alarm then reads that run's
/// jobs page from the local CI (`traffic-cost fixture-runs`) and each
/// task's records artifact under `records-<rustc>-<task_id>-<id>-1`, both
/// of which `traffic-cost.sh` publishes before the lanes start.
fn workflow_run_body(task: &InFlightRun) -> String {
    workflow_delivery_body(
        "completed",
        stow_types::trusted_builder::WORKFLOW_FILE,
        task.run_id,
        &run_title(task.rustc_version, &task.task_id),
    )
}

pub(super) fn workflow_delivery_body(
    action: &str,
    workflow: &str,
    run_id: u64,
    title: &str,
) -> String {
    serde_json::json!({
        "action": action,
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "display_title": title,
            "event": "workflow_dispatch",
            "head_branch": stow_types::trusted_builder::BRANCH,
            "path": format!(
                ".github/workflows/{}",
                workflow
            ),
            "conclusion": (action == "completed").then_some("success"),
            "id": run_id,
            "run_attempt": 1,
            "html_url": run_url(&run_id.to_string()),
            "head_repository": {
                "full_name": stow_types::trusted_builder::REPOSITORY
            },
            // The fixture's runs are external — seeded on the local CI
            // without a dispatch through it — so their actor is the
            // operator login the mock stamps, not the App's bot
            // (stow#940).
            "triggering_actor": {
                "login": stow_types::local_ci::SEEDED_RUN_OPERATOR_LOGIN
            },
        },
    })
    .to_string()
}

/// A full, nonempty wasm slice isolated from the Linux fixture and byte-path slice.
fn index_report(rustc: &str, counter: u64) -> Result<PublishedRunReport, String> {
    use stow_types::public_cache::{UnitInvocation, required_unit_shapes};

    let mut task = submit_task(rustc, counter)?;
    task.target = "wasm32-unknown-unknown"
        .parse::<TargetTriple>()
        .map_err(|error| error.to_string())?;
    let dependency_identity = task
        .dependency_identity()
        .map_err(|error| error.to_string())?;
    let added = required_unit_shapes(false, UnitInvocation::Target, task.explicit_spelling)
        .into_iter()
        .map(|unit_shape| PublishedSliceRow {
            crate_name: task.crate_name.clone(),
            version: task.version.clone(),
            features_json: task.features_json.clone(),
            node_profile: task.profile,
            unit_shape,
            dependency_identity: dependency_identity.clone(),
        })
        .collect();
    let generation = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos(),
    )
    .map_err(|error| error.to_string())?;
    Ok(PublishedRunReport {
        slices: vec![PublishedSlice {
            target: task.target,
            rustc_version: task.rustc_version,
            base_generation: None,
            generation,
            part: 0,
            parts: 1,
            added,
            retired: Vec::new(),
        }],
    })
}

fn signed_workflow_plan(base: &str, secret: &str, body: String) -> Plan {
    let signature = sign_body(secret, body.as_bytes());
    Plan::PostBytes {
        url: format!("{base}/api/v1/github/workflow-run"),
        headers: vec![
            ("X-GitHub-Event".to_owned(), "workflow_run".to_owned()),
            ("X-Hub-Signature-256".to_owned(), signature),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ],
        body: body.into_bytes(),
    }
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
        dependency_subgraph: stow_types::api::TaskSubgraph {
            root_deps: Vec::new(),
            nodes: Vec::new(),
        },
        host_side: false,
        profile: NodeProfile::Dev,
        explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
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
        source: stow_types::api::CliAdmissionSource::CacheMiss,
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
            profile: NodeProfile::Dev,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependencies: Vec::new(),
            dependency_subgraph: stow_types::api::TaskSubgraph::default(),
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
    let tree = stow_types::api::SubmissionTree::from_enqueue_requests(
        stow_types::api::SubmissionSource::CacheMiss,
        std::slice::from_ref(request),
    )
    .map_err(|error| error.to_string())?;
    let task_id = tree
        .roots
        .first()
        .and_then(|&root| tree.nodes.get(root as usize))
        .map(|node| node.task_id.clone())
        .ok_or("submission tree names no roots")?;
    let request_json = serde_json::to_vec(&tree).map_err(|error| error.to_string())?;
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
        tree,
    })
}

async fn index_report_plan(
    base: &str,
    token_file: &std::path::Path,
    rustc: &str,
    counter: u64,
) -> Result<Plan, String> {
    Ok(Plan::PostJson {
        url: format!("{base}/api/v1/admin/index/published"),
        bearer: Some(
            tokio::fs::read_to_string(token_file)
                .await
                .map_err(|error| error.to_string())?
                .trim()
                .to_owned(),
        ),
        body: serde_json::to_value(index_report(rustc, counter)?)
            .map_err(|error| error.to_string())?,
    })
}

fn public_get_plan(base: &str, paths: &[String], counter: u64) -> Plan {
    let index = usize::try_from(counter).unwrap_or_default() % paths.len();
    Plan::Get {
        url: format!("{base}{}", paths[index]),
        bearer: None,
    }
}

fn preheat_release_plan(base: &str, secret: &str, rustc: &str) -> Result<Plan, String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "provider": "github", "project": "rust-lang/rust", "version": rustc,
        "is_prerelease": false,
    }))
    .map_err(|error| error.to_string())?;
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|error| error.to_string())?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&body);
    Ok(Plan::PostBytes {
        url: format!("{base}/api/v1/newreleases/release"),
        headers: vec![
            ("X-Newreleases-Timestamp".to_owned(), timestamp),
            (
                "X-Newreleases-Signature".to_owned(),
                hex::encode(mac.finalize().into_bytes()),
            ),
            ("Content-Type".to_owned(), "application/json".to_owned()),
        ],
        body,
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
        Fire::HumanLifecycle(_) => Err("human lifecycle has no single-request plan".to_owned()),
        Fire::PublicGet(paths) => Ok(public_get_plan(base, paths, counter)),
        Fire::IndexPull { target, rustc } => plan_index_pull(base, target, rustc, client).await,
        Fire::BundleFetch { rustc, digest } => {
            let digest = digest.clone().unwrap_or_else(|| {
                format!(
                    "sha256:{:064x}",
                    counter.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                )
            });
            Ok(Plan::Get {
                url: format!("{base}/api/v1/bundles/{rustc}/{digest}"),
                bearer: None,
            })
        }
        Fire::StatusRead => {
            // Alternate the per-request read with the fleet-wide status —
            // both are DO reads the model's status rate pays for.
            let path = if counter.is_multiple_of(2) {
                "/api/v1/scheduler/status".to_owned()
            } else if counter % 4 == 1 {
                format!("/api/v1/requests/{REQUEST_FIXTURE_ENQUEUED}")
            } else {
                format!("/api/v1/requests/{REQUEST_FIXTURE_FAILED}")
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
            body: serde_json::to_value(vec![
                stow_types::api::SubmissionTree::from_enqueue_requests(
                    stow_types::api::SubmissionSource::HumanRequest,
                    &[submit_task(rustc, counter)?],
                )
                .map_err(|error| error.to_string())?,
            ])
            .map_err(|error| error.to_string())?,
        }),
        Fire::WorkflowRun(lane) => {
            // An armed run, so the delivery is production's first
            // delivery: the record write and the alarm arm.
            let body = workflow_run_body(&lane.take()?);
            Ok(signed_workflow_plan(base, &lane.secret, body))
        }
        Fire::IndexReport { token_file, rustc } => {
            index_report_plan(base, token_file, rustc, counter).await
        }
        Fire::PreheatRelease { secret, rustc } => preheat_release_plan(base, secret, rustc),
        Fire::WorkflowDelivery {
            secret,
            action,
            workflow,
            title,
        } => Ok(signed_workflow_plan(
            base,
            secret,
            workflow_delivery_body(action, workflow, counter + 1, title),
        )),
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

/// Completed request phases. A missing phase was not reached or was interrupted.
#[derive(Debug, Default, serde::Serialize)]
pub struct RequestTimingMs {
    /// Includes pointer HTTP fetches and credential acquisition when the lane needs them.
    pub planning: Option<f64>,
    /// Through response headers on success; HTTP errors can include their collected body.
    pub response: Option<f64>,
    /// Complete success-body consumption and overload scan.
    pub body: Option<f64>,
}

/// Fire one lane event and retain each completed request phase.
pub async fn fire_once(
    fire: &Fire,
    edge: &Edge,
    client: &mut zenwave::DefaultClient,
    counter: u64,
    timing: &mut RequestTimingMs,
) -> Result<Outcome, String> {
    if let Fire::HumanLifecycle(lane) = fire {
        return lane.fire(edge, client).await;
    }
    let started = tokio::time::Instant::now();
    let planned = plan(fire, edge, client, counter).await;
    timing.planning = Some(started.elapsed().as_secs_f64() * 1000.0);
    let request = match planned? {
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
    let started = tokio::time::Instant::now();
    let response = request.await;
    timing.response = Some(started.elapsed().as_secs_f64() * 1000.0);
    match response {
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
            let started = tokio::time::Instant::now();
            let status = response.status().as_u16();
            let body = response.into_body().into_bytes().await;
            timing.body = Some(started.elapsed().as_secs_f64() * 1000.0);
            let body = match body {
                Ok(body) => body,
                Err(error) => return Ok(Outcome::Transport(error.to_string())),
            };
            let scan = &body[..body.len().min(8 * 1024)];
            let text = String::from_utf8_lossy(scan).to_lowercase();
            let overloaded = matches!(status, 429 | 503) || text.contains("overload");
            timing.body = Some(started.elapsed().as_secs_f64() * 1000.0);
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

/// Build this run's lane set — the public lanes always, the trusted
/// scheduler lanes behind `--scheduler`, the signed callback lane
/// behind `--webhook-secret` — each at `scale` × the model's peak rate,
/// narrowed to `--lanes` when given. An absolute build callback rate
/// overrides only the two build workflow delivery lanes.
pub fn build_lanes(
    args: &LaneArgs,
    model: &LaunchModel,
    scale: f64,
    build_callback_eps: Option<f64>,
) -> Result<Vec<Lane>, String> {
    if build_callback_eps.is_some_and(|rate| !rate.is_finite() || rate <= 0.0) {
        return Err("build callback rate must be finite and positive".to_owned());
    }
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
            fire: Fire::BundleFetch {
                rustc: args.rustc.clone(),
                digest: args.bundle_digest.clone(),
            },
            expected: if args.bundle_digest.is_some() {
                ok2xx
            } else {
                ok_or_404
            },
        },
        Lane {
            name: "status-read",
            eps: eps(EventKind::RequestStatusRead),
            fire: Fire::StatusRead,
            expected: ok2xx,
        },
    ];
    lanes.push(Lane {
        name: "health-probe",
        eps: eps(EventKind::HealthProbe),
        fire: Fire::PublicGet(vec!["/api/v1/scheduler/health".to_owned()]),
        expected: ok2xx,
    });
    lanes.extend(index_lanes(args, model, scale)?);
    lanes.extend(human_lanes(args, model, scale)?);
    if args.scheduler {
        lanes.extend(scheduler_lanes(args, model, scale));
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
    lanes.extend(preheat_lanes(args, model, scale)?);
    lanes.extend(build_workflow_lanes(
        args,
        model,
        scale,
        build_callback_eps,
    )?);
    if !args.lanes.is_empty() {
        lanes.retain(|lane| args.lanes.iter().any(|name| name == lane.name));
        if lanes.is_empty() {
            return Err(format!("no lane matches --lanes {}", args.lanes.join(",")));
        }
    }
    Ok(lanes)
}

fn preheat_lanes(args: &LaneArgs, model: &LaunchModel, scale: f64) -> Result<Vec<Lane>, String> {
    let Some(secret) = &args.newreleases_secret else {
        return Ok(Vec::new());
    };
    let mut lanes = Vec::new();
    let cron = args
        .preheat_cron
        .as_ref()
        .ok_or("preheat CPU needs --preheat-cron")?;
    lanes.push(Lane {
        name: "preheat-release",
        eps: model.monthly_stable_releases() / (f64::from(model.scale.days_per_month) * 86_400.0)
            * scale,
        fire: Fire::PreheatRelease {
            secret: secret.clone(),
            rustc: args.rustc.clone(),
        },
        expected: ok2xx,
    });
    let query = serde_html_form::to_string([("cron", cron)]).map_err(|error| error.to_string())?;
    lanes.push(Lane {
        name: "preheat-scheduled",
        eps: model.monthly_resubmits() / (f64::from(model.scale.days_per_month) * 86_400.0) * scale,
        fire: Fire::PublicGet(vec![format!("/cdn-cgi/local/scheduled?{query}")]),
        expected: ok2xx,
    });
    let webhook = args
        .webhook_secret
        .as_ref()
        .ok_or("preheat CPU needs --webhook-secret")?;
    for (name, action) in [
        ("preheat-requested", "requested"),
        ("preheat-in-progress", "in_progress"),
        ("preheat-completed", "completed"),
    ] {
        lanes.push(Lane {
            name,
            eps: (model.monthly_stable_releases() + model.monthly_resubmits())
                / (f64::from(model.scale.days_per_month) * 86_400.0)
                * scale,
            fire: Fire::WorkflowDelivery {
                secret: webhook.clone(),
                action,
                workflow: stow_types::trusted_builder::PREHEAT_WORKFLOW_FILE,
                title: "Preheat",
            },
            expected: ok2xx,
        });
    }
    for (name, action) in [
        ("preheat-cron-requested", "requested"),
        ("preheat-cron-in-progress", "in_progress"),
        ("preheat-cron-completed", "completed"),
    ] {
        lanes.push(Lane {
            name,
            eps: model.monthly_resubmits() / (f64::from(model.scale.days_per_month) * 86_400.0)
                * scale,
            fire: Fire::WorkflowDelivery {
                secret: webhook.clone(),
                action,
                workflow: "preheat-cron.yml",
                title: "Preheat cron",
            },
            expected: ok2xx,
        });
    }
    Ok(lanes)
}

fn human_lanes(args: &LaneArgs, model: &LaunchModel, scale: f64) -> Result<Vec<Lane>, String> {
    let Some(token_file) = &args.resolve_token_file else {
        return Ok(Vec::new());
    };
    Ok(vec![Lane {
        name: "human-lifecycle",
        eps: model.peak_events_per_second(EventKind::HumanRequest) * scale,
        fire: Fire::HumanLifecycle(super::human::HumanLane::new(
            args.webhook_secret
                .clone()
                .ok_or("human lifecycle needs --webhook-secret")?,
            token_file.clone(),
            args.index_publish_rustc
                .as_deref()
                .ok_or("human lifecycle needs --index-publish-rustc")?,
        )?),
        expected: ok2xx,
    }])
}

fn build_workflow_lanes(
    args: &LaneArgs,
    model: &LaunchModel,
    scale: f64,
    build_callback_eps: Option<f64>,
) -> Result<Vec<Lane>, String> {
    let rate = build_callback_eps
        .unwrap_or_else(|| model.peak_events_per_second(EventKind::BuildCallback) * scale);
    let mut lanes = Vec::new();
    if let Some(secret) = &args.webhook_secret {
        lanes.push(Lane {
            name: "build-requested",
            eps: rate,
            fire: Fire::WorkflowDelivery {
                secret: secret.clone(),
                action: "requested",
                workflow: stow_types::trusted_builder::WORKFLOW_FILE,
                title: "Build crate",
            },
            expected: ok2xx,
        });
        lanes.push(Lane {
            name: "workflow-callback",
            eps: rate,
            fire: Fire::WorkflowRun(CallbackLane::new(secret.clone(), args.queue_rows)?),
            expected: ok2xx,
        });
    }
    Ok(lanes)
}

fn index_lanes(args: &LaneArgs, model: &LaunchModel, scale: f64) -> Result<Vec<Lane>, String> {
    let eps = |kind: EventKind| model.peak_events_per_second(kind) * scale;
    let mut lanes = Vec::new();
    if let Some(token_file) = &args.index_publish_token_file {
        let rustc = args
            .index_publish_rustc
            .as_ref()
            .ok_or("index report requires --index-publish-rustc")?;
        if stow_types::fixture::SEEDED_RUSTC_VERSIONS.contains(&rustc.as_str()) {
            return Err(format!(
                "index-report rustc {rustc} overlaps the seeded population"
            ));
        }
        lanes.push(Lane {
            name: "index-report",
            eps: eps(EventKind::IndexPublish),
            fire: Fire::IndexReport {
                token_file: token_file.clone(),
                rustc: rustc.clone(),
            },
            expected: ok2xx,
        });
    }
    if let Some(secret) = &args.webhook_secret {
        for (name, action) in [
            ("index-requested", "requested"),
            ("index-in-progress", "in_progress"),
            ("index-completed", "completed"),
        ] {
            lanes.push(Lane {
                name,
                eps: eps(EventKind::IndexPublish),
                fire: Fire::WorkflowDelivery {
                    secret: secret.clone(),
                    action,
                    workflow: stow_types::trusted_builder::INDEX_WORKFLOW_FILE,
                    title: "Publish index",
                },
                expected: ok2xx,
            });
        }
    }
    Ok(lanes)
}

/// The `--scheduler` lanes — the trusted surface's admin reads, a queue
/// mutation, and the human-lane submits (the miss lanes' enqueues fire
/// on their own routes, so `trusted-submit` carries only the model's
/// human traffic).
fn scheduler_lanes(args: &LaneArgs, model: &LaunchModel, scale: f64) -> Vec<Lane> {
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

#[cfg(test)]
mod tests {
    use stow_types::do_budgets::WORKER_CPU_BUDGETS;
    use stow_types::launch_model::LaunchModel;

    use stow_types::fixture::FixtureShape;

    use super::{CallbackLane, LaneArgs, build_lanes, workflow_run_body};

    fn lane_args() -> LaneArgs {
        LaneArgs {
            model: "launch-model.toml".into(),
            scheduler: true,
            webhook_secret: Some("secret".to_owned()),
            newreleases_secret: Some("newreleases-secret".to_owned()),
            preheat_cron: Some("17 0 * * *".to_owned()),
            queue_rows: 100_000,
            rustc: "1.85.0".to_owned(),
            lanes: Vec::new(),
            pow_secret: Some("secret".to_owned()),
            pow_min_bits: 12,
            bundle_digest: None,
            index_publish_token_file: Some("index-publish-token".into()),
            index_publish_rustc: Some("1.99.1".to_owned()),
            resolve_token_file: Some("resolve-token".into()),
        }
    }

    #[test]
    fn index_reports_replace_nonempty_membership_on_their_own_slice() {
        let first = super::index_report("1.99.1", 0).expect("report");
        let next = super::index_report("1.99.1", 1).expect("report");
        let row = &first.slices[0];
        assert_eq!(row.target.as_str(), "wasm32-unknown-unknown");
        assert_eq!(row.rustc_version.as_str(), "1.99.1");
        assert!(row.base_generation.is_none());
        assert_eq!((row.part, row.parts), (0, 1));
        assert_ne!(row.added, []);
        assert_eq!(row.retired, []);
        assert_ne!(row.added, next.slices[0].added);
        assert!(next.slices[0].generation > row.generation);
        let shapes = stow_types::public_cache::required_unit_shapes(
            false,
            stow_types::public_cache::UnitInvocation::Target,
            stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        );
        assert_eq!(
            row.added
                .iter()
                .map(|row| row.unit_shape)
                .collect::<Vec<_>>(),
            shapes
        );
    }

    #[test]
    fn index_report_cannot_replace_a_seeded_slice() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        for rustc in stow_types::fixture::SEEDED_RUSTC_VERSIONS {
            let mut args = lane_args();
            args.index_publish_rustc = Some(rustc.to_owned());
            assert!(
                build_lanes(&args, &model, 1.0, None)
                    .err()
                    .expect("overlap")
                    .contains("overlaps")
            );
        }
    }

    #[test]
    fn index_lifecycle_deliveries_use_index_workflow_identity() {
        for action in ["requested", "in_progress", "completed"] {
            let body =
                super::workflow_delivery_body(action, "index-publish.yml", 42, "Publish index");
            let body: serde_json::Value = serde_json::from_str(&body).expect("delivery");
            assert_eq!(body["action"], action);
            assert_eq!(
                body["workflow_run"]["path"],
                ".github/workflows/index-publish.yml"
            );
            assert_eq!(
                body["workflow_run"]["head_branch"],
                stow_types::trusted_builder::BRANCH
            );
            assert_eq!(
                body["workflow_run"]["conclusion"].as_str(),
                (action == "completed").then_some("success")
            );
        }
    }

    #[tokio::test]
    async fn request_timing_separates_delayed_headers_and_complete_body() {
        use std::time::Duration;
        for (header_delay, body_delay) in [
            (Duration::from_millis(150), Duration::ZERO),
            (Duration::ZERO, Duration::from_millis(150)),
        ] {
            let server =
                crate::test_server::Loopback::start(vec![crate::test_server::Step::Delayed {
                    header_delay,
                    body_delay,
                    body: "complete response",
                }])
                .await;
            let edge = crate::Edge::for_test(server.url.clone());
            let fire = super::Fire::PublicGet(vec!["/timing".to_owned()]);
            let mut timing = super::RequestTimingMs::default();
            let outcome = tokio::time::timeout(
                Duration::from_secs(3),
                super::fire_once(&fire, &edge, &mut zenwave::client(), 0, &mut timing),
            )
            .await
            .expect("bounded response")
            .expect("planned request");
            assert!(matches!(
                outcome,
                super::Outcome::Response { status: 200, .. }
            ));
            let response = timing.response.expect("response phase");
            let body = timing.body.expect("complete body phase");
            if header_delay.is_zero() {
                assert!(body >= 140.0, "{timing:?}");
                assert!(body > response, "{timing:?}");
            } else {
                assert!(response >= 140.0, "{timing:?}");
                assert!(response > body, "{timing:?}");
            }
            assert_eq!(server.join().await.len(), 1);
        }
    }

    #[tokio::test]
    async fn interrupted_body_keeps_completed_phases_and_leaves_body_unfinished() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Stall {
            status: 200,
            body: "partial",
            content_length: 64,
        }])
        .await;
        let edge = crate::Edge::for_test(server.url.clone());
        let fire = super::Fire::PublicGet(vec!["/timing".to_owned()]);
        let mut timing = super::RequestTimingMs::default();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            super::fire_once(&fire, &edge, &mut zenwave::client(), 0, &mut timing),
        )
        .await;
        assert!(result.is_err(), "the body remains incomplete");
        assert!(timing.planning.is_some(), "{timing:?}");
        assert!(timing.response.is_some(), "{timing:?}");
        assert!(timing.body.is_none(), "{timing:?}");
        assert_eq!(server.join().await.len(), 1);
    }

    #[test]
    fn build_callback_override_preserves_every_other_lane_and_global_scaling() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let args = lane_args();
        let scale = 32.0;
        let baseline = build_lanes(&args, &model, scale, None).expect("baseline");
        let overridden = build_lanes(&args, &model, scale, Some(6.1)).expect("override");
        assert_eq!(baseline.len(), overridden.len());
        let mut changed = 0;
        for (before, after) in baseline.iter().zip(&overridden) {
            assert_eq!(before.name, after.name);
            if matches!(after.name, "build-requested" | "workflow-callback") {
                assert_eq!(after.eps, 6.1);
                assert_eq!(
                    before.eps,
                    model
                        .peak_events_per_second(stow_types::launch_model::EventKind::BuildCallback)
                        * scale
                );
                changed += 1;
            } else {
                assert_eq!(before.eps, after.eps, "{}", after.name);
            }
        }
        assert_eq!(changed, 2);
        let site = overridden
            .iter()
            .find(|lane| lane.name == "site")
            .expect("site");
        let unscaled = build_lanes(&args, &model, 1.0, None).expect("unscaled");
        assert_eq!(
            site.eps,
            unscaled
                .iter()
                .find(|lane| lane.name == "site")
                .expect("site")
                .eps
                * scale
        );
    }

    #[test]
    fn build_callback_override_rejects_nonpositive_and_nonfinite_rates() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        for rate in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = build_lanes(&lane_args(), &model, 1.0, Some(rate))
                .err()
                .expect("invalid callback rate");
            assert!(error.contains("finite and positive"), "{error}");
        }
    }

    #[tokio::test]
    async fn preheat_lanes_sign_real_entrypoints_and_keep_workflow_identities() {
        use hmac::{KeyInit as _, Mac as _};
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let args = lane_args();
        let lanes = build_lanes(&args, &model, 1.0, None).expect("lanes");
        let edge = crate::Edge::for_test("http://127.0.0.1:8080".to_owned());
        let release = lanes
            .iter()
            .find(|lane| lane.name == "preheat-release")
            .expect("release");
        let super::Plan::PostBytes { url, headers, body } =
            super::plan(&release.fire, &edge, &mut zenwave::client(), 0)
                .await
                .expect("release request")
        else {
            panic!("signed release")
        };
        assert_eq!(url, "http://127.0.0.1:8080/api/v1/newreleases/release");
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .expect("header")
                .1
                .as_str()
        };
        let mut mac =
            super::Hmac::<super::Sha256>::new_from_slice(b"newreleases-secret").expect("key");
        mac.update(header("X-Newreleases-Timestamp").as_bytes());
        mac.update(b".");
        mac.update(&body);
        mac.verify_slice(&hex::decode(header("X-Newreleases-Signature")).expect("hex signature"))
            .expect("valid signature");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("release");
        assert_eq!(payload["provider"], "github");
        assert_eq!(payload["project"], "rust-lang/rust");
        assert_eq!(payload["version"], args.rustc);
        let scheduled = lanes
            .iter()
            .find(|lane| lane.name == "preheat-scheduled")
            .expect("scheduled");
        let super::Plan::Get { url, .. } =
            super::plan(&scheduled.fire, &edge, &mut zenwave::client(), 0)
                .await
                .expect("scheduled request")
        else {
            panic!("native scheduled endpoint")
        };
        let query = serde_html_form::to_string([("cron", "17 0 * * *")]).expect("query");
        assert_eq!(
            url,
            format!("http://127.0.0.1:8080/cdn-cgi/local/scheduled?{query}")
        );
        for (name, workflow, cadence) in [
            (
                "preheat-requested",
                "preheat-admin.yml",
                model.monthly_stable_releases() + model.monthly_resubmits(),
            ),
            (
                "preheat-cron-requested",
                "preheat-cron.yml",
                model.monthly_resubmits(),
            ),
        ] {
            let lane = lanes
                .iter()
                .find(|lane| lane.name == name)
                .expect("workflow lane");
            assert_eq!(
                lane.eps,
                cadence / (f64::from(model.scale.days_per_month) * 86_400.0)
            );
            let super::Plan::PostBytes { headers, body, .. } =
                super::plan(&lane.fire, &edge, &mut zenwave::client(), 0)
                    .await
                    .expect("workflow request")
            else {
                panic!("signed workflow")
            };
            assert!(headers.contains(&(
                "X-Hub-Signature-256".to_owned(),
                super::sign_body("secret", &body)
            )));
            let payload: serde_json::Value = serde_json::from_slice(&body).expect("workflow");
            assert_eq!(
                payload["workflow_run"]["path"],
                format!(".github/workflows/{workflow}")
            );
        }
    }

    #[tokio::test]
    async fn requested_build_lane_signs_the_build_workflow_delivery() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let mut args = lane_args();
        args.lanes = vec!["build-requested".to_owned()];
        let lanes = build_lanes(&args, &model, 1.0, None).expect("requested lane");
        assert_eq!(lanes.len(), 1);
        assert_eq!(
            lanes[0].eps,
            model.peak_events_per_second(stow_types::launch_model::EventKind::BuildCallback)
        );
        let edge = crate::Edge::for_test("http://127.0.0.1:8080".to_owned());
        let request = super::plan(&lanes[0].fire, &edge, &mut zenwave::client(), 41)
            .await
            .expect("request");
        let super::Plan::PostBytes { url, headers, body } = request else {
            panic!("expected signed webhook request");
        };
        assert_eq!(url, "http://127.0.0.1:8080/api/v1/github/workflow-run");
        assert!(headers.contains(&(
            "X-Hub-Signature-256".to_owned(),
            super::sign_body("secret", &body),
        )));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("delivery");
        assert_eq!(body["action"], "requested");
        assert_eq!(body["workflow_run"]["id"], 42);
        assert_eq!(
            body["workflow_run"]["path"],
            ".github/workflows/build-crate.yml"
        );
        assert_eq!(body["workflow_run"]["conclusion"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn truncated_success_body_is_a_transport_failure() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Stall {
            status: 200,
            body: "partial bundle",
            content_length: 64,
        }])
        .await;
        let edge = crate::Edge::for_test(server.url.clone());
        let fire = super::Fire::PublicGet(vec!["/bundle".to_owned()]);
        let mut client = zenwave::client();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            super::fire_once(
                &fire,
                &edge,
                &mut client,
                0,
                &mut super::RequestTimingMs::default(),
            ),
        )
        .await
        .expect("body read completes within the bound")
        .expect("request planned");
        let requests = server.join().await;
        assert_eq!(requests.len(), 1, "the load driver must not retry");
        assert!(matches!(outcome, super::Outcome::Transport(_)));
    }

    #[test]
    fn stored_bundle_lane_rejects_missing_fixture() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let mut args = lane_args();
        args.lanes = vec!["bundle-fetch".to_owned()];
        let lanes = build_lanes(&args, &model, 1.0, None).expect("miss lane");
        assert!((lanes[0].expected)(404));
        args.bundle_digest = Some(format!("sha256:{}", "a".repeat(64)));
        let lanes = build_lanes(&args, &model, 1.0, None).expect("stored bundle lane");
        assert!((lanes[0].expected)(200));
        assert!(!(lanes[0].expected)(404));
    }

    /// The full lane set and the Worker CPU budget table name the same
    /// lanes: a lane without a budget would be measured and never gated,
    /// a budget without a lane would gate nothing.
    #[test]
    fn every_lane_has_a_cpu_budget_and_every_budget_a_lane() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let args = lane_args();
        let mut lanes: Vec<&str> = build_lanes(&args, &model, 1.0, None)
            .expect("lanes")
            .iter()
            .map(|lane| lane.name)
            .collect();
        let mut budgets: Vec<&str> = WORKER_CPU_BUDGETS
            .iter()
            .map(|budget| budget.lane)
            .collect();
        lanes.sort_unstable();
        budgets.sort_unstable();
        assert_eq!(lanes, budgets);
    }

    /// The lane delivers exactly the runs armed, in arming order,
    /// each once: a `build-crate.yml` `completed` whose title decodes
    /// to that task and whose run id is the one it is bound to. With
    /// nothing armed it refuses to fire instead of repeating a run.
    #[test]
    fn the_callback_lane_completes_each_armed_run_once_under_its_id() {
        let rows = 100_000;
        let lane = CallbackLane::new("secret".to_owned(), rows).unwrap();
        lane.replace((0..FixtureShape::IN_FLIGHT_ROWS).rev());
        let mut seen = std::collections::BTreeSet::new();
        for k in (0..FixtureShape::IN_FLIGHT_ROWS).rev() {
            let task = lane.take().unwrap();
            assert_eq!(
                task,
                FixtureShape {
                    queue_rows: u32::try_from(rows).unwrap()
                }
                .in_flight_run(k)
            );
            let body: serde_json::Value = serde_json::from_str(&workflow_run_body(&task)).unwrap();
            let run = &body["workflow_run"];
            let title = run["display_title"].as_str().unwrap();
            assert_eq!(
                stow_types::records::parse_run_title(title),
                Some((task.rustc_version, task.task_id.as_str()))
            );
            assert_eq!(
                run["path"],
                format!(
                    ".github/workflows/{}",
                    stow_types::trusted_builder::WORKFLOW_FILE
                )
            );
            assert_eq!(run["id"], task.run_id);
            assert_eq!(body["action"], "completed");
            assert!(seen.insert(task.task_id));
        }
        assert!(lane.take().is_err());
    }
}
