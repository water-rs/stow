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
    QueueSelector, ResolvedDependencyGraphEntry, SchedulerRearmReport, SchedulerRearmRequest,
};
use stow_types::fixture::{
    FixtureShape, InFlightRun, REQUEST_FIXTURE_ENQUEUED, REQUEST_FIXTURE_FAILED, fixture_task_id,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::launch_model::{EventKind, LaunchModel};
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
    fn new(secret: String, queue_rows: u64) -> Result<Self, String> {
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
fn sign_body(secret: &str, body: &[u8]) -> String {
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
    let run_id = task.run_id;
    serde_json::json!({
        "action": "completed",
        "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
        "workflow_run": {
            "display_title": run_title(task.rustc_version, &task.task_id),
            "event": "workflow_dispatch",
            "head_branch": stow_types::trusted_builder::BRANCH,
            "path": format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::WORKFLOW_FILE
            ),
            "conclusion": "success",
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
            let signature = sign_body(&lane.secret, body.as_bytes());
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
pub async fn fire_once(
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

/// Build this run's lane set — the public lanes always, the trusted
/// scheduler lanes behind `--scheduler`, the signed callback lane
/// behind `--webhook-secret` — each at `scale` × the model's peak rate,
/// narrowed to `--lanes` when given.
pub fn build_lanes(args: &LaneArgs, model: &LaunchModel, scale: f64) -> Result<Vec<Lane>, String> {
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
            expected: ok_or_404,
        },
        Lane {
            name: "status-read",
            eps: eps(EventKind::RequestStatusRead),
            fire: Fire::StatusRead,
            expected: ok2xx,
        },
    ];
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
    if let Some(secret) = &args.webhook_secret {
        lanes.push(Lane {
            name: "workflow-callback",
            eps: eps(EventKind::BuildCallback),
            fire: Fire::WorkflowRun(CallbackLane::new(secret.clone(), args.queue_rows)?),
            expected: ok2xx,
        });
    }
    if !args.lanes.is_empty() {
        lanes.retain(|lane| args.lanes.iter().any(|name| name == lane.name));
        if lanes.is_empty() {
            return Err(format!("no lane matches --lanes {}", args.lanes.join(",")));
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

    /// The full lane set and the Worker CPU budget table name the same
    /// lanes: a lane without a budget would be measured and never gated,
    /// a budget without a lane would gate nothing.
    #[test]
    fn every_lane_has_a_cpu_budget_and_every_budget_a_lane() {
        let model =
            LaunchModel::from_toml(include_str!("../../../launch-model.toml")).expect("model");
        let args = LaneArgs {
            model: "launch-model.toml".into(),
            scheduler: true,
            webhook_secret: Some("secret".to_owned()),
            queue_rows: 100_000,
            rustc: "1.85.0".to_owned(),
            lanes: Vec::new(),
            pow_secret: Some("secret".to_owned()),
            pow_min_bits: 12,
            bundle_digest: None,
        };
        let mut lanes: Vec<&str> = build_lanes(&args, &model, 1.0)
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
            assert!(seen.insert(task.task_id.clone()));
        }
        assert!(lane.take().is_err());
    }
}
