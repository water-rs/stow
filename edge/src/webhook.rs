//! `POST /api/v1/github/workflow-run` — GitHub's `workflow_run` webhook.
//!
//! Completion reaches the scheduler here instead of from CI (stow#455):
//! `build-batch.yml` sets `run-name` to `<rustc>-b<batch_id>`, GitHub
//! delivers the run's `completed` event signed `sha256=<HMAC-SHA256>` with
//! `X-Hub-Signature-256` over the raw body under the
//! `STOW_GITHUB_WEBHOOK_SECRET` binding, and this route parses
//! `display_title` back into its rustc and batch id and forwards the
//! run's identity to the scheduler, which resolves each leg from the
//! signed records artifacts.
//!
//! The route carries no caller-credential gate: the HMAC signature is the
//! authentication. Shed control lives in the zone WAF maintenance rules
//! (`admin/src/maintenance.rs`): the `lanes` scope covers only the
//! scheduler-lane paths, so a partial reopen keeps draining completions,
//! and the `anonymous` scope carves `/api/v1/github` out alongside the
//! trusted prefixes for the same reason. Only `all` blocks the route —
//! the whole site is down then, and a delivery sent during the outage is
//! lost: GitHub never redelivers on its own, and the lease check repairs
//! the batch a lost completion belonged to.

use std::future::Future;

#[cfg(target_arch = "wasm32")]
use crate::api::OkResponse;
use crate::errors::{GetArtifactError, SchedulerClientError};
#[cfg(target_arch = "wasm32")]
use crate::scheduler_client;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use skyzen::Request;
use skyzen::extract::Extractor;
#[cfg(target_arch = "wasm32")]
use skyzen::utils::Json;
use skyzen::utils::State;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::CfDurableNamespace;
#[cfg(target_arch = "wasm32")]
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use stow_types::api::{BatchId, BatchRunComplete};
use stow_types::records::parse_batch_run_title;

type HmacSha256 = Hmac<Sha256>;

/// The `STOW_GITHUB_WEBHOOK_SECRET` binding, stored via `State`.
#[derive(Debug, Clone)]
pub struct WebhookSecret(pub String);

/// The webhook's signing headers and the raw body they cover, pulled off
/// the request by [`SignedDelivery`]'s extractor.
struct SignedDelivery {
    /// The `X-GitHub-Event` value — only `workflow_run` events are
    /// consumed.
    event: String,
    /// The `X-Hub-Signature-256` header (`sha256=<hex>`).
    signature: String,
    /// The exact body bytes the signature covers — never the
    /// deserialized JSON, whose re-serialization GitHub does not promise
    /// is byte-identical.
    body: Vec<u8>,
}

impl Extractor for SignedDelivery {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let header = |name: &str| -> Result<String, GetArtifactError> {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| {
                    GetArtifactError::BadRequestWithMessage(format!(
                        "missing required `{name}` header"
                    ))
                })
        };
        let event = header("X-GitHub-Event")?;
        let signature = header("X-Hub-Signature-256")?;
        let body = skyzen_core::take_body_bytes::<Self>(request)
            .await
            .map_err(|error| {
                GetArtifactError::BadRequestWithMessage(format!("read webhook body: {error}"))
            })?
            .to_vec();
        Ok(Self {
            event,
            signature,
            body,
        })
    }
}

/// A delivery after its HMAC signature verified — the raw event name and
/// body, undecoded. Verification runs before any payload inspection:
/// GitHub's `ping` and the `workflow_run` subscription's
/// `requested`/`in_progress` deliveries all reach the handler, which
/// answers 200 to everything it does not consume.
#[derive(Debug)]
pub struct VerifiedDelivery {
    /// `X-GitHub-Event`.
    event: String,
    /// The exact body bytes the signature covered.
    body: Vec<u8>,
}

impl Extractor for VerifiedDelivery {
    type Error = GetArtifactError;

    async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
        let delivery = SignedDelivery::extract(request).await?;
        let State(secret) = State::<WebhookSecret>::extract(request)
            .await
            .map_err(|error| {
                GetArtifactError::InternalWithMessage(format!(
                    "webhook secret binding missing: {error}"
                ))
            })?;
        verify_signature(&secret.0, &delivery.signature, &delivery.body)?;
        Ok(Self {
            event: delivery.event,
            body: delivery.body,
        })
    }
}

/// The `workflow_run` object fields this route reads — GitHub sends the
/// full run document; the rest is ignored.
#[derive(Debug, serde::Deserialize)]
struct WorkflowRunFields {
    /// `run-name` — the title the trusted workflow stamps.
    display_title: String,
    /// What dispatched the run — must be `workflow_dispatch`.
    event: String,
    head_branch: String,
    path: String,
    /// Read by the batch forward's report and the request run update.
    conclusion: Option<String>,
    id: u64,
    /// `run_attempt` — GitHub's attempt number for the run, a positive
    /// integer. Read by the batch forward's report.
    run_attempt: std::num::NonZeroU32,
    /// Read by the batch forward's report and the request run update.
    html_url: Option<String>,
    /// The repo the head commit lives in — a fork's run names its fork.
    head_repository: RepoRef,
}

/// `full_name` (`owner/name`) of a repo the payload carries.
#[derive(Debug, serde::Deserialize)]
struct RepoRef {
    full_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct WorkflowRunEvent {
    /// The repo the workflow belongs to — the trusted repo.
    repository: RepoRef,
    workflow_run: WorkflowRunFields,
}

/// The delivery's `action` alone — non-`completed` deliveries are
/// ignored without requiring the completed event's shape.
#[derive(serde::Deserialize)]
struct ActionOnly {
    action: String,
}

/// Decode a signed delivery into the `workflow_run` event plus its
/// action. `None` covers everything this hook does not consume —
/// non-`workflow_run` events (`ping`) answer 200 so GitHub's delivery
/// log stays clean; the action is returned for the caller to gate per
/// workflow (a batch run is consumed on `completed`, a resolve run on
/// `in_progress` and `completed`). `Err` is a 400: the signature was
/// fine but the payload is not the shape GitHub documented.
fn decode_delivery(
    delivery: &VerifiedDelivery,
) -> Result<Option<(String, WorkflowRunEvent)>, GetArtifactError> {
    if delivery.event != "workflow_run" {
        return Ok(None);
    }
    let ActionOnly { action } = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    // The two lifecycle actions any trusted workflow consumes: a batch
    // run reports on `completed`, a resolve run on `in_progress` and
    // `completed`. `requested`/`queued`/`waiting` deliveries carry the
    // run but nothing to apply — answer 200 without parsing further.
    if action != "in_progress" && action != "completed" {
        return Ok(None);
    }
    let event: WorkflowRunEvent = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    Ok(Some((action, event)))
}

/// The subject a pinned run's `run-name` decodes to — each trusted
/// workflow stamps its own shape.
#[derive(Debug)]
enum RunSubject<'a> {
    /// `build-batch.yml`'s `<rustc>-b<batch_id>` — a batch run's
    /// completion report (stow#833).
    Batch {
        /// The rustc the batch's legs built under.
        rustc_version: &'a str,
        /// The batch the run reported on.
        batch_id: BatchId,
    },
    /// `resolve-request.yml`'s `resolve-a<attempt>-<request_id>` — the
    /// human request record's lifecycle signal (stow#428).
    Request {
        /// The record's dispatch epoch the run served.
        attempt: u32,
        /// The request record the run served.
        request_id: &'a str,
    },
}

/// The authority boundary a run event must sit inside — a fork or a
/// feature-branch run's signature still verifies, so the run's own
/// fields are what make it ours: a trusted workflow's file
/// (`build-batch.yml` or `resolve-request.yml`), on `main`, dispatched
/// by `workflow_dispatch`, in the trusted repository (its head repo
/// equal to the event repo, so a fork's delivery cannot pose as
/// upstream's).
///
/// Returns the run with its title decoded into its [`RunSubject`]. A
/// pinned run whose title does not parse is a 400 — the workflow stamps
/// every run-name itself, so a shapeless title can only mean a
/// hand-edited dispatch.
fn authorized_run(
    event: &WorkflowRunEvent,
) -> Result<Option<(&WorkflowRunFields, RunSubject<'_>)>, GetArtifactError> {
    let run = &event.workflow_run;
    let pinned = run.head_branch == stow_types::trusted_builder::BRANCH
        && run.event == "workflow_dispatch"
        && run.head_repository.full_name == event.repository.full_name
        && event.repository.full_name == stow_types::trusted_builder::REPOSITORY;
    if !pinned {
        return Ok(None);
    }
    let subject = match run.path.strip_prefix(".github/workflows/") {
        Some(stow_types::trusted_builder::BATCH_WORKFLOW_FILE) => {
            let Some((rustc_version, batch_id)) = parse_batch_run_title(&run.display_title) else {
                return Err(GetArtifactError::BadRequestWithMessage(format!(
                    "run {}'s display_title {:?} is not <rustc>-b<batch_id>",
                    run.id, run.display_title
                )));
            };
            RunSubject::Batch {
                rustc_version,
                batch_id,
            }
        }
        Some(stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE) => {
            let Some((attempt, request_id)) =
                stow_types::records::parse_resolve_run_title(&run.display_title)
            else {
                return Err(GetArtifactError::BadRequestWithMessage(format!(
                    "run {}'s display_title {:?} is not resolve-a<attempt>-<request_id>",
                    run.id, run.display_title
                )));
            };
            RunSubject::Request {
                attempt,
                request_id,
            }
        }
        // Any other workflow in the trusted repo.
        _ => return Ok(None),
    };
    Ok(Some((run, subject)))
}

/// Constant-time check of `sha256=<hex>` against the HMAC of `body` under
/// `secret`. `Mac::verify_slice` is the constant-time compare; a
/// malformed or wrong-length signature fails the same way rather than
/// short-circuiting on shape.
fn verify_signature(secret: &str, signature: &str, body: &[u8]) -> Result<(), GetArtifactError> {
    let Some(hex_signature) = signature.strip_prefix("sha256=") else {
        return Err(GetArtifactError::Unauthorized);
    };
    let expected = hex::decode(hex_signature).map_err(|_| GetArtifactError::Unauthorized)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
    mac.update(body);
    mac.verify_slice(&expected)
        .map_err(|_| GetArtifactError::Unauthorized)
}

/// `POST /api/v1/github/workflow-run`.
///
/// Everything this hook does not consume answers 200 — a `ping`, a
/// `requested` action, a resolve run's non-lifecycle action, and a run
/// outside the authority boundary are deliveries, not failures. Consumed
/// events always answer 200 too: the scheduler's 404/409 answers mean the
/// event names nothing live, so they are logged, not propagated. Only a
/// malformed payload (400), a bad signature (401), and an upstream failure
/// (500) leave the 2xx path. GitHub never redelivers a failed delivery on
/// its own, so a 500 loses the event; for a batch completion the lease
/// check repairs the loss.
#[cfg(target_arch = "wasm32")]
pub async fn github_workflow_run(
    delivery: VerifiedDelivery,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let Some((action, event)) = decode_delivery(&delivery)? else {
        tracing::debug!(event = %delivery.event, "ignoring non-workflow_run delivery");
        return Ok(Json(OkResponse { ok: true }));
    };
    let Some((run, subject)) = authorized_run(&event)? else {
        tracing::debug!("ignoring workflow_run outside the authority boundary");
        return Ok(Json(OkResponse { ok: true }));
    };
    match subject {
        RunSubject::Batch {
            rustc_version,
            batch_id,
        } if action == "completed" => {
            forward_batch_completion(&scheduler, run, rustc_version, &batch_id).await?;
        }
        RunSubject::Request {
            attempt,
            request_id,
        } if action == "in_progress" || action == "completed" => {
            update_request_run(&scheduler, run, &action, attempt, request_id).await?;
        }
        // A batch run's `requested`/`in_progress` and a resolve run's
        // `requested`/`waiting`: the batch's lifecycle starts at
        // `completed` and the request's record is `accepted` at
        // dispatch — neither event carries anything to apply. The
        // batch arm in particular touches nothing but the DO forward:
        // its leg resolution runs in the alarm pass (stow#833 §3.2).
        _ => {}
    }
    Ok(Json(OkResponse { ok: true }))
}

/// The one outbound channel a `build-batch.yml` `completed` delivery
/// uses: the forward to the object's `POST /batches/{batch_id}/
/// complete`. `CfDurableNamespace` carries it on wasm; tests stub it
/// to count what the handler sends. Keeping it a trait is what makes
/// "the batch arm issues no GitHub or GHCR call" host-testable — the
/// handler holds no channel but this one.
trait BatchCompletionForward: Sync {
    /// Forward `report` to `POST /batches/{batch_id}/complete`.
    fn send_batch_complete<'a>(
        &'a self,
        batch_id: &'a BatchId,
        report: &'a BatchRunComplete,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a;
}

#[cfg(target_arch = "wasm32")]
impl BatchCompletionForward for CfDurableNamespace {
    fn send_batch_complete<'a>(
        &'a self,
        batch_id: &'a BatchId,
        report: &'a BatchRunComplete,
    ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
        scheduler_client::send_batch_complete(self, batch_id, report).into_send()
    }
}

/// `build-batch.yml` `completed` — forward the run's identity
/// verbatim to `POST /batches/{batch_id}/complete`; the object records
/// it on the batch row and the alarm pass resolves each leg
/// (stow#833 §3.2). An unknown batch is an orphan run from an
/// abandoned dispatch — the object's 404 is logged, never an error back
/// to GitHub.
async fn forward_batch_completion(
    forward: &impl BatchCompletionForward,
    run: &WorkflowRunFields,
    rustc_version: &str,
    batch_id: &BatchId,
) -> Result<(), GetArtifactError> {
    let completion = BatchRunComplete {
        run_id: run.id,
        run_attempt: run.run_attempt.get(),
        conclusion: run.conclusion.clone().unwrap_or_default(),
        html_url: run.html_url.clone().unwrap_or_default(),
    };
    match forward.send_batch_complete(batch_id, &completion).await {
        Ok(()) => {
            tracing::info!(
                %batch_id,
                run_id = run.id,
                rustc_version,
                "batch run completion forwarded"
            );
        }
        Err(SchedulerClientError::Http {
            status: 404, body, ..
        }) => {
            tracing::warn!(
                %batch_id,
                %body,
                "batch completion named no live batch"
            );
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(%batch_id, %error, "forward batch completion");
            });
        }
    }
    Ok(())
}

/// `resolve-request.yml` `in_progress`/`completed` — the request
/// record's lifecycle channel (`accepted` → `resolving`, and the
/// backstop that fails a run which finished without an outcome).
#[cfg(target_arch = "wasm32")]
async fn update_request_run(
    scheduler: &CfDurableNamespace,
    run: &WorkflowRunFields,
    action: &str,
    attempt: u32,
    request_id: &str,
) -> Result<(), GetArtifactError> {
    let update = stow_types::api::RequestRunUpdate {
        attempt,
        action: if action == "completed" {
            stow_types::api::RequestRunAction::Completed
        } else {
            stow_types::api::RequestRunAction::InProgress
        },
        conclusion: run.conclusion.clone(),
        run_id: Some(run.id.to_string()),
        run_url: run.html_url.clone(),
    };
    match scheduler_client::send_request_run_update(scheduler, request_id, &update).await {
        Ok(()) => {
            tracing::info!(request_id, attempt, %action, "request run update applied");
        }
        // Unknown record or a superseded attempt — consumed, never an
        // error back to GitHub: a stale run's events cannot apply to
        // the record's live attempt by design.
        Err(crate::errors::SchedulerClientError::Http {
            status: 404 | 409,
            body,
            ..
        }) => {
            tracing::warn!(
                request_id,
                %body,
                "request run update did not match the live attempt"
            );
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(request_id, %error, "forward request run update");
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "webhook-secret";

    fn signed_body(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// A request the way GitHub sends it: event + signature headers over
    /// the raw body, the `STOW_GITHUB_WEBHOOK_SECRET` binding layered in
    /// as `State`.
    fn delivery_request(event: &str, body: &[u8], signature: &str) -> Request {
        let mut request = Request::new(skyzen::Body::from(body.to_vec()));
        request
            .headers_mut()
            .insert("X-GitHub-Event", event.parse().expect("header value"));
        request.headers_mut().insert(
            "X-Hub-Signature-256",
            signature.parse().expect("header value"),
        );
        request
            .extensions_mut()
            .insert(State(WebhookSecret(SECRET.to_owned())));
        request
    }

    async fn verified(event: &str, body: &[u8]) -> Result<VerifiedDelivery, GetArtifactError> {
        let signature = signed_body(SECRET, body);
        let mut request = delivery_request(event, body, &signature);
        VerifiedDelivery::extract(&mut request).await
    }

    fn completed_event(over: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
        let mut event = serde_json::json!({
            "action": "completed",
            "repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
            "workflow_run": {
                "display_title": "1.99.0-serde-1.0.0-abc123",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "path": ".github/workflows/build-crate.yml",
                "conclusion": "success",
                "id": 987_654_321_u64,
                "run_attempt": 1,
                "html_url": "https://github.com/water-rs/stow/actions/runs/987654321",
                "head_repository": {"full_name": stow_types::trusted_builder::REPOSITORY},
            },
        });
        over(&mut event);
        serde_json::to_vec(&event).expect("event json")
    }

    #[test]
    fn a_correct_signature_verifies() {
        let body = b"{}";
        let signature = signed_body("secret", body);
        assert!(verify_signature("secret", &signature, body).is_ok());
    }

    #[test]
    fn wrong_secret_or_tampered_body_rejects() {
        let body = b"{}";
        let signature = signed_body("secret", body);
        assert!(verify_signature("other", &signature, body).is_err());
        assert!(verify_signature("secret", &signature, b"{\"x\":1}").is_err());
    }

    #[test]
    fn malformed_signatures_reject() {
        let body = b"{}";
        for signature in ["", "sha256=", "sha1=abc", "sha256=zz", "abc"] {
            assert!(
                verify_signature("secret", signature, body).is_err(),
                "{signature:?}"
            );
        }
    }

    /// A bad signature fails before the payload is ever looked at —
    /// `ping`, `in_progress`, everything.
    #[tokio::test]
    async fn a_bad_signature_rejects_401_before_any_decode() {
        for event in ["ping", "workflow_run"] {
            let mut request = delivery_request(event, b"{}", "sha256=deadbeef");
            let error = VerifiedDelivery::extract(&mut request)
                .await
                .expect_err("bad signature rejects");
            assert!(matches!(error, GetArtifactError::Unauthorized), "{event}");
        }
    }

    /// `ping` is a delivery GitHub requires to succeed — ignored, 200.
    #[tokio::test]
    async fn a_ping_event_is_ignored() {
        let delivery = verified("ping", b"{\"zen\":\"huh\"}")
            .await
            .expect("signed ping verifies");
        assert!(decode_delivery(&delivery).expect("ping decodes").is_none());
    }

    /// `requested`/`queued`/`waiting` deliveries on the `workflow_run`
    /// subscription are lifecycle noise — ignored, 200, before the run
    /// payload is ever parsed.
    #[tokio::test]
    async fn a_non_lifecycle_action_is_ignored() {
        for action in ["requested", "queued", "waiting"] {
            let body =
                format!("{{\"action\":\"{action}\",\"repository\":{{}},\"workflow_run\":{{}}}}");
            let delivery = verified("workflow_run", body.as_bytes())
                .await
                .expect("signed delivery verifies");
            assert!(
                decode_delivery(&delivery)
                    .unwrap_or_else(|error| unreachable!("{action} decodes: {error}"))
                    .is_none(),
                "{action}"
            );
        }
    }

    /// A signed, well-formed run outside the authority boundary —
    /// forked head repo, a non-dispatch event, another repository, a
    /// different workflow file — is ignored with 200.
    #[tokio::test]
    async fn a_run_outside_the_authority_boundary_is_ignored() {
        let cases = [
            completed_event(|event| {
                event["workflow_run"]["head_repository"]["full_name"] =
                    serde_json::json!("attacker/fork");
            }),
            completed_event(|event| {
                event["workflow_run"]["event"] = serde_json::json!("pull_request");
            }),
            completed_event(|event| {
                event["repository"]["full_name"] = serde_json::json!("attacker/fork");
            }),
            completed_event(|event| {
                event["workflow_run"]["path"] =
                    serde_json::json!(".github/workflows/index-publish.yml");
            }),
            completed_event(|event| {
                event["workflow_run"]["head_branch"] = serde_json::json!("dev");
            }),
            // `build-crate.yml` is a reusable workflow the batch calls,
            // never dispatched itself: a run of it is outside the
            // boundary however well pinned.
            completed_event(|_| {}),
        ];
        for body in cases {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            assert!(authorized_run(&event).expect("checks").is_none());
        }
    }

    /// `run_attempt` is required and positive — a delivery that cannot
    /// name its run's attempt is malformed like any other missing field.
    #[tokio::test]
    async fn a_run_without_a_valid_attempt_is_a_400() {
        for body in [
            completed_event(|event| {
                let _ = event["workflow_run"]
                    .as_object_mut()
                    .expect("workflow_run object")
                    .remove("run_attempt");
            }),
            completed_event(|event| {
                event["workflow_run"]["run_attempt"] = serde_json::json!(0);
            }),
        ] {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let error = decode_delivery(&delivery).expect_err("an unusable run_attempt rejects");
            assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
        }
    }

    /// A `resolve-request.yml` run on both lifecycle actions decodes
    /// `resolve-a<attempt>-<request_id>` into the request subject.
    #[tokio::test]
    async fn a_resolve_run_decodes_its_request_subject() {
        for action in ["in_progress", "completed"] {
            let body = completed_event(|event| {
                event["action"] = serde_json::json!(action);
                event["workflow_run"]["path"] = serde_json::json!(format!(
                    ".github/workflows/{}",
                    stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
                ));
                event["workflow_run"]["display_title"] = serde_json::json!(
                    stow_types::records::resolve_run_title(2, "req-serde-1.0.0-ab12")
                );
            });
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (decoded, event) = decode_delivery(&delivery)
                .expect("decodes")
                .unwrap_or_else(|| unreachable!("{action} decodes"));
            assert_eq!(decoded, action);
            let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
            let RunSubject::Request {
                attempt,
                request_id,
            } = subject
            else {
                panic!("resolve-request.yml decodes a request subject");
            };
            assert_eq!((attempt, request_id), (2, "req-serde-1.0.0-ab12"));
            assert_eq!(run.id, 987_654_321_u64);
        }
    }

    /// A pinned resolve run whose title is not
    /// `resolve-a<attempt>-<request_id>` is a 400 — same rule as a
    /// build run's.
    #[tokio::test]
    async fn a_resolve_run_with_a_shapeless_title_is_a_400() {
        let body = completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] = serde_json::json!("not-a-resolve-title");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let error = authorized_run(&event).expect_err("shapeless title rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// A pinned batch run whose title is not `<rustc>-b<batch_id>` is a
    /// 400 — the workflow stamps run-name itself, so a shapeless title
    /// means the dispatch was hand-edited.
    #[tokio::test]
    async fn an_authorized_run_with_a_shapeless_title_is_a_400() {
        let body = batch_completed_event(|event| {
            event["workflow_run"]["display_title"] = serde_json::json!("nodashintitle");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let error = authorized_run(&event).expect_err("shapeless title rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// A signed but malformed `workflow_run` payload is a 400.
    #[tokio::test]
    async fn a_malformed_completed_payload_is_a_400() {
        let delivery = verified("workflow_run", b"{\"action\":\"completed\"}")
            .await
            .expect("signed delivery verifies");
        let error = decode_delivery(&delivery).expect_err("malformed payload rejects");
        assert!(matches!(error, GetArtifactError::BadRequestWithMessage(_)));
    }

    /// The batch workflow's file and title stamp, applied to a
    /// `completed` delivery.
    fn batch_completed_event(over: impl Fn(&mut serde_json::Value)) -> Vec<u8> {
        completed_event(|event| {
            event["workflow_run"]["path"] = serde_json::json!(format!(
                ".github/workflows/{}",
                stow_types::trusted_builder::BATCH_WORKFLOW_FILE
            ));
            event["workflow_run"]["display_title"] =
                serde_json::json!(stow_types::records::batch_run_title(
                    "1.99.0",
                    &"0123456789abcdef0123456789abcdef"
                        .parse::<BatchId>()
                        .expect("batch id")
                ));
            over(event);
        })
    }

    /// A `build-batch.yml` run decodes `<rustc>-b<batch_id>` into the
    /// batch subject — inside the same authority boundary a build run
    /// sits in (stow#833 §3.2).
    #[tokio::test]
    async fn a_batch_run_decodes_its_batch_subject() {
        let body = batch_completed_event(|_| {});
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Batch {
            rustc_version,
            batch_id,
        } = subject
        else {
            panic!("build-batch.yml decodes a batch subject");
        };
        assert_eq!(rustc_version, "1.99.0");
        assert_eq!(
            batch_id,
            "0123456789abcdef0123456789abcdef"
                .parse()
                .expect("batch id")
        );
        assert_eq!(run.id, 987_654_321_u64);
    }

    /// A `build-batch.yml` run outside the authority boundary —
    /// another branch, another event, another repo — is refused like
    /// any other run's delivery.
    #[tokio::test]
    async fn a_batch_run_outside_the_authority_boundary_is_ignored() {
        let cases = [
            batch_completed_event(|event| {
                event["workflow_run"]["head_branch"] = serde_json::json!("dev");
            }),
            batch_completed_event(|event| {
                event["workflow_run"]["event"] = serde_json::json!("pull_request");
            }),
            batch_completed_event(|event| {
                event["repository"]["full_name"] = serde_json::json!("attacker/fork");
            }),
            batch_completed_event(|event| {
                event["workflow_run"]["head_repository"]["full_name"] =
                    serde_json::json!("attacker/fork");
            }),
        ];
        for body in cases {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let (_action, event) = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            assert!(authorized_run(&event).expect("checks").is_none());
        }
    }

    /// The batch forward's test double: records the calls —
    /// `send_batch_complete` is the batch arm's only outbound channel,
    /// so this log is the whole of what the handler can do out.
    #[derive(Default)]
    struct CountingForward {
        calls: std::sync::Mutex<Vec<(BatchId, BatchRunComplete)>>,
        /// Scripted status — when `Some`, the stub answers
        /// `SchedulerClientError::Http` with it.
        status: Option<u16>,
    }

    impl BatchCompletionForward for CountingForward {
        fn send_batch_complete<'a>(
            &'a self,
            batch_id: &'a BatchId,
            report: &'a BatchRunComplete,
        ) -> impl Future<Output = Result<(), SchedulerClientError>> + Send + 'a {
            self.calls
                .lock()
                .expect("calls")
                .push((batch_id.clone(), report.clone()));
            std::future::ready(self.status.map_or(Ok(()), |status| {
                Err(SchedulerClientError::Http {
                    url: format!("https://scheduler.internal/batches/{batch_id}/complete"),
                    status,
                    body: "{\"error\":\"unknown batch\"}".to_owned(),
                })
            }))
        }
    }

    /// The batch arm's `completed` handler issues exactly one outbound
    /// call — the `POST /batches/{batch_id}/complete` forward carrying
    /// the run's identity verbatim; it holds no GitHub or GHCR channel
    /// at all (stow#833 §3.2).
    #[tokio::test]
    async fn a_batch_completion_makes_one_do_forward_and_nothing_else() {
        let body = batch_completed_event(|event| {
            event["workflow_run"]["conclusion"] = serde_json::json!("failure");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Batch {
            rustc_version,
            batch_id,
        } = subject
        else {
            panic!("build-batch.yml decodes a batch subject");
        };
        let forward = CountingForward::default();
        forward_batch_completion(&forward, run, rustc_version, &batch_id)
            .await
            .expect("forwarded");
        let calls = forward.calls.lock().expect("calls").clone();
        assert_eq!(calls.len(), 1, "the batch arm issues only the DO forward");
        let (called_id, report) = &calls[0];
        assert_eq!(*called_id, batch_id);
        assert_eq!(report.run_id, 987_654_321);
        assert_eq!(report.run_attempt, 1);
        assert_eq!(report.conclusion, "failure");
        assert_eq!(
            report.html_url,
            "https://github.com/water-rs/stow/actions/runs/987654321"
        );
    }

    /// A DO 404 — an unknown batch, the orphan of an abandoned
    /// dispatch — is consumed: logged, still 200 to GitHub. A 5xx does
    /// propagate as a 500; GitHub never redelivers it, so the lease
    /// check repairs the loss.
    #[tokio::test]
    async fn a_batch_completion_404_is_consumed_but_a_5xx_is_not() {
        let body = batch_completed_event(|_| {});
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let (_action, event) = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, subject) = authorized_run(&event).expect("checks").expect("authorized");
        let RunSubject::Batch {
            rustc_version,
            batch_id,
        } = subject
        else {
            panic!("build-batch.yml decodes a batch subject");
        };
        let unknown = CountingForward {
            status: Some(404),
            ..CountingForward::default()
        };
        forward_batch_completion(&unknown, run, rustc_version, &batch_id)
            .await
            .expect("an unknown batch is consumed, not propagated");
        let failing = CountingForward {
            status: Some(500),
            ..CountingForward::default()
        };
        let error = forward_batch_completion(&failing, run, rustc_version, &batch_id)
            .await
            .expect_err("a DO failure propagates as a 500");
        assert!(matches!(error, GetArtifactError::InternalWithMessage(_)));
    }
}
