//! `POST /api/v1/github/workflow-run` — GitHub's `workflow_run` webhook.
//!
//! Completion reaches the scheduler here instead of from CI (stow#455):
//! `build-crate.yml` sets `run-name` to `<rustc>-<task_id>`, GitHub
//! delivers the run's `completed` event signed `sha256=<HMAC-SHA256>` with
//! `X-Hub-Signature-256` over the raw body under the
//! `STOW_GITHUB_WEBHOOK_SECRET` binding, and this route parses
//! `display_title` back into its rustc and task id. A `success`
//! conclusion is only forwarded once the run's
//! `records-<rustc>-<task_id hash>` artifact exists in GHCR — the registry is
//! the record store, so the record must be where the claim says it is
//! before the queue marks the work done.
//!
//! The route carries no caller-credential gate: the HMAC signature is the
//! authentication. Shed control lives in the zone WAF maintenance rules
//! (`admin/src/maintenance.rs`): the `lanes` scope covers only the
//! scheduler-lane paths, so a partial reopen keeps draining completions,
//! and the `anonymous` scope carves `/api/v1/github` out alongside the
//! trusted prefixes for the same reason. Only `all` blocks the route —
//! the whole site is down then, and GitHub redelivers what the outage
//! delayed.

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
#[cfg(target_arch = "wasm32")]
use stow_types::api::WorkflowRunComplete;
use stow_types::records::parse_run_title;
#[cfg(target_arch = "wasm32")]
use stow_types::records::{RECORDS_ARTIFACT_TYPE, RECORDS_TASK_ID_ANNOTATION, records_tag};
#[cfg(target_arch = "wasm32")]
use stow_types::registry::{GHCR_BASE, repository_path};

#[cfg(target_arch = "wasm32")]
use crate::api::{GhcrConfig, OkResponse};
use crate::errors::GetArtifactError;
#[cfg(target_arch = "wasm32")]
use crate::fetch_guard::OutboundPool;
#[cfg(target_arch = "wasm32")]
use crate::{ghcr, scheduler_client};

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
    /// `run-name` — the `<rustc>-<task_id>` title `build-crate.yml` stamps.
    display_title: String,
    /// What dispatched the run — must be `workflow_dispatch`.
    event: String,
    head_branch: String,
    path: String,
    /// Read only by the wasm handler's completion record.
    #[allow(dead_code)]
    conclusion: Option<String>,
    id: u64,
    /// Read only by the wasm handler's completion record.
    #[allow(dead_code)]
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

/// Decode a signed delivery into the event worth completing. `None`
/// covers everything this hook does not consume — non-`workflow_run`
/// events (`ping`) and `workflow_run` actions other than `completed`
/// (`requested`, `in_progress`) all answer 200 so GitHub's delivery log
/// stays clean. `Err` is a 400: the signature was fine but the payload
/// is not the shape GitHub documented.
fn decode_delivery(
    delivery: &VerifiedDelivery,
) -> Result<Option<WorkflowRunEvent>, GetArtifactError> {
    if delivery.event != "workflow_run" {
        return Ok(None);
    }
    let ActionOnly { action } = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    if action != "completed" {
        return Ok(None);
    }
    // `in_progress`/`requested` runs carry a different shape than
    // `completed`; the full event is required only for what we consume.
    let event: WorkflowRunEvent = serde_json::from_slice(&delivery.body).map_err(|error| {
        GetArtifactError::BadRequestWithMessage(format!("malformed workflow_run payload: {error}"))
    })?;
    Ok(Some(event))
}

/// The authority boundary a completion must sit inside — a fork or a
/// feature-branch run's signature still verifies, so the run's own
/// fields are what make it ours: the build workflow's file, on `main`,
/// dispatched by `workflow_dispatch`, in the trusted repository (its
/// head repo equal to the event repo, so a fork's delivery cannot
/// pose as upstream's).
///
/// Returns the run with its title parsed back into `(rustc_version,
/// task_id)`. A pinned run whose title does not parse is a 400 — the
/// workflow stamps every run-name itself, so a shapeless title can only
/// mean a hand-edited dispatch.
fn authorized_run(
    event: &WorkflowRunEvent,
) -> Result<Option<(&WorkflowRunFields, &str, &str)>, GetArtifactError> {
    let run = &event.workflow_run;
    let pinned = run.path.strip_prefix(".github/workflows/")
        == Some(stow_types::trusted_builder::WORKFLOW_FILE)
        && run.head_branch == stow_types::trusted_builder::BRANCH
        && run.event == "workflow_dispatch"
        && run.head_repository.full_name == event.repository.full_name
        && event.repository.full_name == stow_types::trusted_builder::REPOSITORY;
    if !pinned {
        return Ok(None);
    }
    let Some((rustc_version, task_id)) = parse_run_title(&run.display_title) else {
        return Err(GetArtifactError::BadRequestWithMessage(format!(
            "run {}'s display_title {:?} is not <rustc>-<task_id>",
            run.id, run.display_title
        )));
    };
    Ok(Some((run, rustc_version, task_id)))
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
/// `requested`/`in_progress` action, and a run outside the authority
/// boundary are deliveries, not failures, and GitHub retries non-2xx.
/// Consumed completions always answer 200 too: a retried delivery
/// changes nothing about an already-completed or unknown task, so the
/// scheduler's 404/409 answers are logged, not propagated. Only a
/// malformed payload (400), a bad signature (401), and an upstream
/// failure (500, worth a GitHub retry) leave the 2xx path.
#[cfg(target_arch = "wasm32")]
pub async fn github_workflow_run(
    delivery: VerifiedDelivery,
    State(ghcr): State<GhcrConfig>,
    State(scheduler): State<CfDurableNamespace>,
) -> Result<Json<OkResponse>, GetArtifactError> {
    let Some(event) = decode_delivery(&delivery)? else {
        tracing::debug!(event = %delivery.event, "ignoring non-completed webhook delivery");
        return Ok(Json(OkResponse { ok: true }));
    };
    let Some((run, rustc_version, task_id)) = authorized_run(&event)? else {
        tracing::debug!("ignoring workflow_run outside the authority boundary");
        return Ok(Json(OkResponse { ok: true }));
    };

    let mut success = run.conclusion.as_deref() == Some("success");
    let mut error = None;
    if success {
        match records_artifact_exists(&ghcr, rustc_version, task_id).await {
            Ok(true) => {}
            Ok(false) => {
                success = false;
                error = Some(format!(
                    "GitHub reports success but the records artifact for task {task_id} is not in GHCR"
                ));
                tracing::error!(task_id, "successful run produced no records artifact");
            }
            Err(fetch_error) => {
                // A registry hiccup is transient: answer 500 so GitHub's
                // redelivery retries the completion instead of dropping it.
                tracing::warn!(task_id, %fetch_error, "records artifact check failed");
                return Err(GetArtifactError::InternalWithMessage(format!(
                    "verify records artifact for {task_id}: {fetch_error}"
                )));
            }
        }
    } else {
        error = Some(format!(
            "workflow run concluded `{}`{}",
            run.conclusion.as_deref().unwrap_or("<none>"),
            run.html_url
                .as_deref()
                .map(|url| format!(" ({url})"))
                .unwrap_or_default()
        ));
    }

    let completion = WorkflowRunComplete {
        task_id: task_id.to_owned(),
        success,
        error,
        github_run_id: Some(run.id.to_string()),
    };
    match scheduler_client::send_run_complete(&scheduler, &completion).await {
        Ok(()) => {
            tracing::info!(task_id, success, "workflow_run completion applied");
        }
        // The queue's 404/409 mean the task is not live for this event —
        // consumed, never an error back to GitHub.
        Err(crate::errors::SchedulerClientError::Http {
            status: 404 | 409,
            body,
            ..
        }) => {
            tracing::warn!(task_id, %body, "workflow_run completion did not match a live task");
        }
        Err(other) => {
            return Err(GetArtifactError::from(other)).inspect_err(|error| {
                tracing::error!(task_id, %error, "forward workflow_run completion");
            });
        }
    }
    Ok(Json(OkResponse { ok: true }))
}

/// Whether GHCR holds the task's records artifact — the manifest's
/// artifact type and task-id annotation must both match, so a tag
/// pointing at anything else does not satisfy the check.
#[cfg(target_arch = "wasm32")]
async fn records_artifact_exists(
    config: &GhcrConfig,
    rustc_version: &str,
    task_id: &str,
) -> Result<bool, ghcr::FetchError> {
    let tag = records_tag(rustc_version, task_id);
    let reference = format!("{GHCR_BASE}:{tag}");
    let Some(repository) = repository_path(&reference) else {
        return Err(ghcr::FetchError::InvalidRequest(format!(
            "malformed records reference {reference}"
        )));
    };
    let response = ghcr::open_manifest(
        &config.base_url,
        repository,
        &tag,
        &config.tokens,
        &OutboundPool::new(),
    )
    .await;
    let mut manifest = match response {
        Ok(response) => response,
        Err(ghcr::FetchError::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    let body =
        manifest.text().into_send().await.map_err(|error| {
            ghcr::FetchError::Network(format!("read records manifest: {error}"))
        })?;
    let manifest: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| ghcr::FetchError::Network(format!("parse records manifest: {error}")))?;
    let artifact_type_matches = manifest
        .get("artifactType")
        .and_then(|value| value.as_str())
        == Some(RECORDS_ARTIFACT_TYPE);
    let task_id_matches = manifest
        .get("annotations")
        .and_then(|annotations| annotations.get(RECORDS_TASK_ID_ANNOTATION))
        .and_then(|value| value.as_str())
        == Some(task_id);
    if !(artifact_type_matches && task_id_matches) {
        tracing::warn!(
            task_id = %task_id,
            artifact_type_matches,
            task_id_matches,
            "records tag exists but manifest shape does not match"
        );
        return Ok(false);
    }
    Ok(true)
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

    /// `requested`/`in_progress`/`queued` deliveries on the
    /// `workflow_run` subscription are lifecycle noise — ignored, 200.
    #[tokio::test]
    async fn a_non_completed_action_is_ignored() {
        for action in ["requested", "in_progress", "queued", "waiting"] {
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
        ];
        for body in cases {
            let delivery = verified("workflow_run", &body)
                .await
                .expect("signed delivery verifies");
            let event = decode_delivery(&delivery)
                .expect("decodes")
                .expect("completed action");
            assert!(authorized_run(&event).expect("checks").is_none());
        }
    }

    /// The happy path pins everything, splits the title into
    /// `(rustc, task_id)`, and the run id arrives as `u64`.
    #[tokio::test]
    async fn a_dispatched_main_build_run_is_authorized() {
        let body = completed_event(|_| {});
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let event = decode_delivery(&delivery)
            .expect("decodes")
            .expect("completed action");
        let (run, rustc_version, task_id) =
            authorized_run(&event).expect("checks").expect("authorized");
        assert_eq!(rustc_version, "1.99.0");
        assert_eq!(task_id, "serde-1.0.0-abc123");
        assert_eq!(run.id, 987_654_321_u64);
    }

    /// A pinned run whose title is not `<rustc>-<task_id>` is a 400 —
    /// the workflow stamps run-name itself, so a shapeless title means
    /// the dispatch was hand-edited.
    #[tokio::test]
    async fn an_authorized_run_with_a_shapeless_title_is_a_400() {
        let body = completed_event(|event| {
            event["workflow_run"]["display_title"] = serde_json::json!("nodashintitle");
        });
        let delivery = verified("workflow_run", &body)
            .await
            .expect("signed delivery verifies");
        let event = decode_delivery(&delivery)
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
}
