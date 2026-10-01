//! `POST /reconcile` — the in-flight↔GitHub reconciliation (stow#526).
//!
//! The queue half is `queue::reconcile_in_flight`; this module is the
//! orchestration around it — the paginated `build-crate.yml` run
//! listing (`dispatch::list_build_runs`), the webhook-shaped
//! completion verdicts (`webhook::build_run_completion`), and the
//! report the watchdog's `edge.reconcile_drift` signal reads.

/// What can fail in a reconcile pass. Queue work keeps `QueueError`;
/// the GitHub-side leg — credential arm, bindings, token mint, run
/// listing — reports the dispatch pass's own `DispatchError`; plain
/// binding reads carry the worker error's text.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// Row reads, `complete_run` applies, the stale reclaim.
    #[error(transparent)]
    Queue(#[from] crate::errors::QueueError),
    /// Credential, token mint and `build-crate.yml` run listing.
    #[cfg(target_arch = "wasm32")]
    #[error(transparent)]
    Dispatch(#[from] super::dispatch::DispatchError),
    /// `Cloudflare Workers` binding reads (`GITHUB_REPO`, the
    /// `GITHUB_APP_*` secrets) — a malformed deploy, not SQL.
    #[error("{0}")]
    Binding(String),
}

/// The whole pass — what `POST /reconcile` runs. Report-first: it
/// lists the runs the in-flight set needs once, applies the webhook's
/// own transition to completed-but-unreported rows and the existing
/// stale-reclaim to stale missing rows, and hands back the report —
/// the watchdog's drift signal is the only notification consumer.
#[cfg(target_arch = "wasm32")]
pub async fn pass(
    env: &skyzen::runtime::wasm::WasmEnv,
    db: &skyzen_services::durable::DurableDb,
    settings: &super::queue::SchedulerSettings,
    window_minutes: u32,
) -> Result<stow_types::api::ReconcileReport, ReconcileError> {
    use futures_util::StreamExt as _;
    use stow_types::api::ReconcileRun;

    use super::queue::{
        ReconcileCompletion, reconcile_in_flight, reconcile_in_flight_rows, reconcile_pending,
    };

    let rows = reconcile_in_flight_rows(db, settings).await?;
    // `updated_at` is ordered oldest-first, so row 0 bounds the set's
    // age — `list_build_runs` turns it into the `created>=` clause.
    let runs: Vec<ReconcileRun> = if rows.is_empty() {
        Vec::new()
    } else {
        list_runs(env, db, Some(&rows[0].updated_at)).await?
    };
    // Records checks are independent GHCR fetches — resolve them
    // concurrently, bounded by the shared outbound cap
    // (`fetch_guard::MAX_OUTBOUND_INFLIGHT`) so a large unreported set
    // cannot fan out wider than any other fetch batch.
    let completions: Vec<ReconcileCompletion> =
        futures_util::stream::iter(reconcile_pending(&rows, &runs).into_iter().map(
            |pending| async move {
                ReconcileCompletion {
                    task_id: pending.task_id.clone(),
                    completion: resolve_completion(env, &pending).await,
                }
            },
        ))
        .buffer_unordered(crate::fetch_guard::MAX_OUTBOUND_INFLIGHT)
        .collect()
        .await;
    Ok(reconcile_in_flight(db, settings, &rows, &runs, &completions, window_minutes).await?)
}

/// The paginated `build-crate.yml` run list — the credential arm the
/// dispatch pass authenticates with, flipped to a GET.
#[cfg(target_arch = "wasm32")]
async fn list_runs(
    env: &skyzen::runtime::wasm::WasmEnv,
    db: &skyzen_services::durable::DurableDb,
    created_since: Option<&str>,
) -> Result<Vec<stow_types::api::ReconcileRun>, ReconcileError> {
    use super::dispatch::{DispatchCredential, DispatchError, list_build_runs};
    use super::object::{
        CredentialSource, GITHUB_REPO_BINDING, credential_source, read_string_binding,
    };
    use crate::fetch_guard::OutboundPool;

    let (credential, repo) =
        match credential_source(env).map_err(|error| ReconcileError::Binding(error.to_string()))? {
            CredentialSource::LocalCi(url) => (DispatchCredential::LocalCi(url), String::new()),
            CredentialSource::GitHub(config) => (
                DispatchCredential::GitHub(
                    crate::github_app::installation_token(db, &config)
                        .await
                        .map_err(|error| DispatchError::TokenMint(error.to_string()))?,
                ),
                read_string_binding(env, GITHUB_REPO_BINDING)
                    .map_err(|error| ReconcileError::Binding(error.to_string()))?,
            ),
        };
    let pool = OutboundPool::new();
    Ok(list_build_runs(&credential, &repo, created_since, &pool).await?)
}

/// The `WorkflowRunComplete` one pending row resolves to — the same
/// success/records/error mapping the webhook applies
/// (`webhook::build_run_completion`), so the reconcile apply is the
/// transition the lost delivery would have made, not a parallel one.
/// A records-check fetch error becomes the row's `Err` — the webhook
/// answers it 500 for a retry, and the report carries it unapplied.
#[cfg(target_arch = "wasm32")]
async fn resolve_completion(
    env: &skyzen::runtime::wasm::WasmEnv,
    pending: &super::queue::ReconcilePending,
) -> Result<stow_types::api::WorkflowRunComplete, String> {
    use crate::api::GhcrConfig;
    use crate::entry::GHCR_BASE_URL_BINDING;

    let ghcr = GhcrConfig {
        base_url: crate::env_binding::optional_string(env.as_js(), GHCR_BASE_URL_BINDING)
            .unwrap_or_else(|| crate::ghcr::default_base_url().to_owned()),
        tokens: crate::registry_auth::RegistryTokens::default(),
    };
    crate::webhook::build_run_completion(
        &ghcr,
        &pending.rustc_version,
        &pending.task_id,
        pending.run.conclusion.as_deref(),
        pending.run.run_id,
        pending.run.html_url.as_deref(),
    )
    .await
    .map_err(|error| error.to_string())
}
