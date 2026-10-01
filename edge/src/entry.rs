//! Cloudflare Workers bootstrap: binds D1, the scheduler Durable Object,
//! the CF cache, and GHCR config, then mounts the public API routes.

use skyzen::routing::{CreateRouteNode, Route, RouteNode, Router};
use skyzen::runtime::wasm;
use skyzen::utils::State;
use skyzen_cloudflare::{CfCache, CfD1, CfDurableNamespace};
use skyzen_services::Db;

use stow_types::admission;

use crate::api::GhcrConfig;
use crate::stats::StatsContext;
use crate::{api, env_binding, ghcr, github_auth, runtime_settings, scheduler, site, webhook};

const STOW_DB_BINDING: &str = "STOW_DB";
const SCHEDULER_BINDING: &str = "SCHEDULER";
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";
const STOW_OIDC_AUDIENCE_BINDING: &str = "STOW_OIDC_AUDIENCE";
const GHCR_BASE_URL_BINDING: &str = "GHCR_BASE_URL";
const STOW_LOCAL_CI_URL_BINDING: &str = "STOW_LOCAL_CI_URL";
const GITHUB_APP_ID_BINDING: &str = "GITHUB_APP_ID";
const GITHUB_APP_INSTALLATION_ID_BINDING: &str = "GITHUB_APP_INSTALLATION_ID";
const GITHUB_APP_PRIVATE_KEY_BINDING: &str = "GITHUB_APP_PRIVATE_KEY";
const STOW_POW_CHALLENGE_SECRET_BINDING: &str = "STOW_POW_CHALLENGE_SECRET";
const STOW_POW_MIN_BITS_BINDING: &str = "STOW_POW_MIN_BITS";
const STOW_MAX_QUEUE_PENDING_BINDING: &str = "STOW_MAX_QUEUE_PENDING";
const TURNSTILE_SECRET_KEY_BINDING: &str = "TURNSTILE_SECRET_KEY";
const TURNSTILE_HOSTNAME_BINDING: &str = "TURNSTILE_HOSTNAME";
const TURNSTILE_SITE_KEY_BINDING: &str = "TURNSTILE_SITE_KEY";
const STOW_ANALYTICS_BINDING: &str = "STOW_ANALYTICS";
const CF_ACCOUNT_ID_BINDING: &str = "CF_ACCOUNT_ID";
const CF_ANALYTICS_TOKEN_BINDING: &str = "CF_ANALYTICS_TOKEN";
const STOW_STATS_SQL_URL_BINDING: &str = "STOW_STATS_SQL_URL";
const STOW_GITHUB_WEBHOOK_SECRET_BINDING: &str = "STOW_GITHUB_WEBHOOK_SECRET";

/// `WinterCG` `fetch` export the generated Worker shim calls.
///
/// Written by hand rather than `#[skyzen::main]`: the macro's entry function
/// takes no arguments and 0.3 removed the ambient `current_env()`, so the
/// only way to keep reading every binding eagerly at startup is to take the
/// `env` that `launch` hands the endpoint factory.
#[::skyzen::wasm_bindgen::prelude::wasm_bindgen(wasm_bindgen = ::skyzen::wasm_bindgen)]
pub async fn fetch(
    request: wasm::Request,
    env: wasm::Env,
    ctx: wasm::ExecutionContext,
) -> Result<wasm::Response, skyzen::wasm_bindgen::JsValue> {
    crate::console_log::init();
    wasm::launch(|env| async move { worker(&env) }, request, env, ctx).await
}

fn worker(env: &wasm::Env) -> crate::no_store::NoStoreOnError<Router> {
    let d1 = CfD1::from_env(env, STOW_DB_BINDING)
        .unwrap_or_else(|error| panic!("failed to load D1 binding '{STOW_DB_BINDING}': {error}"));
    let db = Db::new(d1);
    let scheduler = CfDurableNamespace::from_env(env, SCHEDULER_BINDING).unwrap_or_else(|error| {
        panic!("failed to load Durable Object binding '{SCHEDULER_BINDING}': {error}")
    });
    let cache = CfCache::default();
    let analytics = env_binding::required_analytics_dataset(env, STOW_ANALYTICS_BINDING);
    let account_id = env_binding::required_string(env, CF_ACCOUNT_ID_BINDING);
    let stats = StatsContext {
        analytics_token: env_binding::required_string(env, CF_ANALYTICS_TOKEN_BINDING),
        // `STOW_STATS_SQL_URL` is the mock manifest's override; it is
        // absent in production, where the route always posts the account's
        // real endpoint. The token rides in Authorization, so the same
        // loopback rule `STOW_LOCAL_CI_URL` gets applies here.
        sql_url: env_binding::optional_string(env, STOW_STATS_SQL_URL_BINDING).map_or_else(
            || {
                format!(
                    "{}/{}/analytics_engine/sql",
                    crate::stats::SQL_API_URL,
                    account_id
                )
            },
            |url| {
                crate::scheduler::object::loopback_url("STOW_STATS_SQL_URL", &url)
                    .unwrap_or_else(|error| panic!("{error}"))
            },
        ),
    };
    // The scheduler Durable Object reads the same bindings lazily on each
    // dispatch pass; probing them here fails worker startup on a missing
    // App credential instead of surfacing it as a burned dispatch
    // attempt. Local-CI dispatch needs none of them.
    if env_binding::optional_string(env, STOW_LOCAL_CI_URL_BINDING).is_none() {
        env_binding::required_string(env, GITHUB_APP_ID_BINDING);
        env_binding::required_string(env, GITHUB_APP_INSTALLATION_ID_BINDING);
        env_binding::required_string(env, GITHUB_APP_PRIVATE_KEY_BINDING);
    }
    let ghcr = GhcrConfig {
        base_url: env_binding::optional_string(env, GHCR_BASE_URL_BINDING)
            .unwrap_or_else(|| ghcr::default_base_url().to_owned()),
        tokens: crate::registry_auth::RegistryTokens::default(),
    };
    let resolver_settings = runtime_settings::ResolverSettings::from_env(env);
    let pow_admission = api::PowAdmission {
        challenge_secret: env_binding::required_string(env, STOW_POW_CHALLENGE_SECRET_BINDING),
        min_bits: env_binding::optional_u32(env, STOW_POW_MIN_BITS_BINDING)
            .unwrap_or(admission::DEFAULT_POW_MIN_BITS),
        max_queue_pending: env_binding::optional_u32(env, STOW_MAX_QUEUE_PENDING_BINDING)
            .unwrap_or(scheduler::queue::DEFAULT_MAX_QUEUE_PENDING),
    };

    let site = site::SiteConfig {
        turnstile_site_key: env_binding::required_string(env, TURNSTILE_SITE_KEY_BINDING),
    };

    // When the GitHub trust check upstream is rate-limited, this renders
    // the 503 with the `Retry-After` GitHub asked for.
    let trust_gate = github_auth::TrustRateLimitGate;

    let mut nodes = anonymous_nodes();
    nodes.extend(trusted_nodes(&trust_gate));
    // The GitHub `workflow_run` webhook's authentication is its
    // `X-Hub-Signature-256` HMAC — it carries neither the trust gate's
    // caller credential nor the zone WAF rules' shedding (completions
    // must drain during a partial reopen).
    nodes.push("/api/v1/github/workflow-run".post(webhook::github_workflow_run));

    let router = Route::new(nodes)
        .with(db)
        .with(State(scheduler))
        .with(State(cache))
        .with(State(analytics))
        .with(State(stats))
        .with(State(ghcr))
        .with(State(resolver_settings))
        .with(State(pow_admission))
        .with(State(site))
        .with(State(crate::turnstile::CfTurnstileVerifier::new(
            env_binding::required_string(env, TURNSTILE_SECRET_KEY_BINDING),
            env_binding::required_string(env, TURNSTILE_HOSTNAME_BINDING),
        )))
        .with(State(github_auth::GitHubTrustConfig {
            repo: env_binding::required_string(env, GITHUB_REPO_BINDING),
            oidc_audience: env_binding::required_string(env, STOW_OIDC_AUDIENCE_BINDING),
        }))
        .with(State(github_auth::Jwks::default()))
        .with(State(github_auth::PushVerdicts::default()))
        .with(State(webhook::WebhookSecret(env_binding::required_string(
            env,
            STOW_GITHUB_WEBHOOK_SECRET_BINDING,
        ))))
        .build();

    // The outermost response boundary — every error answer leaves here,
    // so `Cache-Control: no-store` is stamped in one place rather than
    // per handler (`no_store` module docs).
    crate::no_store::NoStoreOnError::new(router)
}

/// Every route that requires a trusted caller — the admin surface and
/// the scheduler lane — each wrapped in `gate` so a rate-limited GitHub
/// trust check answers 503 + `Retry-After` instead of the bare error
/// envelope.
fn trusted_nodes(gate: &github_auth::TrustRateLimitGate) -> [RouteNode; 3] {
    [
        "/api/v1/admin"
            .route((
                "/artifacts".at(api::list_artifact_records),
                "/coverage/{crate_name}".at(api::artifact_coverage),
                "/index/{target}/{rustc_version}"
                    .at(api::list_artifact_index)
                    .post(api::record_published_index),
                "/dispatch-freeze"
                    .at(api::get_dispatch_freeze)
                    .post(api::set_dispatch_freeze),
                "/queue".at(api::admin_queue_list),
                "/queue/retry".post(api::admin_queue_retry),
                "/queue/cancel".post(api::admin_queue_cancel),
                "/queue/promote".post(api::admin_queue_promote),
                "/queue/purge".post(api::admin_queue_purge),
                "/scheduler/migrate".post(api::admin_scheduler_migrate),
                "/scheduler/budget".post(api::admin_scheduler_budget),
                "/scheduler/budget/seed".post(api::admin_scheduler_budget_seed),
                "/status".at(api::admin_status),
            ))
            .with(gate.clone()),
        // Split out of the admin group to stay under the router's
        // route-tuple arity — the URLs are unchanged.
        "/api/v1/admin/artifacts"
            .route((
                "/sync".post(api::sync_artifacts),
                "/prune".post(api::prune_artifacts),
                "/{target}/{rustc_version}/{c_metadata}".at(api::inspect_artifact),
            ))
            .with(gate.clone()),
        "/api/v1/scheduler"
            .route((
                "/tasks/submit".post(api::submit_scheduler_tasks),
                "/requests/{request_id}/outcome".post(api::scheduler_request_outcome),
                "/status".at(api::scheduler_status),
            ))
            .with(gate.clone()),
    ]
}

/// Every route an unauthenticated caller can reach — artifact byte reads,
/// catalog search, miss-admission minting and enqueue redemption, the
/// human request lane, and the site pages. The anonymous-traffic breaker
/// is the zone's `stow maintenance: anonymous` WAF rule (`stow-admin
/// maintenance`), not a gate here — blocked requests never invoke the
/// Worker. The `scheduler_lanes` mounts share their path constants with
/// that rule's `scheduler lanes` scope, so the rule and the router can
/// never disagree on which lanes reach the Durable Object.
fn anonymous_nodes() -> Vec<RouteNode> {
    use stow_types::api::scheduler_lanes as lanes;
    vec![
        "/".at(site::index),
        "/install.sh".at(site::install_sh),
        "/install.ps1".at(site::install_ps1),
        "/stats".at(site::stats_page),
        lanes::REQUEST_PAGE.at(site::request_status),
        "/api/v1/bundles/{digest}".at(api::get_bundle),
        "/api/v1/crates".route((
            "/search".at(api::search_crates),
            "/{crate_name}/versions".at(api::crate_versions),
            "/{crate_name}/versions/{version}/features".at(api::crate_features),
        )),
        "/api/v1/index".route((
            "/{target}/{rustc_version}".at(api::get_index_slice_digest),
            "/{target}/{rustc_version}/{digest}".at(api::get_index_slice),
        )),
        lanes::ADMISSIONS.post(api::mint_miss_admissions),
        "/api/v1/stats".at(api::usage_stats),
        lanes::ENQUEUE.post(api::enqueue_admitted_task),
        lanes::REQUESTS.post(api::submit_crate_request),
        lanes::REQUEST.at(api::crate_request_status),
    ]
}
