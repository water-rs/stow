//! Cloudflare Workers bootstrap: binds D1, the scheduler Durable Object,
//! the CF cache, and GHCR config, then mounts the public API routes.

use skyzen::Method;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::runtime::wasm::current_env;
use skyzen::utils::State;
use skyzen_cloudflare::{CfCache, CfD1, CfDurableNamespace};
use skyzen_services::Db;

use crate::api::GhcrConfig;
use crate::{api, env_binding, ghcr, runtime_settings};

const STOW_DB_BINDING: &str = "STOW_DB";
const SCHEDULER_BINDING: &str = "SCHEDULER";
const SCHEDULER_AUTH_TOKEN_BINDING: &str = "SCHEDULER_AUTH_TOKEN";
const REGISTER_AUTH_TOKEN_BINDING: &str = "REGISTER_AUTH_TOKEN";
const GHCR_TOKEN_BINDING: &str = "GHCR_TOKEN";
const GHCR_BASE_URL_BINDING: &str = "GHCR_BASE_URL";

#[skyzen::main]
fn worker() -> Router {
    let env = current_env().unwrap_or_else(|| panic!("Cloudflare Workers env is unavailable"));
    let d1 = CfD1::from_env(&env, STOW_DB_BINDING)
        .unwrap_or_else(|error| panic!("failed to load D1 binding '{STOW_DB_BINDING}': {error}"));
    let db = Db::new(d1);
    let scheduler = CfDurableNamespace::from_env(&env, SCHEDULER_BINDING).unwrap_or_else(|error| {
        panic!("failed to load Durable Object binding '{SCHEDULER_BINDING}': {error}")
    });
    let cache = CfCache::default();
    let ghcr = GhcrConfig {
        token: env_binding::required_string(&env, GHCR_TOKEN_BINDING),
        base_url: env_binding::optional_string(&env, GHCR_BASE_URL_BINDING)
            .unwrap_or_else(|| ghcr::default_base_url().to_owned()),
    };
    let resolver_settings = runtime_settings::ResolverSettings::from_env(&env);

    Route::new((
        "/api/v1/artifacts".route((
            "/{target}/{rustc_version}/{c_metadata}".at(api::get_artifact),
            "/semantic".post(api::get_semantic_artifact),
            "/batch".post(api::get_artifact_batch),
            "/{target}/{rustc_version}/{c_metadata}".endpoint(
                Method::HEAD,
                skyzen::handler::into_endpoint(api::check_artifact),
            ),
        )),
        "/api/v1/admin".route((
            "/artifacts/register".post(api::register_artifacts),
        )),
        "/api/v1/catalog".route((
            "/graph".post(api::analyze_dependency_graph),
            "/resolve-lockfile".post(api::resolve_lockfile),
        )),
        "/api/v1/scheduler".route((
            "/tasks/submit".post(api::submit_scheduler_tasks),
            "/complete".post(api::complete_build),
            "/status".at(api::scheduler_status),
        )),
    ))
    .with(db)
    .with(State(scheduler))
    .with(State(cache))
    .with(State(ghcr))
    .with(State(resolver_settings))
    .with(State(api::SchedulerApiAccess {
        auth_token: env_binding::optional_string(&env, SCHEDULER_AUTH_TOKEN_BINDING),
    }))
    .with(State(api::RegisterApiAccess {
        auth_token: env_binding::optional_string(&env, REGISTER_AUTH_TOKEN_BINDING),
    }))
    .build()
}
