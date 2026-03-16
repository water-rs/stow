//! Edge endpoint and scheduler Durable Object for stow.

mod api;
mod cache;
mod db;
mod ghcr;
mod miss_logger;
mod scheduler;

use js_sys::Reflect;
use skyzen::routing::{CreateRouteNode, Route, Router};
use skyzen::runtime::wasm::current_env;
use skyzen::utils::State;
use skyzen::Method;
use skyzen_cloudflare::{CfCache, CfD1, CfDurableNamespace};
use skyzen_services::Db;
use wasm_bindgen::JsValue;

use crate::api::GhcrConfig;

const STOW_DB_BINDING: &str = "STOW_DB";
const SCHEDULER_BINDING: &str = "SCHEDULER";
const GHCR_TOKEN_BINDING: &str = "GHCR_TOKEN";
const GHCR_BASE_URL_BINDING: &str = "GHCR_BASE_URL";

#[skyzen::main]
fn worker() -> Router {
    let env = current_env().unwrap_or_else(|| panic!("Cloudflare Workers env is unavailable"));
    let d1 = CfD1::from_env(&env, STOW_DB_BINDING)
        .unwrap_or_else(|error| panic!("failed to load D1 binding '{STOW_DB_BINDING}': {error}"));
    let db = Db::new(d1.clone());
    let scheduler = CfDurableNamespace::from_env(&env, SCHEDULER_BINDING).unwrap_or_else(|error| {
        panic!("failed to load Durable Object binding '{SCHEDULER_BINDING}': {error}")
    });
    let cache = CfCache::default();
    let ghcr = GhcrConfig {
        token: read_string_binding(&env, GHCR_TOKEN_BINDING),
        base_url: read_optional_string_binding(&env, GHCR_BASE_URL_BINDING)
            .unwrap_or_else(|| ghcr::default_base_url().to_owned()),
    };

    Route::new((
        "/api/v1/artifacts".route((
            "/{target}/{rustc_version}/{c_metadata}".at(api::get_artifact),
            "/{target}/{rustc_version}/{c_metadata}"
                .endpoint(Method::HEAD, skyzen::handler::into_endpoint(api::check_artifact)),
        )),
        "/api/v1/catalog".route((
            "/graph".post(api::analyze_dependency_graph),
        )),
        "/api/v1/status".route((
            "/{crate_name}".at(api::get_status),
        )),
    ))
    .with(db)
    .with(State(scheduler))
    .with(State(cache))
    .with(State(ghcr))
    .build()
}

fn read_string_binding(env: &JsValue, binding_name: &str) -> String {
    let value = Reflect::get(env, &JsValue::from_str(binding_name)).unwrap_or_else(|_| {
        panic!("failed to read Cloudflare Workers binding '{binding_name}'")
    });

    value.as_string().unwrap_or_else(|| {
        panic!("Cloudflare Workers binding '{binding_name}' must be a string secret")
    })
}

fn read_optional_string_binding(env: &JsValue, binding_name: &str) -> Option<String> {
    let value = Reflect::get(env, &JsValue::from_str(binding_name)).ok()?;
    if value.is_undefined() || value.is_null() {
        return None;
    }
    value.as_string().or_else(|| {
        panic!("Cloudflare Workers binding '{binding_name}' must be a string");
    })
}
