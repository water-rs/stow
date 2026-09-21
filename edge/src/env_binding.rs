//! Typed readers for Cloudflare Workers string bindings.
//!
//! Thin wrappers over `skyzen_cloudflare::CfSecret::classic` (required) and a
//! `Reflect` probe (optional) that fail-fast on configuration errors at
//! worker startup.

use js_sys::Reflect;
use wasm_bindgen::JsValue;

/// Read a required string binding. Panics if the binding is missing or
/// not a string — these are configuration errors that must fail fast at
/// worker startup, not at request time.
pub fn required_string(env: &JsValue, binding_name: &str) -> String {
    skyzen_cloudflare::CfSecret::classic(env, binding_name).map_or_else(
        |error| panic!("{error}"),
        |secret| secret.expose().to_owned(),
    )
}

/// Read a required Analytics Engine dataset binding. Panics if the
/// binding is missing — configuration errors fail fast at worker startup.
pub fn required_analytics_dataset(
    env: &JsValue,
    binding_name: &str,
) -> skyzen_cloudflare::worker::AnalyticsEngineDataset {
    let value = Reflect::get(env, &JsValue::from_str(binding_name))
        .unwrap_or_else(|error| panic!("read binding '{binding_name}': {error:?}"));
    assert!(
        !(value.is_undefined() || value.is_null()),
        "missing Analytics Engine binding '{binding_name}'"
    );
    skyzen_cloudflare::worker::EnvBinding::get(value).unwrap_or_else(|error| {
        panic!("binding '{binding_name}' is not an Analytics Engine dataset: {error}")
    })
}

/// Read an optional string binding. Returns `None` when the binding is
/// undefined or null. Panics only if the binding is present but not a string.
pub fn optional_string(env: &JsValue, binding_name: &str) -> Option<String> {
    let value = Reflect::get(env, &JsValue::from_str(binding_name))
        .unwrap_or_else(|error| panic!("read binding '{binding_name}': {error:?}"));
    if value.is_undefined() || value.is_null() {
        return None;
    }
    Some(
        value
            .as_string()
            .unwrap_or_else(|| panic!("binding '{binding_name}' must be a string")),
    )
}

/// Read an optional `u32` binding. `None` when unset or malformed — a
/// malformed value warns and falls back to the caller's default, matching
/// the rest of the tunable bindings.
pub fn optional_u32(env: &JsValue, binding_name: &str) -> Option<u32> {
    let raw = optional_string(env, binding_name)?;
    match raw.parse::<u32>() {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(
                binding = binding_name,
                %error,
                raw = %raw,
                "ignoring malformed u32 binding"
            );
            None
        }
    }
}
