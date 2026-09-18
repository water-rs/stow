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
