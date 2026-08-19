//! Typed readers for Cloudflare Workers string bindings.
//!
//! Thin wrappers over `skyzen_cloudflare::{required_secret, optional_secret}`
//! that fail-fast on configuration errors at worker startup.

use wasm_bindgen::JsValue;

/// Read a required string binding. Panics if the binding is missing or
/// not a string — these are configuration errors that must fail fast at
/// worker startup, not at request time.
pub fn required_string(env: &JsValue, binding_name: &str) -> String {
    skyzen_cloudflare::required_secret(env, binding_name)
        .unwrap_or_else(|error| panic!("{error}"))
}

/// Read an optional string binding. Returns `None` when the binding is
/// undefined or null. Panics only if the binding is present but not a string.
pub fn optional_string(env: &JsValue, binding_name: &str) -> Option<String> {
    skyzen_cloudflare::optional_secret(env, binding_name)
        .unwrap_or_else(|error| panic!("{error}"))
}
