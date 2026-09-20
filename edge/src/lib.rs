//! Edge endpoint and scheduler Durable Object for stow.
//!
//! Module layout is split by target so all cache/scheduler logic stays
//! host-testable: the unconditional modules compile (and run their unit
//! tests) on the host toolchain, while everything touching Cloudflare
//! bindings is `wasm32`-only.

// Host-testable core: pure logic plus backend-abstracted data access.
//
// Host builds compile these modules solely to run their unit tests — every
// runtime caller lives behind the wasm gate below, so dead-code analysis is
// only meaningful for the wasm target.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod admission;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod catalog;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod crates_io_index;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod db;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod dependency_resolver;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod errors;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod github_app;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod github_auth;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod lookup_key;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod miss_logger;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod registry_auth;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod resolver;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod rust_channel;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod scheduler;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod site;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod sql_batch;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod turnstile;

// Cloudflare-bound serving surface.
#[cfg(target_arch = "wasm32")]
mod api;
#[cfg(target_arch = "wasm32")]
mod cache;
#[cfg(target_arch = "wasm32")]
mod cf_http;
#[cfg(target_arch = "wasm32")]
mod console_log;
#[cfg(target_arch = "wasm32")]
mod crates_io;
#[cfg(target_arch = "wasm32")]
mod entry;
#[cfg(target_arch = "wasm32")]
mod env_binding;
#[cfg(target_arch = "wasm32")]
mod ghcr;
#[cfg(target_arch = "wasm32")]
mod runtime_settings;
#[cfg(target_arch = "wasm32")]
mod scheduler_client;
