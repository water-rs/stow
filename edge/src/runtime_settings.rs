//! Runtime-tunable concurrency knobs for the edge worker.
//!
//! Defaults are conservative; operators can override via Cloudflare Workers
//! `vars` bindings without rebuilding the worker.

use crate::env_binding;
use wasm_bindgen::JsValue;

const STOW_MAX_EXPANDED_TASKS_BINDING: &str = "STOW_MAX_EXPANDED_TASKS";
const STOW_HUMAN_MAX_CLOSURE_BINDING: &str = "STOW_HUMAN_MAX_CLOSURE";

const DEFAULT_MAX_EXPANDED_TASKS: usize = 4096;
const DEFAULT_HUMAN_MAX_CLOSURE: usize = 150;

/// Concurrency knobs for admission minting and the request lane.
#[derive(Debug, Clone)]
pub struct ResolverSettings {
    /// Cap on the size of an expanded transitive graph; larger requests are rejected.
    pub max_expanded_tasks: usize,
    /// Largest dependency closure `POST /api/v1/requests` accepts; larger
    /// closures are refused with 422.
    pub human_max_closure: usize,
}

impl ResolverSettings {
    /// Read the settings from Cloudflare Workers env, falling back to defaults
    /// when a binding is unset or malformed.
    pub fn from_env(env: &JsValue) -> Self {
        Self {
            max_expanded_tasks: parse_usize(env, STOW_MAX_EXPANDED_TASKS_BINDING)
                .unwrap_or(DEFAULT_MAX_EXPANDED_TASKS),
            human_max_closure: parse_usize(env, STOW_HUMAN_MAX_CLOSURE_BINDING)
                .unwrap_or(DEFAULT_HUMAN_MAX_CLOSURE),
        }
    }
}

impl Default for ResolverSettings {
    fn default() -> Self {
        Self {
            max_expanded_tasks: DEFAULT_MAX_EXPANDED_TASKS,
            human_max_closure: DEFAULT_HUMAN_MAX_CLOSURE,
        }
    }
}

fn parse_usize(env: &JsValue, name: &str) -> Option<usize> {
    let raw = env_binding::optional_string(env, name)?;
    match raw.parse::<usize>() {
        Ok(value) if value > 0 => Some(value),
        Ok(_) => {
            tracing::warn!(binding = name, "ignoring zero-valued concurrency binding");
            None
        }
        Err(error) => {
            tracing::warn!(binding = name, %error, raw = %raw, "ignoring malformed concurrency binding");
            None
        }
    }
}
