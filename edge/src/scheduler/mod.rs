pub mod dispatch;
pub mod queue;

use skyzen_cloudflare::CfDurableSqlite;
use stow_types::api::{BuildCompleteReport, EnqueueRequest, MissBoost};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The Scheduler Durable Object.
///
/// A singleton DO that manages the build queue. Accessed by name "scheduler".
/// Uses built-in DO SQLite storage for persistence.
#[wasm_bindgen]
pub struct Scheduler {
    sql: CfDurableSqlite,
    env: JsValue,
}

#[wasm_bindgen]
impl Scheduler {
    #[wasm_bindgen(constructor)]
    pub fn new(state: JsValue, env: JsValue) -> Self {
        let sql = CfDurableSqlite::from_state(&state).expect("DO SQLite not available");

        // Initialize schema on first use
        if let Err(e) = queue::init_schema(&sql) {
            tracing::error!(error = %e, "failed to initialize scheduler schema");
        }

        Self { sql, env }
    }

    /// Handle incoming HTTP requests to the scheduler DO.
    ///
    /// Routes:
    /// - POST /enqueue — add build requests to queue
    /// - POST /complete — CI reports job completion
    /// - POST /boost — edge reports cache miss
    /// - GET /status — queue overview
    pub async fn fetch(&self, request: web_sys::Request) -> web_sys::Response {
        let url = request.url();
        let method = request.method();
        let path = url
            .split('/')
            .last()
            .unwrap_or("");

        let result = match (method.as_str(), path) {
            ("POST", "enqueue") => self.handle_enqueue(request).await,
            ("POST", "complete") => self.handle_complete(request).await,
            ("POST", "boost") => self.handle_boost(request).await,
            ("GET", "status") => self.handle_status().await,
            _ => json_response(404, r#"{"error":"not found"}"#),
        };

        match result {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(error = %e, "scheduler handler error");
                json_response(500, r#"{"error":"internal error"}"#)
                    .unwrap_or_else(|_| panic!("failed to create error response"))
            }
        }
    }
}

impl Scheduler {
    async fn handle_enqueue(&self, request: web_sys::Request) -> Result<web_sys::Response, String> {
        let body = read_body(&request).await?;
        let requests: Vec<EnqueueRequest> =
            serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))?;

        let inserted = queue::enqueue(&self.sql, &requests)?;

        // Try to dispatch after enqueue
        self.try_dispatch().await;

        json_response(
            200,
            &serde_json::json!({"inserted": inserted}).to_string(),
        )
    }

    async fn handle_complete(&self, request: web_sys::Request) -> Result<web_sys::Response, String> {
        let body = read_body(&request).await?;
        let report: BuildCompleteReport =
            serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))?;

        queue::complete(&self.sql, &report)?;

        // Try to dispatch next tasks after completion
        self.try_dispatch().await;

        json_response(200, r#"{"ok":true}"#)
    }

    async fn handle_boost(&self, request: web_sys::Request) -> Result<web_sys::Response, String> {
        let body = read_body(&request).await?;
        let boost: MissBoost =
            serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))?;

        queue::boost(&self.sql, &boost)?;

        json_response(200, r#"{"ok":true}"#)
    }

    async fn handle_status(&self) -> Result<web_sys::Response, String> {
        let status = queue::status(&self.sql)?;
        let body = serde_json::to_string(&status).map_err(|e| format!("serialize: {e}"))?;
        json_response(200, &body)
    }

    async fn try_dispatch(&self) {
        let gh_token = get_env_var(&self.env, "GITHUB_TOKEN").unwrap_or_default();
        let repo = get_env_var(&self.env, "GITHUB_REPO").unwrap_or_default();

        if gh_token.is_empty() || repo.is_empty() {
            tracing::warn!("missing GITHUB_TOKEN or GITHUB_REPO, skipping dispatch");
            return;
        }

        let tasks = match queue::pop_highest_priority(&self.sql, 5) {
            Ok(tasks) => tasks,
            Err(e) => {
                tracing::error!(error = %e, "failed to pop tasks");
                return;
            }
        };

        for (task_id, crate_name, version, target) in tasks {
            if let Err(e) =
                dispatch::trigger_build(&task_id, &crate_name, &version, &target, &gh_token, &repo)
                    .await
            {
                tracing::error!(task_id, error = %e, "dispatch failed");
            }
        }
    }
}

fn get_env_var(env: &JsValue, name: &str) -> Option<String> {
    js_sys::Reflect::get(env, &JsValue::from_str(name))
        .ok()
        .and_then(|v| v.as_string())
}

async fn read_body(request: &web_sys::Request) -> Result<Vec<u8>, String> {
    let promise = request
        .array_buffer()
        .map_err(|e| format!("body read: {e:?}"))?;
    let buffer = JsFuture::from(promise)
        .await
        .map_err(|e| format!("body await: {e:?}"))?;
    let array = js_sys::Uint8Array::new(&buffer);
    Ok(array.to_vec())
}

fn json_response(status: u16, body: &str) -> Result<web_sys::Response, String> {
    let init = web_sys::ResponseInit::new();
    init.set_status(status);

    let headers = web_sys::Headers::new().map_err(|e| format!("headers: {e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("header set: {e:?}"))?;
    init.set_headers(&headers);

    web_sys::Response::new_with_opt_str_and_init(Some(body), &init)
        .map_err(|e| format!("response: {e:?}"))
}
