//! Cloudflare's v4 API as `stow-admin` reads it: the account API token,
//! the REST base, and the GraphQL Analytics query every analytics reader
//! (`watchdog`, `deploy verdict`) sends through.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stow_types::stow_error;
use zenwave::{Client as _, ResponseExt as _};

/// The v4 REST base; GraphQL, Analytics Engine SQL and Email Sending all
/// hang off it.
pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The environment variable carrying the account API token.
pub const API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// How long one analytics POST may take before it counts as failed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

/// The account API token from [`API_TOKEN_ENV`].
///
/// # Errors
/// The variable is unset.
pub fn api_token() -> stow_types::error::Result<String> {
    std::env::var(API_TOKEN_ENV).map_err(|_| stow_error!("missing {API_TOKEN_ENV}"))
}

/// One GraphQL request body.
#[derive(Debug, Serialize)]
struct Request<'a, V> {
    query: &'a str,
    variables: &'a V,
}

/// A `{"data": …, "errors": …}` answer to a `viewer { accounts(…) { <T> } }`
/// query — the shape every analytics query shares.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    /// Present on success.
    data: Option<Viewer<T>>,
    /// Present on failure — Cloudflare reports field errors here,
    /// sometimes alongside partial `data`.
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Debug, Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct Viewer<T> {
    viewer: Accounts<T>,
}

#[derive(Debug, Deserialize)]
struct Accounts<T> {
    /// One entry per account the filter matched — the tag names exactly one.
    accounts: Vec<T>,
}

impl<T> Envelope<T> {
    /// `data.viewer.accounts[0]`. A non-empty `errors` array is a hard
    /// error even beside partial data — never a partial read.
    ///
    /// # Errors
    /// GraphQL errors, or an answer that carries no account.
    pub fn into_account(self) -> Result<T, String> {
        if let Some(errors) = self.errors.filter(|errors| !errors.is_empty()) {
            let messages = errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("Cloudflare GraphQL errors: {messages}"));
        }
        self.data
            .and_then(|data| data.viewer.accounts.into_iter().next())
            .ok_or_else(|| "Cloudflare GraphQL answer carried no account data".to_owned())
    }
}

/// POST `query` with `variables` to the GraphQL Analytics API and decode
/// the one account it filters on.
///
/// # Errors
/// Transport, HTTP status, decode and GraphQL errors, as text.
pub async fn query_account<V: Serialize + Sync, T: DeserializeOwned>(
    token: &str,
    query: &str,
    variables: &V,
) -> Result<T, String> {
    let url = format!("{API_BASE}/graphql");
    let body = Request { query, variables };
    let mut client = zenwave::client().timeout(REQUEST_TIMEOUT);
    let envelope: Envelope<T> = client
        .post(&url)
        .and_then(|request| request.header("Authorization", format!("Bearer {token}")))
        .and_then(|request| request.json_body(&body))
        .map_err(|error| format!("POST {url}: {error}"))?
        .await
        .map_err(|error| format!("POST {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| format!("POST {url}: {error}"))?
        .into_json()
        .await
        .map_err(|error| format!("decode {url}: {error}"))?;
    envelope.into_account()
}
