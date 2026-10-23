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

/// `STOW_CF_ANALYTICS_SQL_BASE` — test-only override of the REST base
/// Analytics Engine SQL POSTs target. Production never sets it; a
/// mock/e2e harness points it at a loopback fixture.
pub const ANALYTICS_SQL_BASE_ENV: &str = "STOW_CF_ANALYTICS_SQL_BASE";

/// REST base the `analytics_engine/sql` POSTs target: [`API_BASE`],
/// unless [`ANALYTICS_SQL_BASE_ENV`] names a loopback fixture. The
/// loopback pin is a credential guard — `Authorization` carries the
/// account API token, so a remote override would exfiltrate it.
///
/// # Errors
/// The override is set but does not parse as a URL or names a
/// non-loopback host.
pub fn analytics_sql_base() -> stow_types::error::Result<String> {
    let Ok(base) = std::env::var(ANALYTICS_SQL_BASE_ENV) else {
        return Ok(API_BASE.to_owned());
    };
    loopback_sql_base(&base)
}

/// The `STOW_CF_ANALYTICS_SQL_BASE` loopback pin on one candidate URL.
fn loopback_sql_base(base: &str) -> stow_types::error::Result<String> {
    let parsed = url::Url::parse(base)
        .map_err(|error| stow_error!("{ANALYTICS_SQL_BASE_ENV} {base:?}: {error}"))?;
    let loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !loopback {
        return Err(stow_error!(
            "{ANALYTICS_SQL_BASE_ENV} must name a loopback host, got {base:?}"
        ));
    }
    Ok(base.trim_end_matches('/').to_owned())
}

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
    let envelope: Envelope<T> = graphql(token, query, variables).await?;
    envelope.into_account()
}

/// A `{"data": …, "errors": …}` answer to a `viewer { zones(…) { <T> } }`
/// query — the zone sibling of [`Envelope`].
#[derive(Debug, Deserialize)]
pub struct ZoneEnvelope<T> {
    /// Present on success.
    data: Option<ZoneViewer<T>>,
    /// Present on failure.
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Debug, Deserialize)]
struct ZoneViewer<T> {
    viewer: Zones<T>,
}

#[derive(Debug, Deserialize)]
struct Zones<T> {
    /// One entry per zone the filter matched — the tag names exactly one.
    zones: Vec<T>,
}

impl<T> ZoneEnvelope<T> {
    /// `data.viewer.zones[0]` with the same hard-error rule as
    /// [`Envelope::into_account`].
    ///
    /// # Errors
    /// GraphQL errors, or an answer that carries no zone.
    pub fn into_zone(self) -> Result<T, String> {
        if let Some(errors) = self.errors.filter(|errors| !errors.is_empty()) {
            let messages = errors
                .iter()
                .map(|error| error.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("Cloudflare GraphQL errors: {messages}"));
        }
        self.data
            .and_then(|data| data.viewer.zones.into_iter().next())
            .ok_or_else(|| "Cloudflare GraphQL answer carried no zone data".to_owned())
    }
}

/// POST `query` with `variables` to the GraphQL Analytics API and decode
/// the one zone it filters on.
///
/// # Errors
/// Transport, HTTP status, decode and GraphQL errors, as text.
pub async fn query_zone<V: Serialize + Sync, T: DeserializeOwned>(
    token: &str,
    query: &str,
    variables: &V,
) -> Result<T, String> {
    let envelope: ZoneEnvelope<T> = graphql(token, query, variables).await?;
    envelope.into_zone()
}

/// The shared GraphQL POST both envelope kinds decode.
async fn graphql<V: Serialize + Sync, T: DeserializeOwned>(
    token: &str,
    query: &str,
    variables: &V,
) -> Result<T, String> {
    let url = format!("{API_BASE}/graphql");
    let body = Request { query, variables };
    let mut client = zenwave::client().timeout(REQUEST_TIMEOUT);
    client
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
        .map_err(|error| format!("decode {url}: {error}"))
}

/// The Analytics Engine `FORMAT JSON` envelope — typed rows under
/// `data`, errors under `errors`. `stow_types::analytics` owns the row
/// shape; this envelope adds the `errors` arm an operator command
/// cannot afford to lose (a failed query beside empty data must be a
/// hard error, not zero rows).
#[derive(Debug, Deserialize)]
struct SqlEnvelope<T> {
    /// Queried rows — decode each numeric column with
    /// `stow_types::analytics::de_u64` / `de_f64` to match its type;
    /// `FORMAT JSON` quotes 64-bit integers.
    data: Vec<T>,
    /// Present on failure.
    errors: Option<Vec<GraphqlError>>,
}

/// Run `sql` against the account's Analytics Engine datasets and decode
/// the rows as `T` — a struct whose numeric fields carry the
/// `stow_types::analytics` deserializers.
///
/// # Errors
/// Transport, HTTP status, decode and API errors, as text.
pub async fn analytics_engine_sql<T: DeserializeOwned>(
    sql_base: &str,
    token: &str,
    account_id: &str,
    sql: &str,
) -> Result<Vec<T>, String> {
    let url = format!("{sql_base}/accounts/{account_id}/analytics_engine/sql");
    let mut client = zenwave::client().timeout(REQUEST_TIMEOUT);
    let request = client
        .post(&url)
        .and_then(|request| request.header("Authorization", format!("Bearer {token}")))
        .and_then(|request| {
            request
                .header("Content-Type", "text/plain")
                .map(|request| request.bytes_body(sql.as_bytes().to_vec()))
        })
        .map_err(|error| format!("POST {url}: {error}"))?;
    let envelope: SqlEnvelope<T> = request
        .await
        .map_err(|error| format!("POST {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| format!("POST {url}: {error}"))?
        .into_json()
        .await
        .map_err(|error| format!("decode {url}: {error}"))?;
    if let Some(errors) = envelope.errors.filter(|errors| !errors.is_empty()) {
        let messages = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("Analytics Engine SQL errors: {messages}"));
    }
    Ok(envelope.data)
}

#[cfg(test)]
mod tests {
    /// The override pin: loopback hosts pass (trailing slash trimmed),
    /// anything remote or unparseable is refused.
    #[test]
    fn analytics_sql_base_override_is_loopback_only() {
        assert_eq!(
            super::loopback_sql_base("http://127.0.0.1:9000/").unwrap(),
            "http://127.0.0.1:9000"
        );
        super::loopback_sql_base("http://localhost:1").unwrap();
        super::loopback_sql_base("http://[::1]:1").unwrap();
        for remote in [
            "https://api.cloudflare.com/client/v4",
            "http://10.0.0.1",
            "not a url",
        ] {
            super::loopback_sql_base(remote).expect_err(remote);
        }
    }
}
