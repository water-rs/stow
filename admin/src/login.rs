//! `stow-admin login` — the operator's edge credential, bound to their
//! GitHub account (stow#953).
//!
//! GitHub's device flow for the `stow-ci` App issues a user token
//! (`ghu_`) that expires after eight hours. It lives in the OS
//! credential store, never in a file or the environment, and it is the
//! only credential an operator's machine sends to the edge: the edge
//! authorizes it by its holder's push access to `water-rs/stow`, so a
//! token minted for someone without push serves nothing. A long-lived
//! `gh auth token`, with every scope gh was granted, never leaves the
//! machine for the edge.

use std::time::Duration;

use clap::Args;
use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi as _;
use serde::{Deserialize, Serialize};
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

/// The `stow-ci` App's OAuth client id — public, it identifies the App
/// in the device flow and authenticates nothing on its own.
const CLIENT_ID: &str = "Iv23liIBZ88bqYTJoVm7";
const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The credential-store entry: one operator token per OS user.
const SERVICE: &str = "dev.waterui.stow-admin";
const ACCOUNT: &str = "operator";
/// A token this close to expiry is treated as expired, so a command
/// never starts on a credential that dies mid-run.
const EXPIRY_MARGIN_SECS: i64 = 300;

#[derive(Args)]
pub struct LoginArgs {
    /// Forget the stored token instead of signing in.
    #[arg(long)]
    logout: bool,
}

/// What the credential store holds: the token and when GitHub said it
/// expires.
#[derive(Serialize, Deserialize)]
struct StoredToken {
    token: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct DeviceCodeRequest<'a> {
    client_id: &'a str,
}

#[derive(Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize)]
struct AccessTokenRequest<'a> {
    client_id: &'a str,
    device_code: &'a str,
    grant_type: &'a str,
}

/// GitHub answers a pending poll with 200 and an `error` field, so the
/// two shapes share one body.
#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
    error_description: Option<String>,
    interval: Option<u64>,
}

pub async fn run(args: LoginArgs) -> stow_types::error::Result<()> {
    let entry = entry()?;
    if args.logout {
        return match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(stow_error!("delete the stored operator token: {error}")),
        };
    }
    let code: DeviceAuthorization = post(
        DEVICE_CODE_URL,
        &DeviceCodeRequest {
            client_id: CLIENT_ID,
        },
    )
    .await?;
    tracing::info!(
        "open {} and enter {} to authorize stow-admin as your GitHub account",
        code.verification_uri,
        code.user_code
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = Duration::from_secs(code.interval);
    loop {
        tokio::time::sleep(interval).await;
        if tokio::time::Instant::now() >= deadline {
            return Err(stow_error!(
                "the device code expired before it was authorized — run `stow-admin login` again"
            ));
        }
        let answer: AccessTokenResponse = post(
            ACCESS_TOKEN_URL,
            &AccessTokenRequest {
                client_id: CLIENT_ID,
                device_code: &code.device_code,
                grant_type: DEVICE_GRANT,
            },
        )
        .await?;
        match (answer.access_token, answer.error.as_deref()) {
            (Some(token), _) => {
                let expires_in = answer.expires_in.ok_or_else(|| {
                    stow_error!(
                        "GitHub issued a non-expiring token — enable \"Expire user authorization tokens\" on the stow-ci App"
                    )
                })?;
                let stored = StoredToken {
                    token,
                    expires_at: now_unix() + expires_in,
                };
                let json = serde_json::to_string(&stored)
                    .map_err(|error| stow_error!("encode the operator token: {error}"))?;
                entry
                    .set_password(&json)
                    .map_err(|error| stow_error!("store the operator token: {error}"))?;
                tracing::info!("signed in; the token expires in {} h", expires_in / 3600);
                return Ok(());
            }
            (None, Some("authorization_pending")) => {}
            // RFC 8628 §3.5: every slow_down adds five seconds; GitHub
            // also sends the new interval.
            (None, Some("slow_down")) => {
                interval = answer
                    .interval
                    .map_or(interval + Duration::from_secs(5), Duration::from_secs);
            }
            (None, error) => {
                return Err(stow_error!(
                    "GitHub refused the device authorization: {} {}",
                    error.unwrap_or("no error code"),
                    answer.error_description.unwrap_or_default()
                ));
            }
        }
    }
}

/// The stored operator token, or an error naming `stow-admin login`
/// when there is none or it has expired.
pub fn stored_token() -> stow_types::error::Result<String> {
    let json = match entry()?.get_password() {
        Ok(json) => json,
        Err(keyring_core::Error::NoEntry) => {
            return Err(stow_error!(
                "not signed in — run `stow-admin login` to authorize as your GitHub account"
            ));
        }
        Err(error) => return Err(stow_error!("read the stored operator token: {error}")),
    };
    let stored: StoredToken = serde_json::from_str(&json)
        .map_err(|error| stow_error!("decode the stored operator token: {error}"))?;
    if stored.expires_at - EXPIRY_MARGIN_SECS <= now_unix() {
        return Err(stow_error!(
            "the operator token has expired — run `stow-admin login` again"
        ));
    }
    Ok(stored.token)
}

fn entry() -> stow_types::error::Result<Entry> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new();
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_keyring_store::Store::new();
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new();
    store
        .and_then(|store| store.build(SERVICE, ACCOUNT, None))
        .map_err(|error| stow_error!("open the OS credential store: {error}"))
}

async fn post<B: Serialize + Sync, T: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> stow_types::error::Result<T> {
    let mut client = zenwave::client();
    client
        .post(url)
        .and_then(|request| request.header("Accept", "application/json"))
        .and_then(|request| request.json_body(body))
        .map_err(|error| stow_error!("POST {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("POST {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("POST {url}: {error}"))?
        .into_json()
        .await
        .map_err(|error| stow_error!("decode {url}: {error}"))
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
