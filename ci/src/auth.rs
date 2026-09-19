//! GitHub identity for calls into the edge's trusted endpoints.
//!
//! The edge accepts exactly two credential shapes on `Authorization:
//! Bearer`, and this process picks by environment:
//!
//! - **GitHub Actions OIDC JWT** — minted per-run inside the trusted
//!   `publish` job (`id-token: write`). The runner exports
//!   `ACTIONS_ID_TOKEN_REQUEST_URL`/`ACTIONS_ID_TOKEN_REQUEST_TOKEN`; one
//!   GET returns a JWT whose `aud` the edge pins next to the repo and
//!   workflow claims. Nothing is stored or shared — the token dies with
//!   the run.
//! - **GitHub user token** — the developer's own credential (`GH_TOKEN`/
//!   `GITHUB_TOKEN`, else `gh auth token`), used by `stow-build serve`
//!   and any local invocation. The edge checks it against the repo's
//!   collaborator permissions, so access follows GitHub role changes with
//!   nothing to rotate.

use std::fmt::Write as _;

use zenwave::{Client, ResponseExt};

const ACTIONS_ID_TOKEN_REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const STOW_OIDC_AUDIENCE_ENV: &str = "STOW_OIDC_AUDIENCE";

/// The Actions OIDC endpoint's response — `value` is the minted JWT.
#[derive(serde::Deserialize)]
struct OidcResponse {
    value: String,
}

/// The bearer credential the edge's trusted endpoints accept. In GitHub
/// Actions this is the run's OIDC JWT; anywhere else it is the developer's
/// GitHub user token.
pub async fn edge_bearer() -> stow_types::error::Result<String> {
    if let Some(token) = actions_oidc_token().await? {
        return Ok(token);
    }
    github_user_token().await
}

/// The Actions OIDC token for `STOW_OIDC_AUDIENCE`, or `None` when the
/// process is not running under a job granted `id-token: write`.
async fn actions_oidc_token() -> stow_types::error::Result<Option<String>> {
    let (Ok(request_url), Ok(request_token)) = (
        std::env::var(ACTIONS_ID_TOKEN_REQUEST_URL_ENV),
        std::env::var(ACTIONS_ID_TOKEN_REQUEST_TOKEN_ENV),
    ) else {
        return Ok(None);
    };
    let audience = std::env::var(STOW_OIDC_AUDIENCE_ENV).map_err(|_| {
        stow_types::stow_error!("{STOW_OIDC_AUDIENCE_ENV} is required to mint the edge OIDC token")
    })?;

    let mut client = zenwave::client();
    let response = client
        .get(format!("{request_url}&audience={}", urlencoded(&audience)))?
        .header("Authorization", format!("bearer {request_token}"))?
        .header("Accept", "application/json")?
        .await
        .map_err(|error| stow_types::stow_error!("mint actions OIDC token: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_types::stow_error!("actions OIDC endpoint rejected: {error}"))?;
    let body: OidcResponse = response
        .into_json()
        .await
        .map_err(|error| stow_types::stow_error!("decode actions OIDC token response: {error}"))?;
    // Mask before anything downstream could echo it — the JWT must never
    // reach the run log. `println!` is required: workflow commands are
    // stdout protocol, not diagnostics.
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        println!("::add-mask::{}", body.value);
    }
    Ok(Some(body.value))
}

/// The developer's GitHub credential: `GH_TOKEN`/`GITHUB_TOKEN` when set —
/// the precedence `gh` itself follows — else `gh auth token`.
async fn github_user_token() -> stow_types::error::Result<String> {
    for name in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(token) = std::env::var(name)
            && !token.is_empty()
        {
            return Ok(token);
        }
    }
    let output = async_process::Command::new("gh")
        .args(["auth", "token"])
        .output()
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "run `gh auth token` — install gh and `gh auth login`, or set GH_TOKEN: {error}"
            )
        })?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "`gh auth token` failed ({}): {} — run `gh auth login` or set GH_TOKEN",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let token = String::from_utf8(output.stdout)
        .map_err(|error| stow_types::stow_error!("`gh auth token` output is not UTF-8: {error}"))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(stow_types::stow_error!(
            "`gh auth token` printed nothing — run `gh auth login` or set GH_TOKEN"
        ));
    }
    Ok(token.to_owned())
}

/// Percent-encode a query value — the OIDC endpoint takes the audience as
/// a query parameter and `https://…` carries reserved characters.
fn urlencoded(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            byte => {
                write!(encoded, "%{byte:02X}").expect("write! into String is infallible");
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::urlencoded;

    #[test]
    fn urlencoded_escapes_reserved() {
        assert_eq!(
            urlencoded("https://stow.waterui.dev"),
            "https%3A%2F%2Fstow.waterui.dev"
        );
        assert_eq!(urlencoded("plain-value_1.0~x"), "plain-value_1.0~x");
    }
}
