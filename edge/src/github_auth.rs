//! GitHub-identity authentication for the trusted write surface.
//!
//! The scheduler-control and artifact-register endpoints previously sat
//! behind two long-lived shared secrets (`x-stow-scheduler-token`,
//! `x-stow-register-token`). Both are replaced by GitHub identity on a
//! single `Authorization: Bearer` header — nothing is stored anywhere:
//!
//! - **GitHub Actions OIDC JWT** — the `build-crate.yml` workflow mints a
//!   token per run (`id-token: write`); the edge verifies the RS256
//!   signature against GitHub's JWKS and pins `iss`, `aud`, `repository`,
//!   and the workflow ref. Only dispatched `build-crate.yml` runs can ever
//!   satisfy the pin — the workflow's only trigger is `workflow_dispatch`
//!   on `main`, and a fork's runs carry its own `repository` claim.
//! - **Repo-push credential** — the admin path and non-OIDC CI calls:
//!   the edge asks `GET /repos/{repo}` what the credential's own
//!   permissions are and requires `push` (which `admin` implies). That
//!   shape covers user tokens (`gh auth token`), fine-grained PATs, and
//!   Actions `GITHUB_TOKEN` installation tokens alike — the last is how
//!   the mock-e2e job drives a local edge. No bespoke secret exists to
//!   leak or rotate.
//!
//! Signature verification and claims validation are pure and host-tested;
//! only the two upstream GETs (JWKS, repo permission) go through the
//! injectable [`GitHubTrustApi`].

use serde::Deserialize;
use sha2::Digest as _;

/// The OIDC issuer every GitHub Actions token carries.
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// GitHub's OIDC signing keys endpoint.
const OIDC_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// The workflow whose runs may drive the CI-write endpoints.
const BUILD_WORKFLOW_FILE: &str = "build-crate.yml";

/// Clock-skew allowance on `exp`/`nbf` — GitHub's tokens are minted seconds
/// before use, so a minute is already generous.
const CLOCK_LEEWAY_SECS: i64 = 60;

/// A caller that cleared the trust check. Carried into tracing so the
/// register/complete logs name *who* wrote rather than "someone with the
/// token".
#[derive(Debug, Clone)]
pub enum TrustedCaller {
    /// A GitHub Actions OIDC identity.
    Actions {
        /// `owner/repo/.github/workflows/<file>.yml@refs/...` of the job.
        job_workflow_ref: String,
        /// The workflow run id, for correlating a register back to its run.
        run_id: String,
    },
    /// A GitHub credential that proved push access to the repo — a user
    /// token (label is the login) or an installation token such as the
    /// `GITHUB_TOKEN` the mock-e2e job drives the local edge with.
    Push {
        /// The token owner's GitHub login, or the credential class when
        /// the token cannot call user endpoints (app tokens 403 on
        /// `/user`).
        label: String,
    },
}

impl std::fmt::Display for TrustedCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Actions {
                job_workflow_ref,
                run_id,
            } => write!(f, "actions:{job_workflow_ref} run {run_id}"),
            Self::Push { label } => write!(f, "push:{label}"),
        }
    }
}

/// Which callers a handler accepts. Every policy admits a credential that
/// proves push access to the repo — the local dev loop and `stow-admin`
/// both run under the developer's own GitHub identity. The policies differ
/// in how tightly OIDC callers are pinned.
#[derive(Debug, Clone, Copy)]
pub enum Policy {
    /// OIDC only from `build-crate.yml` on `refs/heads/main` — artifact
    /// registration and completion reports. The machine path that writes
    /// `artifacts` rows stays pinned to the exact identity the cosign
    /// signature asserts.
    BuildWorkflow,
    /// OIDC from any workflow inside the trusted repo — scheduler task
    /// submission (the `preheat-admin.yml` workflow uses this).
    RepoWriter,
}

/// Non-secret trust configuration (worker vars).
#[derive(Debug, Clone)]
pub struct GitHubTrustConfig {
    /// `owner/repo` every credential must resolve inside.
    pub repo: String,
    /// The `aud` the CI side requests when it mints its OIDC token.
    pub oidc_audience: String,
}

/// Ways authentication can fail. `Unauthorized` means the credential itself
/// did not clear; `Upstream` means GitHub could not be consulted — kept
/// distinct so an upstream outage is not misread as a bad credential.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The credential was absent, malformed, or failed its check.
    #[error("unauthorized")]
    Unauthorized,
    /// A GitHub/JWKS fetch or response failed.
    #[error("github trust upstream: {0}")]
    Upstream(String),
}

/// The HTTP surface the auth layer needs. The wasm impl calls GitHub through
/// the worker fetch API; tests substitute a stub so every policy branch stays
/// host-verified. `Sync` + `Send` bounds mirror `CratesIo`: `&impl
/// GitHubTrustApi` must stay sendable across awaits inside extractors.
pub trait GitHubTrustApi: Sync {
    /// The current GitHub Actions OIDC signing keys.
    fn jwks(&self) -> impl Future<Output = Result<JwkSet, AuthError>> + Send;
    /// A caller label for `token` when it has push access to `repo`,
    /// `None` when the token is valid but lacks push (or is invalid).
    fn repo_push_login(
        &self,
        token: &str,
        repo: &str,
    ) -> impl Future<Output = Result<Option<String>, AuthError>> + Send;
}

/// Authenticate an `Authorization: Bearer` credential under `policy`.
///
/// JWT-shaped credentials (a `kid`+`alg` header) take the OIDC path; every
/// other shape is treated as a GitHub user token and — when the policy
/// allows user callers — checked against the repo's collaborator
/// permissions.
pub async fn authenticate(
    config: &GitHubTrustConfig,
    api: &impl GitHubTrustApi,
    bearer: &str,
    policy: Policy,
    now_unix: i64,
) -> Result<TrustedCaller, AuthError> {
    if looks_like_jwt(bearer) {
        return authenticate_oidc(config, api, bearer, policy, now_unix).await;
    }
    if !looks_like_user_token(bearer) {
        return Err(AuthError::Unauthorized);
    }
    api.repo_push_login(bearer, &config.repo)
        .await?
        .map_or(Err(AuthError::Unauthorized), |label| {
            Ok(TrustedCaller::Push { label })
        })
}

/// The OIDC path: fetch JWKS, verify RS256, then check every claim that
/// pins the token to this deployment — issuer, audience, repo, expiry —
/// and the policy's workflow pin.
async fn authenticate_oidc(
    config: &GitHubTrustConfig,
    api: &impl GitHubTrustApi,
    token: &str,
    policy: Policy,
    now_unix: i64,
) -> Result<TrustedCaller, AuthError> {
    let (header, signing_input, signature, claims) = decode_jwt(token)?;
    let jwks = api.jwks().await?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == header.kid && key.kty == "RSA")
        .ok_or(AuthError::Unauthorized)?;
    verify_rs256(key, signing_input.as_bytes(), &signature)?;

    if claims.iss != OIDC_ISSUER
        || !claims.aud.contains(&config.oidc_audience)
        || claims.exp + CLOCK_LEEWAY_SECS <= now_unix
        || claims
            .nbf
            .is_some_and(|nbf| nbf - CLOCK_LEEWAY_SECS > now_unix)
        || claims.repository != config.repo
    {
        return Err(AuthError::Unauthorized);
    }
    let workflow_prefix = format!("{}/.github/workflows/", config.repo);
    if !claims.job_workflow_ref.starts_with(&workflow_prefix) {
        return Err(AuthError::Unauthorized);
    }
    if matches!(policy, Policy::BuildWorkflow)
        && claims.job_workflow_ref
            != format!("{workflow_prefix}{BUILD_WORKFLOW_FILE}@refs/heads/main")
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(TrustedCaller::Actions {
        job_workflow_ref: claims.job_workflow_ref,
        run_id: claims.run_id,
    })
}

/// GitHub's credential formats are published: `ghp_`/`github_pat_` are
/// personal tokens, `gho_` OAuth, `ghu_`/`ghs_`/`ghr_` app and refresh
/// tokens. Anything else is not a GitHub credential — rejecting it here
/// keeps a garbage bearer from fanning out to the permission API.
fn looks_like_user_token(token: &str) -> bool {
    const PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"];
    PREFIXES.iter().any(|prefix| token.starts_with(prefix))
}

/// Three base64url segments with a decodable JSON header carrying `kid` —
/// GitHub's OIDC tokens always set one; user tokens never parse as JWTs at
/// all, so a failed header decode routes to the token path rather than a
/// hard rejection.
fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(_), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    b64url_decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<JwtHeader>(&bytes).ok())
        .is_some_and(|header| header.alg == "RS256")
}

/// The JWT header fields the verifier uses.
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// The claims subset the policy pins.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    iss: String,
    #[serde(default)]
    aud: Audience,
    exp: i64,
    #[serde(default)]
    nbf: Option<i64>,
    repository: String,
    job_workflow_ref: String,
    #[serde(default)]
    run_id: String,
}

/// `aud` arrives as a string for a single audience and an array for many.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum Audience {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, wanted: &str) -> bool {
        match self {
            Self::None => false,
            Self::One(aud) => aud == wanted,
            Self::Many(auds) => auds.iter().any(|aud| aud == wanted),
        }
    }
}

/// One RSA signing key from GitHub's JWKS.
#[derive(Debug, Deserialize)]
pub struct Jwk {
    /// Key type — always `RSA` on GitHub's set.
    pub kty: String,
    /// Key id matching the JWT header.
    pub kid: String,
    /// Base64url-unsigned modulus.
    pub n: String,
    /// Base64url-unsigned exponent.
    pub e: String,
}

/// The JWKS document.
#[derive(Debug, Deserialize)]
pub struct JwkSet {
    /// Signing keys, newest first.
    pub keys: Vec<Jwk>,
}

/// Split a compact JWT into its signing input, signature, and typed
/// claims — no trust yet, just shape.
fn decode_jwt(token: &str) -> Result<(JwtHeader, String, Vec<u8>, OidcClaims), AuthError> {
    let mut parts = token.splitn(3, '.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Unauthorized);
    };
    let header: JwtHeader =
        serde_json::from_slice(&b64url_decode(header_b64)?).map_err(|_| AuthError::Unauthorized)?;
    if header.alg != "RS256" {
        return Err(AuthError::Unauthorized);
    }
    let claims: OidcClaims = serde_json::from_slice(&b64url_decode(payload_b64)?)
        .map_err(|_| AuthError::Unauthorized)?;
    let signature = b64url_decode(signature_b64)?;
    Ok((
        header,
        format!("{header_b64}.{payload_b64}"),
        signature,
        claims,
    ))
}

/// SHA-256's DER `DigestInfo` prefix — `Pkcs1v15Sign::new::<D>` would couple
/// us to rsa's `digest` version, which edge's sha2 release does not match,
/// so the `DigestInfo` is assembled from the published constant instead.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// The value RS256 actually signs: `DigestInfo(SHA-256) || digest`.
fn sha256_digest_info(signing_input: &[u8]) -> Vec<u8> {
    let digest = sha2::Sha256::digest(signing_input);
    let mut framed = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + digest.len());
    framed.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    framed.extend_from_slice(&digest);
    framed
}

/// Verify the RS256 signature — JWK modulus/exponent to a public key, then
/// PKCS#1 v1.5 over the framed digest of `header.payload`.
fn verify_rs256(jwk: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<(), AuthError> {
    let n = rsa::BigUint::from_bytes_be(&b64url_decode(&jwk.n)?);
    let e = rsa::BigUint::from_bytes_be(&b64url_decode(&jwk.e)?);
    let key = rsa::RsaPublicKey::new(n, e).map_err(|_| AuthError::Unauthorized)?;
    key.verify(
        rsa::Pkcs1v15Sign::new_unprefixed(),
        &sha256_digest_info(signing_input),
        signature,
    )
    .map_err(|_| AuthError::Unauthorized)
}

/// Base64url-decode, tolerating the absent padding JWKS/JWT fields omit.
fn b64url_decode(value: &str) -> Result<Vec<u8>, AuthError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthError::Unauthorized)
}

#[cfg(target_arch = "wasm32")]
pub use cf_impl::CfGitHubTrust;

/// The production [`GitHubTrustApi`]: two GETs through the worker fetch
/// API. No JWKS cache — the authed surface sees a handful of calls per
/// build, and a cached keyset is state a malformed response could poison.
#[cfg(target_arch = "wasm32")]
mod cf_impl {
    use super::{AuthError, GitHubTrustApi, JwkSet, OIDC_JWKS_URL};
    use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};

    /// Fetches GitHub's OIDC JWKS and repo-permission checks through the
    /// worker's outbound fetch.
    pub struct CfGitHubTrust;

    /// GET `url` with the given bearer (empty string sends none) and parse
    /// the JSON body. 404/401/403 return `None` — for permission checks
    /// that is "no", for JWKS the caller turns it into `Upstream`.
    async fn get_json<T: serde::de::DeserializeOwned>(
        url: &str,
        bearer: &str,
    ) -> Result<Option<T>, AuthError> {
        let auth = format!("Bearer {bearer}");
        let headers: &[(&str, &str)] = if bearer.is_empty() {
            &[("User-Agent", "stow-edge"), ("Accept", "application/json")]
        } else {
            &[
                ("User-Agent", "stow-edge"),
                ("Accept", "application/json"),
                ("Authorization", auth.as_str()),
            ]
        };
        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Get,
                url,
                headers,
                None,
            )
            .map_err(|error| AuthError::Upstream(format!("build request: {error}")))?,
        );
        let mut response = SendWrapper::new(
            skyzen_cloudflare::CfFetch
                .request(&request)
                .await
                .map_err(|error| AuthError::Upstream(format!("fetch {url}: {error}")))?,
        );
        let status = response.status_code();
        if matches!(status, 401 | 403 | 404) {
            return Ok(None);
        }
        let text = response
            .text()
            .into_send()
            .await
            .map_err(|error| AuthError::Upstream(format!("read {url} body: {error}")))?;
        if !(200..300).contains(&status) {
            return Err(AuthError::Upstream(format!("{url} -> {status}")));
        }
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| AuthError::Upstream(format!("decode {url}: {error}")))
    }

    #[derive(serde::Deserialize)]
    struct GitHubUser {
        login: String,
    }

    #[derive(serde::Deserialize)]
    struct RepoResponse {
        #[serde(default)]
        permissions: RepoPermissions,
    }

    /// `GET /repos/{repo}` reports the calling credential's own effective
    /// access — `admin` implies `push` — for user tokens, fine-grained
    /// PATs, and Actions `GITHUB_TOKEN` installation tokens alike.
    #[derive(Default, serde::Deserialize)]
    struct RepoPermissions {
        #[serde(default)]
        push: bool,
        #[serde(default)]
        admin: bool,
    }

    /// Label for the log when `/user` is unreachable — app and
    /// installation tokens (`ghs_`, `GITHUB_TOKEN`) 403 on user endpoints.
    fn credential_class(token: &str) -> &'static str {
        if token.starts_with("ghs_") {
            "github-app-installation"
        } else if token.starts_with("github_pat_") {
            "fine-grained-pat"
        } else {
            "unknown-credential"
        }
    }

    impl GitHubTrustApi for CfGitHubTrust {
        async fn jwks(&self) -> Result<JwkSet, AuthError> {
            get_json::<JwkSet>(OIDC_JWKS_URL, "")
                .await?
                .ok_or_else(|| AuthError::Upstream(format!("{OIDC_JWKS_URL} not found")))
        }

        async fn repo_push_login(
            &self,
            token: &str,
            repo: &str,
        ) -> Result<Option<String>, AuthError> {
            let url = format!("https://api.github.com/repos/{repo}");
            let Some(repo_info) = get_json::<RepoResponse>(&url, token).await? else {
                return Ok(None);
            };
            if !(repo_info.permissions.push || repo_info.permissions.admin) {
                return Ok(None);
            }
            let label = get_json::<GitHubUser>("https://api.github.com/user", token)
                .await?
                .map_or_else(|| credential_class(token).to_owned(), |user| user.login);
            Ok(Some(label))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use std::sync::Mutex;

    const NOW: i64 = 1_800_000_000;

    /// Test-only RSA keypair — generated for this file, trusted by nobody.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCvpT7SKFU7bFwh\n00io+azXHJeHgs8ndSr8LwAddqeXzs4d2opqaHXKl4QctxMx7mDFNxv2odvluqGI\nYKmjRjlCgMOiCVNfxCCEZK+SMN2MMivKiXErYPBsixX4K0HHrg2ItispOz30EwKy\nNCK2QFYPZyxgRvxMbCx36/ZycTk3Yi89q9YfIHuYXZhYMYoiqg9Uxv780rKwiV9Z\na4e7wh13KApNgwrov3ane+L8qwmBg9laN/zxIII6Gq6gAKvn3Qe5LUwjdWIhlTgc\ncf1DSUR9V4grUoqIZfQTDJwIFgcnyGi/YIJmGebQjXBSuZUM8/31Gt1M9si8V4Mx\nQMpyxLPRAgMBAAECgf8ugN3ySzaAzIXdAnh8zk8ec6wXHoiD+xyaD3711+Mzrihp\nHJNS7JVDLi4YibiwODQmx8uJYOnZ8E07lareCErgtYp4slMUXf3RrS9O0aYlXRlT\noXdrLpVlYp7r+puep2BLe7SeAk7iXH7EFw6F/BtDGzLJfAHVazrHGRIuNal8s5fz\nXw7Yy02gUN13yjkX7GlGFGgTPwxVNqkwRM9rMxwMsPQbQZbXZNqGsAWnecEfLnQ+\nsPu8S0WeGG4pyo39xEdLBzE4hQ8ugvun20MjVgSVbAZjY/TCJ3xRWWh3ENpjfM4X\ntW9+/tHuxrz9o+e7hH5s6fHUFdj2uZjZ55DgYUECgYEA9pm79cZBar+hCpjJaR26\ndRKScFNIphax2axmAMhRhfHGT0uJAxZm3hdTg1HvXnPq8VMeP7lBFngZpPkDfbl7\n3O1yMlTXeVPyKFx88fu76lyplijhh1VoCqvkaVWjjPP+4/j6Uuq9nC7ESzEj0UN3\n0ChtUbAqorTzQt9pIEGoQuECgYEAtlcmWxMCvlgWQOsE6l3U9uKdxvx92lRb9VJZ\nUMie70QuntO3Hxh3KjTYjEfsNNX71p6TOtM+SiKZrf2/0QzOoA5gi3Ko6KjoDzoL\nXLkuRAX1jVQl178M0wc/5T5d9G+7RvNz/RlY2IpliPBcquHIUQZMfO7eu2XL9hcT\nNhPTfvECgYBrHlSbakc4S410wPGci6FXAX5C9Kp2Gx2eZFjatilTebae8zzM7oo4\npwFL5eeIq+m+clCNdbdkPz9EfjaaAlxfl3Unj9sZhPGHvsU3iBYUs7Om2pM86kiL\neid56g1lSQfLl3eFVRqQIXB7CRl56Ui+TxFNjqy2iMuynMFZlau1gQKBgGt/c6hr\ny8lGC1CYfdxiF0S6E4SVpOjLpS87LlbXAARVcRrH/ITDmrVyVFxXpqT7pq4/7NLY\naTexsGKIX8ayQzrPXxG3Nmd79NvNP5eZwPHvhXWdr3XDN59N/dh77U5HdOR+cNo9\nUEjRRsz1z9waoktKaFubRAq9GALsVbIi/CQxAoGBANLMLkjAW9TVkHkQuerUIbw9\nSI6VeqLtaMg5g9N1CHEm8/mwhqNLkeE+/o4SxKL7fsLaEMgwv07zPlyCAEPdxVUa\nhPh9XBM36onGbm78D+oRm9FzKkR1aZxP39prVbMaq0apQ62lrFcyWXDSSK0ErJsD\n9TEpEFsejdPB0ss9ISKC\n-----END PRIVATE KEY-----";

    /// A second keypair, for tokens signed by a key the JWKS does not
    /// advertise.
    const FORGER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAYlj/FX2agaBT\nVZ17cHcBQ1nnCslA//pKvLyWIYGQNaHsgfuA8Ltp6m1+TJThqGmo6gJblddDyFCs\np1OijdbE+kr1qmPieorZccmp7YVKUSJRfCD62X/vX70vglGvcB6qLzy+mWvL1C6s\nGAklpP/eogigiHxoXoIG91difgLqe7yxZi1yYOFWyLg/xgDBfOK47DF6OYyIjgNO\n1Wi4KwmKe3VgtGUHYq2rndeIMrhhzQrpsHoBlZ5jgDjmO6nDvS6TPgj21lJnktAZ\ngUVDxbX4/jWmNF8Q9WIJAXWQWxgw2FAUN9Zxc/xR42VWXxAExPRRdFs/6oO3HkDs\nL+he5AT1AgMBAAECggEAU/kZm44H2y8FihpuuPioGTcKwNxmaCbTW1fygR1y7j1a\nxl8eJnPtehfHXz+SJMVcCUzLZqqK4Z1ICXSn/uYmfqg5m+2Z17tha/RM8A0rBvtP\nHX4u7w+M1jFV5KzfdtJbsDEaNJ/G+5tMG/YJ2BKjVMwpM9kfZHcMDnpb/DPAlhRW\ngfk3D21ZhuCdP79ZN5yZBKmtvjKWkn79AquAyEPLw3/bz9bfDbGlNylMjwiv2e3s\nd/88tkPY5H+JHssXjckAWSgFZ7BWl2kClk20r9uHgTGMgX3da+Nfufw4AwzKEmZH\ngCa8d/TFz+/GeDGHUjx4DH1pIkCAlB7NzZI25vwW6QKBgQDrOhP1XdxzpKhxr87G\nMGjRoUQFYygjSpumzBni6AH2goGBt0SCFJ5/PWDkFxkPPvlaeqxgBcwgW6IOlx5N\nsStXSUCEk1+6YIbll/ydbUQbXehOkROcxB+71TWhhooXT9CiV60Zv2j46Y8dx92V\nOtRYy+d+rTPRYfA+67dOn5Y9VwKBgQDRX7KlZcET04FWU9uVyTWRG6RbMxyby4tg\n89hu9YJVR3uq0XzIgeSkDSKNqzkQeb5Hen3SYHE+POopG15hmGQAixVRIVldBNk+\n8EVANd3gJvzLQlqP/XdYp5AsUcvf3SSV2zMegPRkUhppGTM266Bd3wdlpEHd37NV\nULWO30wUkwKBgQCJa6mjTA1xZf2eRTZIpJln9o21lAMr8vdSD6UD4cTbzcx5Cqc0\nU3VxIluLhU73kDO+vzIa+ugQ81eOrIxgmSOX38yYZzyitqe4U/2Zvu7uCgOgerL5\nf76GTn4BeocMLW3WmeAfzao22MPqgwwZlX/ezGjWobtHFK91IuI5RZRRCwKBgF78\nb2uh8iowdijX+nLFyct/It1NHtl/Skg92B7eurY9q9kfGOFOLJBQdTCYUVcsJCsB\nYzuiDT4THJhxlivomtW0Q4N/Aa+1l2l6T7CFv5cFmQINpFBWyWIrArlYkomJJiPm\nQhbAoh8xMFIl4Jo145cyq4RtNISYDB/UccnTfAyJAoGAZSgHtjW1/S5aJeUghdC1\nOHJlLkG7gQilvCck/WhttBOkWzAFEXifBEgV39LRIFTJITe0g1EzuRCSQgFeENSJ\n06uLhQsXU8cFhEewDDOd1f+4fMYGCzeHyaqf3z4pl31D7MmCs9hx8h3dlOjEJfUa\natwqaJKjOz/vJfhUrJ2CE0Q=\n-----END PRIVATE KEY-----";

    fn test_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).expect("test key")
    }

    fn forger_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::from_pkcs8_pem(FORGER_KEY_PEM).expect("forger key")
    }

    fn test_config() -> GitHubTrustConfig {
        GitHubTrustConfig {
            repo: "water-rs/stow".to_owned(),
            oidc_audience: "https://stow.waterui.dev".to_owned(),
        }
    }

    /// Programmable trust surface: a fixed keyset plus whichever login the
    /// repo-permission check should report.
    struct StubTrust {
        jwk: Jwk,
        push_login: Mutex<Option<String>>,
    }

    impl StubTrust {
        fn for_key(key: &rsa::RsaPrivateKey) -> Self {
            let public = key.to_public_key();
            Self {
                jwk: Jwk {
                    kty: "RSA".to_owned(),
                    kid: "test-kid".to_owned(),
                    n: b64url_encode(&public.n().to_bytes_be()),
                    e: b64url_encode(&public.e().to_bytes_be()),
                },
                push_login: Mutex::new(None),
            }
        }
    }

    impl GitHubTrustApi for StubTrust {
        fn jwks(&self) -> impl Future<Output = Result<JwkSet, AuthError>> + Send {
            std::future::ready(Ok(JwkSet {
                keys: vec![Jwk {
                    kty: self.jwk.kty.clone(),
                    kid: self.jwk.kid.clone(),
                    n: self.jwk.n.clone(),
                    e: self.jwk.e.clone(),
                }],
            }))
        }

        fn repo_push_login(
            &self,
            _token: &str,
            _repo: &str,
        ) -> impl Future<Output = Result<Option<String>, AuthError>> + Send {
            std::future::ready(Ok(self.push_login.lock().expect("lock").clone()))
        }
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Mint a compact JWT: JSON header + JSON claims, RS256-signed.
    fn mint_jwt(key: &rsa::RsaPrivateKey, claims: &serde_json::Value) -> String {
        let header = b64url_encode(br#"{"alg":"RS256","typ":"JWT","kid":"test-kid"}"#);
        let payload = b64url_encode(serde_json::to_string(&claims).expect("claims").as_bytes());
        let signing_input = format!("{header}.{payload}");
        let signature = key
            .sign(
                rsa::Pkcs1v15Sign::new_unprefixed(),
                &sha256_digest_info(signing_input.as_bytes()),
            )
            .expect("sign jwt");
        format!("{signing_input}.{}", b64url_encode(&signature))
    }

    fn actions_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": OIDC_ISSUER,
            "aud": "https://stow.waterui.dev",
            "exp": NOW + 600,
            "nbf": NOW - 60,
            "repository": "water-rs/stow",
            "job_workflow_ref":
                "water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main",
            "run_id": "12345",
        })
    }

    fn assert_unauthorized(result: &Result<TrustedCaller, AuthError>) {
        assert!(
            matches!(result, Err(AuthError::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
    }

    #[tokio::test]
    async fn valid_actions_oidc_token_is_trusted() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let token = mint_jwt(&key, &actions_claims());
        let caller = authenticate(&test_config(), &api, &token, Policy::BuildWorkflow, NOW)
            .await
            .expect("actions token");
        let TrustedCaller::Actions {
            job_workflow_ref,
            run_id,
        } = caller
        else {
            panic!("expected Actions caller");
        };
        assert!(job_workflow_ref.contains("build-crate.yml"));
        assert_eq!(run_id, "12345");
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["aud"] = serde_json::json!("https://elsewhere.example");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::BuildWorkflow,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn wrong_repo_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["repository"] = serde_json::json!("someone/fork");
        claims["job_workflow_ref"] =
            serde_json::json!("someone/fork/.github/workflows/build-crate.yml@refs/heads/main");
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::BuildWorkflow,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn other_workflow_cannot_write() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["job_workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/ci.yml@refs/heads/main");
        // The same repo's other workflows may submit tasks...
        let caller = authenticate(
            &test_config(),
            &api,
            &mint_jwt(&key, &claims),
            Policy::RepoWriter,
            NOW,
        )
        .await;
        assert!(matches!(caller, Ok(TrustedCaller::Actions { .. })));
        // ...but only build-crate.yml may register artifacts.
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::BuildWorkflow,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn build_workflow_on_other_ref_cannot_write() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["job_workflow_ref"] =
            serde_json::json!("water-rs/stow/.github/workflows/build-crate.yml@refs/heads/topic");
        // The branch build is still a repo workflow — scheduler ops pass…
        assert!(
            authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::RepoWriter,
                NOW,
            )
            .await
            .is_ok()
        );
        // …but artifact writes pin the exact `main` ref, matching the
        // cosign identity clients verify.
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::BuildWorkflow,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn garbage_bearer_is_rejected_without_upstream_call() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        // Not a JWT and not a GitHub token shape — fails before the
        // permission check would fire (the stub has no login programmed).
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                "not-a-credential",
                Policy::RepoWriter,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        let mut claims = actions_claims();
        claims["exp"] = serde_json::json!(NOW - 3600);
        assert_unauthorized(
            &authenticate(
                &test_config(),
                &api,
                &mint_jwt(&key, &claims),
                Policy::BuildWorkflow,
                NOW,
            )
            .await,
        );
    }

    #[tokio::test]
    async fn forged_signature_is_rejected() {
        let key = test_key();
        let other = forger_key();
        let api = StubTrust::for_key(&key);
        // Signed by a different key than the JWKS advertises.
        let token = mint_jwt(&other, &actions_claims());
        assert_unauthorized(
            &authenticate(&test_config(), &api, &token, Policy::BuildWorkflow, NOW).await,
        );
    }

    #[tokio::test]
    async fn repo_push_user_submits_tasks() {
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let caller = authenticate(
            &test_config(),
            &api,
            "ghp_example-token",
            Policy::RepoWriter,
            NOW,
        )
        .await
        .expect("user token");
        assert!(matches!(caller, TrustedCaller::Push { ref label } if label == "lexoliu"));
    }

    #[tokio::test]
    async fn push_user_registers_artifacts() {
        // Local dev drives the same register endpoint with the developer's
        // own GitHub token — push users pass under every policy.
        let key = test_key();
        let api = StubTrust::for_key(&key);
        *api.push_login.lock().expect("lock") = Some("lexoliu".to_owned());
        let caller = authenticate(
            &test_config(),
            &api,
            "ghp_example-token",
            Policy::BuildWorkflow,
            NOW,
        )
        .await
        .expect("user token");
        assert!(matches!(caller, TrustedCaller::Push { ref label } if label == "lexoliu"));
    }

    #[tokio::test]
    async fn user_without_push_is_rejected() {
        let key = test_key();
        for policy in [Policy::RepoWriter, Policy::BuildWorkflow] {
            let api = StubTrust::for_key(&key);
            *api.push_login.lock().expect("lock") = None;
            assert_unauthorized(
                &authenticate(&test_config(), &api, "ghp_example-token", policy, NOW).await,
            );
        }
    }
}
