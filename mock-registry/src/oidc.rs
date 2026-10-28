//! The mock stack's GitHub Actions OIDC issuer (stow#955). The mock edge
//! verifies Actions tokens exactly as production does — RS256 against
//! the issuer's key set, then issuer, audience, expiry, repository and
//! the route's workflow pin — except that it fetches the key set from the
//! GitHub API stub (`STOW_GITHUB_API_URL`, loopback-only and absent from
//! the production manifest) instead of `token.actions.githubusercontent.com`.
//! `serve` publishes the key set; `oidc-token` signs the token a script
//! hands the mock edge in place of a workflow run's.
//!
//! The key is a committed fixture, like the edge verifier's test key:
//! nothing outside the mock stack trusts it.

use clap::Args;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::traits::PublicKeyParts as _;
use sha2::Digest as _;

/// The issuer's signing key.
const ISSUER_KEY_PEM: &str = include_str!("oidc-issuer.pem");

/// The `kid` the key set and every token share.
const KID: &str = "mock-oidc";

/// The issuer GitHub stamps on every Actions token — the edge pins it.
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// `GITHUB_REPO` in `edge/Skyzen.mock.toml`: the repository the mock
/// edge pins every token to.
const REPOSITORY: &str = "water-rs/stow";

/// `STOW_OIDC_AUDIENCE` in `edge/Skyzen.mock.toml`: the audience the mock
/// edge requires.
const AUDIENCE: &str = "https://stow.waterui.dev";

/// SHA-256's DER `DigestInfo` prefix — PKCS#1 v1.5 framing done by hand,
/// as the edge's verifier does, because `rsa` 0.9 and `sha2` 0.11 do not
/// share a `digest` version.
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// `stow-mock-registry oidc-token` — one workflow run's identity.
#[derive(Debug, Clone, Args)]
pub struct OidcTokenArgs {
    /// The workflow file under `.github/workflows/` the run belongs to,
    /// e.g. `operations.yml`.
    #[arg(long)]
    workflow: String,
    /// The ref the run executes at; its workflow is read at the same ref.
    #[arg(long = "ref", default_value = "refs/heads/main")]
    git_ref: String,
    /// The login that triggered the run.
    #[arg(long, default_value = "stow-mock-operator")]
    actor: String,
    /// Seconds the token stays valid. A real Actions token lives minutes
    /// and stow-admin re-mints it per request; a script that hands one
    /// token to a long lane sets the lane's length here.
    #[arg(long = "lifetime-secs", default_value_t = 600)]
    lifetime_secs: i64,
}

/// The JWT header.
#[derive(serde::Serialize)]
struct Header {
    alg: &'static str,
    typ: &'static str,
    kid: &'static str,
}

/// The Actions claims the edge reads, in GitHub's shape.
#[derive(serde::Serialize)]
struct Claims {
    iss: &'static str,
    aud: &'static str,
    sub: String,
    repository: &'static str,
    job_workflow_ref: String,
    workflow_ref: String,
    #[serde(rename = "ref")]
    git_ref: String,
    actor: String,
    run_id: String,
    run_attempt: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

/// The issuer key.
///
/// # Panics
/// The committed fixture fails to parse — a broken checkout.
#[must_use]
pub fn signing_key() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs8_pem(ISSUER_KEY_PEM).expect("mock OIDC issuer key parses")
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The issuer's key set, in the JWKS shape GitHub serves.
#[must_use]
pub fn jwks(key: &rsa::RsaPrivateKey) -> serde_json::Value {
    let public = key.to_public_key();
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": KID,
            "n": b64url(&public.n().to_bytes_be()),
            "e": b64url(&public.e().to_bytes_be()),
        }],
    })
}

/// Sign a token for `run`.
///
/// # Errors
/// The claims fail to serialize or the key fails to sign.
pub fn mint(key: &rsa::RsaPrivateKey, run: &OidcTokenArgs) -> stow_types::error::Result<String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let workflow = format!(
        "{REPOSITORY}/.github/workflows/{}@{}",
        run.workflow, run.git_ref
    );
    let claims = Claims {
        iss: ISSUER,
        aud: AUDIENCE,
        sub: format!("repo:{REPOSITORY}:ref:{}", run.git_ref),
        repository: REPOSITORY,
        job_workflow_ref: workflow.clone(),
        workflow_ref: workflow,
        git_ref: run.git_ref.clone(),
        actor: run.actor.clone(),
        run_id: "1".to_owned(),
        run_attempt: "1".to_owned(),
        iat: now,
        nbf: now - 60,
        exp: now + run.lifetime_secs,
    };
    let header = Header {
        alg: "RS256",
        typ: "JWT",
        kid: KID,
    };
    let signing_input = format!(
        "{}.{}",
        b64url(&serde_json::to_vec(&header)?),
        b64url(&serde_json::to_vec(&claims)?)
    );
    let digest = sha2::Sha256::digest(signing_input.as_bytes());
    let mut framed = SHA256_DIGEST_INFO_PREFIX.to_vec();
    framed.extend_from_slice(&digest);
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &framed)
        .map_err(|error| stow_types::stow_error!("sign the mock OIDC token: {error}"))?;
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}

#[cfg(test)]
mod tests {
    use super::{AUDIENCE, OidcTokenArgs, REPOSITORY, SHA256_DIGEST_INFO_PREFIX};
    use sha2::Digest as _;

    /// The issuer's pins are the mock edge's own configuration.
    #[test]
    fn the_issuer_matches_the_mock_manifest() {
        let manifest = include_str!("../../edge/Skyzen.mock.toml");
        assert!(
            manifest.contains(&format!("STOW_OIDC_AUDIENCE = \"{AUDIENCE}\"")),
            "edge/Skyzen.mock.toml's audience moved"
        );
        assert!(
            manifest.contains(&format!("GITHUB_REPO = \"{REPOSITORY}\"")),
            "edge/Skyzen.mock.toml's repository moved"
        );
    }

    /// A minted token verifies against the published key set and names
    /// the run it was asked for.
    #[test]
    fn a_minted_token_verifies_against_the_key_set() {
        use base64::Engine as _;
        let key = super::signing_key();
        let token = super::mint(
            &key,
            &OidcTokenArgs {
                workflow: "operations.yml".to_owned(),
                git_ref: "refs/heads/main".to_owned(),
                actor: "octo-dispatcher".to_owned(),
                lifetime_secs: 600,
            },
        )
        .expect("mint");
        let (signing_input, signature) = token.rsplit_once('.').expect("three segments");
        let decode = |segment: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segment)
                .expect("base64url")
        };
        let mut framed = SHA256_DIGEST_INFO_PREFIX.to_vec();
        framed.extend_from_slice(&sha2::Sha256::digest(signing_input.as_bytes()));
        key.to_public_key()
            .verify(
                rsa::Pkcs1v15Sign::new_unprefixed(),
                &framed,
                &decode(signature),
            )
            .expect("signature verifies");
        let jwks = super::jwks(&key);
        let header: serde_json::Value =
            serde_json::from_slice(&decode(signing_input.split('.').next().expect("header")))
                .expect("header json");
        assert_eq!(header["kid"], jwks["keys"][0]["kid"]);
        let claims: serde_json::Value =
            serde_json::from_slice(&decode(signing_input.split('.').nth(1).expect("claims")))
                .expect("claims json");
        let workflow = "water-rs/stow/.github/workflows/operations.yml@refs/heads/main";
        assert_eq!(claims["job_workflow_ref"], workflow);
        assert_eq!(claims["workflow_ref"], workflow);
        assert_eq!(claims["ref"], "refs/heads/main");
        assert_eq!(claims["actor"], "octo-dispatcher");
        assert_eq!(claims["aud"], AUDIENCE);
    }
}
