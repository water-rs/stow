//! Registry authentication, adapted from `util/auth/mod.rs`.
//!
//! The `cargo:token` credential source (config `token` values and
//! `CARGO_*_TOKEN` environment variables) is fully portable and implemented
//! here. External credential-provider processes cannot exist on wasm, so
//! requesting one fails with an explicit error — the same error shape cargo
//! uses for missing credentials rather than a silent anonymous fallback.

use crate::core::SourceId;
use crate::util::context::{ConfigKey, OptValue, PathAndArgs};
use crate::util::credential::{Operation, Secret};
use crate::util::{CargoResult, GlobalContext};
use anyhow::bail;
use core::fmt;
use serde::Deserialize;
use std::error::Error;
use url::Url;

/// `[registries.NAME]` tables.
///
/// The values here should be kept in sync with `RegistryConfigExtended`
/// (ported verbatim from cargo).
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct RegistryConfig {
    pub index: Option<String>,
    pub token: OptValue<Secret<String>>,
    pub credential_provider: Option<PathAndArgs>,
    pub secret_key: OptValue<Secret<String>>,
    pub secret_key_subject: Option<String>,
    /// Minimum publish age threshold for RFC 3923
    pub min_publish_age: Option<String>,
    #[serde(rename = "protocol")]
    _protocol: Option<String>,
}

/// The `[registry]` table, which has more keys than the `[registries.NAME]` tables.
///
/// Ported verbatim from cargo.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct RegistryConfigExtended {
    pub index: Option<String>,
    pub token: OptValue<Secret<String>>,
    pub credential_provider: Option<PathAndArgs>,
    pub secret_key: OptValue<Secret<String>>,
    pub secret_key_subject: Option<String>,
    /// Minimum publish age threshold for RFC 3923
    pub min_publish_age: Option<String>,
    /// Global default Minimum publish age threshold for RFC 3923
    pub global_min_publish_age: Option<String>,
    #[serde(rename = "default")]
    _default: Option<String>,
    #[serde(rename = "global-credential-providers")]
    _global_credential_providers: Option<Vec<String>>,
}

impl RegistryConfigExtended {
    pub fn to_registry_config(self) -> RegistryConfig {
        RegistryConfig {
            index: self.index,
            token: self.token,
            credential_provider: self.credential_provider,
            secret_key: self.secret_key,
            secret_key_subject: self.secret_key_subject,
            min_publish_age: self.min_publish_age,
            _protocol: None,
        }
    }
}

/// Gets the token for the given registry from config / environment, the
/// `cargo:token` source. Returns `None` when nothing is configured.
fn token_from_config(gctx: &GlobalContext, sid: &SourceId) -> CargoResult<Option<Secret<String>>> {
    if let Some(name) = sid.alt_registry_key() {
        let token = gctx
            .get::<RegistryConfig>(&format!("registries.{name}"))?
            .token;
        if let Some(token) = token {
            return Ok(Some(token.val));
        }
        // Also check the CARGO_REGISTRIES_<NAME>_TOKEN environment variable,
        // which the typed config API exposes via `Env`.
        let key = ConfigKey::from_str(&format!("registries.{name}.token"));
        let env_key = key.as_env_key();
        if let Some(token) = gctx.get_env_os(env_key) {
            if let Some(token) = token.to_str() {
                return Ok(Some(Secret::from(token.to_string())));
            }
        }
    } else {
        let token = gctx.get::<RegistryConfigExtended>("registry")?.token;
        if let Some(token) = token {
            return Ok(Some(token.val));
        }
        if let Ok(token) = gctx.get_env("CARGO_REGISTRY_TOKEN") {
            return Ok(Some(Secret::from(token.to_string())));
        }
    }
    Ok(None)
}

/// Returns the token to use for the given registry, or an error if none is
/// available (ported semantics of `auth::auth_token` restricted to the
/// `cargo:token` provider — the only credential source that cannot run
/// external helper processes).
pub fn auth_token(
    gctx: &GlobalContext,
    sid: &SourceId,
    login_url: Option<&Url>,
    operation: Operation<'_>,
    _headers: Vec<String>,
    _require_cred_provider_config: bool,
) -> CargoResult<String> {
    let _ = operation;
    // Registry credential-provider processes cannot run in this build; if
    // one is configured, say so rather than silently doing something else.
    if let Some(name) = sid.alt_registry_key() {
        if gctx
            .get::<RegistryConfig>(&format!("registries.{name}"))?
            .credential_provider
            .is_some()
        {
            bail!("credential providers for registry `{name}` are not supported in this build");
        }
    } else if gctx
        .get::<RegistryConfigExtended>("registry")?
        .credential_provider
        .is_some()
    {
        bail!("registry credential providers are not supported in this build");
    }

    match token_from_config(gctx, sid)? {
        Some(token) => Ok(token.expose()),
        None => Err(AuthorizationError::new(
            gctx,
            *sid,
            login_url.cloned(),
            AuthorizationErrorReason::TokenMissing,
        )?
        .into()),
    }
}

/// Reason indicating what failed when authorization was required.
/// Ported verbatim from cargo.
#[derive(Debug, PartialEq)]
pub enum AuthorizationErrorReason {
    TokenMissing,
    TokenRejected,
}

impl fmt::Display for AuthorizationErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationErrorReason::TokenMissing => write!(f, "no token found"),
            AuthorizationErrorReason::TokenRejected => write!(f, "token rejected"),
        }
    }
}

/// An authorization error from accessing a registry.
/// Ported from cargo; the credential-provider display hint is always false
/// in this build since external providers are unsupported.
#[derive(Debug)]
pub struct AuthorizationError {
    /// Url that was attempted
    sid: SourceId,
    /// The `registry.default` config value.
    default_registry: Option<String>,
    /// Url where the user could log in.
    pub login_url: Option<Url>,
    /// Specific reason indicating what failed
    reason: AuthorizationErrorReason,
    /// Whether the cached token appears to lack an authentication scheme.
    token_lacks_scheme: Option<bool>,
}

impl AuthorizationError {
    pub fn new(
        gctx: &GlobalContext,
        sid: SourceId,
        login_url: Option<Url>,
        reason: AuthorizationErrorReason,
    ) -> CargoResult<Self> {
        let cache = gctx.credential_cache();
        let token_lacks_scheme = cache
            .get(sid.canonical_url())
            .map(|entry| !entry.token_value.as_deref().expose().contains(' '));
        Ok(AuthorizationError {
            sid,
            default_registry: gctx.default_registry()?,
            login_url,
            reason,
            token_lacks_scheme,
        })
    }
}

impl Error for AuthorizationError {}
impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sid.is_crates_io() {
            let args = if self.default_registry.is_some() {
                " --registry crates-io"
            } else {
                ""
            };
            write!(f, "{}, please run `cargo login{args}`", self.reason)
        } else if let Some(name) = self.sid.alt_registry_key() {
            write!(
                f,
                "{} for `{}`",
                self.reason,
                self.sid.display_registry_name()
            )?;
            let key = ConfigKey::from_str(&format!("registries.{name}.token"));
            write!(
                f,
                ", please run `cargo login --registry {name}`\n\
                or use environment variable {}",
                key.as_env_key()
            )
        } else {
            write!(
                f,
                "{} for `{}`",
                self.reason,
                self.sid.display_registry_name()
            )
        }
    }
}
