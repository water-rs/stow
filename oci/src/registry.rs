use oci_client::Reference;
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use stow_types::error::Context;
use stow_types::registry::{GHCR_REGISTRY_URL, verify_oci_digest};

use crate::client::RegistrySession;

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";

/// The one registry credential the trusted publish stage holds: the
/// artifacts and their signature images push with the same pair, so a
/// runner needs no Docker CLI or Docker config file.
#[derive(Debug, Clone)]
pub struct RegistryCredentials {
    /// Registry basic-auth username (`GHCR_USERNAME`).
    pub username: String,
    /// Registry basic-auth password or token (`GHCR_TOKEN`).
    pub password: String,
}

impl RegistryCredentials {
    /// Read `GHCR_USERNAME` / `GHCR_TOKEN` from the job environment.
    ///
    /// # Errors
    ///
    /// Returns an error when either variable is unset or not Unicode.
    pub fn from_env() -> stow_types::error::Result<Self> {
        Ok(Self {
            username: env_required(GHCR_USERNAME_ENV)?,
            password: env_required(GHCR_TOKEN_ENV)?,
        })
    }
}

/// Download one blob's bytes.
pub async fn pull_blob(
    session: &RegistrySession,
    descriptor: &OciDescriptor,
) -> stow_types::error::Result<Vec<u8>> {
    session
        .pull_blob(&descriptor.digest)
        .await
        .map_err(|error| stow_types::stow_error!("pull blob {}: {error}", descriptor.digest))
}

/// The value of a required environment variable, or an error naming it.
pub fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name)
        .map_err(|_| stow_types::stow_error!("missing required environment variable {name}"))
}

/// A `scheme://host[:port]` registry root — the OCI API base every
/// per-repository session hangs its `/v2/<repository>/…` URLs off.
///
/// Production is [`GHCR_REGISTRY_URL`]; the mock registry serves the same
/// paths over plain HTTP, so the URL scheme selects the client protocol.
/// `STOW_REGISTRY_BASE_URL` on the CLI redirects every pull through this
/// type. The repository is never part of the configured root: each pull or
/// push names the package its rustc derives.
#[derive(Debug, Clone)]
pub struct RegistryBase {
    scheme: String,
    registry: String,
}

impl RegistryBase {
    /// Parse `<scheme>://<host>[:<port>]` — the registry root. `http` stays
    /// plaintext for the mock registry, `https` is the production TLS path.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL has no scheme, an unsupported scheme,
    /// an empty host, or a path — the per-rustc repository is appended by
    /// code, never configured.
    pub fn parse(base_url: &str) -> stow_types::error::Result<Self> {
        let (scheme, rest) = base_url.split_once("://").ok_or_else(|| {
            stow_types::stow_error!("registry base URL {base_url:?} has no scheme")
        })?;
        if !matches!(scheme, "https" | "http") {
            return Err(stow_types::stow_error!(
                "registry base URL {base_url:?} uses unsupported scheme {scheme:?}"
            ));
        }
        let registry = rest.trim_end_matches('/');
        if registry.is_empty() || registry.contains('/') {
            return Err(stow_types::stow_error!(
                "registry base URL {base_url:?} must be the registry root —                  scheme://host[:port] with no repository path"
            ));
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            registry: registry.to_owned(),
        })
    }

    /// The production base.
    ///
    /// # Errors
    ///
    /// Returns an error if [`GHCR_REGISTRY_URL`] is malformed — a bug, not
    /// a runtime condition.
    pub fn production() -> stow_types::error::Result<Self> {
        Self::parse(GHCR_REGISTRY_URL)
    }

    /// The URL scheme the base declared (`http` or `https`) — the session
    /// keeps it verbatim so mock registries stay plaintext.
    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The `host[:port]` segment asset URLs hang off.
    pub(crate) fn registry(&self) -> &str {
        &self.registry
    }
}

/// Pull the manifest `reference` resolves to: the content digest the session
/// validated and the parsed manifest. The digest is the body's hash — the
/// registry header when it agrees, never the tag itself.
///
/// # Errors
///
/// Returns an error when the pull fails or the body is not an OCI image
/// manifest.
pub async fn pull_tagged_manifest(
    session: &RegistrySession,
    reference: &Reference,
) -> stow_types::error::Result<(String, OciImageManifest)> {
    let (bytes, digest) = session
        .pull_manifest(reference)
        .await
        .map_err(|error| stow_types::stow_error!("pull manifest {reference}: {error}"))?;
    let manifest: OciImageManifest = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("parse manifest for {reference}"))?;
    Ok((digest, manifest))
}

/// Download `descriptor`'s blob, requiring its bytes to hash to
/// `descriptor.digest` — the distribution API trusts the registry with
/// naming, never with content.
///
/// # Errors
///
/// Returns an error when the pull fails or the digest mismatches.
pub async fn pull_blob_verified(
    session: &RegistrySession,
    descriptor: &OciDescriptor,
) -> stow_types::error::Result<Vec<u8>> {
    let bytes = pull_blob(session, descriptor).await?;
    verify_oci_digest(&bytes, &descriptor.digest)
        .map_err(|error| stow_types::stow_error!("verify blob {}: {error}", descriptor.digest))?;
    Ok(bytes)
}
