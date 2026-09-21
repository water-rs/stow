use oci_client::Reference;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use oci_client::secrets::RegistryAuth;
use stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE;
use stow_types::error::Context;
use stow_types::registry::{GHCR_V2_BASE_URL, verify_oci_digest};

const GHCR_USERNAME_ENV: &str = "GHCR_USERNAME";
const GHCR_TOKEN_ENV: &str = "GHCR_TOKEN";

/// The one registry credential the trusted publish stage holds: the OCI
/// uploader and cosign push with the same pair, so a runner needs no Docker
/// CLI or Docker config file.
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

/// The registry client every stow publish/pull path shares.
#[must_use]
pub fn registry_client(credentials: &RegistryCredentials) -> (Client, RegistryAuth) {
    (
        Client::new(ClientConfig::default()),
        RegistryAuth::Basic(credentials.username.clone(), credentials.password.clone()),
    )
}

/// Download one blob's bytes.
pub async fn pull_blob(
    client: &Client,
    reference: &Reference,
    descriptor: &OciDescriptor,
) -> stow_types::error::Result<Vec<u8>> {
    let bytes = crate::backpressure::retrying_rate_limits("pull blob", || async {
        let mut bytes = Vec::new();
        client.pull_blob(reference, descriptor, &mut bytes).await?;
        Ok(bytes)
    })
    .await
    .map_err(|error| {
        stow_types::stow_error!("pull blob {} of {reference}: {error}", descriptor.digest)
    })?;
    Ok(bytes)
}

/// The manifest bytes exactly as the registry stores them under `digest`:
/// what the bundle carries in `oci/manifest.json`, and what a CLI re-hashes
/// against the cosign payload.
pub async fn pull_manifest_by_digest(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
    digest: &str,
) -> stow_types::error::Result<Vec<u8>> {
    let by_digest: Reference = format!(
        "{}/{}@{digest}",
        reference.registry(),
        reference.repository()
    )
    .parse()?;
    let (bytes, served_digest) = crate::backpressure::retrying_rate_limits("pull manifest", || {
        client.pull_manifest_raw(&by_digest, auth, &[OCI_IMAGE_MANIFEST_MEDIA_TYPE])
    })
    .await
    .map_err(|error| stow_types::stow_error!("pull manifest {by_digest}: {error}"))?;
    if served_digest != digest {
        return Err(stow_types::stow_error!(
            "manifest {by_digest} was served as {served_digest}"
        ));
    }
    Ok(bytes.to_vec())
}

/// The value of a required environment variable, or an error naming it.
pub fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name)
        .map_err(|_| stow_types::stow_error!("missing required environment variable {name}"))
}

/// A `scheme://host/v2/repository` registry API base.
///
/// Production is [`GHCR_V2_BASE_URL`]; the mock registry serves the same
/// paths over plain HTTP, so the URL scheme selects the client protocol.
/// `STOW_REGISTRY_BASE_URL` on the CLI redirects every pull through this
/// type.
#[derive(Debug, Clone)]
pub struct RegistryBase {
    registry: String,
    repository: String,
    protocol: ClientProtocol,
}

impl RegistryBase {
    /// Parse `<scheme>://<host>/v2/<repository>`; `http` selects
    /// [`ClientProtocol::Http`], `https` the default TLS path.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL has no scheme, an unsupported scheme,
    /// or no repository path after `/v2/`.
    pub fn parse(base_url: &str) -> stow_types::error::Result<Self> {
        let (scheme, rest) = base_url.split_once("://").ok_or_else(|| {
            stow_types::stow_error!("registry base URL {base_url:?} has no scheme")
        })?;
        let protocol = match scheme {
            "https" => ClientProtocol::Https,
            "http" => ClientProtocol::Http,
            other => {
                return Err(stow_types::stow_error!(
                    "registry base URL {base_url:?} uses unsupported scheme {other:?}"
                ));
            }
        };
        let (registry, path) = rest.split_once('/').ok_or_else(|| {
            stow_types::stow_error!("registry base URL {base_url:?} has no repository path")
        })?;
        let repository = path
            .strip_prefix("v2/")
            .unwrap_or(path)
            .trim_end_matches('/');
        if repository.is_empty() {
            return Err(stow_types::stow_error!(
                "registry base URL {base_url:?} has an empty repository path"
            ));
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            protocol,
        })
    }

    /// The production base.
    ///
    /// # Errors
    ///
    /// Returns an error if [`GHCR_V2_BASE_URL`] is malformed — a bug, not a
    /// runtime condition.
    pub fn production() -> stow_types::error::Result<Self> {
        Self::parse(GHCR_V2_BASE_URL)
    }

    /// The anonymous pull client every stow read path uses — the cache
    /// package is public.
    #[must_use]
    pub fn client(&self) -> (Client, RegistryAuth) {
        (
            Client::new(ClientConfig {
                protocol: self.protocol.clone(),
                ..ClientConfig::default()
            }),
            RegistryAuth::Anonymous,
        )
    }

    /// `<registry>/<repository>:<tag>` as a pull reference.
    ///
    /// # Errors
    ///
    /// Returns an error when `tag` cannot form a valid OCI reference.
    pub fn reference(&self, tag: &str) -> stow_types::error::Result<Reference> {
        format!("{}/{}:{tag}", self.registry, self.repository)
            .parse()
            .wrap_err_with(|| format!("build OCI reference for tag {tag:?}"))
    }

    /// `<registry>/<repository>@<digest>` as a pull reference — the form a
    /// blob-by-digest download needs (the descriptor carries the digest; the
    /// reference carries the repository).
    ///
    /// # Errors
    ///
    /// Returns an error when `digest` cannot form a valid OCI reference.
    pub fn digest_reference(&self, digest: &str) -> stow_types::error::Result<Reference> {
        format!("{}/{}@{digest}", self.registry, self.repository)
            .parse()
            .wrap_err_with(|| format!("build OCI reference for digest {digest:?}"))
    }
}

/// Pull the manifest `reference` resolves to: the content digest the client
/// validated and the parsed manifest. The digest is the body's hash — the
/// registry header when it agrees, never the tag itself.
///
/// # Errors
///
/// Returns an error when the pull fails or the body is not an OCI image
/// manifest.
pub async fn pull_tagged_manifest(
    client: &Client,
    auth: &RegistryAuth,
    reference: &Reference,
) -> stow_types::error::Result<(String, OciImageManifest)> {
    let (bytes, digest) = client
        .pull_manifest_raw(reference, auth, &[OCI_IMAGE_MANIFEST_MEDIA_TYPE])
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
    client: &Client,
    reference: &Reference,
    descriptor: &OciDescriptor,
) -> stow_types::error::Result<Vec<u8>> {
    let bytes = pull_blob(client, reference, descriptor).await?;
    verify_oci_digest(&bytes, &descriptor.digest).map_err(|error| {
        stow_types::stow_error!("verify blob {} of {reference}: {error}", descriptor.digest)
    })?;
    Ok(bytes)
}
