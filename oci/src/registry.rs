use oci_client::Reference;
use oci_client::client::{Client, ClientConfig};
use oci_client::manifest::OciDescriptor;
use oci_client::secrets::RegistryAuth;
use stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE;

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
    let mut bytes = Vec::new();
    client
        .pull_blob(reference, descriptor, &mut bytes)
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
    let (bytes, served_digest) = client
        .pull_manifest_raw(&by_digest, auth, &[OCI_IMAGE_MANIFEST_MEDIA_TYPE])
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
