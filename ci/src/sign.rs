use std::collections::BTreeMap;

use async_process::Command;

use crate::upload::RegistryCredentials;

/// Sign every pushed artifact with cosign (keyless, the job's OIDC identity).
///
/// The signature is pushed to the same registry as the artifact, so cosign
/// gets the registry credentials on its command line rather than from a
/// Docker config file that not every runner can produce.
pub async fn sign_artifacts(
    digests_by_reference: &BTreeMap<String, String>,
    credentials: &RegistryCredentials,
) -> stow_types::error::Result<()> {
    for (reference, digest) in digests_by_reference {
        let image = format!("{reference}@{digest}");
        let status = Command::new("cosign")
            .arg("sign")
            .arg("--yes")
            .arg("--registry-username")
            .arg(&credentials.username)
            .arg("--registry-password")
            .arg(&credentials.password)
            .arg(&image)
            .status()
            .await?;
        if !status.success() {
            return Err(stow_types::stow_error!(
                "cosign sign failed for {image} with status {status}"
            ));
        }

        tracing::info!(image = %image, "signed OCI artifact with cosign");
    }

    Ok(())
}
