use async_process::Command;

use crate::registry::RegistryCredentials;

/// Sign one pushed artifact with cosign (keyless, the job's OIDC identity).
///
/// The signature is pushed to the same registry as the artifact, so cosign
/// gets the registry credentials on its command line rather than from a
/// Docker config file that not every runner can produce.
///
/// # Errors
///
/// Returns an error when `cosign` cannot be spawned or exits non-zero.
pub async fn sign_artifact(
    reference: &str,
    digest: &str,
    credentials: &RegistryCredentials,
) -> stow_types::error::Result<()> {
    let image = format!("{reference}@{digest}");
    let status = Command::new("cosign")
        .args(sign_args(reference, &image, credentials))
        .status()
        .await?;
    if !status.success() {
        return Err(stow_types::stow_error!(
            "cosign sign failed for {image} with status {status}"
        ));
    }

    tracing::info!(image = %image, "signed OCI artifact with cosign");
    Ok(())
}

/// The `cosign sign` argv for one artifact.
///
/// cosign v3 signs in its "new bundle format" by default: the signature
/// becomes an OCI 1.1 referrer of the manifest (on GHCR, the referrers
/// fallback tag `sha256-<digest>`), and nothing is written to the
/// `sha256-<digest>.sig` tag the CLI's `pull_signature_materials` reads,
/// so every verification fails with `manifest unknown`. The two flags pin
/// the legacy layout: `--use-signing-config=false` (the TUF signing
/// config requires the bundle format) and `--new-bundle-format=false`.
/// cosign prints a deprecation notice for the latter; the layout stays
/// until the CLI verifies sigstore bundles.
///
/// `--sign-container-identity` is what puts the tagged reference into the
/// payload's `critical.identity.docker-reference`. Without it cosign writes
/// `Image.Repository.Name()` — `ghcr.io/water-rs/stow-cache`, the bare
/// repository with the tag stripped — and the CLI, which requires that field
/// to equal the artifact's `oci_reference`, rejects every signature. Since
/// every artifact is now a tag of one repository, the bare repository name
/// identifies nothing at all, so the claimed identity has to be set
/// explicitly.
fn sign_args(reference: &str, image: &str, credentials: &RegistryCredentials) -> Vec<String> {
    vec![
        "sign".to_owned(),
        "--yes".to_owned(),
        "--use-signing-config=false".to_owned(),
        "--new-bundle-format=false".to_owned(),
        "--sign-container-identity".to_owned(),
        reference.to_owned(),
        "--registry-username".to_owned(),
        credentials.username.clone(),
        "--registry-password".to_owned(),
        credentials.password.clone(),
        image.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{RegistryCredentials, sign_args};

    /// The signed `docker-reference` must be the exact reference the CLI
    /// compares against, tag included — not the repository cosign would
    /// otherwise derive from the digest.
    #[test]
    fn sign_claims_the_tagged_reference_as_the_container_identity() {
        let reference = "ghcr.io/water-rs/stow-cache:serde.1.0.219-x86_64-linux-1.91.1-0123abcd-fedcba9876543210";
        let args = sign_args(
            reference,
            &format!("{reference}@sha256:00"),
            &RegistryCredentials {
                username: "user".to_owned(),
                password: "token".to_owned(),
            },
        );

        let identity = args
            .iter()
            .position(|arg| arg == "--sign-container-identity")
            .and_then(|index| args.get(index + 1));
        assert_eq!(identity.map(String::as_str), Some(reference));
        assert_eq!(
            args.last().map(String::as_str),
            Some(&*format!("{reference}@sha256:00"))
        );
    }

    /// cosign v3 defaults to the bundle format, which stores the signature
    /// as an OCI referrer instead of the `.sig` tag the CLI reads.
    #[test]
    fn sign_pins_the_legacy_signature_layout() {
        let args = sign_args(
            "ghcr.io/water-rs/stow-cache:index.x86_64-unknown-linux-gnu.1.98.1",
            "ghcr.io/water-rs/stow-cache:index.x86_64-unknown-linux-gnu.1.98.1@sha256:00",
            &RegistryCredentials {
                username: "user".to_owned(),
                password: "token".to_owned(),
            },
        );
        assert!(args.iter().any(|arg| arg == "--use-signing-config=false"));
        assert!(args.iter().any(|arg| arg == "--new-bundle-format=false"));
    }
}
