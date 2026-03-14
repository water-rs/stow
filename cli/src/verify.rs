use eyre::Context;
use sigstore::cosign::verification_constraint::{
    CertSubjectUrlVerifier, VerificationConstraintVec,
};
use sigstore::cosign::{verify_constraints, CosignCapabilities};
use sigstore::errors::SigstoreVerifyConstraintsError;
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;

use crate::config::StowConfig;
use crate::fetch::ArtifactBundle;

const TRUSTED_CERT_URL: &str =
    "https://github.com/stow-rs/stow/.github/workflows/build-caches.yml@refs/heads/main";
const TRUSTED_CERT_ISSUER: &str = "https://token.actions.githubusercontent.com";

pub async fn verify_bundle_signature(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let cache_dir = config.cache_dir.join("sigstore");
    let manifest = bundle.manifest.clone();
    smol::unblock(move || verify_bundle_signature_blocking(&cache_dir, manifest)).await?;
    Ok(())
}

fn verify_bundle_signature_blocking(
    cache_dir: &std::path::Path,
    manifest: stow_types::bundle::ArtifactBundleManifest,
) -> eyre::Result<()> {
    std::fs::create_dir_all(cache_dir)
        .wrap_err_with(|| format!("create sigstore cache dir {}", cache_dir.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("create tokio runtime for sigstore verification")?;
    runtime.block_on(async move {
        let trust_root = SigstoreTrustRoot::new(Some(cache_dir))
            .await
            .wrap_err("load sigstore trust root")?;
        let mut client = sigstore::cosign::ClientBuilder::default()
            .with_trust_repository(&trust_root)
            .wrap_err("configure sigstore trust repository")?
            .build()
            .wrap_err("build sigstore cosign client")?;
        let image: OciReference = manifest
            .oci_reference
            .parse()
            .map_err(|error| eyre::eyre!("parse OCI reference {}: {error}", manifest.oci_reference))?;
        let auth = Auth::Anonymous;
        let (signature_image, source_digest) = client
            .triangulate(&image, &auth)
            .await
            .wrap_err("triangulate sigstore signature image")?;
        if source_digest != manifest.oci_digest {
            return Err(eyre::eyre!(
                "sigstore source digest mismatch: expected {}, got {}",
                manifest.oci_digest,
                source_digest
            ));
        }

        let trusted_layers = client
            .trusted_signature_layers(&auth, &manifest.oci_digest, &signature_image)
            .await
            .wrap_err("load trusted signature layers from registry")?;
        let constraints: VerificationConstraintVec = vec![Box::new(CertSubjectUrlVerifier {
            url: TRUSTED_CERT_URL.to_owned(),
            issuer: TRUSTED_CERT_ISSUER.to_owned(),
        })];

        verify_constraints(&trusted_layers, constraints.iter()).map_err(
            |SigstoreVerifyConstraintsError {
                 unsatisfied_constraints,
             }| {
                eyre::eyre!(
                    "sigstore verification constraints were not satisfied: {:?}",
                    unsatisfied_constraints
                )
            },
        )?;
        Ok(())
    })
}
