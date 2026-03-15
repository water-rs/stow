use eyre::Context;
use serde::Serialize;
use sigstore::bundle::verify::policy::{Identity, VerificationPolicy};
use sigstore::cosign::bundle::Bundle as RekorBundle;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

use crate::config::{StowConfig, VerifyMode};
use crate::fetch::ArtifactBundle;

const TRUSTED_CERT_URL: &str =
    "https://github.com/stow-rs/stow/.github/workflows/build-crate.yml@refs/heads/main";
const TRUSTED_CERT_ISSUER: &str = "https://token.actions.githubusercontent.com";

pub async fn verify_bundle_signature(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let bundle = bundle.clone();
    let config = config.clone();
    smol::unblock(move || verify_bundle_signature_blocking(&config, &bundle)).await?;
    Ok(())
}

fn verify_bundle_signature_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    match config.verify_mode {
        VerifyMode::GithubCi => verify_bundle_signature_github_ci_blocking(config, bundle),
        VerifyMode::MockKey => verify_bundle_signature_mock_key_blocking(config, bundle),
    }
}

fn verify_bundle_signature_github_ci_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let cache_dir = config.cache_dir.join("sigstore");
    std::fs::create_dir_all(&cache_dir)
        .wrap_err_with(|| format!("create sigstore cache dir {}", cache_dir.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("create tokio runtime for sigstore verification")?;
    runtime.block_on(async move {
        let trust_root = SigstoreTrustRoot::new(Some(&cache_dir))
            .await
            .wrap_err("load sigstore trust root")?;
        let mut rekor_keys = std::collections::BTreeMap::new();
        for (key_id, key_bytes) in trust_root.rekor_keys()? {
            rekor_keys.insert(key_id, CosignVerificationKey::try_from_pem(key_bytes)?);
        }
        let identity_policy = Identity::new(TRUSTED_CERT_URL, TRUSTED_CERT_ISSUER);

        for material in &bundle.manifest.sigstore_signatures {
            let payload_bytes = verified_payload_bytes(bundle, material)?;

            if let Some(rekor_bundle_json) = material.rekor_bundle_json.as_ref() {
                let rekor_bundle: RekorBundle = serde_json::from_str(rekor_bundle_json)
                    .wrap_err("parse embedded rekor bundle")?;
                verify_rekor_bundle(&rekor_bundle, &rekor_keys)?;
            }

            let cert = Certificate::from_pem(material.certificate_pem.as_bytes())
                .wrap_err("parse fulcio certificate from bundle")?;
            verify_certificate_chain(&trust_root, &cert)?;
            identity_policy
                .verify(&cert)
                .map_err(|error| eyre::eyre!("certificate identity verification failed: {error}"))?;

            let verification_key = CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info)
                .wrap_err("extract verification key from certificate")?;
            verification_key
                .verify_signature(Signature::Base64Encoded(material.signature.as_bytes()), payload_bytes)
                .wrap_err("verify cosign signature against payload")?;
            return Ok(());
        }

        Err(eyre::eyre!(
            "no embedded sigstore signature satisfied the GitHub CI trust policy"
        ))
    })
}

fn verify_bundle_signature_mock_key_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> eyre::Result<()> {
    let public_key_path = config
        .mock_public_key_path
        .as_ref()
        .ok_or_else(|| eyre::eyre!("mock verify mode requires a public key path"))?;
    let public_key = std::fs::read(public_key_path)
        .wrap_err_with(|| format!("read mock public key {}", public_key_path.display()))?;
    let verification_key = CosignVerificationKey::from_pem(
        &public_key,
        &SigningScheme::ECDSA_P256_SHA256_ASN1,
    )
    .wrap_err("parse mock public key")?;

    for material in &bundle.manifest.sigstore_signatures {
        let payload_bytes = verified_payload_bytes(bundle, material)?;
        verification_key
            .verify_signature(Signature::Base64Encoded(material.signature.as_bytes()), payload_bytes)
            .wrap_err("verify mock signature against payload")?;
        return Ok(());
    }

    Err(eyre::eyre!(
        "no embedded signature satisfied the mock trust policy"
    ))
}

fn verified_payload_bytes<'a>(
    bundle: &'a ArtifactBundle,
    material: &stow_types::bundle::SigstoreSignature,
) -> eyre::Result<&'a [u8]> {
    let payload_bytes = bundle
        .files
        .get(&material.payload_path)
        .ok_or_else(|| eyre::eyre!("bundle is missing sigstore payload {}", material.payload_path))?;
    let simple_signing: SimpleSigning = serde_json::from_slice(payload_bytes)
        .wrap_err("parse cosign simple-signing payload")?;
    if simple_signing.critical.identity.docker_reference != bundle.manifest.oci_reference {
        return Err(eyre::eyre!(
            "signature payload docker reference mismatch: expected {}, got {}",
            bundle.manifest.oci_reference,
            simple_signing.critical.identity.docker_reference
        ));
    }
    if !simple_signing.satisfies_manifest_digest(&bundle.manifest.oci_digest) {
        return Err(eyre::eyre!(
            "signature payload did not satisfy OCI manifest digest {}",
            bundle.manifest.oci_digest
        ));
    }
    Ok(payload_bytes)
}

fn verify_rekor_bundle(
    bundle: &RekorBundle,
    rekor_keys: &std::collections::BTreeMap<String, CosignVerificationKey>,
) -> eyre::Result<()> {
    let mut payload_json = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut payload_json, olpc_cjson::CanonicalFormatter::new());
    bundle.payload.serialize(&mut serializer)?;
    let rekor_key = rekor_keys
        .get(&bundle.payload.log_id)
        .ok_or_else(|| eyre::eyre!("missing Rekor public key for {}", bundle.payload.log_id))?;
    rekor_key
        .verify_signature(
            Signature::Base64Encoded(bundle.signed_entry_timestamp.as_bytes()),
            &payload_json,
        )
        .wrap_err("verify Rekor signed entry timestamp")
}

fn verify_certificate_chain(
    trust_root: &SigstoreTrustRoot,
    cert: &Certificate,
) -> eyre::Result<()> {
    let cert_der = rustls_pki_types::CertificateDer::from(
        cert.to_der()
            .wrap_err("encode certificate to DER for webpki verification")?,
    );
    let end_entity = webpki::EndEntityCert::try_from(&cert_der)
        .map_err(|error| eyre::eyre!("parse end-entity certificate for webpki: {error}"))?;
    let trust_anchors = trust_root
        .fulcio_certs()?
        .into_iter()
        .map(|certificate| webpki::anchor_from_trusted_cert(&certificate).map(|anchor| anchor.to_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| eyre::eyre!("convert Fulcio trust anchors: {error}"))?;
    let verification_time = rustls_pki_types::UnixTime::since_unix_epoch(
        cert.tbs_certificate.validity.not_before.to_unix_duration(),
    );
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            verification_time,
            webpki::KeyUsage::required(
                const_oid::db::rfc5280::ID_KP_CODE_SIGNING.as_bytes(),
            ),
            None,
            None,
        )
        .map_err(|error| eyre::eyre!("verify Fulcio certificate chain: {error}"))?;
    Ok(())
}
