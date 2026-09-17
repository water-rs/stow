use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::policy::{Identity, VerificationPolicy};
use sigstore::cosign::bundle::Bundle as RekorBundle;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};
use sigstore::trust::TrustRoot;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use stow_types::error::Context;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

use crate::artifact_cache;
use crate::artifact_cache::CachedArtifactBundle;
use crate::config::{StowConfig, VerifyMode};
use crate::fetch::ArtifactBundle;

const TRUSTED_CERT_URL: &str = stow_types::trusted_builder::CERTIFICATE_IDENTITY;
const TRUSTED_CERT_ISSUER: &str = stow_types::trusted_builder::CERTIFICATE_ISSUER;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VerifiedTrustMarker {
    version: u8,
    policy: String,
}

pub async fn verify_bundle_signature(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    let bundle = bundle.clone();
    let config = config.clone();
    smol::unblock(move || verify_bundle_signature_blocking(&config, &bundle)).await?;
    Ok(())
}

pub async fn verify_cached_bundle_signature(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let expected_marker = expected_trust_marker(config)?;
    if cached_trust_marker_matches(bundle, &expected_marker) {
        return Ok(());
    }

    let config = config.clone();
    let verify_config = config.clone();
    let oci_reference = bundle.oci_reference.clone();
    let oci_digest = bundle.oci_digest.clone();
    let sigstore_signatures = bundle.sigstore_signatures.clone();
    let entry_dir = bundle.entry_dir.clone();
    smol::unblock(move || {
        verify_cached_bundle_signature_blocking(
            &verify_config,
            &oci_reference,
            &oci_digest,
            &sigstore_signatures,
            &entry_dir,
        )
    })
    .await?;
    write_cached_trust_marker(&config, bundle, &expected_marker).await?;
    Ok(())
}

pub async fn persist_cached_bundle_trust_marker(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let marker = expected_trust_marker(config)?;
    write_cached_trust_marker(config, bundle, &marker).await
}

fn verify_bundle_signature_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    match config.verify_mode {
        VerifyMode::GithubCi => verify_bundle_signature_github_ci_blocking(config, bundle),
        VerifyMode::MockKey => verify_bundle_signature_mock_key_blocking(config, bundle),
    }
}

fn verify_cached_bundle_signature_blocking(
    config: &StowConfig,
    oci_reference: &str,
    oci_digest: &str,
    sigstore_signatures: &[stow_types::bundle::SigstoreSignature],
    entry_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    for material in sigstore_signatures {
        let payload_path = entry_dir.join(&material.payload_path);
        let payload_bytes = std::fs::read(&payload_path)
            .wrap_err_with(|| format!("read cached sigstore payload {}", payload_path.display()))?;
        verify_cached_signature_material(
            config,
            oci_reference,
            oci_digest,
            material,
            &payload_bytes,
        )?;
    }
    if sigstore_signatures.is_empty() {
        return Err(stow_types::stow_error!(
            "cached bundle does not contain any embedded sigstore signatures"
        ));
    }
    Ok(())
}

fn verify_bundle_signature_github_ci_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    if bundle
        .manifest
        .sigstore_signatures
        .iter()
        .any(|material| material.certificate_pem == "mock-local")
    {
        return Err(stow_types::stow_error!(
            "bundle is signed by the local mock registry, but stow is using github-ci verification; set STOW_VERIFY_MODE=mock-key and STOW_MOCK_PUBLIC_KEY_PATH=/path/to/mock.pub for local mock e2e"
        ));
    }

    let cache_dir = config.cache_dir.join("sigstore");
    std::fs::create_dir_all(&cache_dir)
        .wrap_err_with(|| format!("create sigstore cache dir {}", cache_dir.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("create tokio runtime for sigstore verification")?;
    runtime.block_on(async move {
        let trust_root = {
            let _guard = tracing::info_span!("stow.sigstore.trust_root.refresh").entered();
            SigstoreTrustRoot::new(Some(&cache_dir))
                .await
                .wrap_err("load sigstore trust root")?
        };
        let mut rekor_keys = std::collections::BTreeMap::new();
        for (key_id, key_bytes) in trust_root.rekor_keys()? {
            rekor_keys.insert(key_id, CosignVerificationKey::try_from_der(key_bytes)?);
        }
        let identity_policy = Identity::new(TRUSTED_CERT_URL, TRUSTED_CERT_ISSUER);

        if let Some(material) = bundle.manifest.sigstore_signatures.first() {
            let payload_bytes = verified_payload_bytes(bundle, material)?;
            verify_signature_material_with_trust_root(
                &trust_root,
                &rekor_keys,
                &identity_policy,
                material,
                payload_bytes,
            )?;
            return Ok(());
        }

        Err(stow_types::stow_error!(
            "no embedded sigstore signature satisfied the GitHub CI trust policy"
        ))
    })
}

fn verify_bundle_signature_mock_key_blocking(
    config: &StowConfig,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    let public_key_path = config
        .mock_public_key_path
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("mock verify mode requires a public key path"))?;
    let public_key = std::fs::read(public_key_path)
        .wrap_err_with(|| format!("read mock public key {}", public_key_path.display()))?;
    let verification_key =
        CosignVerificationKey::from_pem(&public_key, &SigningScheme::ECDSA_P256_SHA256_ASN1)
            .wrap_err("parse mock public key")?;

    if let Some(material) = bundle.manifest.sigstore_signatures.first() {
        let payload_bytes = verified_payload_bytes(bundle, material)?;
        verify_signature_material_mock(&verification_key, material, payload_bytes)?;
        return Ok(());
    }

    Err(stow_types::stow_error!(
        "no embedded signature satisfied the mock trust policy"
    ))
}

fn expected_trust_marker(config: &StowConfig) -> stow_types::error::Result<VerifiedTrustMarker> {
    let policy = match config.verify_mode {
        VerifyMode::GithubCi => {
            format!("github-ci:{TRUSTED_CERT_URL}:{TRUSTED_CERT_ISSUER}")
        }
        VerifyMode::MockKey => {
            let public_key_path = config.mock_public_key_path.as_ref().ok_or_else(|| {
                stow_types::stow_error!("mock verify mode requires a public key path")
            })?;
            let public_key = std::fs::read(public_key_path)
                .wrap_err_with(|| format!("read mock public key {}", public_key_path.display()))?;
            format!("mock-key:{}", hex::encode(Sha256::digest(public_key)))
        }
    };

    Ok(VerifiedTrustMarker { version: 1, policy })
}

fn cached_trust_marker_matches(
    bundle: &CachedArtifactBundle,
    expected: &VerifiedTrustMarker,
) -> bool {
    bundle.verified_marker_version == Some(expected.version)
        && bundle
            .verified_marker_policy
            .as_deref()
            .is_some_and(|policy| policy == expected.policy)
}

async fn write_cached_trust_marker(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
    marker: &VerifiedTrustMarker,
) -> stow_types::error::Result<()> {
    artifact_cache::persist_cached_bundle_trust_marker(
        config,
        bundle,
        marker.version,
        &marker.policy,
    )
    .await
}

fn verified_payload_bytes<'a>(
    bundle: &'a ArtifactBundle,
    material: &stow_types::bundle::SigstoreSignature,
) -> stow_types::error::Result<&'a [u8]> {
    let payload_bytes = bundle.files.get(&material.payload_path).ok_or_else(|| {
        stow_types::stow_error!(
            "bundle is missing sigstore payload {}",
            material.payload_path
        )
    })?;
    let simple_signing: SimpleSigning =
        serde_json::from_slice(payload_bytes).wrap_err("parse cosign simple-signing payload")?;
    if simple_signing.critical.identity.docker_reference != bundle.manifest.oci_reference {
        return Err(stow_types::stow_error!(
            "signature payload docker reference mismatch: expected {}, got {}",
            bundle.manifest.oci_reference,
            simple_signing.critical.identity.docker_reference
        ));
    }
    if !simple_signing.satisfies_manifest_digest(&bundle.manifest.oci_digest) {
        return Err(stow_types::stow_error!(
            "signature payload did not satisfy OCI manifest digest {}",
            bundle.manifest.oci_digest
        ));
    }
    Ok(payload_bytes)
}

fn verify_cached_signature_material(
    config: &StowConfig,
    oci_reference: &str,
    oci_digest: &str,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
) -> stow_types::error::Result<()> {
    match config.verify_mode {
        VerifyMode::GithubCi => verify_signature_material_github_ci(
            config,
            material,
            payload_bytes,
            oci_reference,
            oci_digest,
        ),
        VerifyMode::MockKey => verify_signature_material_mock_key(
            config,
            material,
            payload_bytes,
            oci_reference,
            oci_digest,
        ),
    }
}

fn verify_signature_material_github_ci(
    config: &StowConfig,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
    oci_reference: &str,
    oci_digest: &str,
) -> stow_types::error::Result<()> {
    if material.certificate_pem == "mock-local" {
        return Err(stow_types::stow_error!(
            "bundle is signed by the local mock registry, but stow is using github-ci verification; set STOW_VERIFY_MODE=mock-key and STOW_MOCK_PUBLIC_KEY_PATH=/path/to/mock.pub for local mock e2e"
        ));
    }
    let payload_bytes = verify_payload_identity(payload_bytes, oci_reference, oci_digest)?;
    let cache_dir = config.cache_dir.join("sigstore");
    std::fs::create_dir_all(&cache_dir)
        .wrap_err_with(|| format!("create sigstore cache dir {}", cache_dir.display()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .wrap_err("create tokio runtime for sigstore verification")?;
    runtime.block_on(async move {
        let trust_root = {
            let _guard = tracing::info_span!("stow.sigstore.trust_root.refresh").entered();
            SigstoreTrustRoot::new(Some(&cache_dir))
                .await
                .wrap_err("load sigstore trust root")?
        };
        let mut rekor_keys = std::collections::BTreeMap::new();
        for (key_id, key_bytes) in trust_root.rekor_keys()? {
            rekor_keys.insert(key_id, CosignVerificationKey::try_from_der(key_bytes)?);
        }
        let identity_policy = Identity::new(TRUSTED_CERT_URL, TRUSTED_CERT_ISSUER);
        verify_signature_material_with_trust_root(
            &trust_root,
            &rekor_keys,
            &identity_policy,
            material,
            payload_bytes,
        )
    })
}

fn verify_signature_material_mock_key(
    config: &StowConfig,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
    oci_reference: &str,
    oci_digest: &str,
) -> stow_types::error::Result<()> {
    let public_key_path = config
        .mock_public_key_path
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("mock verify mode requires a public key path"))?;
    let public_key = std::fs::read(public_key_path)
        .wrap_err_with(|| format!("read mock public key {}", public_key_path.display()))?;
    let verification_key =
        CosignVerificationKey::from_pem(&public_key, &SigningScheme::ECDSA_P256_SHA256_ASN1)
            .wrap_err("parse mock public key")?;
    let payload_bytes = verify_payload_identity(payload_bytes, oci_reference, oci_digest)?;
    verify_signature_material_mock(&verification_key, material, payload_bytes)
}

fn verify_signature_material_with_trust_root(
    trust_root: &SigstoreTrustRoot,
    rekor_keys: &std::collections::BTreeMap<String, CosignVerificationKey>,
    identity_policy: &Identity,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
) -> stow_types::error::Result<()> {
    if let Some(rekor_bundle_json) = material.rekor_bundle_json.as_ref() {
        let rekor_bundle: RekorBundle =
            serde_json::from_str(rekor_bundle_json).wrap_err("parse embedded rekor bundle")?;
        verify_rekor_bundle(&rekor_bundle, rekor_keys)?;
    }

    let cert = Certificate::from_pem(material.certificate_pem.as_bytes())
        .wrap_err("parse fulcio certificate from bundle")?;
    verify_certificate_chain(trust_root, &cert)?;
    identity_policy.verify(&cert).map_err(|error| {
        stow_types::stow_error!("certificate identity verification failed: {error}")
    })?;

    let verification_key =
        CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info)
            .wrap_err("extract verification key from certificate")?;
    verification_key
        .verify_signature(
            Signature::Base64Encoded(material.signature.as_bytes()),
            payload_bytes,
        )
        .wrap_err("verify cosign signature against payload")
}

fn verify_signature_material_mock(
    verification_key: &CosignVerificationKey,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
) -> stow_types::error::Result<()> {
    verification_key
        .verify_signature(
            Signature::Base64Encoded(material.signature.as_bytes()),
            payload_bytes,
        )
        .wrap_err("verify mock signature against payload")
}

fn verify_payload_identity<'a>(
    payload_bytes: &'a [u8],
    oci_reference: &str,
    oci_digest: &str,
) -> stow_types::error::Result<&'a [u8]> {
    let simple_signing: SimpleSigning =
        serde_json::from_slice(payload_bytes).wrap_err("parse cosign simple-signing payload")?;
    if simple_signing.critical.identity.docker_reference != oci_reference {
        return Err(stow_types::stow_error!(
            "signature payload docker reference mismatch: expected {}, got {}",
            oci_reference,
            simple_signing.critical.identity.docker_reference
        ));
    }
    if !simple_signing.satisfies_manifest_digest(oci_digest) {
        return Err(stow_types::stow_error!(
            "signature payload did not satisfy OCI manifest digest {}",
            oci_digest
        ));
    }
    Ok(payload_bytes)
}

fn verify_rekor_bundle(
    bundle: &RekorBundle,
    rekor_keys: &std::collections::BTreeMap<String, CosignVerificationKey>,
) -> stow_types::error::Result<()> {
    let mut payload_json = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(
        &mut payload_json,
        olpc_cjson::CanonicalFormatter::new(),
    );
    bundle.payload.serialize(&mut serializer)?;
    let rekor_key = rekor_keys.get(&bundle.payload.log_id).ok_or_else(|| {
        stow_types::stow_error!("missing Rekor public key for {}", bundle.payload.log_id)
    })?;
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
) -> stow_types::error::Result<()> {
    let cert_der = rustls_pki_types::CertificateDer::from(
        cert.to_der()
            .wrap_err("encode certificate to DER for webpki verification")?,
    );
    let end_entity = webpki::EndEntityCert::try_from(&cert_der).map_err(|error| {
        stow_types::stow_error!("parse end-entity certificate for webpki: {error}")
    })?;
    let trust_anchors = trust_root
        .fulcio_certs()?
        .into_iter()
        .map(|certificate| {
            webpki::anchor_from_trusted_cert(&certificate).map(|anchor| anchor.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| stow_types::stow_error!("convert Fulcio trust anchors: {error}"))?;
    let verification_time = rustls_pki_types::UnixTime::since_unix_epoch(
        cert.tbs_certificate.validity.not_before.to_unix_duration(),
    );
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &[],
            verification_time,
            webpki::KeyUsage::required(const_oid::db::rfc5280::ID_KP_CODE_SIGNING.as_bytes()),
            None,
            None,
        )
        .map_err(|error| stow_types::stow_error!("verify Fulcio certificate chain: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, SigstoreSignature,
    };

    use super::verify_bundle_signature_blocking;
    use crate::config::{StowConfig, VerifyMode};
    use crate::fetch::{ArtifactBundle, bundle_file_path};

    #[test]
    fn github_ci_mode_reports_actionable_mock_local_error() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir: tempdir.path().join(".stow"),
            request_timeout: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_secs(60),
            graph_cache_ttl: Duration::from_secs(60),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            verify_mode: VerifyMode::GithubCi,
            mock_public_key_path: None,
            state_db_pool: StowConfig::default_state_db_pool(),
        };
        let bundle = mock_local_bundle();

        let error = verify_bundle_signature_blocking(&config, &bundle)
            .expect_err("mock-local must fail in github-ci mode");
        let message = error.to_string();
        assert!(message.contains("local mock registry"));
        assert!(message.contains("STOW_VERIFY_MODE=mock-key"));
    }

    fn mock_local_bundle() -> ArtifactBundle {
        let payload_path = "sigstore/payload-0.json".to_owned();
        let payload_bytes = br#"{"critical":{"identity":{"docker-reference":"ghcr.io/water-rs/stow-cache/demo:artifact"},"image":{"docker-manifest-digest":"sha256:demo"},"type":"cosign container image signature"},"optional":null}"#.to_vec();
        ArtifactBundle {
            manifest: ArtifactBundleManifest {
                oci_reference: "ghcr.io/water-rs/stow-cache/demo:artifact".to_owned(),
                oci_digest: "sha256:demo".to_owned(),
                config: ArtifactBlobConfig {
                    compile_key: "compile-key".to_owned(),
                    crate_name: stow_types::identity::CrateName::parse("demo").unwrap(),
                    crate_version: stow_types::identity::CrateVersion::new(
                        semver::Version::parse("1.0.0").unwrap(),
                    ),
                    c_metadata: stow_types::identity::CMetadata::parse("abcd").unwrap(),
                    extra_filename: "-abcd".to_owned(),
                    target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
                    rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
                    features_json: stow_types::identity::FeaturesJson::default(),
                    dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson::default(),
                    dependency_compile_keys_json: "[]".to_owned(),
                    profile: stow_types::platform::Profile {
                        opt_level: "0".to_owned(),
                        debuginfo: 0,
                        debug_assertions: true,
                        overflow_checks: true,
                        panic: stow_types::platform::PanicStrategy::Unwind,
                    },
                    emit: vec!["metadata".to_owned()],
                    artifact_size: 4,
                    kind: ArtifactKind::Rlib,
                    crate_types: vec![RustCrateType::Lib],
                    outputs: vec![ArtifactBundleFile {
                        file_name: "libdemo.rmeta".to_owned(),
                        media_type: stow_types::bundle::STOW_RMETA_MEDIA_TYPE.to_owned(),
                        sha256: "deadbeef".to_owned(),
                    }],
                    native: None,
                    native_archive: None,},
                sigstore_signatures: vec![SigstoreSignature {
                    payload_path: payload_path.clone(),
                    signature: "signature".to_owned(),
                    certificate_pem: "mock-local".to_owned(),
                    rekor_bundle_json: None,
                }],
            },
            files: BTreeMap::from([
                (payload_path, payload_bytes),
                (bundle_file_path("libdemo.rmeta"), b"demo".to_vec()),
                (
                    stow_types::bundle::STOW_OCI_MANIFEST_PATH.to_owned(),
                    b"{}".to_vec(),
                ),
                (
                    stow_types::bundle::STOW_OCI_CONFIG_PATH.to_owned(),
                    b"{}".to_vec(),
                ),
            ]),
        }
    }
}
