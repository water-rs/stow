//! Cosign signature verification against the Fulcio/Rekor trust root.
//!
//! The pure machinery `stow-cli`'s verify path and `stow-admin`'s records
//! reads share (stow#455): the caller supplies the signature material
//! pulled from the `sha256-<digest>.sig` artifact, the canonical OCI
//! reference and digest the signature must bind, and the certificate
//! identity it must attest.
//!
//! `mock-verify` swaps the Fulcio/Rekor chain for a local keypair — the
//! mock registry's `SimpleSigning` signatures. Production binaries keep
//! the feature off so no build of the tool accepts a mock key by
//! accident.

use base64::Engine as _;
use rustls_pki_types::{TrustAnchor, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::policy::{Identity, VerificationPolicy};
use sigstore::cosign::bundle::Bundle as RekorBundle;
use sigstore::cosign::payload::SimpleSigning;
#[cfg(feature = "mock-verify")]
use sigstore::crypto::SigningScheme;
use sigstore::crypto::{CosignVerificationKey, Signature};
use sigstore::trust::TrustRoot;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use stow_types::error::Context;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

const TRUSTED_CERT_ISSUER: &str = stow_types::trusted_builder::CERTIFICATE_ISSUER;

/// Dispatch `material`'s verification on `trust`: Fulcio/Rekor + pinned
/// certificate identity under [`Trust::GithubCi`], the local keypair
/// under `MockKey`.
///
/// # Errors
///
/// Whatever the selected verifier fails on — the exact signature checks
/// are each arm's.
pub fn verify_material(
    trust: &Trust,
    oci_reference: &str,
    oci_digest: &str,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
    certificate_identity: &str,
) -> stow_types::error::Result<()> {
    match trust {
        Trust::GithubCi(trust) => verify_signature_material_github_ci(
            trust,
            material,
            payload_bytes,
            oci_reference,
            oci_digest,
            certificate_identity,
        ),
        #[cfg(feature = "mock-verify")]
        Trust::MockKey(public_key_path) => verify_signature_material_mock_key(
            public_key_path,
            material,
            payload_bytes,
            oci_reference,
            oci_digest,
        ),
    }
}

/// Verify `materials` — every signature layer the artifact's
/// `sha256-<digest>.sig` manifest carries.
///
/// Tags can share a manifest digest, so one `.sig` legitimately holds
/// several payloads, one per tag; the artifact verifies when one
/// layer's signature checks out under `trust` AND its payload binds
/// `oci_reference` at `oci_digest`. The trust rule does not loosen: a
/// payload naming another reference is still never accepted, only
/// skipped as a candidate.
///
/// # Errors
///
/// `materials` is empty, or no layer both verified and bound the
/// expected reference and digest — the error lists the docker
/// references the layers did name.
pub fn verify_materials(
    trust: &Trust,
    oci_reference: &str,
    oci_digest: &str,
    materials: &[stow_types::bundle::BundleSignatureMaterial],
    certificate_identity: &str,
) -> stow_types::error::Result<()> {
    if materials.is_empty() {
        return Err(stow_types::stow_error!(
            "{oci_reference} carries no signature materials"
        ));
    }
    let mut seen_references = Vec::new();
    let mut last_error = None;
    for material in materials {
        if let Ok(payload) = serde_json::from_slice::<SimpleSigning>(&material.payload_bytes)
            && !seen_references.contains(&payload.critical.identity.docker_reference)
        {
            seen_references.push(payload.critical.identity.docker_reference);
        }
        let signature = stow_types::bundle::SigstoreSignature {
            payload_path: material.payload_path.clone(),
            signature: material.signature.clone(),
            certificate_pem: material.certificate_pem.clone(),
            rekor_bundle_json: material.rekor_bundle_json.clone(),
        };
        match verify_material(
            trust,
            oci_reference,
            oci_digest,
            &signature,
            &material.payload_bytes,
            certificate_identity,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(stow_types::stow_error!(
        "{oci_reference}: no signature layer bound this reference (saw {seen_references:?}): {}",
        last_error.map_or_else(
            || "no verifiable layers".to_owned(),
            |error| error.to_string(),
        )
    ))
}

/// The verification material a caller resolved for its verify mode.
#[derive(Debug)]
pub enum Trust {
    /// Fulcio/Rekor with a pinned GitHub certificate identity.
    GithubCi(std::sync::Arc<TrustMaterial>),
    /// The mock registry's local ECDSA key (`mock-verify` builds only).
    #[cfg(feature = "mock-verify")]
    MockKey(std::path::PathBuf),
}

/// Verify `material` — signature, Rekor entry binding, Fulcio chain at
/// integrated time — and pin its certificate to `certificate_identity`.
///
/// # Errors
///
/// A `mock-local` certificate, a payload/digest mismatch, a missing or
/// malformed Rekor bundle, and any signature or chain failure all error.
pub fn verify_signature_material_github_ci(
    trust: &TrustMaterial,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
    oci_reference: &str,
    oci_digest: &str,
    certificate_identity: &str,
) -> stow_types::error::Result<()> {
    if material.certificate_pem == "mock-local" {
        return Err(stow_types::stow_error!(
            "bundle is signed by the local mock registry, but stow is using github-ci verification; local mock e2e needs a stow-cli built with the `mock-verify` feature, STOW_VERIFY_MODE=mock-key and STOW_MOCK_PUBLIC_KEY_PATH=/path/to/mock.pub"
        ));
    }
    let payload_bytes = verify_payload_identity(payload_bytes, oci_reference, oci_digest)?;
    let identity_policy = Identity::new(certificate_identity, TRUSTED_CERT_ISSUER);
    verify_signature_material(trust, &identity_policy, material, payload_bytes)
}

#[cfg(feature = "mock-verify")]
/// Parse the mock registry's public key for `mock-verify` mode.
///
/// # Errors
///
/// The key file is unreadable or not ECDSA P-256 PEM.
pub fn mock_verification_key(
    public_key_path: &std::path::Path,
) -> stow_types::error::Result<CosignVerificationKey> {
    let public_key = std::fs::read(public_key_path)
        .wrap_err_with(|| format!("read mock public key {}", public_key_path.display()))?;
    CosignVerificationKey::from_pem(&public_key, &SigningScheme::ECDSA_P256_SHA256_ASN1)
        .wrap_err("parse mock public key")
}

/// The `mock-verify` arm: verify `material` against the mock registry's
/// local public key after the same payload-identity check.
///
/// # Errors
///
/// An unreadable/unparsable public key, payload mismatch, or signature
/// failure.
#[cfg(feature = "mock-verify")]
pub fn verify_signature_material_mock_key(
    public_key_path: &std::path::Path,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
    oci_reference: &str,
    oci_digest: &str,
) -> stow_types::error::Result<()> {
    let verification_key = mock_verification_key(public_key_path)?;
    let payload_bytes = verify_payload_identity(payload_bytes, oci_reference, oci_digest)?;
    verify_signature_material_mock(&verification_key, material, payload_bytes)
}

/// The parts of the Sigstore trust root verification consumes: Fulcio CA
/// anchors and Rekor log keys by log id. Built from the TUF root in
/// production and from a throwaway CA in tests.
///
/// Loading it is the expensive half of verification — a TUF root load and
/// the anchor/key parsing behind it cost well over a second — while
/// checking one signature against it is milliseconds. It is therefore
/// built once per process and shared, through
/// [`StowConfig::trust_material`], rather than rebuilt per artifact.
#[derive(Debug)]
pub struct TrustMaterial {
    fulcio_anchors: Vec<TrustAnchor<'static>>,
    rekor_keys: std::collections::BTreeMap<String, CosignVerificationKey>,
}

/// Load the Sigstore trust root once, for the whole process.
///
/// # Errors
///
/// A sigstore cache directory that cannot be created, a TUF root that
/// cannot be loaded, and a root that carries no Rekor key.
pub async fn load_trust_material(
    cache_dir: &std::path::Path,
) -> stow_types::error::Result<TrustMaterial> {
    let cache_dir = cache_dir.join("sigstore");
    async_fs::create_dir_all(&cache_dir)
        .await
        .wrap_err_with(|| format!("create sigstore cache dir {}", cache_dir.display()))?;
    // The span is attached to the future rather than entered around the
    // await: an entered guard is not `Send`, and this future crosses a
    // task boundary.
    let trust_root = tracing::Instrument::instrument(
        SigstoreTrustRoot::new(Some(&cache_dir)),
        tracing::info_span!("stow.sigstore.trust_root.refresh"),
    )
    .await
    .wrap_err("load sigstore trust root")?;
    TrustMaterial::from_trust_root(&trust_root)
}

impl TrustMaterial {
    fn from_trust_root(trust_root: &SigstoreTrustRoot) -> stow_types::error::Result<Self> {
        let fulcio_anchors = trust_root
            .fulcio_certs()?
            .into_iter()
            .map(|certificate| {
                webpki::anchor_from_trusted_cert(&certificate).map(|anchor| anchor.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| stow_types::stow_error!("convert Fulcio trust anchors: {error}"))?;
        let mut rekor_keys = std::collections::BTreeMap::new();
        for (key_id, key_bytes) in trust_root.rekor_keys()? {
            rekor_keys.insert(key_id, CosignVerificationKey::try_from_der(key_bytes)?);
        }
        if rekor_keys.is_empty() {
            return Err(stow_types::stow_error!(
                "sigstore trust root carries no Rekor public key; github-ci verification cannot check transparency-log entries"
            ));
        }
        Ok(Self {
            fulcio_anchors,
            rekor_keys,
        })
    }
}

/// Verify one cosign signature against the Fulcio/Rekor trust root.
///
/// A Fulcio certificate lives for minutes, so "the certificate was valid
/// at some point" proves nothing about a signature made later with a
/// leaked key. The Rekor entry is the only evidence of *when* the
/// signature was made, and it is only evidence for *this* signature if
/// its body carries the same signature, certificate and payload digest.
/// Verification therefore requires the bundle, ties its body to the
/// material, and checks the certificate at the log's integrated time.
///
/// # Errors
///
/// Missing Rekor bundle, unbound or malformed entry, a certificate
/// outside its validity window at the log time, an `identity_policy`
/// mismatch, or a bad signature all error.
pub fn verify_signature_material(
    trust: &TrustMaterial,
    identity_policy: &Identity,
    material: &stow_types::bundle::SigstoreSignature,
    payload_bytes: &[u8],
) -> stow_types::error::Result<()> {
    let rekor_bundle_json = material.rekor_bundle_json.as_ref().ok_or_else(|| {
        stow_types::stow_error!(
            "signature carries no Rekor bundle; github-ci verification requires transparency-log proof of signing time"
        )
    })?;
    let rekor_bundle: RekorBundle =
        serde_json::from_str(rekor_bundle_json).wrap_err("parse embedded rekor bundle")?;
    verify_rekor_bundle(&rekor_bundle, &trust.rekor_keys)?;

    let cert = Certificate::from_pem(material.certificate_pem.as_bytes())
        .wrap_err("parse fulcio certificate from bundle")?;
    let signature_bytes = decode_base64(&material.signature, "cosign signature")?;
    verify_rekor_entry_binds_material(&rekor_bundle, &cert, &signature_bytes, payload_bytes)?;

    let integrated_time = rekor_integrated_time(&rekor_bundle)?;
    verify_certificate_chain(&trust.fulcio_anchors, &cert, integrated_time)?;
    identity_policy.verify(&cert).map_err(|error| {
        stow_types::stow_error!("certificate identity verification failed: {error}")
    })?;

    let verification_key =
        CosignVerificationKey::try_from(&cert.tbs_certificate.subject_public_key_info)
            .wrap_err("extract verification key from certificate")?;
    verification_key
        .verify_signature(Signature::Raw(&signature_bytes), payload_bytes)
        .wrap_err("verify cosign signature against payload")
}

/// The `hashedrekord` entry body cosign uploads to Rekor.
#[derive(Debug, Deserialize)]
struct HashedRekordBody {
    kind: String,
    spec: HashedRekordSpec,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashedRekordSpec {
    signature: HashedRekordSignature,
    data: HashedRekordData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashedRekordSignature {
    content: String,
    public_key: HashedRekordPublicKey,
}

#[derive(Debug, Deserialize)]
struct HashedRekordPublicKey {
    content: String,
}

#[derive(Debug, Deserialize)]
struct HashedRekordData {
    hash: HashedRekordHash,
}

#[derive(Debug, Deserialize)]
struct HashedRekordHash {
    algorithm: String,
    value: String,
}

const HASHED_REKORD_KIND: &str = "hashedrekord";
const HASHED_REKORD_SHA256: &str = "sha256";

/// Require the Rekor entry to describe exactly this signature: same
/// signature bytes, same certificate (compared as DER, so PEM formatting
/// cannot matter), same payload digest.
fn verify_rekor_entry_binds_material(
    bundle: &RekorBundle,
    cert: &Certificate,
    signature_bytes: &[u8],
    payload_bytes: &[u8],
) -> stow_types::error::Result<()> {
    let body_bytes = decode_base64(&bundle.payload.body, "rekor entry body")?;
    let body: HashedRekordBody =
        serde_json::from_slice(&body_bytes).wrap_err("parse rekor hashedrekord entry body")?;
    if body.kind != HASHED_REKORD_KIND {
        return Err(stow_types::stow_error!(
            "rekor entry kind is {:?}, expected {HASHED_REKORD_KIND}",
            body.kind
        ));
    }
    if body.spec.data.hash.algorithm != HASHED_REKORD_SHA256 {
        return Err(stow_types::stow_error!(
            "rekor entry hashes the payload with {:?}, expected {HASHED_REKORD_SHA256}",
            body.spec.data.hash.algorithm
        ));
    }
    let payload_digest = hex::encode(Sha256::digest(payload_bytes));
    if !body
        .spec
        .data
        .hash
        .value
        .eq_ignore_ascii_case(&payload_digest)
    {
        return Err(stow_types::stow_error!(
            "rekor entry records payload digest {}, but the payload being verified hashes to {payload_digest}",
            body.spec.data.hash.value
        ));
    }
    let entry_signature = decode_base64(&body.spec.signature.content, "rekor entry signature")?;
    if entry_signature != signature_bytes {
        return Err(stow_types::stow_error!(
            "rekor entry records a different signature than the one being verified"
        ));
    }
    let entry_cert_pem = decode_base64(
        &body.spec.signature.public_key.content,
        "rekor entry certificate",
    )?;
    let entry_cert = Certificate::from_pem(&entry_cert_pem)
        .wrap_err("parse certificate recorded in rekor entry")?;
    let entry_cert_der = entry_cert
        .to_der()
        .wrap_err("encode rekor entry certificate to DER")?;
    let cert_der = cert.to_der().wrap_err("encode bundle certificate to DER")?;
    if entry_cert_der != cert_der {
        return Err(stow_types::stow_error!(
            "rekor entry records a different certificate than the one being verified"
        ));
    }
    Ok(())
}

fn rekor_integrated_time(bundle: &RekorBundle) -> stow_types::error::Result<UnixTime> {
    let seconds = u64::try_from(bundle.payload.integrated_time).map_err(|_| {
        stow_types::stow_error!(
            "rekor entry integrated time {} is before the Unix epoch",
            bundle.payload.integrated_time
        )
    })?;
    Ok(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        seconds,
    )))
}

fn decode_base64(value: &str, what: &str) -> stow_types::error::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|error| stow_types::stow_error!("decode base64 {what}: {error}"))
}

#[cfg(feature = "mock-verify")]
/// Verify `material` against a raw ECDSA key — the `mock-verify` path.
///
/// # Errors
///
/// The signature fails against the payload.
#[cfg(feature = "mock-verify")]
pub fn verify_signature_material_mock(
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

/// Require the `SimpleSigning` payload to name `oci_reference` and cover
/// `oci_digest` — the binding that stops a signature on one artifact
/// being replayed against another.
///
/// # Errors
///
/// A payload that is not `SimpleSigning` JSON, names a different
/// reference, or covers a different digest.
pub fn verify_payload_identity<'a>(
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

/// Verify the Fulcio chain with the certificate's validity window evaluated
/// at `verification_time` — the Rekor integrated time, never the
/// certificate's own `not_before`.
fn verify_certificate_chain(
    trust_anchors: &[TrustAnchor<'static>],
    cert: &Certificate,
    verification_time: UnixTime,
) -> stow_types::error::Result<()> {
    let cert_der = rustls_pki_types::CertificateDer::from(
        cert.to_der()
            .wrap_err("encode certificate to DER for webpki verification")?,
    );
    let end_entity = webpki::EndEntityCert::try_from(&cert_der).map_err(|error| {
        stow_types::stow_error!("parse end-entity certificate for webpki: {error}")
    })?;
    let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    let at = verification_time.as_secs();
    if at < not_before.as_secs() || at > not_after.as_secs() {
        return Err(stow_types::stow_error!(
            "signature was logged at unix time {at}, outside the certificate validity window {}..={}",
            not_before.as_secs(),
            not_after.as_secs()
        ));
    }
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            trust_anchors,
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

    use stow_types::bundle::SigstoreSignature;

    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    use super::{TrustMaterial, verify_signature_material, verify_signature_material_github_ci};

    const CERTIFICATE_IDENTITY: &str = stow_types::trusted_builder::CERTIFICATE_IDENTITY;
    const CERTIFICATE_ISSUER: &str = super::TRUSTED_CERT_ISSUER;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
        PublicKeyData as _, SanType,
    };
    use sigstore::bundle::verify::policy::Identity;
    use sigstore::cosign::bundle::{Bundle as RekorBundle, Payload as RekorPayload};
    use sigstore::crypto::{CosignVerificationKey, SigningScheme};

    const FULCIO_OIDC_ISSUER_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
    const REKOR_LOG_ID: &str = "test-log";
    /// Certificate validity window: a Fulcio-like ten minutes.
    const NOT_BEFORE: i64 = 1_800_000_000;
    const NOT_AFTER: i64 = NOT_BEFORE + 600;

    fn base64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A signing identity: a leaf certificate and its private key.
    struct Leaf {
        key: KeyPair,
        pem: String,
    }

    /// A throwaway Fulcio: one CA, one leaf certificate carrying the trusted
    /// workflow identity, and a Rekor log key.
    struct MiniSigstore {
        trust: TrustMaterial,
        ca: CertifiedIssuer<'static, KeyPair>,
        leaf: Leaf,
        rekor_key: KeyPair,
    }

    impl MiniSigstore {
        fn new() -> Self {
            let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            ca_params.not_before =
                time::OffsetDateTime::from_unix_timestamp(NOT_BEFORE - 86_400).unwrap();
            ca_params.not_after =
                time::OffsetDateTime::from_unix_timestamp(NOT_AFTER + 86_400).unwrap();
            let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

            let rekor_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let rekor_verification_key = CosignVerificationKey::from_der(
                &rekor_key.subject_public_key_info(),
                &SigningScheme::ECDSA_P256_SHA256_ASN1,
            )
            .unwrap();
            let anchor = webpki::anchor_from_trusted_cert(ca.der())
                .unwrap()
                .to_owned();
            let leaf = Self::issue_leaf(&ca, CERTIFICATE_IDENTITY);
            Self {
                trust: TrustMaterial {
                    fulcio_anchors: vec![anchor],
                    rekor_keys: BTreeMap::from([(REKOR_LOG_ID.to_owned(), rekor_verification_key)]),
                },
                ca,
                leaf,
                rekor_key,
            }
        }

        /// A Fulcio-shaped leaf for `identity`, valid for `NOT_BEFORE..=NOT_AFTER`.
        fn issue_leaf(ca: &CertifiedIssuer<'static, KeyPair>, identity: &str) -> Leaf {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                FULCIO_OIDC_ISSUER_OID,
                CERTIFICATE_ISSUER.as_bytes().to_vec(),
            )];
            params.not_before = time::OffsetDateTime::from_unix_timestamp(NOT_BEFORE).unwrap();
            params.not_after = time::OffsetDateTime::from_unix_timestamp(NOT_AFTER).unwrap();
            let certificate = params.signed_by(&key, ca).unwrap();
            Leaf {
                key,
                pem: certificate.pem(),
            }
        }

        /// Another leaf from the same CA carrying the same identity.
        fn another_leaf(&self) -> Leaf {
            Self::issue_leaf(&self.ca, CERTIFICATE_IDENTITY)
        }

        /// A leaf from the same CA for a workflow that is not the trusted one.
        fn impostor_leaf(&self) -> Leaf {
            Self::issue_leaf(
                &self.ca,
                "https://github.com/someone-else/stow/.github/workflows/build-crate.yml@refs/heads/main",
            )
        }

        /// The `hashedrekord` body cosign uploads for `signature` over `payload`
        /// made with `leaf`.
        fn hashed_rekord_body(leaf: &Leaf, payload: &[u8], signature: &[u8]) -> serde_json::Value {
            serde_json::json!({
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": {
                    "data": { "hash": { "algorithm": "sha256", "value": hex::encode(Sha256::digest(payload)) } },
                    "signature": {
                        "content": base64(signature),
                        "publicKey": { "content": base64(leaf.pem.as_bytes()) }
                    }
                }
            })
        }

        /// A Rekor bundle whose entry is `body`, integrated at
        /// `integrated_time` in log `log_id`, with a genuine SET.
        fn rekor_bundle_for_body(
            &self,
            body: &serde_json::Value,
            integrated_time: i64,
            log_id: &str,
        ) -> String {
            let payload = RekorPayload {
                body: base64(body.to_string().as_bytes()),
                integrated_time,
                log_index: 1,
                log_id: log_id.to_owned(),
            };
            let mut canonical = Vec::new();
            let mut serializer = serde_json::Serializer::with_formatter(
                &mut canonical,
                olpc_cjson::CanonicalFormatter::new(),
            );
            serde::Serialize::serialize(&payload, &mut serializer).unwrap();
            let set = rcgen::SigningKey::sign(&self.rekor_key, &canonical).unwrap();
            serde_json::to_string(&RekorBundle {
                signed_entry_timestamp: base64(&set),
                payload,
            })
            .unwrap()
        }

        /// A genuine Rekor entry for `payload` signed with `signature` by
        /// `leaf`, integrated at `integrated_time`.
        fn rekor_bundle(
            &self,
            leaf: &Leaf,
            payload: &[u8],
            signature: &[u8],
            integrated_time: i64,
        ) -> String {
            self.rekor_bundle_for_body(
                &Self::hashed_rekord_body(leaf, payload, signature),
                integrated_time,
                REKOR_LOG_ID,
            )
        }

        /// Signature material produced by `leaf` for `payload`, logged at
        /// `integrated_time`.
        fn material_from(
            &self,
            leaf: &Leaf,
            payload: &[u8],
            integrated_time: i64,
        ) -> SigstoreSignature {
            let signature = rcgen::SigningKey::sign(&leaf.key, payload).unwrap();
            SigstoreSignature {
                payload_path: "sigstore/payload-0.json".to_owned(),
                signature: base64(&signature),
                certificate_pem: leaf.pem.clone(),
                rekor_bundle_json: Some(self.rekor_bundle(
                    leaf,
                    payload,
                    &signature,
                    integrated_time,
                )),
            }
        }

        fn material(&self, payload: &[u8], integrated_time: i64) -> SigstoreSignature {
            self.material_from(&self.leaf, payload, integrated_time)
        }

        fn verify(
            &self,
            material: &SigstoreSignature,
            payload: &[u8],
        ) -> stow_types::error::Result<()> {
            let policy = Identity::new(CERTIFICATE_IDENTITY, CERTIFICATE_ISSUER);
            verify_signature_material(&self.trust, &policy, material, payload)
        }
    }

    #[test]
    fn genuine_signature_logged_inside_validity_passes() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        sigstore
            .verify(&sigstore.material(payload, NOT_BEFORE + 30), payload)
            .unwrap();
    }

    #[test]
    fn signature_without_rekor_bundle_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        material.rekor_bundle_json = None;
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(error.to_string().contains("no Rekor bundle"), "{error}");
    }

    #[test]
    fn rekor_entry_for_a_different_payload_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let other = sigstore.material(b"another artifact", NOT_BEFORE + 30);
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        // A genuine, SET-valid entry — just not for this signature.
        material.rekor_bundle_json = other.rekor_bundle_json;
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(error.to_string().contains("payload digest"), "{error}");
    }

    #[test]
    fn rekor_entry_with_a_different_signature_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        // Same payload, freshly signed: ECDSA is randomized, so the bytes differ.
        let other_signature = rcgen::SigningKey::sign(&sigstore.leaf.key, payload).unwrap();
        material.rekor_bundle_json =
            Some(sigstore.rekor_bundle(&sigstore.leaf, payload, &other_signature, NOT_BEFORE + 30));
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(error.to_string().contains("different signature"), "{error}");
    }

    #[test]
    fn rekor_entry_naming_a_different_certificate_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&material.signature)
            .unwrap();
        // Same signature bytes and payload, but the entry attributes them to
        // another certificate with the same identity.
        material.rekor_bundle_json = Some(sigstore.rekor_bundle(
            &sigstore.another_leaf(),
            payload,
            &signature,
            NOT_BEFORE + 30,
        ));
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error.to_string().contains("different certificate"),
            "{error}"
        );
    }

    #[test]
    fn rekor_entry_of_another_kind_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&material.signature)
            .unwrap();
        let mut body = MiniSigstore::hashed_rekord_body(&sigstore.leaf, payload, &signature);
        body["kind"] = serde_json::Value::from("intoto");
        material.rekor_bundle_json =
            Some(sigstore.rekor_bundle_for_body(&body, NOT_BEFORE + 30, REKOR_LOG_ID));
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error.to_string().contains("expected hashedrekord"),
            "{error}"
        );
    }

    #[test]
    fn rekor_entry_from_an_unknown_log_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&material.signature)
            .unwrap();
        let body = MiniSigstore::hashed_rekord_body(&sigstore.leaf, payload, &signature);
        material.rekor_bundle_json =
            Some(sigstore.rekor_bundle_for_body(&body, NOT_BEFORE + 30, "unknown-log"));
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error.to_string().contains("missing Rekor public key"),
            "{error}"
        );
    }

    #[test]
    fn certificate_from_an_untrusted_ca_is_rejected() {
        let sigstore = MiniSigstore::new();
        let other_ca = MiniSigstore::new();
        let payload = b"payload";
        // Logged in the trusted Rekor, but the leaf chains to a CA that is
        // not in the trust root.
        let material = sigstore.material_from(&other_ca.leaf, payload, NOT_BEFORE + 30);
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("verify Fulcio certificate chain"),
            "{error}"
        );
    }

    #[test]
    fn certificate_for_another_workflow_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let material = sigstore.material_from(&sigstore.impostor_leaf(), payload, NOT_BEFORE + 30);
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("certificate identity verification failed"),
            "{error}"
        );
    }

    #[test]
    fn signature_logged_after_certificate_expiry_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let material = sigstore.material(payload, NOT_AFTER + 3600);
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the certificate validity window"),
            "{error}"
        );
    }

    #[test]
    fn signature_logged_before_certificate_validity_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let material = sigstore.material(payload, NOT_BEFORE - 1);
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the certificate validity window"),
            "{error}"
        );
    }

    #[test]
    fn tampered_set_is_rejected() {
        let sigstore = MiniSigstore::new();
        let payload = b"payload";
        let mut material = sigstore.material(payload, NOT_BEFORE + 30);
        let mut bundle: RekorBundle =
            serde_json::from_str(material.rekor_bundle_json.as_deref().unwrap()).unwrap();
        bundle.payload.integrated_time += 1;
        material.rekor_bundle_json = Some(serde_json::to_string(&bundle).unwrap());
        let error = sigstore.verify(&material, payload).unwrap_err();
        assert!(
            error.to_string().contains("Rekor signed entry timestamp"),
            "{error}"
        );
    }

    #[test]
    fn github_ci_mode_reports_actionable_mock_local_error() {
        let trust = TrustMaterial {
            fulcio_anchors: Vec::new(),
            rekor_keys: BTreeMap::new(),
        };
        let material = SigstoreSignature {
            payload_path: "sigstore/payload-0.json".to_owned(),
            signature: "signature".to_owned(),
            certificate_pem: "mock-local".to_owned(),
            rekor_bundle_json: None,
        };
        let error = verify_signature_material_github_ci(
            &trust,
            &material,
            b"payload",
            "ghcr.io/water-rs/stow-cache:demo.artifact",
            "sha256:demo",
            CERTIFICATE_IDENTITY,
        )
        .expect_err("mock-local must fail in github-ci mode");
        let message = error.to_string();
        assert!(message.contains("local mock registry"));
        assert!(message.contains("mock-verify"));
    }

    /// One `BundleSignatureMaterial` for `reference` over `digest`,
    /// signed by the fixture leaf.
    fn signed_material(
        sigstore: &MiniSigstore,
        reference: &str,
        digest: &str,
        index: usize,
    ) -> stow_types::bundle::BundleSignatureMaterial {
        let payload = serde_json::to_vec(&sigstore::cosign::payload::SimpleSigning::new(
            &reference.parse().expect("reference parses"),
            digest,
        ))
        .expect("payload serializes");
        let material = sigstore.material(&payload, NOT_BEFORE + 30);
        stow_types::bundle::BundleSignatureMaterial {
            payload_path: format!("sigstore/payload-{index}.json"),
            payload_bytes: payload,
            signature: material.signature,
            certificate_pem: material.certificate_pem,
            rekor_bundle_json: material.rekor_bundle_json,
        }
    }

    /// Tags sharing a manifest digest share one `.sig` manifest, so its
    /// layers name several references; the layer binding the expected
    /// reference verifies wherever it sits.
    #[test]
    fn materials_verify_on_the_layer_binding_the_reference() {
        let sigstore = MiniSigstore::new();
        let digest = format!("sha256:{:064x}", 1);
        let expected = "ghcr.io/water-rs/stow-cache:folded.aarch64-apple-darwin.1.98.1";
        let other = "ghcr.io/water-rs/stow-cache:folded.x86_64-pc-windows-msvc.1.98.1";
        // The matching layer is deliberately not first.
        let materials = [other, expected]
            .iter()
            .enumerate()
            .map(|(index, reference)| signed_material(&sigstore, reference, &digest, index))
            .collect::<Vec<_>>();
        super::verify_materials(
            &super::Trust::GithubCi(std::sync::Arc::new(sigstore.trust)),
            expected,
            &digest,
            &materials,
            CERTIFICATE_IDENTITY,
        )
        .expect("the layer binding the expected reference verifies");
    }

    /// A `.sig` whose only layer names another reference is rejected,
    /// and the error lists the references it saw.
    #[test]
    fn materials_binding_only_another_reference_are_rejected() {
        let sigstore = MiniSigstore::new();
        let digest = format!("sha256:{:064x}", 1);
        let other = "ghcr.io/water-rs/stow-cache:folded.x86_64-pc-windows-msvc.1.98.1";
        let materials = vec![signed_material(&sigstore, other, &digest, 0)];
        let error = super::verify_materials(
            &super::Trust::GithubCi(std::sync::Arc::new(sigstore.trust)),
            "ghcr.io/water-rs/stow-cache:folded.aarch64-apple-darwin.1.98.1",
            &digest,
            &materials,
            CERTIFICATE_IDENTITY,
        )
        .expect_err("a signature naming another tag must not satisfy this one");
        let message = error.to_string();
        assert!(message.contains(other), "{message}");
    }
}
