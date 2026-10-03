use serde::{Deserialize, Serialize};
use sigstore::bundle::verify::policy::Identity;
use sigstore::cosign::payload::SimpleSigning;
use stow_types::error::Context;

// The signature-verification machinery itself lives in `stow-oci` — the
// same Fulcio/Rekor + pinned-identity check `stow-admin index export`
// applies to records artifacts (stow#455). This module keeps only the
// StowConfig-coupled pieces: mode resolution, bundle framing, and the
// trust-marker cache.
pub use stow_oci::verify::{Trust, TrustMaterial, load_trust_material};
#[cfg(feature = "mock-verify")]
use stow_oci::verify::{mock_verification_key, verify_signature_material_mock};
use stow_oci::verify::{verify_material, verify_signature_material};

/// Resolve the verification material this config's verify mode needs.
///
/// # Errors
///
/// Whatever loading the Sigstore trust root fails with.
pub async fn resolve_trust(config: &StowConfig) -> stow_types::error::Result<Trust> {
    match &config.verify_mode {
        VerifyMode::GithubCi => Ok(Trust::GithubCi(config.trust_material().await?)),
        #[cfg(feature = "mock-verify")]
        VerifyMode::MockKey {
            public_key_path, ..
        } => Ok(Trust::MockKey(public_key_path.clone())),
    }
}

/// Start resolving the trust material on a spawned task so its cold-cache
/// TUF download overlaps the caller's own network work instead of stacking
/// behind it (stow#347). `Trust::MockKey` resolves without any fetch, so
/// the spawn is cheap on the mock path too.
pub fn spawn_trust(
    config: &StowConfig,
) -> tokio::task::JoinHandle<stow_types::error::Result<Trust>> {
    let config = config.clone();
    tokio::task::spawn(async move { resolve_trust(&config).await })
}

use crate::artifact_cache;
use crate::artifact_cache::CachedArtifactBundle;
use crate::config::{StowConfig, VerifyMode};
use crate::fetch::{ArtifactBundle, FetchRequest};

const TRUSTED_CERT_URL: &str = stow_types::trusted_builder::CERTIFICATE_IDENTITY;
const TRUSTED_CERT_ISSUER: &str = stow_types::trusted_builder::CERTIFICATE_ISSUER;
const INDEX_CERT_URL: &str = stow_types::trusted_builder::INDEX_CERTIFICATE_IDENTITY;

/// Bumped whenever the meaning of "verified" changes, so verdicts minted
/// under an older scheme are re-verified instead of trusted. Version 2:
/// github-ci verification requires a Rekor entry bound to the signature and
/// evaluates the certificate at its integrated time.
const TRUST_MARKER_VERSION: u8 = 2;

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
    match &config.verify_mode {
        VerifyMode::GithubCi => {
            let trust = config.trust_material().await?;
            smol::unblock(move || verify_bundle_signature_github_ci_blocking(&trust, &bundle))
                .await?;
        }
        #[cfg(feature = "mock-verify")]
        VerifyMode::MockKey {
            public_key_path, ..
        } => {
            let public_key_path = public_key_path.clone();
            smol::unblock(move || {
                verify_bundle_signature_mock_key_blocking(&public_key_path, &bundle)
            })
            .await?;
        }
    }
    Ok(())
}

pub async fn verify_cached_bundle_signature(
    config: &StowConfig,
    bundle: &CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    // A locally-built entry is trusted by construction: it was produced by
    // rustc on this machine and never carries sigstore material, so the
    // remote verification path and its trust marker do not apply.
    if bundle.provenance == artifact_cache::ArtifactProvenance::Local {
        return Ok(());
    }
    let expected_marker = expected_trust_marker(config);
    if cached_trust_marker_matches(bundle, &expected_marker) {
        return Ok(());
    }

    let config = config.clone();
    let trust = resolve_trust(&config).await?;
    let oci_reference = bundle.oci_reference.clone();
    let oci_digest = bundle.oci_digest.clone();
    let sigstore_signatures = bundle.sigstore_signatures.clone();
    let entry_dir = bundle.entry_dir.clone();
    smol::unblock(move || {
        verify_cached_bundle_signature_blocking(
            &trust,
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
    let marker = expected_trust_marker(config);
    write_cached_trust_marker(config, bundle, &marker).await
}

/// Store an already-verified downloaded bundle, then persist its trust marker
/// when the stored entry is remote.
///
/// Local-first store may return an existing local entry covering the same
/// identity: that entry is trusted by construction and comes back unmarked —
/// a correctly cached artifact is not a store failure. When the marker write
/// itself fails on a remote entry, the entry is evicted so a later lookup
/// cannot serve an unmarked artifact.
pub async fn store_downloaded_bundle_with_trust_marker(
    config: &StowConfig,
    request: &FetchRequest<'_>,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<CachedArtifactBundle> {
    let cached_bundle = artifact_cache::store_downloaded_bundle(config, request, bundle).await?;
    if cached_bundle.provenance == artifact_cache::ArtifactProvenance::Remote
        && let Err(error) = persist_cached_bundle_trust_marker(config, &cached_bundle).await
    {
        artifact_cache::remove_cached_bundle(config, request)
            .await
            .wrap_err("evict cache entry missing trust marker")?;
        return Err(error.wrap_err("persist local stow cache trust marker"));
    }
    Ok(cached_bundle)
}

/// Verify an index manifest's signature material with the same machinery
/// bundles get — the cosign payload binding, Rekor entry, and Fulcio chain
/// — with the certificate pinned to the index-publish workflow identity
/// rather than the build workflow. The download path resolves `trust`
/// concurrently with the slice pull, so it arrives already resolved
/// (stow#347).
///
/// One valid signature is enough, matching the bundle path. `materials`
/// come from the `sha256-<hex>.sig` image pulled next to the index
/// manifest; `oci_reference` is the canonical
/// `ghcr.io/water-rs/stow-cache:index.<target>.<rustc>` the signer bound
/// (the transport base never rewrites it).
///
/// # Errors
///
/// Returns an error when `materials` is empty or no signature satisfies
/// the trust's policy.
pub async fn verify_index_signature_with_trust(
    trust: Trust,
    oci_reference: &str,
    oci_digest: &str,
    materials: &[stow_types::bundle::BundleSignatureMaterial],
) -> stow_types::error::Result<()> {
    if materials.is_empty() {
        return Err(stow_types::stow_error!(
            "index manifest {oci_digest} carries no signature materials"
        ));
    }
    let materials = materials.to_vec();
    let oci_reference = oci_reference.to_owned();
    let oci_digest = oci_digest.to_owned();
    smol::unblock(move || {
        stow_oci::verify::verify_materials(
            &trust,
            &oci_reference,
            &oci_digest,
            &materials,
            INDEX_CERT_URL,
        )
    })
    .await
}

fn verify_cached_bundle_signature_blocking(
    trust: &Trust,
    oci_reference: &str,
    oci_digest: &str,
    sigstore_signatures: &[stow_types::bundle::SigstoreSignature],
    entry_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    if sigstore_signatures.is_empty() {
        return Err(stow_types::stow_error!(
            "cached bundle does not contain any embedded sigstore signatures"
        ));
    }
    let mut last_error = None;
    for material in sigstore_signatures {
        let payload_path = entry_dir.join(&material.payload_path);
        let payload_bytes = std::fs::read(&payload_path)
            .wrap_err_with(|| format!("read cached sigstore payload {}", payload_path.display()))?;
        match verify_material(
            trust,
            oci_reference,
            oci_digest,
            material,
            &payload_bytes,
            TRUSTED_CERT_URL,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!("no embedded sigstore signature verified for {oci_reference}")
    }))
}

fn verify_bundle_signature_github_ci_blocking(
    trust: &TrustMaterial,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    if bundle
        .manifest
        .sigstore_signatures
        .iter()
        .any(|material| material.certificate_pem == "mock-local")
    {
        return Err(stow_types::stow_error!(
            "bundle is signed by the local mock registry, but stow is using github-ci verification; local mock e2e needs a stow-cli built with the `mock-verify` feature, STOW_VERIFY_MODE=mock-key and STOW_MOCK_PUBLIC_KEY_PATH=/path/to/mock.pub"
        ));
    }

    let identity_policy = Identity::new(TRUSTED_CERT_URL, TRUSTED_CERT_ISSUER);
    let mut last_error = None;
    for material in &bundle.manifest.sigstore_signatures {
        let payload_bytes = match verified_payload_bytes(bundle, material) {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match verify_signature_material(trust, &identity_policy, material, payload_bytes) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!(
            "no embedded sigstore signature satisfied the GitHub CI trust policy"
        )
    }))
}

#[cfg(feature = "mock-verify")]
fn verify_bundle_signature_mock_key_blocking(
    public_key_path: &std::path::Path,
    bundle: &ArtifactBundle,
) -> stow_types::error::Result<()> {
    let verification_key = mock_verification_key(public_key_path)?;

    let mut last_error = None;
    for material in &bundle.manifest.sigstore_signatures {
        let payload_bytes = match verified_payload_bytes(bundle, material) {
            Ok(payload_bytes) => payload_bytes,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match verify_signature_material_mock(&verification_key, material, payload_bytes) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        stow_types::stow_error!("no embedded signature satisfied the mock trust policy")
    }))
}

fn expected_trust_marker(config: &StowConfig) -> VerifiedTrustMarker {
    let policy = match &config.verify_mode {
        VerifyMode::GithubCi => {
            format!("github-ci:{TRUSTED_CERT_URL}:{TRUSTED_CERT_ISSUER}")
        }
        #[cfg(feature = "mock-verify")]
        VerifyMode::MockKey {
            public_key_sha256, ..
        } => format!("mock-key:{public_key_sha256}"),
    };

    VerifiedTrustMarker {
        version: TRUST_MARKER_VERSION,
        policy,
    }
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
