//! `stow-admin index resign`: the one-time re-sign of a rustc's published
//! index slices from the branch identity to the release-tag identity.
//!
//! Until the release-tag switch `index-publish.yml` signed at
//! `refs/heads/main`; readers now accept release tags only. Each
//! `index.<target>.<rustc>` slice and its `folded.<target>.<rustc>`
//! companion keeps its manifest and gains a signature, made by this run,
//! at the same digest. A slice that already verifies under the new identity
//! is left alone, so a rerun writes nothing. The command is deleted once the
//! operator's run has finished (stow#1517), and the old identity lives here
//! alone.

use clap::Args;
use futures_util::StreamExt as _;
use stow_oci::resign::{ExactIdentity, Identities, Resigned, resign_manifest};
use stow_oci::verify::ReleaseIdentity;
use stow_types::api::CI_TARGET_TRIPLES;
use stow_types::identity::WireRustcVersion;
use stow_types::index::{folded_tag, index_tag};
use stow_types::registry::cache_repository;
use stow_types::stow_error;
use stow_types::trusted_builder::{CERTIFICATE_ISSUER, TrustedWorkflow};

use crate::render;

/// The certificate subject `index-publish.yml` signed under before the
/// release-tag switch.
const OLD_INDEX_IDENTITY: &str =
    "https://github.com/water-rs/stow/.github/workflows/index-publish.yml@refs/heads/main";

/// Slices re-signed in flight. Each is one signature and one `.sig`
/// push; the publisher's write budget bounds the registry side.
const RESIGN_CONCURRENCY: usize = 8;

#[derive(Args)]
pub struct IndexResignArgs {
    /// The rustc whose published slices are re-signed.
    #[arg(long)]
    rustc_version: String,
}

/// What a re-sign pass did, printed as one JSON line.
#[derive(Debug, Default, serde::Serialize)]
struct Summary {
    /// Tags that gained a signature.
    signed: Vec<String>,
    /// Tags that already carried one under the new identity.
    already: Vec<String>,
    /// Slices of the rustc with no published tag.
    absent: Vec<String>,
}

/// Re-sign every published `index`/`folded` slice of `args.rustc_version`.
pub async fn run(args: IndexResignArgs) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(&args.rustc_version)
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let trust = stow_oci::verify::records_trust().await?;
    let publisher = stow_oci::Publisher::from_env(http, &trust, TrustedWorkflow::INDEX)?;
    let repository = cache_repository(&rustc_version);
    let session = publisher.session(&repository)?;
    let old = ExactIdentity::new(OLD_INDEX_IDENTITY, CERTIFICATE_ISSUER);
    let new = ReleaseIdentity::new(TrustedWorkflow::INDEX);
    let sign = |reference: String, digest: String| {
        let (publisher, session) = (&publisher, &session);
        async move { publisher.signer().sign(session, &reference, &digest).await }
    };

    let tags = CI_TARGET_TRIPLES.iter().flat_map(|target| {
        [
            index_tag(target, rustc_version.as_str()),
            folded_tag(target, rustc_version.as_str()),
        ]
    });
    let mut outcomes = futures_util::stream::iter(tags.map(|tag| {
        let (session, repository, trust, old, new, sign) =
            (&session, &repository, &trust, &old, &new, &sign);
        async move {
            let reference = session.reference(&tag)?;
            let digest = match session.fetch_manifest_digest(&reference).await {
                Ok(digest) => digest,
                Err(error) if error.is_not_found() => return Ok((tag, None)),
                Err(error) => return Err(stow_error!("head {reference}: {error}")),
            };
            let resigned = resign_manifest(
                session,
                trust,
                &reference,
                &repository.reference(&tag),
                &digest,
                Identities { old, new },
                sign,
            )
            .await
            .map_err(|error| error.wrap_err(format!("re-sign {tag}")))?;
            Ok((tag, Some(resigned)))
        }
    }))
    .buffer_unordered(RESIGN_CONCURRENCY);

    let mut summary = Summary::default();
    let mut failed = 0;
    while let Some(outcome) = outcomes.next().await {
        match outcome {
            Ok((tag, Some(Resigned::Signed))) => summary.signed.push(tag),
            Ok((tag, Some(Resigned::Already))) => summary.already.push(tag),
            Ok((tag, None)) => summary.absent.push(tag),
            Err::<_, stow_types::error::Error>(error) => {
                failed += 1;
                tracing::error!(%error, "re-signing a slice failed");
            }
        }
    }
    summary.signed.sort();
    summary.already.sort();
    summary.absent.sort();
    render::emit_line(&serde_json::to_string(&summary)?);
    if failed > 0 {
        return Err(stow_error!(
            "{failed} slices of {rustc_version} failed to re-sign; the rest are signed"
        ));
    }
    Ok(())
}
