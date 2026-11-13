//! Everything a trusted publish holds: the registry credential, the
//! process's HTTP client and write budget, and the keyless signer.

use stow_types::registry::CacheRepository;
use stow_types::trusted_builder::{ReleaseTag, TrustedWorkflow};

use crate::client::{RegistryHttp, RegistrySession};
use crate::registry::{RegistryBase, RegistryCredentials};
use crate::sign::KeylessSigner;
use crate::throttle::WriteBudget;
use crate::verify::Trust;

/// One process's publishing context. Every push session it opens spends
/// the one [`WriteBudget`], and every signature rides the one
/// [`KeylessSigner`], so a process publishing from many tasks at once
/// shares both.
#[derive(Debug, Clone)]
pub struct Publisher {
    credentials: RegistryCredentials,
    http: RegistryHttp,
    writes: WriteBudget,
    signer: KeylessSigner,
}

impl Publisher {
    /// A publisher over explicit parts.
    #[must_use]
    pub const fn new(
        credentials: RegistryCredentials,
        http: RegistryHttp,
        writes: WriteBudget,
        signer: KeylessSigner,
    ) -> Self {
        Self {
            credentials,
            http,
            writes,
            signer,
        }
    }

    /// The trusted job's publisher: `GHCR_USERNAME`/`GHCR_TOKEN`, the
    /// `STOW_GHCR_WRITES_PER_MINUTE` budget, and a keyless signer under the
    /// job's OIDC identity checking its signatures against `trust` and
    /// the subject of `workflow` at the release tag the job runs at
    /// (`GITHUB_REF`, not `GITHUB_WORKFLOW_REF`, which names a called
    /// workflow's file): a signature under any other is never published.
    ///
    /// # Errors
    ///
    /// A credential or the OIDC endpoint is missing from the job
    /// environment, `GITHUB_REF` is not a release tag ref, the write rate
    /// is malformed, or `trust` is the mock key.
    pub fn from_env(
        http: RegistryHttp,
        trust: &Trust,
        workflow: TrustedWorkflow,
    ) -> stow_types::error::Result<Self> {
        let github_ref = std::env::var("GITHUB_REF").map_err(|error| {
            stow_types::stow_error!("keyless signing needs GITHUB_REF: {error}")
        })?;
        let certificate_identity = signing_san(workflow, &github_ref)?;
        let signer =
            KeylessSigner::from_env(http.clone(), trust.sigstore()?, &certificate_identity)?;
        Ok(Self::new(
            RegistryCredentials::from_env()?,
            http,
            WriteBudget::from_env()?,
            signer,
        ))
    }

    /// The credentialed session on the production registry for
    /// `repository`.
    ///
    /// # Errors
    ///
    /// The production registry URL is malformed — a bug, not a runtime
    /// condition.
    pub fn session(
        &self,
        repository: &CacheRepository,
    ) -> stow_types::error::Result<RegistrySession> {
        Ok(RegistryBase::production()?.push_session(
            repository,
            &self.credentials,
            &self.http,
            &self.writes,
        ))
    }

    /// The signer every signature of this publisher rides.
    #[must_use]
    pub const fn signer(&self) -> &KeylessSigner {
        &self.signer
    }
}

/// The certificate subject a job running `workflow` at `github_ref` is
/// issued: the exact subject the signer checks its own signatures for.
///
/// # Errors
///
/// `github_ref` is not `refs/tags/` and a release tag.
fn signing_san(workflow: TrustedWorkflow, github_ref: &str) -> stow_types::error::Result<String> {
    let tag = github_ref
        .strip_prefix("refs/tags/")
        .ok_or_else(|| {
            stow_types::stow_error!(
                "keyless signing runs only on a release tag, but GITHUB_REF is {github_ref:?}"
            )
        })?
        .parse::<ReleaseTag>()
        .map_err(|error| stow_types::stow_error!("keyless signing: {error}"))?;
    Ok(workflow.san(&tag))
}

#[cfg(test)]
mod tests {
    use super::signing_san;
    use stow_types::trusted_builder::TrustedWorkflow;

    #[test]
    fn the_signing_subject_is_the_workflow_at_the_job_tag() {
        assert_eq!(
            signing_san(TrustedWorkflow::BUILD, "refs/tags/v1.2.3").unwrap(),
            "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/tags/v1.2.3"
        );
    }

    #[test]
    fn a_job_off_a_release_tag_does_not_sign() {
        for github_ref in [
            "refs/heads/main",
            "refs/tags/stow-cli-v1.2.3",
            "refs/tags/v1.2",
            "v1.2.3",
        ] {
            assert!(
                signing_san(TrustedWorkflow::INDEX, github_ref).is_err(),
                "{github_ref}"
            );
        }
    }
}
