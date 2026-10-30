//! Everything a trusted publish holds: the registry credential, the
//! process's HTTP client and write budget, and the keyless signer.

use stow_types::registry::CacheRepository;

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
    /// job's OIDC identity checking its signatures against `trust`.
    ///
    /// # Errors
    ///
    /// A credential or the OIDC endpoint is missing from the job
    /// environment, the write rate is malformed, or `trust` is the mock
    /// key.
    pub fn from_env(http: RegistryHttp, trust: &Trust) -> stow_types::error::Result<Self> {
        let signer = KeylessSigner::from_env(http.clone(), trust.sigstore()?)?;
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
