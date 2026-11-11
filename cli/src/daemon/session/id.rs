//! A session's identity and its directory on disk.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use stow_types::error::{Context, Result};

/// 128 random bits naming one session, minted where the session opens.
///
/// Random, so a variable a build leaves behind never names a session of a
/// later process generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// A fresh identity from the operating system's randomness.
    ///
    /// # Panics
    ///
    /// The operating system has no randomness to give; nothing can open a
    /// session then.
    #[must_use]
    pub fn mint() -> Self {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).expect("the operating system's randomness is available");
        Self(bytes)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for SessionId {
    type Err = String;

    /// Parse the 32 lowercase hex digits [`fmt::Display`] writes.
    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        let mut bytes = [0; 16];
        if raw.len() != 32 || raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(format!("`{raw}` is not 32 lowercase hex digits"));
        }
        hex::decode_to_slice(raw, &mut bytes)
            .map_err(|error| format!("`{raw}` is not a session id: {error}"))?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for SessionId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for SessionId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// The directory a session keeps its on-disk state in: the provenance
/// marks of the units it compiled locally. It lives under the run
/// directory's `sessions` and is removed when the session ends; a start
/// of the daemon removes the ones a dead process left.
#[derive(Debug)]
pub struct SessionDir(PathBuf);

impl SessionDir {
    /// Create the directory of session `id` under `sessions`, owner-only.
    ///
    /// # Errors
    ///
    /// The directory cannot be created.
    pub fn create(sessions: &Path, id: SessionId) -> Result<Self> {
        let path = sessions.join(id.to_string());
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .wrap_err_with(|| format!("create the session directory {}", path.display()))?;
        Ok(Self(path))
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionDir, SessionId};

    #[test]
    fn an_id_round_trips_through_its_text() {
        let id = SessionId::mint();
        assert_eq!(id.to_string().len(), 32);
        assert_eq!(id.to_string().parse::<SessionId>(), Ok(id));
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(serde_json::from_str::<SessionId>(&json).expect("parse"), id);
        assert_ne!(SessionId::mint(), id, "ids are random");
    }

    #[test]
    fn text_that_is_not_an_id_is_refused() {
        for bad in [
            "",
            "short",
            &"G".repeat(32),
            &"A".repeat(32),
            &"0".repeat(33),
        ] {
            assert!(bad.parse::<SessionId>().is_err(), "`{bad}`");
        }
    }

    #[test]
    fn a_session_directory_is_named_by_its_id() {
        let root = tempfile::tempdir().expect("tempdir");
        let id = SessionId::mint();
        let dir = SessionDir::create(root.path(), id).expect("create");
        assert!(dir.path().is_dir());
        assert!(dir.path().ends_with(id.to_string()));
    }
}
