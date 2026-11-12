//! A session's identity and its directory on disk.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use stow_types::error::{Context, Result};

use crate::daemon::owner::CargoOwner;

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

    /// Record the cargo this session belongs to, so a daemon that starts
    /// while that cargo still runs can tell which build lost its session.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn record_owner(&self, owner: CargoOwner) -> Result<()> {
        let path = self.0.join(OWNER_FILE);
        std::fs::write(&path, format!("{} {}\n", owner.pid, owner.started))
            .wrap_err_with(|| format!("record the owner in {}", path.display()))
    }
}

/// The file in a session directory that names the cargo the session
/// belongs to. A driver's session has none.
const OWNER_FILE: &str = "owner";

/// The cargo that the session directory `dir` belongs to, when it records
/// one.
///
/// # Errors
///
/// The file exists and cannot be read or is not an owner record.
pub fn recorded_owner(dir: &Path) -> Result<Option<CargoOwner>> {
    let path = dir.join(OWNER_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).wrap_err_with(|| format!("read {}", path.display())),
    };
    let parsed = text.trim().split_once(' ').and_then(|(pid, started)| {
        Some(CargoOwner {
            pid: pid.parse().ok()?,
            started: started.parse().ok()?,
        })
    });
    parsed.map(Some).ok_or_else(|| {
        stow_types::stow_error!("{} is not an owner record: {text:?}", path.display())
    })
}

/// Remove everything in the session directory `dir` except the record of
/// its owner: what a cargo that outlived its session leaves to be
/// refused by.
///
/// # Errors
///
/// An entry cannot be listed or removed.
pub fn keep_only_owner(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).wrap_err_with(|| format!("list {}", dir.display()))? {
        let entry = entry.wrap_err_with(|| format!("list {}", dir.display()))?;
        if entry.file_name() == OWNER_FILE {
            continue;
        }
        let path = entry.path();
        let removed = if entry
            .file_type()
            .wrap_err_with(|| format!("stat {}", path.display()))?
            .is_dir()
        {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.wrap_err_with(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SessionDir, SessionId, keep_only_owner, recorded_owner};
    use crate::daemon::owner::CargoOwner;

    #[test]
    fn a_recorded_owner_survives_the_removal_of_everything_else() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = SessionDir::create(root.path(), SessionId::mint()).expect("create");
        assert_eq!(recorded_owner(dir.path()).expect("no record"), None);
        let owner = CargoOwner {
            pid: 4242,
            started: 987_654_321,
        };
        dir.record_owner(owner).expect("record");
        std::fs::create_dir_all(dir.path().join("local-build")).expect("marks");
        std::fs::write(dir.path().join("local-build").join("mark"), b"x").expect("mark");
        std::fs::write(dir.path().join("stray"), b"x").expect("stray");
        keep_only_owner(dir.path()).expect("keep only the owner");
        assert_eq!(recorded_owner(dir.path()).expect("record"), Some(owner));
        assert_eq!(std::fs::read_dir(dir.path()).expect("list").count(), 1);
    }

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
