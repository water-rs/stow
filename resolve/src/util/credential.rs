//! Credential value types carried over from `cargo-credential`.
//!
//! The `cargo-credential` crate does not compile on `wasm32-unknown-unknown`
//! (its `stdio` module shells out to credential-provider processes, which
//! cannot exist there). Only the two pure data types stow-resolve needs are
//! carried here verbatim; the credential-process protocol itself lives behind
//! the truthful error in [`crate::util::auth`], because spawning a provider
//! process is a host capability, not something wasm can approximate.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper for values that should not be printed.
///
/// This type does not implement `Display`, and has a `Debug` impl that hides
/// the contained value.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T> {
    inner: T,
}

impl<T> Secret<T> {
    /// Unwraps the contained value.
    ///
    /// Use of this method marks the boundary of where the contained value is
    /// hidden.
    pub fn expose(self) -> T {
        self.inner
    }

    /// Converts a `Secret<T>` to a `Secret<&T::Target>`.
    pub fn as_deref(&self) -> Secret<&<T as Deref>::Target>
    where
        T: Deref,
    {
        Secret::from(self.inner.deref())
    }

    /// Converts a `Secret<T>` to a `Secret<&T>`.
    pub fn as_ref(&self) -> Secret<&T> {
        Secret::from(&self.inner)
    }

    /// Converts a `Secret<T>` to a `Secret<U>` by applying `f` to the contained value.
    pub fn map<U, F>(self, f: F) -> Secret<U>
    where
        F: FnOnce(T) -> U,
    {
        Secret::from(f(self.inner))
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("inner", &"REDACTED")
            .finish()
    }
}

impl<T> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self { inner }
    }
}

/// A record of what kind of operation is happening that we should generate a token for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[serde(tag = "operation", rename_all = "kebab-case")]
pub enum Operation<'a> {
    /// The user is attempting to fetch a crate.
    Read,
    /// The user is attempting to publish a crate.
    Publish {
        /// The name of the crate
        name: &'a str,
        /// The version of the crate
        vers: &'a str,
        /// The checksum of the crate file being uploaded
        cksum: &'a str,
    },
    /// The user is attempting to yank a crate.
    Yank {
        /// The name of the crate
        name: &'a str,
        /// The version of the crate
        vers: &'a str,
    },
    /// The user is attempting to unyank a crate.
    Unyank {
        /// The name of the crate
        name: &'a str,
        /// The version of the crate
        vers: &'a str,
    },
    /// The user is attempting to modify the owners of a crate.
    Owners {
        /// The name of the crate
        name: &'a str,
    },
    #[serde(other)]
    Unknown,
}
