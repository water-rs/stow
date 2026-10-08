//! Newtype wrappers for the five-element artifact identity carried over the
//! wire and persisted in D1.
//!
//! The canonical identity tuple is `(crate_name, version, features_json,
//! target, rustc_version)`. Historically each was a bare `String` on the wire
//! and the edge worker re-validated them per request via hand-rolled
//! `validate_*` helpers. These newtypes move the validation into
//! `serde::Deserialize`, so:
//!
//! * Every wire payload either parses successfully into a structured value or
//!   produces a precise deserialize error at the protocol boundary.
//! * Edge handlers receive types that are correct-by-construction.
//! * Adding or renaming a constraint becomes a compile-time edit, not a
//!   per-call-site audit.
//!
//! All wrappers serialize as the same primitive (string for most, JSON-encoded
//! string for [`FeaturesJson`] and [`DependencyCMetadataJson`]) so the wire
//! format is byte-for-byte identical to the previous stringly-typed shape.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Context as _;

/// Errors produced while parsing wire identity values.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The crate name violates crates.io's allowed character / length rules.
    #[error("invalid crate_name `{0}`: must be 1..=128 ASCII alphanumeric, `-` or `_`")]
    InvalidCrateName(String),
    /// The cargo `-C metadata` value is not a hex hash of length 1..=64.
    #[error("invalid c_metadata `{0}`: must be 1..=64 ASCII hex digits")]
    InvalidCMetadata(String),
    /// The target triple has unexpected characters or length.
    #[error("invalid target `{0}`: must be 1..=128 alphanumeric, `-` or `_`")]
    InvalidTarget(String),
    /// The crate version is not semver.
    #[error("invalid version `{0}`: must be a semver release like 1.0.219")]
    InvalidCrateVersion(String),
    /// The rustc version string failed shape validation.
    #[error("invalid rustc_version `{0}`: must be 1..=64 alphanumeric, `.`, `-`, or `_`")]
    InvalidRustcVersion(String),
    /// One feature name is empty, too long, or violates cargo's grammar.
    #[error(
        "invalid feature name `{0}`: cargo requires an XID start, `_`, or digit first character, then XID continue, `-`, `+`, or `.` (no `dep:` prefix, no `/`), 1..=128 chars"
    )]
    InvalidFeatureName(String),
    /// A feature list was not strictly sorted and deduplicated.
    #[error("features must be strictly sorted and deduplicated")]
    UnsortedFeatures,
    /// An emit entry is empty, too long, or contains invalid characters.
    #[error("invalid emit entry `{0}`: must be 1..=32 alphanumeric, `-`, or `_`")]
    InvalidEmitEntry(String),
    /// An emit list was not strictly sorted and deduplicated.
    #[error("emit entries must be strictly sorted and deduplicated")]
    UnsortedEmit,
    /// Failed to parse a JSON wrapper string.
    #[error("invalid JSON wrapper: {0}")]
    InvalidJsonWrapper(String),
    /// Dependency identities not sorted by `(crate_name, c_metadata)`.
    #[error("dependency_c_metadata_json must be sorted by (crate_name, c_metadata)")]
    UnsortedDependencyIdentities,
    /// A dependency-identity digest is not exactly 64 lowercase hex digits.
    #[error("invalid dependency_identity `{0}`: must be exactly 64 lowercase ASCII hex digits")]
    InvalidDependencyIdentity(String),
}

fn validate_crate_name(value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(IdentityError::InvalidCrateName(value.to_owned()));
    }
    Ok(())
}

fn validate_c_metadata(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(IdentityError::InvalidCMetadata(value.to_owned()));
    }
    Ok(())
}

fn validate_target(value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(IdentityError::InvalidTarget(value.to_owned()));
    }
    Ok(())
}

fn validate_rustc_version(value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(IdentityError::InvalidRustcVersion(value.to_owned()));
    }
    Ok(())
}

/// Validate one Cargo feature name.
///
/// The grammar is cargo's own, mirrored from
/// `cargo_util_schemas::restricted_names::validate_feature_name`
/// (cargo-util-schemas 0.14, <https://github.com/rust-lang/cargo>):
/// non-empty, never starting with `dep:` and containing no `/`; the
/// first character is a Unicode XID start character, `_`, or an ASCII
/// digit, and every later character is a Unicode XID continue character,
/// `-`, `+`, or `.`. The 128-char bound is this wire format's own —
/// cargo imposes no length limit. `c++20` is a legal feature name (a
/// real one — rust-lang/rust's `compiler/rustc_feature` declares it);
/// `+foo` is not, because `+` is XID continue but not XID start.
///
/// # Errors
/// Returns [`IdentityError::InvalidFeatureName`] when the name violates
/// the grammar.
pub fn validate_feature_name(value: &str) -> Result<(), IdentityError> {
    let reject = || IdentityError::InvalidFeatureName(value.to_owned());
    if value.is_empty() || value.len() > 128 || value.starts_with("dep:") || value.contains('/') {
        return Err(reject());
    }
    let mut chars = value.chars();
    if let Some(first) = chars.next()
        && !(unicode_ident::is_xid_start(first) || first == '_' || first.is_ascii_digit())
    {
        return Err(reject());
    }
    if !chars.all(|ch| unicode_ident::is_xid_continue(ch) || matches!(ch, '-' | '+' | '.')) {
        return Err(reject());
    }
    Ok(())
}

fn validate_features_sorted(features: &[String]) -> Result<(), IdentityError> {
    let mut previous: Option<&str> = None;
    for feature in features {
        validate_feature_name(feature)?;
        if previous.is_some_and(|last| last >= feature.as_str()) {
            return Err(IdentityError::UnsortedFeatures);
        }
        previous = Some(feature.as_str());
    }
    Ok(())
}

fn validate_dependency_identity(value: &str) -> Result<(), IdentityError> {
    if value.len() != 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
    {
        return Err(IdentityError::InvalidDependencyIdentity(value.to_owned()));
    }
    Ok(())
}

fn validate_emit_entry(value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(IdentityError::InvalidEmitEntry(value.to_owned()));
    }
    Ok(())
}

/// Validate that `emit` is strictly sorted, deduplicated, and each entry
/// matches the rustc emit-mode shape.
///
/// # Errors
/// Returns [`IdentityError::InvalidEmitEntry`] for a malformed entry, or
/// [`IdentityError::UnsortedEmit`] when the list is not strictly increasing.
pub fn validate_emit_sorted(emit: &[String]) -> Result<(), IdentityError> {
    let mut previous: Option<&str> = None;
    for entry in emit {
        validate_emit_entry(entry)?;
        if previous.is_some_and(|last| last >= entry.as_str()) {
            return Err(IdentityError::UnsortedEmit);
        }
        previous = Some(entry.as_str());
    }
    Ok(())
}

macro_rules! string_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, $validate:ident, $error:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, utoipa::ToSchema)]
        pub struct $name(String);

        impl $name {
            /// Construct, validating the input.
            ///
            /// # Errors
            /// Returns the [`IdentityError`] variant for this newtype's
            /// validation rule when `value` violates it.
            pub fn parse<S: Into<String>>(value: S) -> Result<Self, IdentityError> {
                let value = value.into();
                $validate(&value)?;
                Ok(Self(value))
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the inner `String`.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<OsStr> for $name {
            fn as_ref(&self) -> &OsStr {
                self.0.as_ref()
            }
        }

        impl AsRef<Path> for $name {
            fn as_ref(&self) -> &Path {
                self.0.as_ref()
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0.as_str() == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0.as_str() == *other
            }
        }

        impl PartialEq<$name> for &str {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0.as_str()
            }
        }

        impl PartialEq<$name> for str {
            fn eq(&self, other: &$name) -> bool {
                self == other.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdentityError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::parse(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

string_newtype!(
    /// A crates.io crate name. ASCII alphanumeric plus `-` and `_`, 1..=128 chars.
    CrateName,
    validate_crate_name,
    InvalidCrateName
);
string_newtype!(
    /// Cargo `-C metadata` value: hex digits, 1..=64 chars.
    CMetadata,
    validate_c_metadata,
    InvalidCMetadata
);
string_newtype!(
    /// A compilation target triple (free-form, validated for shape only).
    TargetTriple,
    validate_target,
    InvalidTarget
);

impl TargetTriple {
    /// Whether the triple targets Windows — an `*-windows-*` OS component
    /// (`windows-msvc`, `windows-gnu`, `windows-gnullvm`).
    #[must_use]
    pub fn is_windows(&self) -> bool {
        self.as_str()
            .split('-')
            .any(|component| component == "windows")
    }
}
string_newtype!(
    /// Wire form of a rustc version string (e.g. `"1.83.0"`). Shape only.
    WireRustcVersion,
    validate_rustc_version,
    InvalidRustcVersion
);

/// Parse `[pkg.rustc].version` out of `channel-rust-stable.toml`, reducing
/// the decorated string (`"1.98.1 (hash date)"`) to the semantic numeric
/// portion.
///
/// Shared by the edge's channel cache and `stow-admin`'s lane setup so both
/// read the version the same way.
///
/// # Errors
/// Returns an [`crate::error::Error`] when the manifest is not TOML, lacks
/// `pkg.rustc.version`, or the version is not valid semver.
pub fn parse_channel_rustc_version(manifest: &str) -> crate::error::Result<WireRustcVersion> {
    use crate::error::Context as _;

    let document: toml::Table =
        toml::from_str(manifest).wrap_err("channel-rust-stable.toml is not TOML")?;
    let raw = document
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| crate::error::Error::msg("channel manifest has no pkg.rustc.version"))?;
    // The manifest decorates the version with build metadata:
    // `"1.98.1 (04b871bb4 2026-01-01)"` — only the leading semver matters.
    let numeric = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| crate::error::Error::msg("channel manifest rustc version is empty"))?;
    let version = semver::Version::parse(numeric)
        .wrap_err_with(|| format!("channel manifest rustc version `{numeric}`"))?;
    WireRustcVersion::parse(version.to_string())
        .wrap_err_with(|| format!("channel manifest rustc version `{numeric}`"))
}

/// A semver crate version (no shape constraints beyond what semver requires).
///
/// We delegate validation to the `semver` crate but still expose this newtype
/// so call sites can switch wire types without hopping back into raw strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CrateVersion(pub semver::Version);

// Hand-written so a malformed version answers with the shape it wanted
// rather than semver's parser position ("unexpected character 's' while
// parsing major version number") — the request form shows the deserialize
// error to whoever typed it.
impl<'de> Deserialize<'de> for CrateVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

// The wire shape is a string; `semver::Version` has no `PartialSchema` impl.
impl utoipa::PartialSchema for CrateVersion {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        <String as utoipa::PartialSchema>::schema()
    }
}

impl utoipa::ToSchema for CrateVersion {}

impl CrateVersion {
    /// Construct from the embedded semver value.
    #[must_use]
    pub const fn new(version: semver::Version) -> Self {
        Self(version)
    }

    /// Borrow the underlying semver value.
    #[must_use]
    pub const fn as_semver(&self) -> &semver::Version {
        &self.0
    }

    /// Consume and return the inner `semver::Version`.
    #[must_use]
    pub fn into_inner(self) -> semver::Version {
        self.0
    }
}

impl fmt::Display for CrateVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for CrateVersion {
    type Err = IdentityError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        semver::Version::parse(value)
            .map(Self)
            .map_err(|_| IdentityError::InvalidCrateVersion(value.to_owned()))
    }
}

/// A canonical features list: strictly sorted, deduplicated.
///
/// On the wire this serializes as a JSON-encoded string (e.g.
/// `"[\"default\",\"std\"]"`) so it is byte-compatible with the legacy
/// `features_json: String` shape used by `BuildTaskPayload` and friends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FeaturesJson(Vec<String>);

// The wire shape is a JSON-encoded string, not an array.
impl utoipa::PartialSchema for FeaturesJson {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        <String as utoipa::PartialSchema>::schema()
    }
}

impl utoipa::ToSchema for FeaturesJson {}

impl FeaturesJson {
    /// Construct from an already-sorted, deduplicated list of features.
    ///
    /// # Errors
    /// Returns [`IdentityError::InvalidFeatureName`] for a malformed feature,
    /// or [`IdentityError::UnsortedFeatures`] when the list violates the
    /// sorted/deduplicated invariant.
    pub fn from_sorted(features: Vec<String>) -> Result<Self, IdentityError> {
        validate_features_sorted(&features)?;
        Ok(Self(features))
    }

    /// Sort, deduplicate, and validate a raw feature list, then construct.
    ///
    /// # Errors
    /// Returns [`IdentityError::InvalidFeatureName`] when a feature name is
    /// malformed.
    pub fn canonicalize(mut features: Vec<String>) -> Result<Self, IdentityError> {
        features.sort();
        features.dedup();
        Self::from_sorted(features)
    }

    /// Borrow the canonical features.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.0
    }

    /// Render the canonical JSON-encoded string used in D1 column storage.
    ///
    /// # Panics
    /// Panics only if `serde_json` fails to serialize a `Vec<String>`, which
    /// cannot happen.
    #[must_use]
    pub fn raw(&self) -> String {
        serde_json::to_string(&self.0).expect("Vec<String> always serializes")
    }
}

impl fmt::Display for FeaturesJson {
    /// Display as the canonical JSON-encoded array string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw())
    }
}

impl Serialize for FeaturesJson {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw().serialize(s)
    }
}

impl<'de> Deserialize<'de> for FeaturesJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let features: Vec<String> = serde_json::from_str(&raw).map_err(|error| {
            serde::de::Error::custom(IdentityError::InvalidJsonWrapper(error.to_string()))
        })?;
        Self::from_sorted(features).map_err(serde::de::Error::custom)
    }
}

/// One entry in `dependency_compile_keys_json`: a dependency crate and the
/// full compile key of the artifact this build resolved it to.
///
/// Producers must emit entries sorted by `(crate_name, compile_key)` and
/// deduplicated; [`Self::canonicalize_list`] does exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyCompileKeyIdentity {
    /// Crate name as known to crates.io.
    pub crate_name: CrateName,
    /// Blake3 compile key of the dependency artifact.
    pub compile_key: String,
}

impl DependencyCompileKeyIdentity {
    /// Sort and deduplicate a list of identities into canonical order.
    #[must_use]
    pub fn canonicalize_list(mut identities: Vec<Self>) -> Vec<Self> {
        identities.sort();
        identities.dedup();
        identities
    }
}

/// One entry in `dependency_c_metadata_json`: `(crate_name, c_metadata)`
/// identifying a dependency artifact already produced by stow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DependencyCMetadataIdentity {
    /// Crate name as known to crates.io.
    pub crate_name: CrateName,
    /// Cargo `-C metadata` value of the dependency artifact.
    pub c_metadata: CMetadata,
}

/// A canonical dependency identity list: strictly sorted by
/// `(crate_name, c_metadata)`, deduplicated.
///
/// On the wire this serializes as a JSON-encoded string (matching the legacy
/// `dependency_c_metadata_json: String` field shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DependencyCMetadataJson(Vec<DependencyCMetadataIdentity>);

// The wire shape is a JSON-encoded string, not an array.
impl utoipa::PartialSchema for DependencyCMetadataJson {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        <String as utoipa::PartialSchema>::schema()
    }
}

impl utoipa::ToSchema for DependencyCMetadataJson {}

impl DependencyCMetadataJson {
    /// Construct from an already-sorted, deduplicated list.
    ///
    /// # Errors
    /// Returns [`IdentityError::UnsortedDependencyIdentities`] when the list
    /// is not strictly increasing by `(crate_name, c_metadata)`.
    pub fn from_sorted(
        identities: Vec<DependencyCMetadataIdentity>,
    ) -> Result<Self, IdentityError> {
        let mut previous: Option<(&str, &str)> = None;
        for identity in &identities {
            let current = (identity.crate_name.as_str(), identity.c_metadata.as_str());
            if previous.is_some_and(|last| last >= current) {
                return Err(IdentityError::UnsortedDependencyIdentities);
            }
            previous = Some(current);
        }
        Ok(Self(identities))
    }

    /// Sort, deduplicate, then construct.
    ///
    /// # Errors
    /// Never fails after sorting and deduplication; the `Result` shape
    /// mirrors [`Self::from_sorted`].
    pub fn canonicalize(
        mut identities: Vec<DependencyCMetadataIdentity>,
    ) -> Result<Self, IdentityError> {
        identities.sort();
        identities.dedup();
        Self::from_sorted(identities)
    }

    /// Borrow the canonical identities.
    #[must_use]
    pub fn entries(&self) -> &[DependencyCMetadataIdentity] {
        &self.0
    }

    /// Render the canonical JSON-encoded string used in D1 column storage.
    ///
    /// # Panics
    /// Panics only if `serde_json` fails to serialize the identity list,
    /// which cannot happen.
    #[must_use]
    pub fn raw(&self) -> String {
        serde_json::to_string(&self.0).expect("dependency identity list always serializes")
    }
}

impl fmt::Display for DependencyCMetadataJson {
    /// Display as the canonical JSON-encoded array string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw())
    }
}

impl Serialize for DependencyCMetadataJson {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.raw().serialize(s)
    }
}

impl<'de> Deserialize<'de> for DependencyCMetadataJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let entries: Vec<DependencyCMetadataIdentity> =
            serde_json::from_str(&raw).map_err(|error| {
                serde::de::Error::custom(IdentityError::InvalidJsonWrapper(error.to_string()))
            })?;
        Self::from_sorted(entries).map_err(serde::de::Error::custom)
    }
}

string_newtype!(
    /// The BLAKE3 digest of a node's sorted, deduplicated direct
    /// dependency task ids — the Merkle commitment a resolved task id
    /// carries (stow#588). Exactly 64 lowercase ASCII hex digits.
    DependencyIdentity,
    validate_dependency_identity,
    InvalidDependencyIdentity
);

impl DependencyIdentity {
    /// The key-derivation context separating dependency digests from
    /// every other BLAKE3 use in stow.
    const DOMAIN: &'static str = "stow.task-dependencies.v1";

    /// The digest committing to a node's direct dependencies: the task
    /// ids sorted and deduplicated — input ordering and repeated edges
    /// change nothing — serialized as a JSON array and hashed under
    /// [`Self::DOMAIN`].
    ///
    /// # Errors
    /// Fails only if `serde_json` cannot serialize a `Vec<&str>`, or a
    /// computed digest fails shape validation.
    pub fn from_task_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> crate::error::Result<Self> {
        let mut sorted: Vec<&str> = ids.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();
        let bytes = serde_json::to_vec(&sorted).wrap_err("serialize dependency task ids")?;
        let digest = hex::encode(blake3::derive_key(Self::DOMAIN, &bytes));
        Ok(Self::parse(digest)?)
    }

    /// The digest a node with no dependencies carries — the canonical
    /// hash of the empty id list, computed like every other digest.
    ///
    /// # Errors
    /// Mirrors [`Self::from_task_ids`].
    pub fn leaf() -> crate::error::Result<Self> {
        Self::from_task_ids(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_manifest_yields_the_numeric_rustc_version() {
        let manifest = "[pkg.rustc]\nversion = \"1.98.1 (04b871bb4 2026-01-01)\"\n";
        let version = super::parse_channel_rustc_version(manifest).expect("parse manifest");
        assert_eq!(version.as_str(), "1.98.1");
    }

    #[test]
    fn channel_manifest_without_a_valid_rustc_version_is_an_error() {
        for manifest in [
            "[pkg.cargo]\nversion = \"0.99.0\"\n",
            "not toml = [",
            "[pkg.rustc]\nversion = \"bad version!!\"\n",
            "[pkg.rustc]\nversion = \"\"\n",
        ] {
            assert!(
                super::parse_channel_rustc_version(manifest).is_err(),
                "`{manifest}` must not produce a rustc identity"
            );
        }
    }

    #[test]
    fn crate_name_accepts_typical() {
        CrateName::parse("serde_json").unwrap();
        CrateName::parse("proc-macro2").unwrap();
    }

    #[test]
    fn crate_name_rejects_empty_and_overlong() {
        assert!(CrateName::parse("").is_err());
        assert!(CrateName::parse("x".repeat(129)).is_err());
        assert!(CrateName::parse("a b").is_err());
    }

    #[test]
    fn c_metadata_must_be_hex() {
        CMetadata::parse("deadbeef").unwrap();
        assert!(CMetadata::parse("xyz").is_err());
    }

    #[test]
    fn rustc_version_shape() {
        WireRustcVersion::parse("1.83.0").unwrap();
        WireRustcVersion::parse("1.91.0-nightly").unwrap();
        assert!(WireRustcVersion::parse("").is_err());
    }

    #[test]
    fn features_json_round_trip() {
        let raw = "[\"default\",\"std\"]";
        let features: FeaturesJson =
            serde_json::from_value(serde_json::Value::String(raw.to_owned())).unwrap();
        assert_eq!(features.features(), &["default", "std"]);
        let serialized = serde_json::to_value(&features).unwrap();
        assert_eq!(serialized, serde_json::Value::String(raw.to_owned()));
    }

    #[test]
    fn features_json_rejects_unsorted() {
        let raw = "[\"std\",\"default\"]";
        let result: Result<FeaturesJson, _> =
            serde_json::from_value(serde_json::Value::String(raw.to_owned()));
        assert!(result.is_err());
    }

    /// Feature names follow cargo's grammar — these assertions mirror the
    /// cases `cargo_util_schemas`' own tests pin
    /// (`restricted_names.rs::valid_feature_names`), plus `+` mid-name,
    /// which rust-lang/rust's `c++20` feature needs.
    #[test]
    fn feature_names_follow_cargo_grammar() {
        for name in [
            "c++20",
            "foo+bar",
            "128bit",
            "_foo",
            "feat-name",
            "feat_name",
            "foo.bar",
        ] {
            assert!(validate_feature_name(name).is_ok(), "{name} must validate");
        }
        for name in [
            "",
            "+foo",
            "-foo",
            ".foo",
            "dep:bar",
            "foo/bar",
            "foo:bar",
            "foo?",
            "?foo",
            "ⒶⒷⒸ",
            "a¼",
            &"x".repeat(129),
        ] {
            assert!(
                validate_feature_name(name).is_err(),
                "{name} must not validate"
            );
        }
    }

    #[test]
    fn dependency_identities_round_trip() {
        let raw = "[{\"crate_name\":\"a\",\"c_metadata\":\"deadbeef\"}]";
        let value: DependencyCMetadataJson =
            serde_json::from_value(serde_json::Value::String(raw.to_owned())).unwrap();
        assert_eq!(value.entries().len(), 1);
        let serialized = serde_json::to_value(&value).unwrap();
        assert_eq!(serialized, serde_json::Value::String(raw.to_owned()));
    }

    #[test]
    fn dependency_identity_is_64_lowercase_hex() {
        let digest = DependencyIdentity::parse(blake3::hash(b"children").to_hex().to_string())
            .expect("a blake3 hex digest validates");
        let serialized = serde_json::to_value(&digest).unwrap();
        assert_eq!(
            serde_json::from_value::<DependencyIdentity>(serialized).unwrap(),
            digest
        );
        for invalid in [
            "",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),
            &"g".repeat(64),
            &format!("{} ", "a".repeat(63)),
        ] {
            assert!(
                DependencyIdentity::parse(invalid).is_err(),
                "`{invalid}` must not validate"
            );
        }
    }

    /// Ordering and repeated ids change nothing — the canonical hash
    /// input is the sorted, deduplicated array.
    #[test]
    fn from_task_ids_ignores_ordering_and_repetition() {
        let expected = DependencyIdentity::from_task_ids(["a", "b", "c"]).unwrap();
        for ids in [
            vec!["c", "b", "a"],
            vec!["b", "a", "a", "c", "b"],
            vec!["a", "b", "c"],
        ] {
            assert_eq!(DependencyIdentity::from_task_ids(ids).unwrap(), expected);
        }
        let changed = DependencyIdentity::from_task_ids(["a", "b", "d"]).unwrap();
        assert_ne!(
            changed, expected,
            "a different child set hashes differently"
        );
    }

    /// A leaf hashes the canonical empty array under the same domain —
    /// no special-cased constant.
    #[test]
    fn leaf_hashes_the_canonical_empty_list() {
        let canonical = hex::encode(blake3::derive_key(DependencyIdentity::DOMAIN, b"[]"));
        assert_eq!(DependencyIdentity::leaf().unwrap().as_str(), canonical);
        assert_eq!(
            DependencyIdentity::leaf().unwrap(),
            DependencyIdentity::from_task_ids([]).unwrap()
        );
    }
}
