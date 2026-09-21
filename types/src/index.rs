//! The signed per-`(target, rustc_version)` artifact index published to
//! GHCR (water-rs/stow#188).
//!
//! One index file covers one slice of the `artifacts` table: every servable
//! row (a pushed bundle) for one target triple and one stable rustc,
//! ordered by `c_metadata`. The CLI downloads the slice its build needs,
//! verifies the cosign signature against
//! [`crate::trusted_builder::INDEX_CERTIFICATE_IDENTITY`], and computes
//! hits, semver-compatible upgrades and misses locally — the dependency
//! graph never leaves the machine.
//!
//! On the wire the index is `zstd`-compressed JSON of [`ArtifactIndex`]
//! with [`encode`] / [`decode`] the only entry points. The header pins a
//! `format_version` readers reject on mismatch and a `row_count` checked
//! against the decoded rows.

use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

/// The `format_version` this crate writes and the only one [`decode`]
/// accepts.
pub const ARTIFACT_INDEX_FORMAT_VERSION: u32 = 1;

/// Media type of the index's single OCI layer — the zstd-compressed
/// [`ArtifactIndex`] JSON.
pub const STOW_INDEX_MEDIA_TYPE: &str = "application/vnd.stow.index.v1+zstd";

/// Media type of the OCI config the index artifact carries.
pub const STOW_INDEX_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.index.config.v1+json";

/// The published artifact index: a versioned header plus the slice's rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIndex {
    /// Versioned header; `row_count` must equal `rows.len()` on decode.
    pub header: ArtifactIndexHeader,
    /// Every servable row of the slice, ordered by `c_metadata`.
    pub rows: Vec<ArtifactIndexRow>,
}

/// The index's self-describing header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIndexHeader {
    /// Format version — [`ARTIFACT_INDEX_FORMAT_VERSION`] in every file
    /// this crate encodes.
    pub format_version: u32,
    /// The slice's compilation target triple.
    pub target: TargetTriple,
    /// The slice's stable rustc version (e.g. `"1.91.1"`).
    pub rustc_version: WireRustcVersion,
    /// RFC 3339 UTC timestamp of the export. Informational only — it
    /// makes every export's bytes unique, so publish-side change
    /// detection digests the rows, never the blob.
    pub generated_at: String,
    /// Number of rows the body carries; [`decode`] rejects a mismatch.
    pub row_count: u64,
}

/// One servable artifact row of the slice — everything a client needs to
/// resolve `(crate, version, features, dependency identities)` to a
/// `bundle_digest` it can fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactIndexRow {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact crate version.
    pub version: CrateVersion,
    /// Canonicalized features list (sorted, deduplicated).
    pub features_json: FeaturesJson,
    /// Sorted `(crate_name, c_metadata)` identities of the dependencies
    /// this artifact was built against — the transitive-closure chain.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// Cargo's `-C metadata` value — the exact cache lookup key.
    pub c_metadata: CMetadata,
    /// Blake3 compile key of this artifact. A row is *canonical* — the
    /// identity semantic matching and closure walks may use — only when
    /// [`crate::public_cache::stable_c_metadata_for_compile_key`] maps it
    /// back to `c_metadata`; non-canonical rows remain servable by exact
    /// `c_metadata` lookup but must not participate in graph analysis.
    pub compile_key: String,
    /// Digest (`sha256:…`) of the `<tag>.bundle` blob the edge streams.
    /// Always non-empty: unbundled rows are not servable and never enter
    /// the index.
    pub bundle_digest: String,
    /// Byte length of that blob.
    pub bundle_size: u64,
    /// Primary artifact kind (rlib / dylib / proc-macro).
    pub artifact_kind: ArtifactKind,
    /// Declared Rust crate types.
    pub crate_types: Vec<RustCrateType>,
    /// Compilation profile observed from the captured rustc invocation.
    pub profile: Profile,
    /// Sorted, deduplicated `--emit` modes observed from the invocation.
    pub emit: Vec<String>,
}

/// The OCI tag of the index artifact for one slice:
/// `index.<target>.<rustc_short>` on `ghcr.io/water-rs/stow-cache`.
///
/// `rustc_short` is the same short form artifact tags carry — the semver
/// rendering `RustcVersion::short` produces, which is exactly the wire
/// version string — passed through the registry's tag-component sanitizer
/// so a `+`-bearing build-metadata suffix folds the same way a crate
/// version does. The target stays verbatim: the `arch-os` short form
/// collapses `aarch64-apple-ios` and `aarch64-apple-ios-sim` onto one tag,
/// so only the full triple keeps the slices distinct.
#[must_use]
pub fn index_tag(target: &str, rustc_version: &str) -> String {
    format!(
        "index.{target}.{}",
        crate::registry::sanitize_oci_tag_component(rustc_version)
    )
}

/// The publish-side content digest: `sha256` over the canonical JSON of
/// everything in the index except the wall-clock `generated_at`.
///
/// `generated_at` makes every export's blob bytes unique, so the blob
/// digest can never signal "unchanged"; this digest is what the
/// index-publish workflow compares (carried in a manifest annotation)
/// to decide whether the slice changed.
///
/// # Errors
///
/// Fails only if serde cannot serialize the fields, which cannot happen.
pub fn content_sha256(index: &ArtifactIndex) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(&(
        index.header.format_version,
        &index.header.target,
        &index.header.rustc_version,
        &index.rows,
    ))?;
    Ok(crate::registry::sha256_digest(&canonical))
}

/// Errors raised by [`encode`] and [`decode`].
#[derive(Debug, thiserror::Error)]
#[cfg(not(target_arch = "wasm32"))]
pub enum IndexError {
    /// Serializing the index to JSON failed.
    #[error("serialize index to JSON: {0}")]
    Serialize(serde_json::Error),
    /// The decompressed payload is not index JSON.
    #[error("parse index JSON: {0}")]
    Deserialize(serde_json::Error),
    /// zstd compression failed.
    #[error("zstd compress index: {0}")]
    Compress(std::io::Error),
    /// The payload is not a zstd frame or decompression failed.
    #[error("zstd decompress index: {0}")]
    Decompress(std::io::Error),
    /// The header names a format this reader does not understand.
    #[error(
        "unsupported index format_version {found}; this reader understands {ARTIFACT_INDEX_FORMAT_VERSION}"
    )]
    UnsupportedFormatVersion {
        /// The version the decoded header declared.
        found: u32,
    },
    /// The header's `row_count` does not match the decoded body.
    #[error("index header declares {declared} rows but the body carries {actual}")]
    RowCountMismatch {
        /// `row_count` as written in the header.
        declared: u64,
        /// The body's actual row count.
        actual: u64,
    },
}

/// Serialize `index` as JSON and zstd-compress it — the bytes the OCI
/// layer carries.
///
/// Not compiled for `wasm32`: `zstd` does not build there and the edge
/// never encodes indexes — producers (admin, CI) and the CLI consumer are
/// all native.
///
/// # Errors
///
/// [`IndexError::Serialize`] or [`IndexError::Compress`].
#[cfg(not(target_arch = "wasm32"))]
pub fn encode(index: &ArtifactIndex) -> Result<Vec<u8>, IndexError> {
    let json = serde_json::to_vec(index).map_err(IndexError::Serialize)?;
    zstd::stream::encode_all(std::io::Cursor::new(json), zstd::DEFAULT_COMPRESSION_LEVEL)
        .map_err(IndexError::Compress)
}

/// Decompress and parse index bytes, then check the header: a foreign
/// `format_version` or a `row_count` that does not match the body is
/// rejected.
///
/// # Errors
///
/// [`IndexError::Decompress`], [`IndexError::Deserialize`],
/// [`IndexError::UnsupportedFormatVersion`], or
/// [`IndexError::RowCountMismatch`].
#[cfg(not(target_arch = "wasm32"))]
pub fn decode(bytes: &[u8]) -> Result<ArtifactIndex, IndexError> {
    use std::io::Read as _;

    /// Decompressed JSON the decoder will read before giving up — a bound
    /// on how much a hostile or corrupt blob can inflate into memory. At
    /// ~1 KB per row this still covers a slice orders of magnitude past
    /// any plausible pool size.
    const MAX_INDEX_JSON_LEN: u64 = 256 * 1024 * 1024;

    let decoder = zstd::stream::read::Decoder::new(std::io::Cursor::new(bytes))
        .map_err(IndexError::Decompress)?;
    let mut json = Vec::new();
    decoder
        .take(MAX_INDEX_JSON_LEN)
        .read_to_end(&mut json)
        .map_err(IndexError::Decompress)?;
    let index: ArtifactIndex = serde_json::from_slice(&json).map_err(IndexError::Deserialize)?;
    if index.header.format_version != ARTIFACT_INDEX_FORMAT_VERSION {
        return Err(IndexError::UnsupportedFormatVersion {
            found: index.header.format_version,
        });
    }
    let actual = index.rows.len() as u64;
    if index.header.row_count != actual {
        return Err(IndexError::RowCountMismatch {
            declared: index.header.row_count,
            actual,
        });
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::*;
    use crate::api::CI_TARGET_TRIPLES;
    use crate::platform::{PanicStrategy, StripLevel};
    use crate::registry::{GHCR_BASE, oci_reference_tag};

    fn index(rows: Vec<ArtifactIndexRow>) -> ArtifactIndex {
        ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target"),
                rustc_version: WireRustcVersion::parse("1.91.1").expect("rustc"),
                generated_at: "2026-09-20T12:00:00Z".to_owned(),
                row_count: rows.len() as u64,
            },
            rows,
        }
    }

    fn row(c_metadata: &str) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: CrateName::parse("serde").expect("crate name"),
            version: CrateVersion::new(Version::new(1, 0, 219)),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            compile_key: format!("{c_metadata}{c_metadata}"),
            bundle_digest: format!("sha256:{c_metadata:0>64}"),
            bundle_size: 1234,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            profile: Profile {
                opt_level: "3".to_owned(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned(), "metadata".to_owned()],
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        let index = index(vec![row("aaaa"), row("bbbb")]);
        let bytes = encode(&index).expect("encode");
        assert_eq!(decode(&bytes).expect("decode"), index);
    }

    #[test]
    fn decode_rejects_a_foreign_format_version() {
        let mut index = index(Vec::new());
        index.header.format_version = 99;
        let bytes = encode(&index).expect("encode");
        let error = decode(&bytes).expect_err("foreign format_version must fail");
        assert!(matches!(
            error,
            IndexError::UnsupportedFormatVersion { found: 99 }
        ));
    }

    #[test]
    fn decode_rejects_a_row_count_that_disagrees_with_the_body() {
        let mut index = index(vec![row("aaaa")]);
        index.header.row_count = 7;
        let bytes = encode(&index).expect("encode");
        let error = decode(&bytes).expect_err("a lying row_count must fail");
        assert!(matches!(
            error,
            IndexError::RowCountMismatch {
                declared: 7,
                actual: 1
            }
        ));
    }

    #[test]
    fn every_ci_target_produces_a_legal_index_tag() {
        for target in CI_TARGET_TRIPLES {
            let tag = index_tag(target, "1.91.1");
            let reference = format!("{GHCR_BASE}:{tag}");
            assert_eq!(
                oci_reference_tag(&reference),
                Some(tag.as_str()),
                "illegal tag for {target}: {tag}"
            );
        }
    }

    #[test]
    fn index_tag_format() {
        assert_eq!(
            index_tag("x86_64-unknown-linux-gnu", "1.91.1"),
            "index.x86_64-unknown-linux-gnu.1.91.1"
        );
        // Build metadata folds the same way artifact tags fold it.
        assert_eq!(
            index_tag("wasm32-unknown-unknown", "1.92.0+dist"),
            "index.wasm32-unknown-unknown.1.92.0_dist"
        );
    }
}
