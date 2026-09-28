//! The digest-addressed index-slice contract the site answers "is this
//! crate cached?" from (water-rs/stow#288): how `Accept-Encoding` picks
//! a `Content-Encoding`, what a layer digest must look like, the Cache
//! API key a slice lives under, and the zstd→gzip transcode for clients
//! that cannot read zstd.
//!
//! Target-agnostic so the negotiation and digest handling unit-test on
//! the host; the wasm handlers in `api.rs` are their only callers.

use std::io::Read as _;

use stow_types::api::{OciDescriptor, OciManifest};
use stow_types::index::STOW_INDEX_MEDIA_TYPE;

/// The `Content-Encoding`s a slice answer may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceEncoding {
    /// The published blob passes through byte-for-byte —
    /// `Content-Encoding: zstd`.
    Zstd,
    /// The blob is transcoded on the worker —
    /// `Content-Encoding: gzip`.
    Gzip,
}

impl SliceEncoding {
    /// The `Content-Encoding` header value the response carries.
    #[must_use]
    pub const fn content_encoding(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }

    /// The last path segment of the slice's Cache API key: the two
    /// encodings hold different bytes for one digest, so they can never
    /// share an entry.
    #[must_use]
    const fn key_variant(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
        }
    }
}

/// Whether one `Accept-Encoding` parameter kills the token it sits on —
/// `zstd;q=0` is an explicit refusal, not an acceptance.
fn is_refusal_parameter(parameter: &str) -> bool {
    let Some((key, value)) = parameter.trim().split_once('=') else {
        return false;
    };
    key.trim().eq_ignore_ascii_case("q")
        && value
            .trim()
            .parse::<f32>()
            .is_ok_and(|quality| quality <= 0.0)
}

/// Pick the response encoding for a request's `Accept-Encoding` header.
/// An explicit `zstd` token passes the blob through unchanged; anything
/// else — the missing token, an empty header, a `q=0` refusal — is
/// served the gzip transcode. Safari only learned zstd in 26.3, and a
/// `*` wildcard is not read as zstd support: gzip is the encoding every
/// browser is guaranteed to decode.
#[must_use]
pub fn negotiate_encoding(accept_encoding: &str) -> SliceEncoding {
    for item in accept_encoding.split(',') {
        let mut parameters = item.split(';');
        if parameters
            .next()
            .is_some_and(|token| token.trim().eq_ignore_ascii_case("zstd"))
            && !parameters.any(is_refusal_parameter)
        {
            return SliceEncoding::Zstd;
        }
    }
    SliceEncoding::Gzip
}

/// Validate a `sha256:<64 lowercase hex>` layer digest — the only shape
/// the digest-addressed route accepts, and the shape every index
/// manifest's layer descriptor carries.
///
/// # Errors
/// [`SliceError::MalformedDigest`] for any other shape.
pub fn parse_layer_digest(digest: &str) -> Result<&str, SliceError> {
    let well_formed = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if well_formed {
        Ok(digest)
    } else {
        Err(SliceError::MalformedDigest(digest.to_owned()))
    }
}

/// The Cache API key under which the slice's bytes live. The layer
/// digest is content-addressed — `(target, rustc)` tags move at every
/// index publish while the digest pins the bytes — so the key is the
/// digest plus the served encoding variant.
#[must_use]
pub fn slice_cache_key(digest: &str, encoding: SliceEncoding) -> String {
    format!("index-slice-v1/{digest}/{}", encoding.key_variant())
}

/// Pull the index layer out of an `index.<target>.<rustc>` manifest.
/// The publish stage writes exactly one layer with
/// [`STOW_INDEX_MEDIA_TYPE`]; any other shape is a manifest that cannot
/// be a stow index slice.
///
/// # Errors
/// [`SliceError::MalformedManifest`] on a layer count other than one or
/// a non-index media type, [`SliceError::MalformedDigest`] when the
/// descriptor's digest is not `sha256:` + 64 hex.
pub fn index_layer(manifest: &OciManifest) -> Result<&OciDescriptor, SliceError> {
    let [layer] = manifest.layers.as_slice() else {
        return Err(SliceError::MalformedManifest(format!(
            "index manifest carries {} layers, expected exactly one",
            manifest.layers.len()
        )));
    };
    if layer.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(SliceError::MalformedManifest(format!(
            "index manifest layer is {}, expected {STOW_INDEX_MEDIA_TYPE}",
            layer.media_type
        )));
    }
    parse_layer_digest(&layer.digest)?;
    Ok(layer)
}

/// Decompressed JSON the transcode reads before giving up — a bound on
/// how much a hostile or corrupt blob can inflate inside one isolate's
/// 128 MiB heap. At ~1 KB per row this still covers a slice orders of
/// magnitude past any plausible pool size.
const MAX_SLICE_JSON_LEN: u64 = 64 * 1024 * 1024;

/// Turn the published zstd blob into the gzip body a non-zstd client
/// gets. The `zstd` crate does not build for wasm32, so the worker's
/// decode side is `ruzstd` — pure Rust — and gzip comes from `flate2`,
/// which compiles everywhere.
///
/// # Errors
/// [`SliceError::Decompress`] when the blob is not a zstd frame or
/// inflates past [`MAX_SLICE_JSON_LEN`], [`SliceError::Compress`] when
/// gzip encoding fails.
pub fn zstd_to_gzip(blob: &[u8]) -> Result<Vec<u8>, SliceError> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(blob)
        .map_err(|error| SliceError::Decompress(error.to_string()))?;
    let mut json = Vec::new();
    decoder
        .take(MAX_SLICE_JSON_LEN + 1)
        .read_to_end(&mut json)
        .map_err(|error| SliceError::Decompress(error.to_string()))?;
    if json.len() as u64 > MAX_SLICE_JSON_LEN {
        return Err(SliceError::Decompress(format!(
            "slice inflates past the {MAX_SLICE_JSON_LEN}-byte transcode bound"
        )));
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &json)
        .map_err(|error| SliceError::Compress(error.to_string()))?;
    encoder
        .finish()
        .map_err(|error| SliceError::Compress(error.to_string()))
}

/// Errors raised by [`parse_layer_digest`], [`index_layer`] and
/// [`zstd_to_gzip`].
#[derive(Debug, thiserror::Error)]
pub enum SliceError {
    /// The digest string is not `sha256:` + 64 lowercase hex digits.
    #[error("malformed layer digest `{0}` — expected sha256:<64 lowercase hex>")]
    MalformedDigest(String),
    /// The manifest document cannot be a stow index slice.
    #[error("{0}")]
    MalformedManifest(String),
    /// The blob is not a zstd frame, or inflates past the transcode bound.
    #[error("decompress index slice: {0}")]
    Decompress(String),
    /// Re-encoding the slice as gzip failed.
    #[error("gzip encode index slice: {0}")]
    Compress(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn descriptor(media_type: &str, digest: &str) -> OciDescriptor {
        OciDescriptor {
            media_type: media_type.to_owned(),
            digest: digest.to_owned(),
            size: 1,
            annotations: BTreeMap::new(),
        }
    }

    fn build_manifest(layers: Vec<OciDescriptor>) -> OciManifest {
        OciManifest {
            schema_version: 2,
            media_type: None,
            config: descriptor("application/vnd.stow.index.config.v1+json", "sha256:cfg"),
            layers,
            annotations: BTreeMap::new(),
        }
    }

    const LAYER_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn zstd_accepted_passes_the_blob_through() {
        assert_eq!(
            negotiate_encoding("gzip, deflate, br, zstd"),
            SliceEncoding::Zstd
        );
        assert_eq!(negotiate_encoding("zstd"), SliceEncoding::Zstd);
        assert_eq!(negotiate_encoding("ZSTD"), SliceEncoding::Zstd);
        assert_eq!(
            negotiate_encoding("br;q=1.0, zstd;q=0.9"),
            SliceEncoding::Zstd
        );
    }

    #[test]
    fn missing_or_refused_zstd_falls_back_to_gzip() {
        assert_eq!(negotiate_encoding("gzip, deflate, br"), SliceEncoding::Gzip);
        assert_eq!(negotiate_encoding(""), SliceEncoding::Gzip);
        assert_eq!(negotiate_encoding("*"), SliceEncoding::Gzip);
        assert_eq!(negotiate_encoding("zstd;q=0"), SliceEncoding::Gzip);
        assert_eq!(negotiate_encoding("zstd;q=0.0"), SliceEncoding::Gzip);
        // A malformed q-value does not count as a refusal — but a
        // client that cannot spell its preference still gets gzip's
        // guaranteed decode path only if it did not also name zstd.
        assert_eq!(negotiate_encoding("zstd;q=abc"), SliceEncoding::Zstd);
    }

    #[test]
    fn digest_accepts_sha256_lower_hex_only() {
        assert_eq!(parse_layer_digest(LAYER_DIGEST).unwrap(), LAYER_DIGEST);
    }

    #[test]
    fn digest_rejects_every_other_shape() {
        for bad in [
            "",
            "sha256:",
            "sha512:0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            "sha256:0123456789abcdef",
            &format!("{LAYER_DIGEST}ff"),
        ] {
            assert!(
                parse_layer_digest(bad).is_err(),
                "{bad} must not parse as a layer digest"
            );
        }
    }

    #[test]
    fn cache_key_is_content_addressed_per_encoding() {
        assert_eq!(
            slice_cache_key("sha256:0123", SliceEncoding::Zstd),
            "index-slice-v1/sha256:0123/zstd"
        );
        assert_eq!(
            slice_cache_key("sha256:0123", SliceEncoding::Gzip),
            "index-slice-v1/sha256:0123/gzip"
        );
    }

    #[test]
    fn index_layer_requires_exactly_one_index_typed_layer() {
        let single = build_manifest(vec![descriptor(STOW_INDEX_MEDIA_TYPE, LAYER_DIGEST)]);
        assert_eq!(index_layer(&single).unwrap().digest, LAYER_DIGEST);

        assert!(index_layer(&build_manifest(Vec::new())).is_err());
        let wrong_type = build_manifest(vec![descriptor("application/octet-stream", LAYER_DIGEST)]);
        assert!(index_layer(&wrong_type).is_err());
        let two_layers = build_manifest(vec![
            descriptor(STOW_INDEX_MEDIA_TYPE, LAYER_DIGEST),
            descriptor(STOW_INDEX_MEDIA_TYPE, LAYER_DIGEST),
        ]);
        assert!(index_layer(&two_layers).is_err());
        let bad_digest = build_manifest(vec![descriptor(STOW_INDEX_MEDIA_TYPE, "sha256:nope")]);
        assert!(index_layer(&bad_digest).is_err());
    }

    #[test]
    fn zstd_blob_transcodes_to_gzip_byte_exact() {
        // The real producer: `stow_types::index::encode` emits exactly
        // the zstd bytes a published slice carries.
        let index = stow_types::index::ArtifactIndex {
            header: stow_types::index::ArtifactIndexHeader {
                format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                target: "x86_64-unknown-linux-gnu".parse().expect("target"),
                rustc_version: "1.98.1".parse().expect("rustc"),
                generated_at: "2026-09-22T00:00:00Z".to_owned(),
                row_count: 0,
            },
            rows: Vec::new(),
        };
        let payload = serde_json::to_vec(&index).expect("index json");
        let zstd = stow_types::index::encode(&index).expect("index encodes");

        let gzip = zstd_to_gzip(&zstd).expect("transcode");

        let mut round_trip = Vec::new();
        flate2::read::GzDecoder::new(&gzip[..])
            .read_to_end(&mut round_trip)
            .expect("gzip decodes");
        assert_eq!(round_trip, payload);
    }

    #[test]
    fn garbage_input_is_a_decompress_error() {
        assert!(zstd_to_gzip(b"not a zstd frame").is_err());
    }
}
