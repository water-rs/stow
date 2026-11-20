//! The digest-addressed index-slice contract the site answers "is this
//! crate cached?" from (water-rs/stow#288): how `Accept-Encoding` picks
//! a `Content-Encoding`, what a layer digest must look like, and the
//! zstd→gzip transcode for clients that cannot read zstd. Caching lives
//! on the response's own `Cache-Control`/`Vary` — Workers Cache keys
//! each encoding variant itself.
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

/// Decompressed JSON the transcode reads before giving up — matches
/// `ArtifactIndex::decode`'s `4 GiB` bound (~2 million rows at the
/// measured ~2,080 B/row slice density). Because chunks stream straight
/// into the gzip encoder without buffering the uncompressed JSON, this
/// bounds CPU/stream length rather than isolate heap.
const MAX_SLICE_JSON_LEN: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum compressed gzip output buffered inside a Worker isolate's
/// `128 MiB` heap. A `255 MiB` JSON slice compresses to ~`22 MiB` of
/// gzip; `64 MiB` leaves room for the input zstd blob and decoder state
/// while stopping a non-compressible zstd bomb before isolate OOM.
const MAX_SLICE_GZIP_LEN: usize = 64 * 1024 * 1024;

/// Streaming chunk size between `ruzstd` and `GzEncoder` (`64 KiB`),
/// keeping uncompressed JSON off the isolate heap.
const TRANSCODE_CHUNK_LEN: usize = 64 * 1024;

/// Turn the published zstd blob into the gzip body a non-zstd client
/// gets. The `zstd` crate does not build for wasm32, so the worker's
/// decode side is `ruzstd` — pure Rust — and gzip comes from `flate2`,
/// which compiles everywhere.
///
/// # Errors
/// [`SliceError::Decompress`] when the blob is not a zstd frame or
/// inflates past [`MAX_SLICE_JSON_LEN`], [`SliceError::Compress`] when
/// gzip encoding fails or exceeds [`MAX_SLICE_GZIP_LEN`].
pub fn zstd_to_gzip(blob: &[u8]) -> Result<Vec<u8>, SliceError> {
    zstd_to_gzip_bounded(blob, MAX_SLICE_JSON_LEN, MAX_SLICE_GZIP_LEN)
}

fn zstd_to_gzip_bounded(
    blob: &[u8],
    max_json_len: u64,
    max_gzip_len: usize,
) -> Result<Vec<u8>, SliceError> {
    struct BoundedVec {
        bytes: Vec<u8>,
        max_len: usize,
    }

    impl std::io::Write for BoundedVec {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(buf.len()) > self.max_len {
                return Err(std::io::Error::other(format!(
                    "gzip slice exceeds the {}-byte output bound",
                    self.max_len
                )));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut decoder = ruzstd::decoding::StreamingDecoder::new(blob)
        .map_err(|error| SliceError::Decompress(error.to_string()))?;
    let mut encoder = flate2::write::GzEncoder::new(
        BoundedVec {
            bytes: Vec::new(),
            max_len: max_gzip_len,
        },
        flate2::Compression::default(),
    );
    let mut chunk = vec![0u8; TRANSCODE_CHUNK_LEN];
    let mut inflated = 0u64;
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|error| SliceError::Decompress(error.to_string()))?;
        if read == 0 {
            break;
        }
        inflated = inflated.saturating_add(read as u64);
        if inflated > max_json_len {
            return Err(SliceError::Decompress(format!(
                "slice inflates past the {max_json_len}-byte transcode bound"
            )));
        }
        std::io::Write::write_all(&mut encoder, &chunk[..read])
            .map_err(|error| SliceError::Compress(error.to_string()))?;
    }
    encoder
        .finish()
        .map(|out| out.bytes)
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
        // The real producer: `stow_shim::encode_index` emits exactly
        // the zstd bytes a published slice carries.
        let index = stow_types::index::ArtifactIndex {
            header: stow_types::index::ArtifactIndexHeader {
                format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                target: "x86_64-unknown-linux-gnu".parse().expect("target"),
                rustc_version: "1.98.1".parse().expect("rustc"),
                generated_at: "2026-09-22T00:00:00Z".to_owned(),
                generation: 1,
                row_count: 0,
            },
            rows: Vec::new(),
            build_scripts: Vec::new(),
            local_programs: Vec::new(),
        };
        let payload = serde_json::to_vec(&index).expect("index json");
        let zstd = stow_shim::encode_index(&index).expect("index encodes");

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

    #[test]
    fn multi_chunk_zstd_stream_transcodes_and_enforces_bounds() {
        let payload: Vec<u8> = (0..(TRANSCODE_CHUNK_LEN * 3 + 17))
            .map(|idx| b"abcdefghijklmnopqrstuvwxyz"[idx % 26])
            .collect();
        let zstd = stow_shim::compress(&payload).expect("compress");

        let gzip =
            zstd_to_gzip_bounded(&zstd, payload.len() as u64, MAX_SLICE_GZIP_LEN).expect("fits");
        let mut round_trip = Vec::new();
        flate2::read::GzDecoder::new(&gzip[..])
            .read_to_end(&mut round_trip)
            .expect("gzip decodes");
        assert_eq!(round_trip, payload);

        let over_inflated =
            zstd_to_gzip_bounded(&zstd, payload.len() as u64 - 1, MAX_SLICE_GZIP_LEN)
                .expect_err("inflated bound exceeded");
        assert!(matches!(over_inflated, SliceError::Decompress(_)));

        let over_gzip = zstd_to_gzip_bounded(&zstd, payload.len() as u64, 16)
            .expect_err("gzip output bound exceeded");
        assert!(matches!(over_gzip, SliceError::Compress(_)));
    }
}
