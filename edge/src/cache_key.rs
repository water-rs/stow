//! CF-cache keys for the bundle payloads the byte path serves, kept
//! target-agnostic so the derivations are unit-testable outside wasm.

/// Bundle-bytes schema version baked into the CF-cache bundle keys. Bump
/// only when the bundle format itself changes; a key-shape change mints
/// fresh keys that simply miss and refill. Version 3 is the first whose
/// bytes are the publish stage's `<tag>.bundle` blob rather than an
/// edge-assembled tar.
pub const EDGE_BUNDLE_SCHEMA_VERSION: u32 = 3;

/// CF-cache key for a bundle. The bundle is the content-addressed blob the
/// trusted publish stage pushed, so `bundle_digest` pins the bytes and is
/// the whole key — the request path carries nothing else.
pub fn bundle_cache_key(bundle_digest: &str) -> String {
    format!("bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/{bundle_digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle key is content-addressed: the publish stage's bundle
    /// digest pins the bytes, so the digest is the whole key.
    #[test]
    fn bundle_cache_key_is_the_bundle_digest() {
        assert_eq!(
            bundle_cache_key("sha256:bbbb"),
            format!("bundle-v{EDGE_BUNDLE_SCHEMA_VERSION}/sha256:bbbb"),
        );
    }
}
