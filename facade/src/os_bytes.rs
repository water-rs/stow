//! Platform-exact encoding of an `OsStr` for the supervisor wire.
//!
//! rustc arguments are paths, and a path is not required to be UTF-8 on
//! either platform stow runs on. The wrapper and the supervisor are the
//! same binary on the same machine, so the wire can carry the platform's
//! own encoding verbatim rather than a lossy string: raw bytes on Unix,
//! little-endian UTF-16 code units on Windows.

use std::ffi::{OsStr, OsString};

/// Encode `value` as the bytes this platform stores it in.
#[must_use]
pub fn encode(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(value).to_vec()
    }
    #[cfg(windows)]
    {
        std::os::windows::ffi::OsStrExt::encode_wide(value)
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}

/// Rebuild the `OsString` [`encode`] produced.
///
/// # Errors
///
/// On Windows, an odd number of bytes cannot be UTF-16 code units.
// Every byte string is a valid Unix `OsStr`, so the Unix arm has no error
// to return — the fallible half of this function is the Windows one, and
// both platforms need the same signature.
pub fn decode(bytes: &[u8]) -> Result<OsString, String> {
    #[cfg(unix)]
    {
        Ok(std::os::unix::ffi::OsStringExt::from_vec(bytes.to_vec()))
    }
    #[cfg(windows)]
    {
        if !bytes.len().is_multiple_of(2) {
            return Err(format!("{} bytes cannot be UTF-16 code units", bytes.len()));
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Ok(std::os::windows::ffi::OsStringExt::from_wide(&units))
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{decode, encode};

    #[test]
    fn a_plain_path_round_trips() {
        let value = OsString::from("/Users/one/.cargo/registry/src/serde-1.0.0/src/lib.rs");
        assert_eq!(decode(&encode(&value)).expect("decode"), value);
    }

    /// The reason this module exists rather than `to_string_lossy`: a path
    /// that is not valid Unicode must survive the round trip unchanged.
    #[cfg(unix)]
    #[test]
    fn a_non_unicode_path_round_trips() {
        let value: OsString = std::os::unix::ffi::OsStringExt::from_vec(vec![b'/', 0xff, b'a']);
        assert_eq!(decode(&encode(&value)).expect("decode"), value);
    }
}
