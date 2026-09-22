//! URL ↔ path conversion helpers.
//!
//! `url::Url::to_file_path` is cfg'd out of the `url` crate on
//! `wasm32-unknown-unknown`. Source ids for `path`/`local-registry`/`git`
//! sources are `file://` URLs, so the conversion is carried here: on host it
//! delegates to the crate method; on wasm it implements the same decode
//! (file scheme, no meaningful host, percent-decoded absolute path).

use std::path::PathBuf;
use url::Url;

/// Equivalent of `Url::to_file_path`: convert a `file://` URL to a local
/// path. Returns `Err(())` for non-file URLs, matching the crate's signature.
#[cfg(not(target_family = "wasm"))]
pub fn url_to_path(url: &Url) -> Result<PathBuf, ()> {
    url.to_file_path()
}

/// `wasm32-unknown-unknown` implementation of [`url_to_path`].
///
/// The VFS is a POSIX-shaped tree, so the decoded path is returned as-is —
/// the same conversion `Url::to_file_path` performs on unix.
#[cfg(target_family = "wasm")]
pub fn url_to_path(url: &Url) -> Result<PathBuf, ()> {
    if url.scheme() != "file" {
        return Err(());
    }
    // `to_file_path` accepts an empty host or localhost; anything else names
    // a remote machine and is not a local path.
    match url.host_str() {
        None | Some("") | Some("localhost") => {}
        _ => return Err(()),
    }
    let path = url.path();
    if !path.starts_with('/') {
        return Err(());
    }
    Ok(PathBuf::from(percent_decode(path)?))
}

#[cfg(target_family = "wasm")]
fn percent_decode(s: &str) -> Result<String, ()> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(());
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(target_family = "wasm")]
fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

/// Equivalent of `Url::from_file_path`: convert a local path to a `file://`
/// URL. On host delegates to the crate method; on wasm builds the URL with
/// the same percent-encoding rules (`url`'s PATH segment encode set).
#[cfg(not(target_family = "wasm"))]
pub fn path_to_url(path: &std::path::Path) -> Result<Url, ()> {
    Url::from_file_path(path)
}

/// `wasm32-unknown-unknown` implementation of [`path_to_url`].
#[cfg(target_family = "wasm")]
pub fn path_to_url(path: &std::path::Path) -> Result<Url, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let mut encoded = String::from("file://");
    for component in path.components() {
        encoded.push('/');
        for b in component.as_os_str().to_string_lossy().as_bytes() {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | 0x27
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@' => encoded.push(*b as char),
                _ => {
                    encoded.push('%');
                    encoded.push(
                        char::from_digit((b >> 4) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase(),
                    );
                    encoded.push(
                        char::from_digit((b & 0xF) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase(),
                    );
                }
            }
        }
    }
    Url::parse(&encoded).map_err(|_| ())
}
