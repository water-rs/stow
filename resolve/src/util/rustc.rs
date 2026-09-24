use std::path::PathBuf;

use anyhow::Context as _;

use crate::util::CargoResult;
use crate::util::interning::InternedString;

/// Information on the `rustc` executable — the injected identity only.
///
/// Upstream probes the binary (`Rustc::new`, `cached_output`, the fingerprint
/// cache, the `ProcessBuilder` helpers); none of that is reachable here —
/// `stow-resolve` never executes rustc, so only the `-vV`-text constructor
/// and the fields the resolver reads are kept.
#[derive(Debug)]
pub struct Rustc {
    /// The location of the exe
    pub path: PathBuf,
    /// An optional program that will be passed the path of the rust exe as its first argument, and
    /// rustc args following this.
    pub wrapper: Option<PathBuf>,
    /// An optional wrapper to be used in addition to `rustc.wrapper` for workspace crates
    pub workspace_wrapper: Option<PathBuf>,
    /// Verbose version information (the output of `rustc -vV`)
    pub verbose_version: String,
    /// The rustc version (`1.23.4-beta.2`), this comes from `verbose_version`.
    pub version: semver::Version,
    /// The host triple (arch-platform-OS), this comes from `verbose_version`.
    pub host: InternedString,
    /// The rustc full commit hash, this comes from `verbose_version`.
    pub commit_hash: Option<String>,
}

impl Rustc {
    /// Constructs a [`Rustc`] from captured `rustc -vV` output — no process
    /// probe. Used when the rustc identity is injected rather than observed
    /// (the worker embeds the pinned toolchain's `-vV` text).
    pub fn new_from_verbose_version(path: PathBuf, verbose_version: String) -> CargoResult<Rustc> {
        Self::from_verbose_version_parts(path, None, None, verbose_version)
    }

    fn from_verbose_version_parts(
        path: PathBuf,
        wrapper: Option<PathBuf>,
        workspace_wrapper: Option<PathBuf>,
        verbose_version: String,
    ) -> CargoResult<Rustc> {
        let extract = |field: &str| -> CargoResult<&str> {
            verbose_version
                .lines()
                .find_map(|l| l.strip_prefix(field))
                .ok_or_else(|| {
                    anyhow::format_err!(
                        "`rustc -vV` didn't have a line for `{}`, got:\n{}",
                        field.trim(),
                        verbose_version
                    )
                })
        };

        let host = extract("host: ")?.into();
        let version = semver::Version::parse(extract("release: ")?).with_context(|| {
            format!(
                "rustc version does not appear to be a valid semver version, from:\n{}",
                verbose_version
            )
        })?;
        let commit_hash = extract("commit-hash: ").ok().map(|hash| {
            // Possible commit-hash values from rustc are SHA hex string and "unknown". See:
            // * https://github.com/rust-lang/rust/blob/531cb83fc/src/bootstrap/src/utils/channel.rs#L73
            // * https://github.com/rust-lang/rust/blob/531cb83fc/compiler/rustc_driver_impl/src/lib.rs#L911-L913
            #[cfg(debug_assertions)]
            if hash != "unknown" {
                debug_assert!(
                    hash.chars().all(|ch| ch.is_ascii_hexdigit()),
                    "commit hash must be a hex string, got: {hash:?}"
                );
                debug_assert!(
                    hash.len() == 40 || hash.len() == 64,
                    "hex string must be generated from sha1 or sha256 (i.e., it must be 40 or 64 characters long)\ngot: {hash:?}"
                );
            }
            hash.to_string()
        });

        Ok(Rustc {
            path,
            wrapper,
            workspace_wrapper,
            verbose_version,
            version,
            host,
            commit_hash,
        })
    }
}
