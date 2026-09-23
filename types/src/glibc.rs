//! The glibc floor a bundle member needs to load.
//!
//! A `dlopen`'d artifact — proc-macro, dylib, cdylib — inherits the
//! version-needed requirements of whatever glibc the builder linked it
//! against. The published index records that floor as `min_glibc` so a
//! client on an older glibc can refuse the row during resolution instead
//! of fetching a bundle rustc then cannot load. `GlibcVersion` is the
//! value on both the D1 artifact record and the signed index row; the
//! `#[cfg]`-gated helpers below it measure the floor from bytes — from a
//! single ELF image at publish time, or from every `files/` member of a
//! stored bundle for backfill.

use std::fmt;
use std::str::FromStr;

/// A `GLIBC_x.y` release the host's libc must reach for an artifact to
/// load. Three components because real tags carry one when they need it —
/// `GLIBC_2.2.5` exists — and `2.2 < 2.2.5` must not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlibcVersion {
    /// The major component — `2` for every glibc release in the wild.
    pub major: u32,
    /// The minor component.
    pub minor: u32,
    /// The patch component, `0` when the tag carries only `major.minor`.
    pub patch: u32,
}

impl GlibcVersion {
    /// Parse one `GLIBC_x.y[.z]` version-needed name — the bytes an ELF
    /// `SHT_GNU_VERNEED` aux entry names, like `b"GLIBC_2.28"`. Returns
    /// `None` for anything else: other namespaces (`GCC_3.0`,
    /// `GLIBCXX_3.4.29`), and glibc's own non-numeric names
    /// (`GLIBC_PRIVATE`, `GLIBC_ABI_DT_RELR`) that pin an ABI property
    /// rather than a release.
    #[must_use]
    pub fn parse_version_tag(name: &[u8]) -> Option<Self> {
        let rest = name.strip_prefix(b"GLIBC_")?;
        let mut numbers = rest.split(|byte| *byte == b'.');
        let major = parse_digits(numbers.next()?)?;
        let minor = parse_digits(numbers.next()?)?;
        let patch = numbers.next().map_or(Some(0), parse_digits)?;
        numbers.next().is_none().then_some(Self {
            major,
            minor,
            patch,
        })
    }
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    text.parse().ok()
}

/// `major.minor`, plus `.patch` only when nonzero — `2.28`, `2.2.5`.
/// The bare two-component rendering is the form every existing release
/// tag and the `gnu_get_libc_version` string share.
impl fmt::Display for GlibcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.patch == 0 {
            write!(f, "{}.{}", self.major, self.minor)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// `"{major}.{minor}[.{patch}]"` — the same shape [`Display`] writes, so
/// `GlibcVersion::from_str(v.to_string().as_str())` round-trips. Anything
/// else — empty components, non-digits, a fourth component — fails.
impl FromStr for GlibcVersion {
    type Err = GlibcVersionParseError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut numbers = text.split('.');
        let parse = |part: Option<&str>| part.and_then(|part| part.parse::<u32>().ok());
        let version = Self {
            major: parse(numbers.next()).ok_or(GlibcVersionParseError)?,
            minor: parse(numbers.next()).ok_or(GlibcVersionParseError)?,
            patch: parse(numbers.next()).unwrap_or(0),
        };
        if numbers.next().is_some() {
            return Err(GlibcVersionParseError);
        }
        Ok(version)
    }
}

/// `FromStr` could not read the text as `major.minor[.patch]` digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlibcVersionParseError;

impl fmt::Display for GlibcVersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected glibc version `major.minor[.patch]`")
    }
}

impl std::error::Error for GlibcVersionParseError {}

/// Wire form is the `Display` string: `"2.28"`, not a two-field object —
/// the row reads like a version, not a struct.
impl serde::Serialize for GlibcVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for GlibcVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// ELF measurement, using `object`'s `SHT_GNU_VERNEED` reader. `zstd` and
/// `object` both stay off wasm32: the only wasm consumer (stow-edge)
/// serves index pages and never measures bytes.
#[cfg(not(target_arch = "wasm32"))]
mod measure {
    use object::read::elf::{ElfFile, FileHeader};
    use std::io::Read as _;

    use super::GlibcVersion;
    use crate::error::Result;
    use crate::stow_error;

    /// Highest `GLIBC_x.y` an ELF image's version-needed entries demand,
    /// or `None` when the bytes are not an ELF image or carry no glibc
    /// requirement at all — a static `bytes` blob, JSON, and a `.rlib`
    /// have no floor, and `None` on a row keeps it servable everywhere.
    ///
    /// # Errors
    ///
    /// Returns an error when the image parses as ELF but its
    /// version-needed table is malformed — a corrupt artifact is a loud
    /// failure, not a silent `None`.
    pub fn min_glibc_of_elf_bytes(bytes: &[u8]) -> Result<Option<GlibcVersion>> {
        let file = match object::File::parse(bytes) {
            Ok(file) => file,
            Err(_) => return Ok(None),
        };
        match file {
            object::File::Elf32(elf) => needed_glibc(&elf),
            object::File::Elf64(elf) => needed_glibc(&elf),
            _ => Ok(None),
        }
    }

    /// The max over one parsed ELF's version-needed aux names. Every
    /// entry the iterator yields is required, so the floor is the
    /// maximum — a `GLIBC_2.28` need under a `libc.so.6` `Verneed` and a
    /// `GLIBC_2.34` need under `ld.so` both count.
    fn needed_glibc<Elf: FileHeader>(
        elf: &ElfFile<'_, Elf>,
    ) -> Result<Option<GlibcVersion>> {
        let endian = elf.endian();
        let data = elf.data();
        let sections = elf.elf_section_table();
        let Some((verneeds, strings_index)) = sections
            .gnu_verneed(endian, data)
            .map_err(|error| stow_error!("read ELF verneed section: {error}"))?
        else {
            return Ok(None);
        };
        let strings = sections
            .strings(endian, data, strings_index)
            .map_err(|error| stow_error!("read ELF verneed string table: {error}"))?;
        let mut floor = None;
        for verneed in verneeds {
            let (_verneed, aux_iterator) =
                verneed.map_err(|error| stow_error!("read ELF verneed entry: {error}"))?;
            for aux in aux_iterator {
                let aux = aux.map_err(|error| stow_error!("read ELF vernaux entry: {error}"))?;
                let name = aux
                    .name(endian, strings)
                    .map_err(|error| stow_error!("read ELF vernaux name: {error}"))?;
                if let Some(version) = GlibcVersion::parse_version_tag(name) {
                    floor = floor.max(Some(version));
                }
            }
        }
        Ok(floor)
    }

    /// Highest `GLIBC_x.y` across a stored bundle's `files/` members —
    /// the same floor publish measures on the outputs themselves, read
    /// back for rows that predate the field. Bundle members under
    /// `files/` are zstd-compressed payloads; every other member (the
    /// manifests, the signature envelopes) is JSON and never an ELF.
    ///
    /// # Errors
    ///
    /// Returns an error when the tar or a compressed member cannot be
    /// read — a bundle that cannot be measured cannot be trusted to keep
    /// its row's floor honest.
    pub fn min_glibc_of_bundle(bundle_bytes: &[u8]) -> Result<Option<GlibcVersion>> {
        let mut archive = tar::Archive::new(bundle_bytes);
        let mut floor = None;
        for entry in archive
            .entries()
            .map_err(|error| stow_error!("read bundle tar: {error}"))?
        {
            let mut entry = entry.map_err(|error| stow_error!("read bundle entry: {error}"))?;
            // Owned so the mutable `read_to_end` borrow below is free.
            let path = entry.path_bytes().into_owned();
            if !path.starts_with(b"files/") {
                continue;
            }
            let mut compressed = Vec::new();
            entry
                .read_to_end(&mut compressed)
                .map_err(|error| {
                    stow_error!(
                        "read bundle member {}: {error}",
                        String::from_utf8_lossy(&path)
                    )
                })?;
            let bytes = zstd::stream::decode_all(std::io::Cursor::new(&compressed))
                .unwrap_or(compressed);
            floor = floor.max(min_glibc_of_elf_bytes(&bytes)?);
        }
        Ok(floor)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use measure::{min_glibc_of_bundle, min_glibc_of_elf_bytes};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_tags() {
        assert_eq!(
            GlibcVersion::parse_version_tag(b"GLIBC_2.28"),
            Some(GlibcVersion {
                major: 2,
                minor: 28,
                patch: 0,
            })
        );
        assert_eq!(
            GlibcVersion::parse_version_tag(b"GLIBC_2.2.5"),
            Some(GlibcVersion {
                major: 2,
                minor: 2,
                patch: 5,
            })
        );
        assert_eq!(GlibcVersion::parse_version_tag(b"GLIBC_PRIVATE"), None);
        assert_eq!(GlibcVersion::parse_version_tag(b"GCC_3.0"), None);
        assert_eq!(GlibcVersion::parse_version_tag(b"GLIBCXX_3.4.29"), None);
        assert_eq!(GlibcVersion::parse_version_tag(b"GLIBC_2"), None);
        assert_eq!(GlibcVersion::parse_version_tag(b"GLIBC_2.28.1.9"), None);
    }

    #[test]
    fn orders_versions() {
        let mut versions = [
            GlibcVersion {
                major: 2,
                minor: 28,
                patch: 0,
            },
            GlibcVersion {
                major: 2,
                minor: 2,
                patch: 5,
            },
            GlibcVersion {
                major: 2,
                minor: 2,
                patch: 4,
            },
            GlibcVersion {
                major: 2,
                minor: 35,
                patch: 0,
            },
        ];
        versions.sort();
        assert_eq!(
            versions,
            [
                GlibcVersion {
                    major: 2,
                    minor: 2,
                    patch: 4
                },
                GlibcVersion {
                    major: 2,
                    minor: 2,
                    patch: 5
                },
                GlibcVersion {
                    major: 2,
                    minor: 28,
                    patch: 0
                },
                GlibcVersion {
                    major: 2,
                    minor: 35,
                    patch: 0
                },
            ]
        );
    }

    #[test]
    fn display_and_from_str_round_trip() {
        for text in ["2.28", "2.35", "0.0", "2.2.5"] {
            let version = GlibcVersion::from_str(text).expect("parse");
            let rendered = version.to_string();
            let reparsed = GlibcVersion::from_str(&rendered).expect("reparse");
            assert_eq!(version, reparsed);
        }
        assert!(GlibcVersion::from_str("").is_err());
        assert!(GlibcVersion::from_str("2").is_err());
        assert!(GlibcVersion::from_str("2.28.x").is_err());
        assert!(GlibcVersion::from_str("2.28.0.1").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let version = GlibcVersion {
            major: 2,
            minor: 28,
            patch: 0,
        };
        let json = serde_json::to_string(&version).expect("serialize");
        assert_eq!(json, "\"2.28\"");
        assert_eq!(
            serde_json::from_str::<GlibcVersion>(&json).expect("deserialize"),
            version
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn measures_a_built_so() {
        // Compile a tiny shared object with the system toolchain rather
        // than checking in a fixture: whatever `cc` this dev machine
        // links is exactly the ELF shape the publish stage measures.
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("probe.c");
        std::fs::write(&source, "int stow_probe(void) { return 42; }").expect("write");
        let output = dir.path().join("probe.so");
        let status = std::process::Command::new("cc")
            .args(["-shared", "-o"])
            .arg(&output)
            .arg(&source)
            .status()
            .expect("run cc");
        assert!(status.success(), "cc failed to build probe .so");
        let bytes = std::fs::read(&output).expect("read probe .so");
        let floor = min_glibc_of_elf_bytes(&bytes).expect("measure");
        // A working libc link can always be measured; on glibc hosts it
        // is Some version, on musl/BSD it is None — both honest.
        if cfg!(all(target_os = "linux", target_env = "gnu")) {
            assert!(floor.is_some(), "probe .so should need some glibc");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn non_elf_bytes_have_no_floor() {
        assert_eq!(
            min_glibc_of_elf_bytes(b"not an elf file").expect("measure"),
            None
        );
        assert_eq!(min_glibc_of_elf_bytes(&[]).expect("measure"), None);
    }
}
