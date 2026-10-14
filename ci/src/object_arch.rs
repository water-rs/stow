//! The machine check every unit's objects pass before the plan writes
//! anything down.
//!
//! A unit's identity names the machine its objects were built for, and
//! the plan stage is the last place a wrong one can be refused: a build
//! script whose `cc` invocation ran a compiler for another machine — the
//! host's `cl.exe` answering an arm64 task (stow#708) — archives foreign
//! objects into outputs and `OUT_DIR` files that otherwise publish
//! unexamined.

use object::read::archive::ArchiveFile;
use object::read::coff::ImportFile;
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{Architecture, FileKind, Object as _};

/// The machine a unit's objects must be for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedArch(Architecture);

impl ExpectedArch {
    /// From a target triple's architecture component — the text before
    /// its first `-`, spelled the way `std::env::consts::ARCH` spells it.
    ///
    /// # Errors
    /// Returns an error when the component names no architecture the
    /// check knows — an unknown machine must fail the plan, not pass
    /// unexamined.
    pub fn of_triple(triple: &str) -> stow_types::error::Result<Self> {
        let architecture = match triple.split('-').next().unwrap_or(triple) {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            "wasm32" => Architecture::Wasm32,
            _ => {
                return Err(stow_types::stow_error!(
                    "no object architecture is known for target {triple}"
                ));
            }
        };
        Ok(Self(architecture))
    }

    /// The builder's own machine, for a host-side unit.
    ///
    /// # Errors
    /// Returns an error when the builder's architecture is one the check
    /// does not know.
    pub fn of_host() -> stow_types::error::Result<Self> {
        Self::of_triple(std::env::consts::ARCH)
    }
}

/// Check every object in `bytes` — a single object, or each member of an
/// archive — and fail on the first one built for another machine. `what`
/// names the file the error points at.
///
/// Bytes that are no object format pass: an `OUT_DIR` holds headers and
/// generated sources beside its objects, and an rlib holds `lib.rmeta`.
///
/// # Errors
/// Returns an error when an object in `bytes` is built for a machine
/// other than `expected`, or when recognised object bytes do not parse.
pub fn check(bytes: &[u8], what: &str, expected: ExpectedArch) -> stow_types::error::Result<()> {
    if let Ok(archive) = ArchiveFile::parse(bytes) {
        for member in archive.members() {
            let member = member
                .map_err(|error| stow_types::stow_error!("read a member of {what}: {error}"))?;
            let name = String::from_utf8_lossy(member.name());
            let data = member.data(bytes).map_err(|error| {
                stow_types::stow_error!("read member {name} of {what}: {error}")
            })?;
            check(data, &format!("{what}({name})"), expected)?;
        }
        return Ok(());
    }
    check_one(bytes, what, expected)
}

/// One object's machine against `expected` — the per-item half of
/// [`check`], reached once `bytes` is known not to parse as an archive.
fn check_one(bytes: &[u8], what: &str, expected: ExpectedArch) -> stow_types::error::Result<()> {
    let Ok(kind) = FileKind::parse(bytes) else {
        return Ok(());
    };
    let found = match kind {
        FileKind::MachOFat32 => return check_fat(MachOFatFile32::parse(bytes), what, expected),
        FileKind::MachOFat64 => return check_fat(MachOFatFile64::parse(bytes), what, expected),
        // `object::File` has no COFF short-import variant.
        FileKind::CoffImport => ImportFile::parse(bytes)
            .map_err(|error| unparsable(what, &error))?
            .architecture(),
        _ => object::File::parse(bytes)
            .map_err(|error| unparsable(what, &error))?
            .architecture(),
    };
    if found != expected.0 {
        return Err(wrong_machine(what, &format!("{found:?}"), expected));
    }
    Ok(())
}

/// A fat Mach-O serves this unit when one of its slices is the expected
/// machine.
fn check_fat<Fat: FatArch>(
    fat: object::read::Result<object::read::macho::MachOFatFile<'_, Fat>>,
    what: &str,
    expected: ExpectedArch,
) -> stow_types::error::Result<()> {
    let fat = fat.map_err(|error| unparsable(what, &error))?;
    let slices: Vec<Architecture> = fat.arches().iter().map(FatArch::architecture).collect();
    if slices.contains(&expected.0) {
        return Ok(());
    }
    Err(wrong_machine(what, &format!("{slices:?}"), expected))
}

/// `bytes` named a known object kind but did not parse — as loud a
/// failure as a wrong machine, since neither should ship.
fn unparsable(what: &str, error: &object::read::Error) -> stow_types::error::Error {
    stow_types::stow_error!("{what} is a recognised object that does not parse: {error}")
}

/// The refusal the whole check exists to deliver.
fn wrong_machine(what: &str, found: &str, expected: ExpectedArch) -> stow_types::error::Error {
    stow_types::stow_error!(
        "{what} is built for {found}, but this unit's objects must be for {expected:?}: \
         a compiler for another machine produced it"
    )
}

/// A minimal relocatable object holding one empty `.text` section —
/// fixtures are built by the tests that need them, never committed.
#[cfg(test)]
pub fn relocatable_object(format: object::BinaryFormat, architecture: Architecture) -> Vec<u8> {
    let mut object = object::write::Object::new(format, architecture, object::Endianness::Little);
    let text = object.section_id(object::write::StandardSection::Text);
    object.append_section_data(text, &[], 1);
    object.write().expect("write fixture object")
}

/// A GNU `ar` archive holding the named members — written by hand
/// because no archive-writer crate is in the tree.
#[cfg(test)]
pub fn gnu_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    // A name too long for the 16-byte header field goes through the `//`
    // names-table member — each long name one `name/\n` entry — and the
    // member's header names it by byte offset, `/<offset>`.
    let mut names_table = Vec::new();
    let rendered: Vec<String> = members
        .iter()
        .map(|(name, _)| {
            if name.len() < 16 {
                format!("{name}/")
            } else {
                let offset = names_table.len();
                names_table.extend_from_slice(name.as_bytes());
                names_table.extend_from_slice(b"/\n");
                format!("/{offset}")
            }
        })
        .collect();
    let mut archive = b"!<arch>\n".to_vec();
    if !names_table.is_empty() {
        write_archive_member(&mut archive, "//", &names_table);
    }
    for ((_, data), name) in members.iter().zip(&rendered) {
        write_archive_member(&mut archive, name, data);
    }
    archive
}

/// Append one `ar` member to `archive`: the 60-byte header — name(16)
/// mtime(12) uid(6) gid(6) mode(8) size(10), then the `\x60\n` trailer —
/// then the data, padded to even.
#[cfg(test)]
fn write_archive_member(archive: &mut Vec<u8>, name: &str, data: &[u8]) {
    archive.extend_from_slice(
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name,
            0,
            0,
            0,
            "100644",
            data.len()
        )
        .as_bytes(),
    );
    archive.extend_from_slice(data);
    if data.len() % 2 == 1 {
        archive.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpectedArch, check, gnu_archive, relocatable_object};
    use object::{Architecture, BinaryFormat};

    #[test]
    fn an_object_for_the_expected_machine_passes() {
        for (format, architecture) in [
            (BinaryFormat::Coff, Architecture::X86_64),
            (BinaryFormat::Coff, Architecture::Aarch64),
            (BinaryFormat::Elf, Architecture::X86_64),
            (BinaryFormat::Elf, Architecture::Aarch64),
            (BinaryFormat::MachO, Architecture::Aarch64),
        ] {
            let bytes = relocatable_object(format, architecture);
            check(&bytes, "fixture.o", ExpectedArch(architecture))
                .unwrap_or_else(|error| panic!("{format:?}/{architecture:?} refused: {error}"));
        }
    }

    #[test]
    fn an_object_for_another_machine_is_refused() {
        let bytes = relocatable_object(BinaryFormat::Coff, Architecture::X86_64);
        let expected =
            ExpectedArch::of_triple("aarch64-pc-windows-msvc").expect("arm64 expectation");
        let error = check(&bytes, "probe.o", expected)
            .expect_err("an x86-64 object must not serve an arm64 unit");
        let message = error.to_string();
        assert!(
            message.contains("X86_64"),
            "names the machine found: {message}"
        );
        assert!(
            message.contains("Aarch64"),
            "names the machine expected: {message}"
        );
    }

    #[test]
    fn an_archive_is_checked_member_by_member() {
        let arm64 = relocatable_object(BinaryFormat::Coff, Architecture::Aarch64);
        let x64 = relocatable_object(BinaryFormat::Coff, Architecture::X86_64);
        let archive = gnu_archive(&[("arm64.o", &arm64), ("x86.o", &x64)]);
        let expected =
            ExpectedArch::of_triple("aarch64-pc-windows-msvc").expect("arm64 expectation");
        let error =
            check(&archive, "probe.a", expected).expect_err("a foreign member must be refused");
        let message = error.to_string();
        assert!(message.contains("x86.o"), "names the member: {message}");
    }

    #[test]
    fn what_is_not_an_object_passes() {
        let expected = ExpectedArch::of_triple("x86_64-pc-windows-msvc").expect("x64 expectation");
        check(
            b"#ifndef PROBE_H\n#define PROBE_H\n#endif\n",
            "probe.h",
            expected,
        )
        .expect("a C header is not an object");
        check(&[], "empty.bin", expected).expect("an empty file is not an object");
        let archive = gnu_archive(&[("notes.txt", b"generated bindings")]);
        check(&archive, "text.a", expected).expect("a text-only archive passes");
    }

    #[test]
    fn a_target_triple_names_its_machine() {
        for triple in stow_types::api::CI_TARGET_TRIPLES {
            ExpectedArch::of_triple(triple)
                .unwrap_or_else(|error| panic!("{triple} has no known machine: {error}"));
        }
        assert!(ExpectedArch::of_triple("riscv64gc-unknown-linux-gnu").is_err());
    }
}
