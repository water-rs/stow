//! Whether two captures of one unit's rlib are the same compilation's
//! product — the member-level check a digest mismatch defers to.
//!
//! An rlib that archives a build script's native objects legitimately
//! hashes differently between two captures of one unit: those objects
//! record where and when their own compiler ran — the `OUT_DIR` path in
//! debug information, and on Windows also the COFF header timestamp and
//! the archive member's name — so the recorded digests cannot tell a
//! duplicate from a forgery (stow#719). What can is what rustc itself
//! wrote: `lib.rmeta` and every `*.rcgu.o` member must be the same
//! sequence — same names, same order, same bytes — while the members a
//! build script's native libraries contributed only have to agree in
//! count.

use object::read::archive::ArchiveFile;

/// Why two archives are not the same unit's product — the first
/// disagreement [`same_rustc_members`] found.
#[derive(Debug)]
pub enum MemberDisagreement {
    /// The named side's bytes do not read as an archive at all — an rlib
    /// is always one.
    NotAnArchive {
        /// Which side failed: `"left"` or `"right"`.
        side: &'static str,
    },
    /// At one position in archive order the two rustc-member sequences
    /// name different members.
    MemberNameDiffers {
        /// The member name the left archive holds at that position.
        left: String,
        /// The member name the right archive holds there.
        right: String,
    },
    /// A rustc member of the same name holds different bytes — two
    /// different compilations wrote it.
    MemberBytesDiffer {
        /// The member whose bytes disagree.
        member: String,
    },
    /// One archive's rustc-member sequence ends before the other's —
    /// the named member exists on that side only.
    MemberOnlyIn {
        /// The member present on one side only.
        member: String,
        /// Which archive holds it: `"left"` or `"right"`.
        side: &'static str,
    },
    /// The members a build script's native libraries contributed differ
    /// in count; their names and bytes are free to differ.
    NativeCount {
        /// How many native members the left archive holds.
        left: usize,
        /// How many native members the right archive holds.
        right: usize,
    },
}

impl std::fmt::Display for MemberDisagreement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArchive { side } => {
                write!(formatter, "the {side} file does not read as an archive")
            }
            Self::MemberNameDiffers { left, right } => write!(
                formatter,
                "the rustc members diverge: {left} in the left archive, {right} in the right"
            ),
            Self::MemberBytesDiffer { member } => {
                write!(formatter, "rustc member {member} differs")
            }
            Self::MemberOnlyIn { member, side } => {
                write!(
                    formatter,
                    "rustc member {member} is present in the {side} archive only"
                )
            }
            Self::NativeCount { left, right } => write!(
                formatter,
                "{left} native members in the left archive, {right} in the right"
            ),
        }
    }
}

/// Whether two rlib captures are one unit's product: `lib.rmeta` and
/// every `*.rcgu.o` member are the same sequence in both — same names,
/// same order, same bytes — and the members the build script's native
/// libraries contributed are the same count. The native members
/// themselves are free to differ: their compiler wrote where and when
/// it ran into them, so two honest captures of one unit produce
/// different ones (stow#719).
///
/// # Errors
/// Returns the first disagreement the comparison finds — which rustc
/// member diverged, which side holds a member alone, the two native
/// member counts, or which file is not an archive.
pub fn same_rustc_members(left: &[u8], right: &[u8]) -> Result<(), MemberDisagreement> {
    let left_members = members(left, "left")?;
    let right_members = members(right, "right")?;
    let mut left_rustc = left_members.rustc.iter();
    let mut right_rustc = right_members.rustc.iter();
    loop {
        match (left_rustc.next(), right_rustc.next()) {
            (None, None) => break,
            (Some(&(name, _)), None) => {
                return Err(MemberDisagreement::MemberOnlyIn {
                    member: member_name(name),
                    side: "left",
                });
            }
            (None, Some(&(name, _))) => {
                return Err(MemberDisagreement::MemberOnlyIn {
                    member: member_name(name),
                    side: "right",
                });
            }
            (Some(&(left_name, left_data)), Some(&(right_name, right_data))) => {
                if left_name != right_name {
                    return Err(MemberDisagreement::MemberNameDiffers {
                        left: member_name(left_name),
                        right: member_name(right_name),
                    });
                }
                if left_data != right_data {
                    return Err(MemberDisagreement::MemberBytesDiffer {
                        member: member_name(left_name),
                    });
                }
            }
        }
    }
    if left_members.native_count != right_members.native_count {
        return Err(MemberDisagreement::NativeCount {
            left: left_members.native_count,
            right: right_members.native_count,
        });
    }
    Ok(())
}

/// One archive's members split the way the agreement rule treats them.
struct ArchiveMembers<'a> {
    /// `lib.rmeta` and the `*.rcgu.o` objects — name and bytes — in
    /// archive order.
    rustc: Vec<(&'a [u8], &'a [u8])>,
    /// How many members a build script's native libraries contributed;
    /// their names and bytes may differ between captures.
    native_count: usize,
}

/// Read `bytes` as an archive and split its members; `side` names which
/// half of the comparison a malformed file blames.
fn members<'a>(
    bytes: &'a [u8],
    side: &'static str,
) -> Result<ArchiveMembers<'a>, MemberDisagreement> {
    let archive =
        ArchiveFile::parse(bytes).map_err(|_| MemberDisagreement::NotAnArchive { side })?;
    let mut rustc = Vec::new();
    let mut native_count = 0usize;
    for member in archive.members() {
        let member = member.map_err(|_| MemberDisagreement::NotAnArchive { side })?;
        let data = member
            .data(bytes)
            .map_err(|_| MemberDisagreement::NotAnArchive { side })?;
        if is_rustc_member(member.name()) {
            rustc.push((member.name(), data));
        } else {
            native_count += 1;
        }
    }
    Ok(ArchiveMembers {
        rustc,
        native_count,
    })
}

/// The members rustc itself writes into an rlib: its metadata under
/// `lib.rmeta` and each codegen unit's object as
/// `<crate>-<hash>.<cgu>.rcgu.o`. Every other member came from the
/// build script's native libraries.
fn is_rustc_member(name: &[u8]) -> bool {
    name == b"lib.rmeta" || name.ends_with(b".rcgu.o")
}

/// A member name for an error message — names are bytes, not text.
fn member_name(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

#[cfg(test)]
mod tests {
    use super::same_rustc_members;
    use crate::object_arch::gnu_archive;

    /// Both archives hold `lib.rmeta` and the codegen object with equal
    /// bytes; the build script's native object differs in bytes *and*
    /// name — each capture recorded its own phase's `OUT_DIR` — and the
    /// pair still agrees (stow#719).
    #[test]
    fn archives_differing_only_in_native_members_agree() {
        let left = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("probe-0123.probe.0.rcgu.o", b"codegen object"),
            ("/tmp/one/out/psm.o", b"native object one"),
        ]);
        let right = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("probe-0123.probe.0.rcgu.o", b"codegen object"),
            ("/tmp/two/out/psm.o", b"native object two"),
        ]);
        same_rustc_members(&left, &right).expect("native members may differ in name and bytes");
    }

    /// Same member names, but the `.rcgu.o` bytes differ — two
    /// different compilations, and the error names the member.
    #[test]
    fn a_different_rustc_object_disagrees() {
        let left = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("probe-0123.probe.0.rcgu.o", b"codegen left"),
        ]);
        let right = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("probe-0123.probe.0.rcgu.o", b"codegen right"),
        ]);
        let error =
            same_rustc_members(&left, &right).expect_err("differing codegen bytes disagree");
        assert!(
            error.to_string().contains("probe-0123.probe.0.rcgu.o"),
            "names the member: {error}"
        );
    }

    /// `lib.rmeta` is rustc's own product: differing metadata is a
    /// different unit outright.
    #[test]
    fn different_metadata_disagrees() {
        let left = gnu_archive(&[("lib.rmeta", b"metadata one")]);
        let right = gnu_archive(&[("lib.rmeta", b"metadata two")]);
        let error = same_rustc_members(&left, &right).expect_err("differing rmeta disagrees");
        assert!(error.to_string().contains("lib.rmeta"), "{error}");
    }

    /// A rustc member that exists on one side only is a different unit —
    /// the error says which member and which side holds it.
    #[test]
    fn a_rustc_member_present_in_one_only_disagrees() {
        let left = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("probe-0123.probe.0.rcgu.o", b"codegen"),
        ]);
        let right = gnu_archive(&[("lib.rmeta", b"metadata")]);
        let error = same_rustc_members(&left, &right).expect_err("a one-sided member disagrees");
        let message = error.to_string();
        assert!(message.contains("probe-0123.probe.0.rcgu.o"), "{message}");
        assert!(message.contains("left"), "names the side: {message}");
    }

    /// The native members' names and bytes are free to differ; their
    /// count is not — the error carries both.
    #[test]
    fn a_different_native_member_count_disagrees() {
        let left = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("/tmp/one/out/psm.o", b"native"),
            ("/tmp/one/out/shim.o", b"second native"),
        ]);
        let right = gnu_archive(&[
            ("lib.rmeta", b"metadata"),
            ("/tmp/two/out/psm.o", b"native"),
        ]);
        let error = same_rustc_members(&left, &right)
            .expect_err("a different native member count disagrees");
        let message = error.to_string();
        assert!(message.contains('2'), "carries the left count: {message}");
        assert!(message.contains('1'), "carries the right count: {message}");
    }

    /// Only archives can agree at the member level — anything else is
    /// not an rlib.
    #[test]
    fn what_is_not_an_archive_disagrees() {
        let archive = gnu_archive(&[("lib.rmeta", b"metadata")]);
        let error = same_rustc_members(&archive, b"not an archive")
            .expect_err("non-archive bytes disagree");
        assert!(
            error.to_string().contains("does not read as an archive"),
            "{error}"
        );
        let error = same_rustc_members(b"not an archive", &archive)
            .expect_err("non-archive bytes disagree");
        assert!(
            error.to_string().contains("does not read as an archive"),
            "{error}"
        );
    }
}
