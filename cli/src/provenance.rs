//! Which artifacts of this build were compiled locally, and what that
//! forbids.
//!
//! A cached artifact is not interchangeable with a local build of the same
//! identity. rustc stamps every crate with an SVH that follows the source
//! path, so the CI copy compiled under the runner's `CARGO_HOME` and the
//! local copy compiled under the developer's never match, and a crate
//! linked against one of them rejects the other:
//!
//! ```text
//! error[E0460]: found possibly newer version of crate `unicode_ident`
//!               which `proc_macro2` depends on
//! ```
//!
//! stow's own identity cannot see that difference — both copies carry the
//! same stable `c_metadata`, which is the point of the identity rewrite —
//! so the rule has to be about provenance instead: once an artifact is
//! built locally, every artifact that was compiled against it must be
//! built locally too. Serving one of them from the cache turns a partial
//! cache into a failed build rather than a slower one.
//!
//! The marker names the artifact itself — `<crate name>-<unit hash>`, read
//! off the `--extern` path cargo hands a consumer: the file stem in cargo's
//! shared `deps` directory, the crate name and the unit directory in its
//! build-unit layout — not the crate or the `--extern` alias. The alias is
//! only what the consumer calls the dependency: a manifest rename
//! (`pki_types` for `rustls_pki_types`) would hide a local build behind the
//! wrong key entirely (stow#733), and the crate name alone marks more than
//! the unit — a build-script probe that borrows a real crate's
//! `--crate-name`, or a second feature set or side of it, would send that
//! crate's consumers local by the dozen (stow#734). A probe never names
//! the unit a consumer links: in the shared layout it carries no
//! `-C extra-filename`, in the build-unit one it writes into its build
//! script run's directory, whose hash is no library's.
//!
//! The markers live in the build's session directory, which only the
//! process deciding the build's units writes. Cargo runs a unit only after
//! its dependencies, so a dependency's marker is on disk before any
//! consumer asks about it. Without that directory (a bare `stow rustc`
//! outside `stow check`) there is no build to reason about and nothing is
//! recorded or refused.

use std::path::{Path, PathBuf};

use stow_types::cargo_layout::UnitDir;
use stow_types::rustc::ParsedExternCrate;

/// Subdirectory of the build's session directory holding one marker per
/// locally compiled artifact.
const LOCAL_BUILD_DIR: &str = "local-build";

/// Record that the artifact `crate_name` + `extra_filename` names was
/// compiled locally for `target` in this build, so artifacts compiled
/// against it stay off the cache.
///
/// `extra_filename` and `out_dir` are the `-C extra-filename` and
/// `--out-dir` the invocation writes its outputs with — cargo's own, since
/// the wrapper hands rustc the argv unchanged — which is what a consumer's
/// `--extern` path spells. A unit whose outputs carry no unit hash in
/// either — a shared-layout build-script probe is exactly such a unit, as
/// is any unit outside cargo's layout — writes nothing a consumer can
/// name, so it records nothing.
///
/// Silently does nothing when the build has no session directory: there is
/// no build-wide view to record into.
pub async fn record_local_build(
    session_dir: Option<&Path>,
    target: &str,
    crate_name: &str,
    extra_filename: &str,
    out_dir: Option<&Path>,
) -> stow_types::error::Result<()> {
    let Some(marker) = out_dir.and_then(|out_dir| marker_name(crate_name, extra_filename, out_dir))
    else {
        return Ok(());
    };
    let Some(dir) = session_dir.map(|session_dir| marker_dir(session_dir, target)) else {
        return Ok(());
    };
    async_fs::create_dir_all(&dir)
        .await
        .map_err(|error| stow_types::stow_error!("create {}: {error}", dir.display()))?;
    let marker = dir.join(marker);
    async_fs::write(&marker, [])
        .await
        .map_err(|error| stow_types::stow_error!("write {}: {error}", marker.display()))
}

/// The first `--extern` dependency of this invocation that the build
/// already compiled locally, if any.
///
/// Its presence means no cached artifact can serve this unit: rustc links
/// a crate to the exact copy of each dependency it was compiled against,
/// and a cached artifact was compiled against the CI copy, not the one
/// cargo is about to hand this invocation.
///
/// `None` when every dependency can still come from the cache, when the
/// unit has no dependencies, and when the build has no session directory
/// to consult.
pub fn locally_built_dependency(
    session_dir: Option<&Path>,
    target: &str,
    extern_crates: &[ParsedExternCrate],
) -> Option<String> {
    if extern_crates.is_empty() {
        return None;
    }
    let dir = marker_dir(session_dir?, target);
    locally_built_dependency_in(&dir, extern_crates)
}

fn locally_built_dependency_in(dir: &Path, extern_crates: &[ParsedExternCrate]) -> Option<String> {
    extern_crates
        .iter()
        .filter_map(|dependency| artifact_marker_name(&dependency.path))
        .find(|marker| dir.join(marker).exists())
}

/// The local-build marker name an `--extern` artifact path spells: the
/// output file's own stem, `<crate name><-C extra-filename>` — the same
/// name the producing unit records. The `--extern` alias is read nowhere:
/// it is the consumer's name for the dependency, and a rename would send
/// this check looking for a marker no artifact carries (stow#733).
///
/// The `lib` prefix is a fact of the extension, not a guess: rustc names
/// `.rlib`, `.rmeta`, `.so` and `.dylib` outputs `lib<crate><extra>` and
/// Windows `.dll` outputs `<crate><extra>`, so `liblibc-<hash>.rlib` and
/// `libc-<hash>.dll` resolve to the same marker `libc-<hash>` either way.
/// `None` for a file cargo may hand that nothing this build compiled can
/// have written: an extension no rustc unit output has, a name with no
/// `-<16 hex>` extra-filename tail, or no file name at all.
///
/// The unit hash comes from cargo's layout: the stem's own tail in the
/// shared `deps` directory, the unit directory in the build-unit layout,
/// where a dylib's file name carries none ([`UnitDir::unit_name`]).
fn artifact_marker_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    let (stem, extension) = file_name.rsplit_once('.')?;
    let stem = match extension {
        "rlib" | "rmeta" | "so" | "dylib" => stem.strip_prefix("lib")?,
        "dll" => stem,
        _ => return None,
    };
    UnitDir::new(path.parent()?).ok()?.unit_name(stem)
}

fn marker_dir(session_dir: &Path, target: &str) -> PathBuf {
    session_dir.join(LOCAL_BUILD_DIR).join(target)
}

/// The marker one locally compiled artifact carries: the crate name in
/// its rustc spelling (a dash is an underscore in `--crate-name` and in
/// the output file name, while a caller may still hold the crates.io
/// spelling) plus the unit hash of the outputs `out_dir` holds —
/// `<crate>-<hash>`, the name [`artifact_marker_name`] reads off a
/// consumer's `--extern`. `None` for outputs no consumer can name.
fn marker_name(crate_name: &str, extra_filename: &str, out_dir: &Path) -> Option<String> {
    UnitDir::new(out_dir).ok()?.unit_name(&format!(
        "{}{}",
        crate_name.replace('-', "_"),
        extra_filename
    ))
}

#[cfg(test)]
mod tests {
    use stow_types::rustc::ParsedExternCrate;

    use super::{artifact_marker_name, locally_built_dependency_in, marker_dir, marker_name};

    const TARGET: &str = "aarch64-apple-darwin";

    fn build_with_local(artifacts: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = marker_dir(temp.path(), TARGET);
        std::fs::create_dir_all(&dir).expect("create marker dir");
        for name in artifacts {
            std::fs::write(dir.join(name), []).expect("write marker");
        }
        (temp, dir)
    }

    fn extern_crate(alias: &str, path: &str) -> ParsedExternCrate {
        ParsedExternCrate {
            crate_name: alias.to_owned(),
            path: std::path::PathBuf::from(path),
        }
    }

    /// stow#733: the marker keys the artifact cargo hands the consumer,
    /// so a dependency renamed in `--extern` is still found — `pki_types`
    /// naming `librustls_pki_types-<hash>.rmeta` hits the
    /// `rustls_pki_types-<hash>` marker.
    #[test]
    fn a_renamed_dependency_still_finds_its_artifact_marker() {
        let (_temp, dir) = build_with_local(&["rustls_pki_types-0123456789abcdef"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[extern_crate(
                    "pki_types",
                    "deps/librustls_pki_types-0123456789abcdef.rmeta"
                )]
            ),
            Some("rustls_pki_types-0123456789abcdef".to_owned())
        );
    }

    /// stow#734: a marker names one unit's output, so an artifact with a
    /// different extra-filename — another feature set, another side, or a
    /// probe that borrowed the crate name — does not match it.
    #[test]
    fn a_differently_hashed_artifact_of_the_same_crate_does_not_match() {
        let (_temp, dir) = build_with_local(&["proc_macro2-0123456789abcdef"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[extern_crate(
                    "proc_macro2",
                    "deps/libproc_macro2-fedcba9876543210.rlib"
                )]
            ),
            None
        );
    }

    /// crates.io spells the crate with a hyphen and rustc with an
    /// underscore; the artifact's file name carries the rustc spelling, so
    /// the marker's crate part normalizes to it.
    #[test]
    fn the_crate_spelling_normalizes_to_the_file_names() {
        for out_dir in [
            "/t/debug/deps",
            "/t/debug/build/unicode-ident/0123456789abcdef/out",
        ] {
            assert_eq!(
                marker_name(
                    "unicode-ident",
                    "-0123456789abcdef",
                    std::path::Path::new(out_dir)
                )
                .as_deref(),
                Some("unicode_ident-0123456789abcdef"),
                "{out_dir}"
            );
        }
    }

    /// Cargo's build-unit layout leaves the hash off a dylib's file name:
    /// the unit directory names it, for the producer and the consumer
    /// alike, and two units of one crate stay apart.
    #[tokio::test]
    async fn a_build_unit_dylib_without_a_hashed_name_is_marked_by_its_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let unit = "/t/debug/build/dyn-dep/0123456789abcdef/out";
        super::record_local_build(
            Some(temp.path()),
            TARGET,
            "dyn_dep",
            "",
            Some(std::path::Path::new(unit)),
        )
        .await
        .expect("record");
        let dir = marker_dir(temp.path(), TARGET);
        for (path, found) in [
            (format!("{unit}/libdyn_dep.so"), true),
            (format!("{unit}/libdyn_dep.dylib"), true),
            (format!("{unit}/dyn_dep.dll"), true),
            (
                "/t/debug/build/dyn-dep/fedcba9876543210/out/libdyn_dep.so".to_owned(),
                false,
            ),
        ] {
            assert_eq!(
                locally_built_dependency_in(&dir, &[extern_crate("dyn_dep", &path)]),
                found.then(|| "dyn_dep-0123456789abcdef".to_owned()),
                "{path}"
            );
        }
    }

    /// A build-unit rlib carries the unit hash both in its name and in its
    /// directory; it is counted once.
    #[test]
    fn a_build_unit_rlib_names_its_unit_once() {
        let (_temp, dir) = build_with_local(&["serde-0123456789abcdef"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[extern_crate(
                    "serde",
                    "/t/debug/build/serde/0123456789abcdef/out/libserde-0123456789abcdef.rmeta"
                )]
            ),
            Some("serde-0123456789abcdef".to_owned())
        );
    }

    /// `libc`'s artifact is `liblibc-<hash>.rlib`: the `lib` prefix is
    /// rustc's, and stripping exactly it leaves the marker the `libc`
    /// unit recorded — no crate named `lib…` can lose its name.
    #[test]
    fn a_crate_named_lib_round_trips() {
        let (_temp, dir) = build_with_local(&["libc-fedcba9876543210"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[extern_crate("libc", "deps/liblibc-fedcba9876543210.rlib")]
            ),
            Some("libc-fedcba9876543210".to_owned())
        );
    }

    /// Every dynamic-library spelling a consumer can be handed resolves:
    /// unix proc-macros and dylibs carry the `lib` prefix, Windows `.dll`
    /// outputs carry none.
    #[test]
    fn dynamic_library_spellings_round_trip() {
        let (_temp, dir) = build_with_local(&["serde_derive-9c7162ae9201c5e4"]);
        for path in [
            "deps/libserde_derive-9c7162ae9201c5e4.so",
            "deps/libserde_derive-9c7162ae9201c5e4.dylib",
            "deps/serde_derive-9c7162ae9201c5e4.dll",
        ] {
            assert_eq!(
                locally_built_dependency_in(&dir, &[extern_crate("serde_derive", path)]),
                Some("serde_derive-9c7162ae9201c5e4".to_owned()),
                "{path} did not resolve to the recorded marker"
            );
        }
    }

    /// A `.dll`'s stem is not prefix-stripped: `libc-<hash>.dll` is the
    /// `libc` artifact, never one named `c`.
    #[test]
    fn a_windows_dll_keeps_a_lib_leading_name() {
        let (_temp, _dir) = build_with_local(&["libc-0123456789abcdef"]);
        assert_eq!(
            artifact_marker_name(&std::path::PathBuf::from("deps/libc-0123456789abcdef.dll")),
            Some("libc-0123456789abcdef".to_owned())
        );
    }

    /// An `--extern` whose path carries no `-<16 hex>` tail names nothing
    /// a cargo unit wrote this build, and is skipped.
    #[test]
    fn unhashed_extern_paths_are_skipped() {
        let (_temp, dir) = build_with_local(&["serde-0123456789abcdef"]);
        for path in ["", "deps/libserde.rlib", "deps/libserde-notahash.rlib"] {
            assert_eq!(
                locally_built_dependency_in(&dir, &[extern_crate("serde", path)]),
                None,
                "{path} should name no artifact this build compiled"
            );
        }
    }

    /// Dependencies nobody built locally leave the cache usable.
    #[test]
    fn untouched_dependencies_leave_the_cache_usable() {
        let (_temp, dir) = build_with_local(&["memchr-0123456789abcdef"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[
                    extern_crate(
                        "unicode_ident",
                        "deps/libunicode_ident-0123456789abcdef.rmeta"
                    ),
                    extern_crate("serde", "deps/libserde-0123456789abcdef.rlib")
                ]
            ),
            None
        );
    }

    /// One locally built dependency is enough to rule the cache out, even
    /// beside dependencies that are still cacheable.
    #[test]
    fn one_local_dependency_rules_out_the_cache() {
        let (_temp, dir) = build_with_local(&["unicode_ident-0123456789abcdef"]);
        assert_eq!(
            locally_built_dependency_in(
                &dir,
                &[
                    extern_crate("serde", "deps/libserde-fedcba9876543210.rlib"),
                    extern_crate(
                        "unicode_ident",
                        "deps/libunicode_ident-0123456789abcdef.rmeta"
                    )
                ]
            ),
            Some("unicode_ident-0123456789abcdef".to_owned())
        );
    }

    /// A leaf crate depends on nothing, so nothing can make it unusable.
    #[test]
    fn a_leaf_invocation_is_always_usable() {
        let (_temp, dir) = build_with_local(&["unicode_ident-0123456789abcdef"]);
        assert_eq!(locally_built_dependency_in(&dir, &[]), None);
    }

    /// A unit with no `-C extra-filename` writes no hashed output a
    /// consumer could name — a build-script probe under a real crate's
    /// `--crate-name` — so it records no marker (stow#734).
    #[tokio::test]
    async fn a_unit_without_extra_filename_records_nothing() {
        let temp = tempfile::tempdir().expect("temp dir");
        for out_dir in [
            // The shared layout's build-script run directory, and a
            // probe's own temporary directory outside cargo's layout.
            "/t/debug/build/proc-macro2-0123456789abcdef/out",
            "/tmp/probe",
        ] {
            super::record_local_build(
                Some(temp.path()),
                TARGET,
                "proc_macro2",
                "",
                Some(std::path::Path::new(out_dir)),
            )
            .await
            .expect("record");
        }
        assert!(
            !marker_dir(temp.path(), TARGET).exists(),
            "a probe-shaped unit left a marker behind"
        );
    }

    /// The recorded marker is the artifact file's own stem, which is what
    /// a later consumer's `--extern` path names.
    #[tokio::test]
    async fn a_recorded_marker_is_the_artifact_file_stem() {
        let temp = tempfile::tempdir().expect("temp dir");
        super::record_local_build(
            Some(temp.path()),
            TARGET,
            "rustls-pki-types",
            "-0123456789abcdef",
            Some(std::path::Path::new("/t/debug/deps")),
        )
        .await
        .expect("record");
        let dir = marker_dir(temp.path(), TARGET);
        assert!(
            dir.join("rustls_pki_types-0123456789abcdef").exists(),
            "the marker names the output file stem"
        );
    }
}
