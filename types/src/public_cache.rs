//! Derivation of the stable artifact identity a crates.io-registry build maps
//! to: the compile key, `c_metadata`, and `extra_filename` computed from a
//! captured rustc invocation.

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::platform::{Profile, StripLevel};
use crate::rustc::ParsedRustcArgs;
use crate::upload_plan::{CompileKeyInputs, compute_compile_key};

/// The cache identity a registry-crate rustc invocation resolves to under
/// stow's stable-identity rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableRegistryArtifactIdentity {
    /// BLAKE3 hash of the full rustc invocation identity.
    pub compile_key: String,
    /// 16-hex-char prefix of `compile_key`, used as `-C metadata`.
    pub c_metadata: String,
    /// `-C extra-filename` matching `c_metadata` (`-{c_metadata}`).
    pub extra_filename: String,
    /// crates.io package name as it appears in the registry path (hyphenated
    /// form).
    pub crate_name: String,
    /// Crate version detected from the registry source path.
    pub version: String,
}

/// Fold a crates.io package name into rustc `--crate-name` form (`-` → `_`).
#[must_use]
pub fn canonical_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Detect `(crate_name, version)` for an invocation whose input file lives
/// under a cargo registry `src/` directory (`<name>-<version>/src/lib.rs`).
///
/// Walks the input path's ancestors and returns the first component of the
/// form `<name>-<semver>` whose name canonicalizes to `parsed.crate_name`.
/// Returns `Ok(None)` for non-registry builds (path or git deps), which the
/// public cache does not serve.
///
/// # Errors
/// Never fails today; the `Result` shape lets callers `?` it uniformly
/// alongside the fallible identity steps.
pub fn detect_registry_crate_version(
    parsed: &ParsedRustcArgs,
) -> crate::error::Result<Option<(String, String)>> {
    let Some(input_path) = parsed.input_path.as_ref() else {
        return Ok(None);
    };
    let crate_name = canonical_crate_name(&parsed.crate_name);
    for ancestor in input_path.ancestors() {
        let Some(component) = ancestor.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if let Some((package_name, version)) =
            split_registry_package_component(component, &crate_name)
        {
            return Ok(Some((package_name, version)));
        }
    }
    Ok(None)
}

/// Compute the stable cache identity for one captured rustc invocation.
///
/// Returns `Ok(None)` when the invocation does not compile a registry crate
/// (see [`detect_registry_crate_version`]). Otherwise derives the compile key
/// over the normalized profile, emit set, and dependency identities, then the
/// stable `c_metadata` / `extra_filename` from that key.
///
/// # Errors
/// Returns an error when the captured crate types or profile values are
/// outside stow's known set, or when the compile-key inputs fail to
/// serialize.
pub fn stable_registry_artifact_identity(
    parsed: &ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<Option<StableRegistryArtifactIdentity>> {
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    stable_registry_artifact_identity_for_package(
        parsed,
        &crate_name,
        &version,
        target,
        rustc_version,
        features_json,
        dependency_c_metadata_json,
    )
    .map(Some)
}

/// Compute the stable cache identity for one captured rustc invocation under
/// an explicitly supplied registry package identity.
///
/// Used by the trusted-build capture path, where the task package is mirrored
/// to a content-addressed directory and cargo hands rustc a relative
/// `src/lib.rs` — there is no `<name>-<version>` path component for
/// [`detect_registry_crate_version`] to find, so the dispatcher supplies the
/// identity it staged.
///
/// # Errors
/// Returns an error when the captured crate types or profile values are
/// outside stow's known set, or when the compile-key inputs fail to
/// serialize.
pub fn stable_registry_artifact_identity_for_package(
    parsed: &ParsedRustcArgs,
    crate_name: &str,
    version: &str,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<StableRegistryArtifactIdentity> {
    let crate_name = crate_name.to_owned();
    let version = version.to_owned();
    let profile = normalized_cache_profile(parsed)?;
    let kind = parsed_artifact_kind(parsed)?;
    let crate_types = parsed_crate_types(parsed)?;
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
    let cfgs = parsed.cfgs.iter().cloned().collect::<Vec<_>>();
    // Empty unless this unit actually links, which keeps every rlib's key
    // exactly what it was before the linker was part of identity.
    let link_options = parsed.link_options_reaching_the_linker();
    let compile_key = compute_compile_key(&CompileKeyInputs {
        crate_name: &crate_name,
        crate_version: &version,
        target,
        rustc_version,
        profile: &profile,
        crate_types: &crate_types,
        emit: &emit,
        features_json,
        dependency_c_metadata_json,
        kind: &kind,
        embed_metadata: parsed.embed_metadata,
        cfgs: &cfgs,
        embed_bitcode: parsed.embed_bitcode,
        link_options: &link_options,
    })?;
    let c_metadata = stable_c_metadata_for_compile_key(&compile_key)?;
    Ok(StableRegistryArtifactIdentity {
        compile_key,
        extra_filename: format!("-{c_metadata}"),
        c_metadata,
        crate_name,
        version,
    })
}

/// Derive the stable `c_metadata` (first 16 hex chars) from a compile key.
///
/// # Errors
/// Returns an error when `compile_key` is shorter than 16 chars or contains
/// non-hex characters.
pub fn stable_c_metadata_for_compile_key(compile_key: &str) -> crate::error::Result<String> {
    const STABLE_METADATA_HEX_LEN: usize = 16;
    if compile_key.len() < STABLE_METADATA_HEX_LEN
        || !compile_key.chars().all(|value| value.is_ascii_hexdigit())
    {
        return Err(crate::stow_error!(
            "compile key `{compile_key}` is not valid hex for stable c_metadata"
        ));
    }
    Ok(compile_key[..STABLE_METADATA_HEX_LEN].to_owned())
}

fn split_registry_package_component(
    component: &str,
    expected_crate_name: &str,
) -> Option<(String, String)> {
    for (index, _) in component.match_indices('-').rev() {
        let crate_name = &component[..index];
        let version = &component[index + 1..];
        if canonical_crate_name(crate_name) != expected_crate_name {
            continue;
        }
        if semver::Version::parse(version).is_err() {
            continue;
        }
        return Some((crate_name.to_owned(), version.to_owned()));
    }
    None
}

/// Normalize a captured invocation's profile for cache identity.
///
/// When the invocation sets no explicit `-C debuginfo`, or does not emit
/// `link` (a metadata-only pass whose debuginfo never reaches an artifact),
/// the level is pinned to 1 so per-phase differences do not split the cache
/// identity. `-C strip` is pinned to `none` unless a crate type is linked,
/// because cargo passes `strip=debuginfo` to every dependency of a profile
/// with `debug = false` and the flag is a no-op for rlibs.
///
/// # Errors
/// Returns an error when the captured `-C debuginfo` or `-C panic` values
/// cannot be parsed.
pub fn normalized_cache_profile(parsed: &ParsedRustcArgs) -> crate::error::Result<Profile> {
    let mut profile = parsed.profile().map_err(crate::error::Error::msg)?;
    if parsed.debuginfo.is_none() || !parsed.emit.iter().any(|entry| entry == "link") {
        profile.debuginfo = 1;
    }
    if !produces_linked_artifact(parsed) {
        profile.strip = StripLevel::None;
    }
    Ok(profile)
}

/// The unit shape a published artifact row carries, from its emit set and
/// normalized `-C debuginfo`.
///
/// Cargo compiles the same crate at different shapes depending on how a
/// consumer's invocation reaches it: a `--target` build passes `-C
/// debuginfo` to every unit (target deps and host units alike), while a
/// native build leaves host units without the flag — the build-override
/// profile — which normalizes to `debuginfo = 1` here
/// ([`normalized_cache_profile`]). A check-only unit emits no `link`.
/// Those two axes are the whole shape space a dependency edge or a
/// coverage check needs: an artifact serving a shape carries its emit
/// and debuginfo, and serving "the crate" means serving every shape the
/// consumer's invocations produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactUnitShape {
    /// `emit` carries `link` and normalized `debuginfo` is 1 — the shape
    /// a native build compiles host units (and anything else without an
    /// explicit `-C debuginfo`) at.
    LinkedDebuginfo1,
    /// `emit` carries `link` and normalized `debuginfo` is 2 — the shape
    /// a `--target` build compiles target deps and host units at.
    LinkedDebuginfo2,
    /// `emit` carries no `link` — the check/metadata unit a `cargo check`
    /// pass compiles target-side units at. Host units keep `link` in
    /// their emit set even under `cargo check`, so they never land here.
    Unlinked,
}

/// Classify one artifact row — from its `--emit` modes and normalized
/// `profile.debuginfo` — into its [`ArtifactUnitShape`].
///
/// `debuginfo` is the *normalized* value a row carries (the profile the
/// record registered). `None`/`Some` below 1 or above 2 classify by the
/// same rule a normalized profile would produce, so a malformed row
/// lands in the class its emit set already implies.
#[must_use]
pub fn artifact_unit_shape(emit: &[String], debuginfo: u32) -> ArtifactUnitShape {
    if !emit.iter().any(|entry| entry == "link") {
        return ArtifactUnitShape::Unlinked;
    }
    if debuginfo == 1 {
        return ArtifactUnitShape::LinkedDebuginfo1;
    }
    ArtifactUnitShape::LinkedDebuginfo2
}

/// The shapes a node's published artifact set must cover — what the
/// servable gate and the coverage checks require before a dependent may
/// consume the node. A target-side node serves the shapes a consumer's
/// `--target` build and `cargo check` produce; a host-side node serves
/// both host-unit shapes — the native one and the `--target` one — so
/// consumers on either invocation shape find their units.
#[must_use]
pub fn required_unit_shapes(host_side: bool) -> &'static [ArtifactUnitShape] {
    if host_side {
        &[
            ArtifactUnitShape::LinkedDebuginfo1,
            ArtifactUnitShape::LinkedDebuginfo2,
        ]
    } else {
        &[
            ArtifactUnitShape::LinkedDebuginfo2,
            ArtifactUnitShape::Unlinked,
        ]
    }
}

/// Whether any of the invocation's crate types goes through the linker.
/// `-C strip` acts at link time only, so it cannot change the bytes of an
/// rlib, rmeta or staticlib and is pinned out of their identity.
fn produces_linked_artifact(parsed: &ParsedRustcArgs) -> bool {
    parsed.crate_types.iter().any(|crate_type| {
        matches!(
            crate_type.as_str(),
            "dylib" | "cdylib" | "proc-macro" | "bin"
        )
    })
}

fn parsed_artifact_kind(parsed: &ParsedRustcArgs) -> crate::error::Result<ArtifactKind> {
    let crate_types = parsed_crate_types(parsed)?;
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::ProcMacro))
    {
        return Ok(ArtifactKind::ProcMacro);
    }
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::Dylib))
    {
        return Ok(ArtifactKind::Dylib);
    }
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::Lib | RustCrateType::Rlib))
    {
        return Ok(ArtifactKind::Rlib);
    }
    Err(crate::stow_error!(
        "unsupported artifact kind for crate types {:?}",
        parsed.crate_types
    ))
}

fn parsed_crate_types(parsed: &ParsedRustcArgs) -> crate::error::Result<Vec<RustCrateType>> {
    parsed
        .crate_types
        .iter()
        .map(|crate_type| match crate_type.as_str() {
            "lib" => Ok(RustCrateType::Lib),
            "rlib" => Ok(RustCrateType::Rlib),
            "dylib" => Ok(RustCrateType::Dylib),
            "cdylib" => Ok(RustCrateType::Cdylib),
            "staticlib" => Ok(RustCrateType::Staticlib),
            "proc-macro" => Ok(RustCrateType::ProcMacro),
            other => Err(crate::stow_error!("unsupported crate type `{other}`")),
        })
        .collect()
}

#[cfg(test)]
mod tests {

    /// The compile key of a unit that never links must not have moved when
    /// link options became part of identity, or every rlib in the catalogue
    /// would need rebuilding. The literal is the key the implementation
    /// produced before the link-options block existed: an empty option list
    /// appends no bytes, so the two byte streams are identical.
    #[test]
    fn an_rlib_keeps_the_compile_key_it_had_before_link_options_were_modeled() {
        let profile = crate::platform::Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: crate::platform::PanicStrategy::Unwind,
            strip: crate::platform::StripLevel::None,
        };
        let key = crate::upload_plan::compute_compile_key(&crate::upload_plan::CompileKeyInputs {
            crate_name: "serde",
            crate_version: "1.0.210",
            target: "x86_64-unknown-linux-gnu",
            rustc_version: "1.98.1",
            profile: &profile,
            crate_types: &[crate::artifact::RustCrateType::Rlib],
            emit: &["link".to_owned(), "metadata".to_owned()],
            features_json: r#"["default","derive"]"#,
            dependency_c_metadata_json: "[]",
            kind: &crate::artifact::ArtifactKind::Rlib,
            embed_metadata: None,
            cfgs: &[],
            embed_bitcode: true,
            link_options: &[],
        })
        .expect("compile key");
        assert_eq!(
            key, "8fe0277663e1a96615932452126980caa87205a3a41a6224c0ebe3194e8371e8",
            "an rlib's identity moved, which would invalidate every rlib in the catalogue"
        );
    }

    /// Two units that differ only in how they were linked are different
    /// artifacts, so they must take different keys — that is the whole
    /// reason the cache can hold both instead of refusing both.
    #[test]
    fn a_link_option_changes_the_key_of_a_unit_that_links() {
        let profile = crate::platform::Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: crate::platform::PanicStrategy::Unwind,
            strip: crate::platform::StripLevel::None,
        };
        let emit = ["link".to_owned()];
        let crate_types = [crate::artifact::RustCrateType::ProcMacro];
        let kind = crate::artifact::ArtifactKind::ProcMacro;
        let mold = ["link-arg=-fuse-ld=mold".to_owned()];
        let key_for = |link_options: &[String]| {
            crate::upload_plan::compute_compile_key(&crate::upload_plan::CompileKeyInputs {
                crate_name: "serde_derive",
                crate_version: "1.0.210",
                target: "x86_64-unknown-linux-gnu",
                rustc_version: "1.98.1",
                profile: &profile,
                crate_types: &crate_types,
                emit: &emit,
                features_json: "[]",
                dependency_c_metadata_json: "[]",
                kind: &kind,
                embed_metadata: None,
                cfgs: &[],
                embed_bitcode: true,
                link_options,
            })
            .expect("compile key")
        };
        let default_linker = key_for(&[]);
        let with_mold = key_for(&mold);
        assert_ne!(
            default_linker, with_mold,
            "a mold-linked proc-macro shares a key with an lld-linked one"
        );
    }

    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use super::{
        ArtifactUnitShape, artifact_unit_shape, normalized_cache_profile, required_unit_shapes,
        stable_registry_artifact_identity,
    };
    use crate::rustc::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn cache_profile_defaults_missing_debuginfo_to_line_tables() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let profile = normalized_cache_profile(&parsed).expect("normalize cache profile");

        assert_eq!(profile.debuginfo, 1);
    }

    #[test]
    fn cache_profile_preserves_explicit_debuginfo_zero() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "debuginfo=0",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let profile = normalized_cache_profile(&parsed).expect("normalize cache profile");

        assert_eq!(profile.debuginfo, 0);
    }

    #[test]
    fn unicode_ident_host_invocation_maps_to_ci_stable_identity() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "-C",
            "embed-bitcode=no",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let identity = stable_registry_artifact_identity(
            &parsed,
            "aarch64-apple-darwin",
            "1.91.1",
            "[]",
            "[]",
        )
        .expect("compute stable registry identity")
        .expect("registry crate identity");

        assert_eq!(identity.c_metadata, "0e63365407e7f07c");
    }

    #[test]
    fn nightly_embed_metadata_flag_changes_the_compile_key() {
        let base_invocation = [
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "-C",
            "embed-bitcode=no",
            "--out-dir",
            "/tmp/out",
        ];
        let baseline = ParsedRustcArgs::parse(&args(&base_invocation))
            .expect("parse unicode-ident rustc args");

        let mut flagged_invocation = base_invocation.to_vec();
        flagged_invocation.extend(["-Z", "embed-metadata=no"]);
        let flagged = ParsedRustcArgs::parse(&args(&flagged_invocation))
            .expect("parse flagged unicode-ident rustc args");
        assert!(!flagged.has_custom_codegen);

        let baseline_identity = stable_registry_artifact_identity(
            &baseline,
            "aarch64-apple-darwin",
            "1.91.1",
            "[]",
            "[]",
        )
        .expect("compute baseline identity")
        .expect("registry crate identity");
        let flagged_identity = stable_registry_artifact_identity(
            &flagged,
            "aarch64-apple-darwin",
            "1.91.1",
            "[]",
            "[]",
        )
        .expect("compute flagged identity")
        .expect("registry crate identity");

        // The flag changes the produced rlib, so it must change the key; an
        // invocation without it keeps the pre-existing key the CI identity
        // test vector above locks in.
        assert_ne!(flagged_identity.compile_key, baseline_identity.compile_key);
        assert_eq!(baseline_identity.c_metadata, "0e63365407e7f07c");
    }

    #[test]
    fn build_script_cfgs_change_the_compile_key() {
        let base_invocation = [
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "-C",
            "embed-bitcode=no",
            "--out-dir",
            "/tmp/out",
        ];
        let baseline = ParsedRustcArgs::parse(&args(&base_invocation)).expect("parse baseline");

        let mut probed_invocation = base_invocation.to_vec();
        probed_invocation.extend(["--cfg", "has_atomics", "--cfg", "feature=\"std\""]);
        let probed = ParsedRustcArgs::parse(&args(&probed_invocation)).expect("parse probed");
        assert_eq!(probed.cfgs, BTreeSet::from(["has_atomics".to_owned()]));
        assert_eq!(probed.features, BTreeSet::from(["std".to_owned()]));

        let identity = |parsed: &ParsedRustcArgs| {
            stable_registry_artifact_identity(parsed, "aarch64-apple-darwin", "1.91.1", "[]", "[]")
                .expect("compute identity")
                .expect("registry crate identity")
        };
        // The cfg selects code in the compiled crate, so the artifact built
        // under CI's probe result must not serve a unit whose local build
        // script probed differently; an invocation without cfgs keeps the
        // pre-existing key the CI identity test vector locks in.
        assert_ne!(
            identity(&probed).compile_key,
            identity(&baseline).compile_key
        );
        assert_eq!(identity(&baseline).c_metadata, "0e63365407e7f07c");

        let mut ordered_invocation = base_invocation.to_vec();
        ordered_invocation.extend(["--cfg", "b", "--cfg", "a"]);
        let mut reordered_invocation = base_invocation.to_vec();
        reordered_invocation.extend(["--cfg", "a", "--cfg", "b"]);
        assert_eq!(
            identity(&ParsedRustcArgs::parse(&args(&ordered_invocation)).expect("parse"))
                .compile_key,
            identity(&ParsedRustcArgs::parse(&args(&reordered_invocation)).expect("parse"))
                .compile_key,
        );
    }

    #[test]
    fn embedded_bitcode_changes_the_compile_key() {
        let base_invocation = [
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ];
        let identity = |extra: &[&str]| {
            let mut invocation = base_invocation.to_vec();
            invocation.extend_from_slice(extra);
            let parsed = ParsedRustcArgs::parse(&args(&invocation)).expect("parse invocation");
            assert!(!parsed.has_custom_codegen);
            (
                parsed.embed_bitcode,
                stable_registry_artifact_identity(
                    &parsed,
                    "aarch64-apple-darwin",
                    "1.91.1",
                    "[]",
                    "[]",
                )
                .expect("compute identity")
                .expect("registry crate identity"),
            )
        };
        let (absent_bitcode, absent) = identity(&[]);
        let (yes_bitcode, yes) = identity(&["-C", "embed-bitcode=yes"]);
        let (no_bitcode, no) = identity(&["-C", "embed-bitcode=no"]);
        // rustc embeds bitcode unless told not to, so an invocation without
        // the flag is the `yes` artifact, never the `no` one cargo emits.
        assert!(absent_bitcode);
        assert!(yes_bitcode);
        assert!(!no_bitcode);
        assert_eq!(absent.compile_key, yes.compile_key);
        assert_ne!(no.compile_key, yes.compile_key);
        assert_eq!(no.c_metadata, "0e63365407e7f07c");
    }

    #[test]
    fn strip_is_pinned_out_of_unlinked_identities() {
        let rlib = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=abc123",
            "-C",
            "strip=debuginfo",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse rlib args");
        assert_eq!(
            normalized_cache_profile(&rlib).expect("profile").strip,
            crate::platform::StripLevel::None
        );

        let proc_macro = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde_derive",
            "--crate-type",
            "proc-macro",
            "--emit",
            "dep-info,link",
            "-C",
            "metadata=abc123",
            "-C",
            "strip=debuginfo",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse proc-macro args");
        assert_eq!(
            normalized_cache_profile(&proc_macro)
                .expect("profile")
                .strip,
            crate::platform::StripLevel::Debuginfo
        );
    }

    #[test]
    fn canonical_profile_json_omits_strip_none() {
        let profile = crate::platform::Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: crate::platform::PanicStrategy::Unwind,
            strip: crate::platform::StripLevel::None,
        };
        let json = serde_json::to_string(&profile).expect("serialize");
        assert!(!json.contains("strip"), "{json}");
        let parsed: crate::platform::Profile = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, profile);
        let stripped = crate::platform::Profile {
            strip: crate::platform::StripLevel::Debuginfo,
            ..profile
        };
        assert!(
            serde_json::to_string(&stripped)
                .expect("serialize")
                .contains("\"strip\":\"debuginfo\"")
        );
    }

    fn emit(modes: &[&str]) -> Vec<String> {
        modes.iter().map(|mode| (*mode).to_owned()).collect()
    }

    #[test]
    fn unit_shape_separates_linked_debuginfo_from_unlinked() {
        // A `--target` build: target deps and host units both carry `-C
        // debuginfo` — LinkedDebuginfo2.
        assert_eq!(
            artifact_unit_shape(&emit(&["dep-info", "metadata", "link"]), 2),
            ArtifactUnitShape::LinkedDebuginfo2
        );
        // A native build's host unit: no `-C debuginfo` flag, normalized
        // to 1 — LinkedDebuginfo1.
        assert_eq!(
            artifact_unit_shape(&emit(&["dep-info", "metadata", "link"]), 1),
            ArtifactUnitShape::LinkedDebuginfo1
        );
        // A check unit: no `link` at any debuginfo level — Unlinked.
        assert_eq!(
            artifact_unit_shape(&emit(&["dep-info", "metadata"]), 1),
            ArtifactUnitShape::Unlinked
        );
        assert_eq!(
            artifact_unit_shape(&emit(&["dep-info", "metadata"]), 2),
            ArtifactUnitShape::Unlinked
        );
        // Degenerate debuginfo values classify by the linked/not rule.
        assert_eq!(
            artifact_unit_shape(&emit(&["link"]), 0),
            ArtifactUnitShape::LinkedDebuginfo2
        );
    }

    #[test]
    fn required_shapes_cover_both_sides_of_the_unit_graph() {
        // A host-side node serves consumers on both invocation
        // spellings: native (LinkedDebuginfo1) and `--target`
        // (LinkedDebuginfo2).
        assert_eq!(
            required_unit_shapes(true),
            &[
                ArtifactUnitShape::LinkedDebuginfo1,
                ArtifactUnitShape::LinkedDebuginfo2,
            ]
        );
        // A target-side node serves the build shape and the check shape.
        assert_eq!(
            required_unit_shapes(false),
            &[
                ArtifactUnitShape::LinkedDebuginfo2,
                ArtifactUnitShape::Unlinked,
            ]
        );
    }
}
