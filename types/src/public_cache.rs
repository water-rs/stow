//! Derivation of the stable artifact identity a crates.io-registry build maps
//! to: the compile key, `c_metadata`, and `extra_filename` computed from a
//! captured rustc invocation.

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::platform::{Profile, StripLevel};
use crate::rustc::ParsedRustcArgs;
use crate::upload_plan::{CompileKeyInputs, compute_compile_key};

/// Where a cached unit's immutable source of truth lives.
///
/// Every keyed source pins content identity without content hashing:
/// crates.io's `(package, version)` pair and a git checkout's `(commit,
/// manifest path inside the repository)` pair each name exactly one
/// source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitSource {
    /// A crates.io package.
    CratesIo {
        /// Package name as it appears in the registry path (hyphenated
        /// form).
        package: String,
        /// Package version parsed from the registry path.
        version: String,
    },
    /// A remote git checkout under cargo's `git/checkouts/` root. The
    /// repository URL is not part of the identity: the commit already
    /// fixes the tree.
    Git {
        /// The full commit id the checkout is reset to.
        commit: String,
        /// The manifest directory's path inside the repository (`""` for
        /// the repository root).
        manifest_path_in_repo: String,
    },
}

/// How far a unit's identity may travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// The identity may be looked up against the remote cache and
    /// reported as a miss.
    Public,
    /// The identity is machine-local: never looked up remotely, never
    /// journaled as a miss, never reported. A git unit, a crates.io unit
    /// with extra codegen, and any unit compiled against a `LocalOnly`
    /// dependency is local-only.
    LocalOnly,
}

impl Reach {
    /// The storage integer of one reach value.
    #[must_use]
    pub const fn to_int(self) -> i64 {
        match self {
            Self::Public => 0,
            Self::LocalOnly => 1,
        }
    }

    /// Decode one stored integer back into a reach; `None` on any value
    /// the table cannot carry.
    #[must_use]
    pub const fn from_int(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Public),
            1 => Some(Self::LocalOnly),
            _ => None,
        }
    }

    /// The tighter of two reaches — a unit is `LocalOnly` when any input
    /// it depends on is.
    #[must_use]
    pub const fn fold(self, other: Self) -> Self {
        match (self, other) {
            (Self::Public, Self::Public) => Self::Public,
            _ => Self::LocalOnly,
        }
    }
}

/// The cache identity a rustc invocation resolves to under stow's
/// stable-identity rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableUnitIdentity {
    /// BLAKE3 hash of the full rustc invocation identity.
    pub compile_key: String,
    /// 16-hex-char prefix of `compile_key`, used as `-C metadata`.
    pub c_metadata: String,
    /// `-C extra-filename` matching `c_metadata` (`-{c_metadata}`).
    pub extra_filename: String,
    /// The package name for a crates.io unit; the rustc crate name for a
    /// git unit.
    pub crate_name: String,
    /// Crate version for a crates.io unit; `""` for a git unit, which no
    /// crates.io version can be.
    pub version: String,
    /// The immutable source the identity keys under.
    pub source: UnitSource,
    /// How far the identity may travel.
    pub reach: Reach,
}

/// Fold a crates.io package name into rustc `--crate-name` form (`-` → `_`).
#[must_use]
pub fn canonical_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// A registry package slot found on an invocation's input path: the
/// `<package>-<version>` directory under `…/registry/src/<index>/`,
/// decomposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPackageSlot {
    /// Package name as it appears in the registry path (hyphenated
    /// form).
    pub package: String,
    /// Package version parsed from the directory name.
    pub version: String,
    /// The `<index>` directory name (`index.crates.io-<hash>`,
    /// `<host>-<hash>`) the slot sits under.
    pub index_dir: String,
}

/// Detect the registry slot an invocation's input file lives under
/// (`<name>-<version>/src/lib.rs` below `…/registry/src/<index>/`).
///
/// The identity comes from the directory at the canonical registry slot
/// `…/registry/src/<index>/<package>-<version>` — both sides see that
/// shape: the CLI wrapper under `$CARGO_HOME`, and the CI capture inside
/// the sandbox where `CARGO_HOME` points at the granted registry. The
/// directory name there is the package name, which the crate name need
/// not equal, so the parse never filters on it. Returns `Ok(None)` for
/// non-registry builds (path or git deps), which the public cache does
/// not serve — a `<name>-<semver>` directory anywhere else in the path
/// is a worktree or vendored copy, not an identity.
///
/// # Errors
/// Never fails today; the `Result` shape lets callers `?` it uniformly
/// alongside the fallible identity steps.
pub fn detect_registry_package_slot(
    parsed: &ParsedRustcArgs,
) -> crate::error::Result<Option<RegistryPackageSlot>> {
    let Some(input_path) = parsed.input_path.as_ref() else {
        return Ok(None);
    };
    for ancestor in input_path.ancestors() {
        if !is_registry_package_slot(ancestor) {
            continue;
        }
        let Some(component) = ancestor.file_name().and_then(|value| value.to_str()) else {
            return Ok(None);
        };
        let Some((package, version)) = split_package_version_component(component) else {
            return Ok(None);
        };
        let Some(index_dir) = ancestor
            .parent()
            .and_then(|index| index.file_name())
            .and_then(|name| name.to_str())
        else {
            return Ok(None);
        };
        return Ok(Some(RegistryPackageSlot {
            package,
            version,
            index_dir: index_dir.to_owned(),
        }));
    }
    Ok(None)
}

/// Detect `(crate_name, version)` for an invocation whose input file lives
/// under a cargo registry `src/` directory — see
/// [`detect_registry_package_slot`].
///
/// # Errors
/// Never fails today; the `Result` shape lets callers `?` it uniformly
/// alongside the fallible identity steps.
pub fn detect_registry_crate_version(
    parsed: &ParsedRustcArgs,
) -> crate::error::Result<Option<(String, String)>> {
    Ok(detect_registry_package_slot(parsed)?.map(|slot| (slot.package, slot.version)))
}

/// The remote git checkout an invocation's input path sits under.
///
/// Finds the checkout root at `<…>/git/checkouts/<ident>/<short id>` and
/// reads the `<short id>` directory name — a prefix of the commit the
/// checkout must resolve to. `None` when no ancestor sits at cargo's
/// checkout slot. Pure path math: the manifest directory's path inside
/// the repository comes from the invocation's `CARGO_MANIFEST_DIR`,
/// which cargo sets on every rustc call.
#[must_use]
pub fn detect_git_checkout(parsed: &ParsedRustcArgs) -> Option<GitCheckout> {
    let input_path = parsed.input_path.as_ref()?;
    for checkout_root in input_path.ancestors() {
        let is_checkout_slot = checkout_root
            .parent()
            .and_then(|ident| ident.parent())
            .is_some_and(|checkouts| {
                checkouts.file_name() == Some(std::ffi::OsStr::new("checkouts"))
            })
            && checkout_root
                .parent()
                .and_then(|ident| ident.parent())
                .and_then(|checkouts| checkouts.parent())
                .is_some_and(|git| git.file_name() == Some(std::ffi::OsStr::new("git")));
        if !is_checkout_slot {
            continue;
        }
        let short_id = checkout_root.file_name()?.to_str()?.to_owned();
        return Some(GitCheckout {
            root: checkout_root.to_path_buf(),
            short_id,
        });
    }
    None
}

/// A cargo git checkout slot found on an invocation's input path.
#[derive(Debug, Clone)]
pub struct GitCheckout {
    /// `<…>/git/checkouts/<ident>/<short id>` — the checkout root.
    pub root: std::path::PathBuf,
    /// The `<short id>` directory name — a prefix of the commit the
    /// checkout resolves to.
    pub short_id: String,
}

/// Compute the stable cache identity for one captured rustc invocation
/// under its detected source.
///
/// # Errors
/// Returns an error when the captured crate types or profile values are
/// outside stow's known set, or when the compile-key inputs fail to
/// serialize.
pub fn stable_unit_identity(
    parsed: &ParsedRustcArgs,
    source: &UnitSource,
    reach: Reach,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<StableUnitIdentity> {
    stable_unit_identity_for_source(
        parsed,
        source,
        reach,
        target,
        rustc_version,
        features_json,
        dependency_c_metadata_json,
    )
}

/// Compute the stable cache identity for one captured rustc invocation under
/// an explicitly supplied crates.io package identity.
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
pub fn stable_unit_identity_for_package(
    parsed: &ParsedRustcArgs,
    crate_name: &str,
    version: &str,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<StableUnitIdentity> {
    let source = UnitSource::CratesIo {
        package: crate_name.to_owned(),
        version: version.to_owned(),
    };
    stable_unit_identity_for_source(
        parsed,
        &source,
        Reach::Public,
        target,
        rustc_version,
        features_json,
        dependency_c_metadata_json,
    )
}

fn stable_unit_identity_for_source(
    parsed: &ParsedRustcArgs,
    source: &UnitSource,
    reach: Reach,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<StableUnitIdentity> {
    let (crate_name, version, git_source) = match source {
        UnitSource::CratesIo { package, version } => (package.clone(), version.clone(), None),
        UnitSource::Git {
            commit,
            manifest_path_in_repo,
        } => (
            parsed.crate_name.clone(),
            String::new(),
            Some(crate::upload_plan::GitSourceInputs {
                commit: commit.as_str(),
                manifest_path_in_repo: manifest_path_in_repo.as_str(),
            }),
        ),
    };
    let extra_codegen = parsed.extra_codegen.clone();
    let cfgs = parsed.cfgs.iter().cloned().collect::<Vec<_>>();
    // Empty unless this unit actually links, which keeps every rlib's key
    // exactly what it was before the linker was part of identity.
    let link_options = parsed.link_options_reaching_the_linker();
    let profile = normalized_cache_profile(parsed)?;
    let kind = parsed_artifact_kind(parsed)?;
    let crate_types = parsed_crate_types(parsed)?;
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
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
        git_source,
        extra_codegen: &extra_codegen,
    })?;
    let c_metadata = stable_c_metadata_for_compile_key(&compile_key)?;
    Ok(StableUnitIdentity {
        compile_key,
        extra_filename: format!("-{c_metadata}"),
        c_metadata,
        crate_name,
        version,
        source: source.clone(),
        reach,
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

/// Split a `<name>-<version>` directory component on the first `-` that
/// leaves a valid semver on the right. A package name never contains a
/// `.`, so no shorter prefix can end in a semver — while a version's
/// prerelease or build metadata may carry hyphens of its own
/// (`1.1.2+spec-1.1.0`), and splitting on a later one would cut the
/// version in half. Registry package dirs carry the *package* name,
/// which differs from the lib crate name whenever the package renames
/// its lib.
fn split_package_version_component(component: &str) -> Option<(String, String)> {
    for (index, _) in component.match_indices('-') {
        let crate_name = &component[..index];
        let version = &component[index + 1..];
        if semver::Version::parse(version).is_err() {
            continue;
        }
        return Some((crate_name.to_owned(), version.to_owned()));
    }
    None
}

/// Whether `dir` sits at `…/registry/src/<index>/<pkg>` — the only layout
/// cargo places extracted registry sources in. Anchoring the fallback to
/// this slot keeps an unrelated `<name>-<version>` directory elsewhere in
/// a path (a vendored copy, a checkout dir) from being read as identity.
fn is_registry_package_slot(dir: &std::path::Path) -> bool {
    let Some(src) = dir.parent().and_then(|index| index.parent()) else {
        return false;
    };
    if src.file_name() != Some(std::ffi::OsStr::new("src")) {
        return false;
    }
    let Some(registry) = src.parent() else {
        return false;
    };
    registry.file_name() == Some(std::ffi::OsStr::new("registry"))
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

/// Which side of the host/target boundary a compiled unit serves.
///
/// A proc-macro, build-dependency or build-script unit compiles for the
/// build host; everything else for the consumer's target. The builder
/// knows the side by construction — a host-side task declares the crate
/// as the wrapper's `[build-dependencies]`, never a normal dependency —
/// so the field is recorded verbatim, never inferred from profile
/// values.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum UnitSide {
    /// A unit a consumer's build compiles for its `--target` platform
    /// (or for the host in a plain native build).
    Target,
    /// A unit cargo compiles for the build host — proc macros, build
    /// dependencies, and the units build scripts depend on.
    Host,
}

impl UnitSide {
    /// The storage integer of one side value.
    #[must_use]
    pub const fn to_int(self) -> i64 {
        match self {
            Self::Target => 0,
            Self::Host => 1,
        }
    }

    /// Decode one stored integer back into a side; `None` on any value
    /// the table cannot carry (a `-1` is corruption, not a row shape).
    #[must_use]
    pub const fn from_int(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Target),
            1 => Some(Self::Host),
            _ => None,
        }
    }
}

/// The cargo invocation spelling a unit was produced under.
///
/// Cargo applies the build-override profile differently at the
/// invocation boundary: a `--target` build hands host units the same
/// debuginfo flags as target units, while a native (no `--target`)
/// build leaves them unpinned — the two spellings compile one host
/// unit to different compile keys, so serving a host dep means serving
/// the shape the consumer's own invocation produces.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum UnitInvocation {
    /// A plain `cargo build`/`check` — no `--target` on the command
    /// line, the spelling a native consumer runs.
    Native,
    /// A `cargo build --target <triple>` — the spelling a cross
    /// consumer runs.
    Target,
}

impl UnitInvocation {
    /// The storage integer of one invocation value.
    #[must_use]
    pub const fn to_int(self) -> i64 {
        match self {
            Self::Native => 0,
            Self::Target => 1,
        }
    }

    /// Decode one stored integer back into an invocation.
    #[must_use]
    pub const fn from_int(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Native),
            1 => Some(Self::Target),
            _ => None,
        }
    }

    /// The invocation spelling a task's build runs under: the cargo
    /// invocation carries `--target` exactly when the task's target
    /// differs from the runner's own platform.
    #[must_use]
    pub fn for_task(target: &str, runner_host_triple: &str) -> Self {
        if target == runner_host_triple {
            Self::Native
        } else {
            Self::Target
        }
    }
}

/// Whether a target-side unit at a host triple keys differently under
/// the explicit `--target <host>` spelling (stow#736).
///
/// The difference exists exactly when a proc-macro is in the unit's
/// `--extern` closure. Derived from the dependency subgraph, so it is
/// not part of the task id.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ExplicitSpelling {
    /// The unit's key is the same under both spellings — no proc-macro
    /// reaches its `--extern` closure, and host-side nodes always
    /// (they already publish both spellings).
    #[default]
    KeysAsNative,
    /// A proc-macro reaches the unit's `--extern` closure: the
    /// proc-macro keys differently per spelling and every unit above
    /// it hashes that in, so the unit must publish the shapes of both
    /// invocation spellings.
    KeysApart,
}

/// Whether a unit reaches the linker (`--emit` carries `link`) or
/// stops at metadata — the check-phase shape.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum UnitKind {
    /// A check/metadata unit — `cargo check`'s product.
    Unlinked,
    /// A built unit — `cargo build`/`test`'s product.
    Linked,
}

impl UnitKind {
    /// The storage integer of one kind value.
    #[must_use]
    pub const fn to_int(self) -> i64 {
        match self {
            Self::Unlinked => 0,
            Self::Linked => 1,
        }
    }

    /// Decode one stored integer back into a kind.
    #[must_use]
    pub const fn from_int(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Unlinked),
            1 => Some(Self::Linked),
            _ => None,
        }
    }

    /// The kind one `--emit` set implies: `link` means the unit links.
    #[must_use]
    pub fn from_emit(emit: &[String]) -> Self {
        if emit.iter().any(|entry| entry == "link") {
            Self::Linked
        } else {
            Self::Unlinked
        }
    }
}

/// The coordinates a registered artifact serves, as the builder knows
/// them by construction.
///
/// Which side the unit compiles for, the cargo invocation spelling
/// that produced it, and whether it links. The scheduler's dependency
/// gate and the coverage checks compare this field — never values
/// re-derived from a normalized profile, which would tie coverage to
/// one profile's defaults.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
pub struct UnitShape {
    /// Which side of the host/target boundary the unit serves.
    pub side: UnitSide,
    /// The invocation spelling that produced it.
    pub invocation: UnitInvocation,
    /// Whether it links.
    pub kind: UnitKind,
}

/// The shapes a node's published artifact set must cover before a
/// dependent may consume it.
///
/// The task's own invocation tells which shapes it produces: a
/// target-side node publishes the linked and unlinked units of its one
/// invocation spelling — the build shape and the check shape `cargo
/// check` compiles for a normal dep. A host-side node publishes only
/// linked units — under both invocation spellings, since consumers on
/// either look the same host unit up at different keys: every phase
/// links host units, because build scripts run and proc-macros load
/// even under `cargo check` (their `--emit` always carries `link`),
/// so the unlinked host shape does not exist.
///
/// The exception is a `KeysApart` target-side node whose own
/// invocation is `Native` (stow#736): its `--extern` closure carries a
/// proc-macro, so the explicit `--target <host>` spelling keys it
/// differently and it owes the linked and unlinked shapes of both
/// spellings. A `KeysApart` node already invoked `Target` — a cross
/// target — changes nothing.
#[must_use]
pub fn required_unit_shapes(
    host_side: bool,
    invocation: UnitInvocation,
    explicit_spelling: ExplicitSpelling,
) -> Vec<UnitShape> {
    if host_side {
        return [UnitInvocation::Native, UnitInvocation::Target]
            .map(|invocation| UnitShape {
                side: UnitSide::Host,
                invocation,
                kind: UnitKind::Linked,
            })
            .into();
    }
    let invocations = if invocation == UnitInvocation::Native
        && explicit_spelling == ExplicitSpelling::KeysApart
    {
        [UnitInvocation::Native, UnitInvocation::Target].as_slice()
    } else {
        std::slice::from_ref(&invocation)
    };
    invocations
        .iter()
        .flat_map(|invocation| {
            [UnitKind::Unlinked, UnitKind::Linked].map(|kind| UnitShape {
                side: UnitSide::Target,
                invocation: *invocation,
                kind,
            })
        })
        .collect()
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
            git_source: None,
            extra_codegen: &[],
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
                git_source: None,
                extra_codegen: &[],
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

    /// The git-source and extra-codegen inputs only ever extend the key —
    /// their absence is byte-for-byte the pre-#1006 stream, which the
    /// golden above already pins. Their presence must tag the key: two
    /// commits of one crate, and two codegen flag sets of one crates.io
    /// unit, are different artifacts.
    #[test]
    fn git_source_and_extra_codegen_change_the_key() {
        let profile = crate::platform::Profile {
            opt_level: "0".to_owned(),
            debuginfo: 2,
            debug_assertions: true,
            overflow_checks: true,
            panic: crate::platform::PanicStrategy::Unwind,
            strip: crate::platform::StripLevel::None,
        };
        let key_for = |git: Option<(&str, &str)>, codegen: &[String]| {
            crate::upload_plan::compute_compile_key(&crate::upload_plan::CompileKeyInputs {
                crate_name: "demo",
                crate_version: "0.1.0",
                target: "aarch64-apple-darwin",
                rustc_version: "1.91.1",
                profile: &profile,
                crate_types: &[crate::artifact::RustCrateType::Rlib],
                emit: &["link".to_owned()],
                features_json: "[]",
                dependency_c_metadata_json: "[]",
                kind: &crate::artifact::ArtifactKind::Rlib,
                embed_metadata: None,
                cfgs: &[],
                embed_bitcode: false,
                link_options: &[],
                git_source: git.map(|(commit, manifest_path_in_repo)| {
                    crate::upload_plan::GitSourceInputs {
                        commit,
                        manifest_path_in_repo,
                    }
                }),
                extra_codegen: codegen,
            })
            .expect("compile key")
        };
        let no_tags = key_for(None, &[]);
        let commit_a = ("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", "demo");
        let commit_b = ("0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b", "demo");
        let subdir = (commit_a.0, "tools/demo");
        assert_ne!(
            no_tags,
            key_for(Some(commit_a), &[]),
            "a git unit shares the plain crates.io key shape"
        );
        assert_ne!(
            key_for(Some(commit_a), &[]),
            key_for(Some(commit_b), &[]),
            "two commits of one crate must not share a key"
        );
        assert_ne!(
            key_for(Some(commit_a), &[]),
            key_for(Some(subdir), &[]),
            "two manifest paths inside one commit must not share a key"
        );
        let lto = ["-C linker-plugin-lto".to_owned()];
        assert_ne!(
            no_tags,
            key_for(None, &lto),
            "an extra-codegen unit shares the plain crates.io key"
        );
        let ordered = [
            "-C link-dead-code=y".to_owned(),
            "-C linker-plugin-lto".to_owned(),
        ];
        assert_ne!(
            key_for(None, &lto),
            key_for(None, &ordered),
            "different codegen flag sets must not share a key"
        );
    }

    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use super::{
        ExplicitSpelling, Reach, StableUnitIdentity, UnitInvocation, UnitKind, UnitShape, UnitSide,
        UnitSource, detect_git_checkout, detect_registry_crate_version,
        detect_registry_package_slot, normalized_cache_profile, required_unit_shapes,
        stable_unit_identity, stable_unit_identity_for_package,
    };
    use crate::rustc::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    /// The identity a crates.io unicode-ident invocation resolves to —
    /// detects the registry slot, then keys it.
    fn test_registry_identity(
        parsed: &ParsedRustcArgs,
    ) -> crate::error::Result<StableUnitIdentity> {
        let (package, version) =
            detect_registry_crate_version(parsed)?.expect("registry crate identity");
        stable_unit_identity_for_package(
            parsed,
            &package,
            &version,
            "aarch64-apple-darwin",
            "1.91.1",
            "[]",
            "[]",
        )
    }

    fn lib_args(codegen: &[&str]) -> Vec<OsString> {
        let mut parts = vec![
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
        parts.extend_from_slice(codegen);
        args(&parts)
    }

    /// stow#1066: the compile keys of the argv CI hands rustc for a
    /// representative dev-profile unit are pinned byte for byte — the
    /// published nodes' keys. They were captured from the parser before
    /// `-O`, `-g`, `--remap-path-prefix`, `-C codegen-units` and
    /// `-C split-debuginfo` reached the key, so a change that moves one
    /// would strand every published node. CI's rustflags carry the
    /// workspace and target-dir remaps and the wrapper appends the mold
    /// link argument; none of them may change a key.
    #[test]
    fn ci_argv_keys_are_pinned() {
        let ci_flags = |split: &[&'static str]| {
            let mut flags = vec!["-C", "embed-bitcode=no", "-C", "debuginfo=2"];
            flags.extend_from_slice(split);
            flags.extend_from_slice(&[
                "--remap-path-prefix=/run/work/ws=stow-ci://workspace",
                "--remap-path-prefix=/run/work/target=stow-ci://target",
                "-C",
                "link-arg=-fuse-ld=mold",
            ]);
            flags
        };
        let key = |parsed: &ParsedRustcArgs, target: &str| {
            stable_unit_identity_for_package(
                parsed,
                "unicode-ident",
                "1.0.24",
                target,
                "1.91.1",
                "[]",
                "[]",
            )
            .expect("identity")
            .compile_key
        };
        let mut apple = ci_flags(&["-C", "split-debuginfo=unpacked"]);
        apple.extend_from_slice(&["--target", "aarch64-apple-darwin"]);
        let apple = ParsedRustcArgs::parse(&lib_args(&apple)).expect("parse");
        assert_eq!(
            key(&apple, "aarch64-apple-darwin"),
            "e5bd73e81ce55ad3154de51bd6b2878a0f9cfb7363decee2aea8952e3f3be621",
        );
        let mut linux = ci_flags(&[]);
        linux.extend_from_slice(&["--target", "x86_64-unknown-linux-gnu"]);
        let linux = ParsedRustcArgs::parse(&lib_args(&linux)).expect("parse");
        assert_eq!(
            key(&linux, "x86_64-unknown-linux-gnu"),
            "d8870d567564eb5aece0400b1ca94e4dc368dfeceee85f716c18eededb998c63",
        );
        let mut linked = ci_flags(&[]);
        linked.extend_from_slice(&[
            "--target",
            "x86_64-unknown-linux-gnu",
            "--crate-type",
            "cdylib",
        ]);
        let linked = ParsedRustcArgs::parse(&lib_args(&linked)).expect("parse");
        assert_eq!(
            key(&linked, "x86_64-unknown-linux-gnu"),
            "553f338fc2fbe3da87a9e8ded69d11cbc33eb84cd734a33e35cce12203e4b46e",
        );
    }

    /// The compile key of the dev-profile unit `lib_args` spells, plus
    /// `flags`, compiled for `target`.
    fn flagged_key(flags: &[&str], target: &str) -> String {
        let mut all = flags.to_vec();
        all.extend_from_slice(&["--target", target]);
        let parsed = ParsedRustcArgs::parse(&lib_args(&all)).expect("parse");
        stable_unit_identity_for_package(
            &parsed,
            "unicode-ident",
            "1.0.24",
            target,
            "1.91.1",
            "[]",
            "[]",
        )
        .expect("identity")
        .compile_key
    }

    fn key_of(flags: &[&str]) -> String {
        flagged_key(flags, "x86_64-unknown-linux-gnu")
    }

    #[track_caller]
    fn assert_keys_apart(left: &[&str], right: &[&str]) {
        assert_ne!(key_of(left), key_of(right), "{left:?} vs {right:?}");
    }

    #[track_caller]
    fn assert_keys_equal(left: &[&str], right: &[&str]) {
        assert_eq!(key_of(left), key_of(right), "{left:?} vs {right:?}");
    }

    /// stow#1066: `-O` is `-C opt-level=3` (rustc --help), and between it
    /// and `-C opt-level` the later flag wins.
    #[test]
    fn optimization_shorthand_keys_as_the_level_it_sets() {
        assert_keys_apart(&["-O"], &[]);
        assert_keys_equal(&["-O"], &["-C", "opt-level=3"]);
        assert_keys_equal(&["-O"], &["--codegen", "opt-level=3"]);
        assert_keys_equal(&["-C", "opt-level=0", "-O"], &["-C", "opt-level=3"]);
        assert_keys_equal(&["-O", "-C", "opt-level=0"], &[]);
        assert_keys_apart(&["-O"], &["-C", "opt-level=2"]);
    }

    /// stow#1066: `-g` is `-C debuginfo=2` (rustc --help), and between it
    /// and `-C debuginfo` the later flag wins.
    #[test]
    fn debuginfo_shorthand_keys_as_the_level_it_sets() {
        assert_keys_apart(&["-g"], &[]);
        assert_keys_equal(&["-g"], &["-C", "debuginfo=2"]);
        assert_keys_equal(&["-C", "debuginfo=0", "-g"], &["-g"]);
        assert_keys_equal(&["-g", "-C", "debuginfo=0"], &["-C", "debuginfo=0"]);
        assert_keys_apart(&["-g"], &["-C", "debuginfo=1"]);
    }

    /// stow#1066: a boolean `-C` option with no value is `yes`, so it
    /// reaches the profile instead of the unmodelled options.
    #[test]
    fn bare_boolean_codegen_options_mean_yes() {
        for option in ["debug-assertions", "overflow-checks"] {
            let optimized = ["-C", "opt-level=3"];
            let bare = [optimized[0], optimized[1], "-C", option];
            let yes_value = format!("{option}=yes");
            let yes = [optimized[0], optimized[1], "-C", yes_value.as_str()];
            assert_keys_equal(&bare, &yes);
            assert_keys_apart(&bare, &optimized);
            let parsed = ParsedRustcArgs::parse(&lib_args(&bare)).expect("parse");
            assert_eq!(parsed.extra_codegen, Vec::<String>::new(), "{option}");
        }
        let parsed = ParsedRustcArgs::parse(&lib_args(&["-C", "embed-bitcode"])).expect("parse");
        assert!(parsed.embed_bitcode);
        assert_keys_equal(&["-C", "embed-bitcode"], &[]);
        assert_keys_apart(&["-C", "embed-bitcode=no"], &["-C", "embed-bitcode"]);
    }

    /// stow#1066: remappings change the paths embedded in the output, so
    /// they key — in argv order, because rustc applies the last one that
    /// matches a path.
    #[test]
    fn remap_path_prefix_keys_in_argv_order() {
        assert_keys_apart(&["--remap-path-prefix=/a=/b"], &[]);
        assert_keys_apart(
            &["--remap-path-prefix=/a=/b"],
            &["--remap-path-prefix=/a=/c"],
        );
        assert_keys_apart(
            &["--remap-path-prefix=/a=/b"],
            &["--remap-path-prefix=/z=/b"],
        );
        assert_keys_equal(
            &["--remap-path-prefix=/a=/b"],
            &["--remap-path-prefix", "/a=/b"],
        );
        assert_keys_apart(
            &["--remap-path-prefix=/a=/x", "--remap-path-prefix=/a/b=/y"],
            &["--remap-path-prefix=/a/b=/y", "--remap-path-prefix=/a=/x"],
        );
        // An earlier repeat of a remapping never wins, so it is not part of
        // the identity.
        assert_keys_equal(
            &[
                "--remap-path-prefix=/a=/b",
                "--remap-path-prefix=/c=/d",
                "--remap-path-prefix=/a=/b",
            ],
            &["--remap-path-prefix=/c=/d", "--remap-path-prefix=/a=/b"],
        );
        // FROM is everything before the last `=`.
        assert_keys_apart(
            &["--remap-path-prefix=/a=b=/c"],
            &["--remap-path-prefix=/a=/c"],
        );
        assert!(ParsedRustcArgs::parse(&lib_args(&["--remap-path-prefix=/a"])).is_err());
    }

    /// stow#1066: the remaps CI's rustflags and a consumer's wrapper add
    /// carry the machine's own paths as FROM and a stow virtual root as
    /// TO. They are on both sides of every match and never enter the key,
    /// whatever the paths; a remap of the consumer's own still does.
    #[test]
    fn stow_virtual_root_remaps_stay_out_of_the_key() {
        let plain = key_of(&[]);
        assert_eq!(
            plain,
            key_of(&["--remap-path-prefix=/run/ci/ws=stow-ci://workspace"])
        );
        assert_eq!(
            plain,
            key_of(&[
                "--remap-path-prefix=/Users/me/ws=stow-ci://workspace",
                "--remap-path-prefix=/run/target=stow-ci://target",
            ])
        );
        assert_keys_apart(
            &[
                "--remap-path-prefix=/run/ws=stow-ci://workspace",
                "--remap-path-prefix=/a=/b",
            ],
            &["--remap-path-prefix=/run/ws=stow-ci://workspace"],
        );
    }

    /// stow#1066: `--remap-path-scope` picks which paths the remappings
    /// reach; the last one wins.
    #[test]
    fn remap_path_scope_keys_with_the_last_value() {
        let remap = "--remap-path-prefix=/a=/b";
        assert_keys_apart(&[remap, "--remap-path-scope=macro"], &[remap]);
        assert_keys_apart(
            &[remap, "--remap-path-scope=macro"],
            &[remap, "--remap-path-scope=debuginfo"],
        );
        assert_keys_equal(
            &[
                remap,
                "--remap-path-scope=object",
                "--remap-path-scope=macro",
            ],
            &[remap, "--remap-path-scope=macro"],
        );
    }

    /// stow#1066: the codegen unit count changes the object code; the
    /// last `-C codegen-units` wins.
    #[test]
    fn codegen_units_key_with_the_last_value() {
        assert_keys_apart(&["-C", "codegen-units=1"], &[]);
        assert_keys_apart(&["-C", "codegen-units=1"], &["-C", "codegen-units=16"]);
        assert_keys_equal(
            &["-C", "codegen-units=16", "-C", "codegen-units=1"],
            &["-C", "codegen-units=1"],
        );
        assert_keys_equal(&["-Ccodegen-units=1"], &["-C", "codegen-units=1"]);
    }

    /// stow#1066: `-C split-debuginfo` changes where debug info lands. The
    /// value cargo's dev profile gives every unit on the target (`unpacked`
    /// on Apple targets, rustc's default elsewhere) is what each published
    /// node has, so it keys like no flag at all.
    #[test]
    fn split_debuginfo_keys_unless_it_is_the_cargo_default() {
        let key = |flag: &str, target: &str| {
            let value = format!("split-debuginfo={flag}");
            flagged_key(&["-C", value.as_str()], target)
        };
        let apple = "aarch64-apple-darwin";
        assert_eq!(key("unpacked", apple), flagged_key(&[], apple));
        assert_ne!(key("packed", apple), flagged_key(&[], apple));
        assert_ne!(key("off", apple), flagged_key(&[], apple));
        assert_ne!(key("packed", apple), key("off", apple));

        let linux = "x86_64-unknown-linux-gnu";
        assert_eq!(key("off", linux), flagged_key(&[], linux));
        assert_ne!(key("unpacked", linux), flagged_key(&[], linux));
        assert_ne!(key("packed", linux), flagged_key(&[], linux));

        let msvc = "x86_64-pc-windows-msvc";
        assert_eq!(key("packed", msvc), flagged_key(&[], msvc));
        assert_ne!(key("off", msvc), flagged_key(&[], msvc));
        assert_ne!(key("unpacked", msvc), flagged_key(&[], msvc));
    }

    /// stow#1066: `-C prefer-dynamic` decides how a dylib, cdylib or bin
    /// links std, so it keys there; cargo adds it to every proc-macro and
    /// it does nothing to an rlib, so it keys nowhere else.
    #[test]
    fn prefer_dynamic_keys_only_where_it_links_std() {
        let key = |crate_type: &str, prefer: bool| {
            let mut flags = vec!["--crate-type", crate_type];
            if prefer {
                flags.extend_from_slice(&["-C", "prefer-dynamic"]);
            }
            flagged_key(&flags, "x86_64-unknown-linux-gnu")
        };
        assert_eq!(key("proc-macro", true), key("proc-macro", false));
        assert_eq!(key("rlib", true), key("rlib", false));
        assert_ne!(key("dylib", true), key("dylib", false));
        assert_ne!(key("cdylib", true), key("cdylib", false));
    }

    /// stow#1047: at a non-zero opt-level an absent `-C debug-assertions`
    /// and `-C overflow-checks` are off, so spelling them on is a
    /// different compile and must be a different key.
    #[test]
    fn optimized_check_defaults_key_apart_from_explicit_checks() {
        let plain = ParsedRustcArgs::parse(&lib_args(&["-C", "opt-level=3"])).expect("parse");
        let checked = ParsedRustcArgs::parse(&lib_args(&[
            "-C",
            "opt-level=3",
            "-C",
            "debug-assertions=yes",
            "-C",
            "overflow-checks=yes",
        ]))
        .expect("parse");
        let plain_profile = normalized_cache_profile(&plain).expect("profile");
        assert!(!plain_profile.debug_assertions, "{plain_profile:?}");
        assert!(!plain_profile.overflow_checks, "{plain_profile:?}");
        assert_ne!(
            test_registry_identity(&plain)
                .expect("identity")
                .compile_key,
            test_registry_identity(&checked)
                .expect("identity")
                .compile_key,
        );
    }

    /// stow#1047: rustc applies `-C target-feature` in argv order, so the
    /// same two flags in the other order are a different compile.
    #[test]
    fn extra_codegen_keeps_its_argv_order_in_the_key() {
        let off_on = ParsedRustcArgs::parse(&lib_args(&[
            "-C",
            "target-feature=-avx2",
            "-C",
            "target-feature=+avx2",
        ]))
        .expect("parse");
        let on_off = ParsedRustcArgs::parse(&lib_args(&[
            "-C",
            "target-feature=+avx2",
            "-C",
            "target-feature=-avx2",
        ]))
        .expect("parse");
        assert_ne!(
            test_registry_identity(&off_on)
                .expect("identity")
                .compile_key,
            test_registry_identity(&on_off)
                .expect("identity")
                .compile_key,
        );
    }

    /// The key `parsed`'s own identity recomputes to when the candidate is
    /// checked under `consumer` and `build_script`.
    fn recomputed_key(
        parsed: &ParsedRustcArgs,
        consumer: &crate::upload_plan::ConsumerInputs,
        build_script: &crate::upload_plan::BuildScriptInputs,
    ) -> String {
        let profile = normalized_cache_profile(parsed).expect("profile");
        let kind = super::parsed_artifact_kind(parsed).expect("kind");
        let crate_types = super::parsed_crate_types(parsed).expect("crate types");
        let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
        crate::upload_plan::candidate_compile_key(
            &crate::upload_plan::CandidateIdentity {
                crate_name: "unicode-ident",
                crate_version: "1.0.24",
                target: "aarch64-apple-darwin",
                rustc_version: "1.91.1",
                features_json: "[]",
                dependency_c_metadata_json: "[]",
                kind: &kind,
                profile: &profile,
                crate_types: &crate_types,
                emit: &emit,
            },
            consumer,
            build_script,
        )
        .expect("candidate key")
    }

    fn consumer_of(
        parsed: &ParsedRustcArgs,
        own: &crate::upload_plan::BuildScriptInputs,
    ) -> crate::upload_plan::ConsumerInputs {
        crate::upload_plan::ConsumerInputs::of(parsed, own)
    }

    /// A candidate compiled with exactly the consumer's inputs recomputes
    /// to its own key; one compiled without the consumer's `--cfg`, extra
    /// codegen or bitcode setting does not (stow#1047).
    #[test]
    fn a_candidate_serves_only_the_inputs_it_was_compiled_with() {
        use crate::upload_plan::BuildScriptInputs;
        let none = BuildScriptInputs::default();
        let candidate = ParsedRustcArgs::parse(&lib_args(&[])).expect("parse");
        let key = test_registry_identity(&candidate)
            .expect("identity")
            .compile_key;
        assert_eq!(
            recomputed_key(&candidate, &consumer_of(&candidate, &none), &none),
            key
        );
        for flags in [
            &["--cfg", "custom"][..],
            &["-C", "target-cpu=znver4"],
            &["-C", "embed-bitcode=no"],
            &["-Z", "embed-metadata=yes"],
        ] {
            let request = ParsedRustcArgs::parse(&lib_args(flags)).expect("parse");
            assert_ne!(
                recomputed_key(&candidate, &consumer_of(&request, &none), &none),
                key,
                "{flags:?} was served an artifact compiled without it"
            );
        }
        // And the other direction: a candidate compiled with a cfg is not
        // served to a request without it.
        let with_cfg = ParsedRustcArgs::parse(&lib_args(&["--cfg", "custom"])).expect("parse");
        let cfg_key = test_registry_identity(&with_cfg)
            .expect("identity")
            .compile_key;
        assert_eq!(
            recomputed_key(&with_cfg, &consumer_of(&with_cfg, &none), &none),
            cfg_key
        );
        assert_ne!(
            recomputed_key(&with_cfg, &consumer_of(&candidate, &none), &none),
            cfg_key
        );
    }

    /// A cfg the candidate's own build script set is part of its key, and
    /// a request whose build script set it too (as a superset or version
    /// substitution may) still matches: the build-script cfgs come from
    /// the candidate's captured output, never from the request.
    #[test]
    fn a_build_scripts_cfg_is_the_candidates_own_not_the_consumers() {
        use crate::upload_plan::BuildScriptInputs;
        let built = ParsedRustcArgs::parse(&lib_args(&["--cfg", "probe_ok"])).expect("parse");
        let key = test_registry_identity(&built)
            .expect("identity")
            .compile_key;
        let candidate_script =
            BuildScriptInputs::from_directives(&["cargo:rustc-cfg=probe_ok".to_owned()]);
        // The request (here without the cfg: a different feature set whose
        // build script emitted none) is served by the candidate, whose
        // cfg comes from its own captured build script output.
        let request = ParsedRustcArgs::parse(&lib_args(&[])).expect("parse");
        assert_eq!(
            recomputed_key(
                &built,
                &consumer_of(&request, &BuildScriptInputs::default()),
                &candidate_script
            ),
            key
        );
        // The same request, whose OWN build script emitted the cfg that is
        // therefore on its argv, subtracts it as the build script's and
        // still matches the same key.
        let request = ParsedRustcArgs::parse(&lib_args(&["--cfg", "probe_ok"])).expect("parse");
        let own = BuildScriptInputs::from_directives(&["cargo::rustc-cfg=probe_ok".to_owned()]);
        assert_eq!(
            recomputed_key(&built, &consumer_of(&request, &own), &own),
            key
        );
        // A cfg both RUSTFLAGS and the build script set appears twice on
        // argv; one occurrence is the consumer's and survives.
        let request =
            ParsedRustcArgs::parse(&lib_args(&["--cfg", "probe_ok", "--cfg", "probe_ok"]))
                .expect("parse");
        let consumer = consumer_of(&request, &own);
        assert_eq!(consumer.cfgs, ["probe_ok"]);
        // A feature cfg is never a build-script cfg.
        assert_eq!(
            BuildScriptInputs::from_directives(&["cargo:rustc-cfg=feature=\"x\"".to_owned()]),
            BuildScriptInputs::default()
        );
    }

    /// Published linking keys keep the serialization they were published
    /// under: cargo's cross-target `-C linker=` comes first on argv and
    /// the pinned mold argument last, and the key carries the argument
    /// first (stow#1047).
    #[test]
    fn a_cross_linking_unit_keeps_its_published_key_shape() {
        let proc_macro = |codegen: &[&str]| {
            let mut parts = vec![
                "--crate-name",
                "serde_derive",
                "--crate-type",
                "proc-macro",
                "--emit",
                "dep-info,link",
                "-C",
                "metadata=a52ee596848c66ca",
                "-C",
                "extra-filename=-aa4980adf969014b",
                "--out-dir",
                "/tmp/out",
                "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_derive-1.0.210/src/lib.rs",
            ];
            parts.extend_from_slice(codegen);
            ParsedRustcArgs::parse(&args(&parts)).expect("parse")
        };
        let parsed = proc_macro(&[
            "-C",
            "linker=aarch64-linux-gnu-gcc",
            "-C",
            "link-arg=-fuse-ld=mold",
        ]);
        let key = test_registry_identity(&parsed)
            .expect("identity")
            .compile_key;
        let profile = normalized_cache_profile(&parsed).expect("profile");
        let published =
            crate::upload_plan::compute_compile_key(&crate::upload_plan::CompileKeyInputs {
                crate_name: "serde_derive",
                crate_version: "1.0.210",
                target: "aarch64-apple-darwin",
                rustc_version: "1.91.1",
                profile: &profile,
                crate_types: &[crate::artifact::RustCrateType::ProcMacro],
                emit: &["dep-info".to_owned(), "link".to_owned()],
                features_json: "[]",
                dependency_c_metadata_json: "[]",
                kind: &super::parsed_artifact_kind(&parsed).expect("kind"),
                embed_metadata: None,
                cfgs: &[],
                embed_bitcode: true,
                link_options: &[
                    "link-arg=-fuse-ld=mold".to_owned(),
                    "linker=aarch64-linux-gnu-gcc".to_owned(),
                ],
                git_source: None,
                extra_codegen: &[],
            })
            .expect("compile key");
        assert_eq!(key, published);
    }

    #[test]
    fn reach_folds_to_the_tightest_value() {
        assert_eq!(Reach::Public.fold(Reach::Public), Reach::Public);
        assert_eq!(Reach::Public.fold(Reach::LocalOnly), Reach::LocalOnly);
        assert_eq!(Reach::LocalOnly.fold(Reach::Public), Reach::LocalOnly);
        assert_eq!(Reach::from_int(0), Some(Reach::Public));
        assert_eq!(Reach::from_int(1), Some(Reach::LocalOnly));
        assert_eq!(Reach::from_int(2), None);
    }

    #[test]
    fn the_registry_slot_names_its_index_dir() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            "/home/user/.cargo/registry/src/index.crates.io-0123abcd/itoa-1.0.0/src/lib.rs",
        ]))
        .expect("parse");
        assert_eq!(
            detect_registry_package_slot(&parsed)
                .expect("slot")
                .map(|slot| slot.index_dir)
                .as_deref(),
            Some("index.crates.io-0123abcd")
        );
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "mycrate",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            "/home/user/.cargo/registry/src/my-mirror.example.com-deadbeef/mycrate-0.2.0/src/lib.rs",
        ]))
        .expect("parse");
        assert_eq!(
            detect_registry_package_slot(&parsed)
                .expect("slot")
                .map(|slot| slot.index_dir)
                .as_deref(),
            Some("my-mirror.example.com-deadbeef")
        );
    }

    #[test]
    fn git_and_registry_identities_of_one_crate_never_share_a_key() {
        // The production git identity keys under an empty version, the
        // registry one under the slot's: the same crate name and version
        // text on both sides must still key apart.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "demo",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
        ]))
        .expect("parse");
        let identity = |source: &UnitSource| {
            stable_unit_identity(
                &parsed,
                source,
                Reach::Public,
                "aarch64-apple-darwin",
                "1.91.1",
                "[]",
                "[]",
            )
            .expect("identity")
        };
        let registry = identity(&UnitSource::CratesIo {
            package: "demo".to_owned(),
            version: "0.1.0".to_owned(),
        });
        let git = identity(&UnitSource::Git {
            commit: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b".to_owned(),
            manifest_path_in_repo: String::new(),
        });
        assert_eq!(git.version, "", "a git unit carries no registry version");
        assert_ne!(registry.compile_key, git.compile_key);
        assert_ne!(registry.c_metadata, git.c_metadata);
    }

    #[test]
    fn detect_git_checkout_reads_the_slot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let checkout = temp
            .path()
            .join("git/checkouts/demo-9f9f9f/1a2b3c4d/tools/demo");
        std::fs::create_dir_all(checkout.join("src")).expect("src dir");
        std::fs::write(
            checkout.join("Cargo.toml"),
            "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n",
        )
        .expect("write manifest");
        let input = checkout.join("src/lib.rs");
        std::fs::write(&input, "pub fn leaf() {}\n").expect("write lib");

        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "demo",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            input.to_str().expect("utf8 path"),
        ]))
        .expect("parse");
        let found = detect_git_checkout(&parsed).expect("checkout slot detected");
        assert_eq!(found.short_id, "1a2b3c4d");
        assert!(
            found.root.ends_with("git/checkouts/demo-9f9f9f/1a2b3c4d"),
            "checkout root names the commit slot: {}",
            found.root.display()
        );

        // A path under neither slot is no source at all.
        let local = temp.path().join("local/demo");
        std::fs::create_dir_all(local.join("src")).expect("local src");
        std::fs::write(
            local.join("Cargo.toml"),
            "[package]\nname=\"local\"\nversion=\"0.1.0\"\n",
        )
        .expect("write local manifest");
        let local_input = local.join("src/lib.rs");
        std::fs::write(&local_input, "pub fn leaf() {}\n").expect("write local lib");
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "local",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            local_input.to_str().expect("utf8 path"),
        ]))
        .expect("parse");
        assert!(detect_git_checkout(&parsed).is_none());
        assert!(
            detect_registry_package_slot(&parsed)
                .expect("slot")
                .is_none()
        );
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
    fn detect_registry_version_reads_package_dir_for_renamed_lib() {
        // Package `redox_syscall` renames its lib to `syscall`; cargo's
        // registry dir still carries the package name, so the slot read
        // must return it — the crate name never filters the slot parse.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "syscall",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/redox_syscall-0.5.17/src/lib.rs",
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
        .expect("parse syscall rustc args");

        assert_eq!(
            detect_registry_crate_version(&parsed).expect("detect"),
            Some(("redox_syscall".to_owned(), "0.5.17".to_owned()))
        );
    }

    /// The CI capture runs inside the sandbox with `CARGO_HOME` pointing
    /// at the granted registry — the slot there is the same
    /// `registry/src/<index>/<pkg>-<version>` shape the CLI sees under
    /// `$CARGO_HOME`.
    #[test]
    fn detect_registry_version_reads_the_sandbox_registry_slot() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "anyhow",
            "--edition=2021",
            "D:/a/_temp/stow/cargo-home/registry/src/index.crates.io-1949cf8c6b5b557f/anyhow-1.0.99/src/lib.rs",
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
        .expect("parse anyhow rustc args");

        assert_eq!(
            detect_registry_crate_version(&parsed).expect("detect"),
            Some(("anyhow".to_owned(), "1.0.99".to_owned()))
        );
    }

    /// The version is everything after the package name: build metadata
    /// and prereleases carry hyphens of their own, and a package name
    /// carries hyphens and digits.
    #[test]
    fn the_package_version_split_keeps_hyphenated_versions_whole() {
        for (component, name, version) in [
            (
                "toml_datetime-1.1.2+spec-1.1.0",
                "toml_datetime",
                "1.1.2+spec-1.1.0",
            ),
            ("clap-4.0.0-rc.1", "clap", "4.0.0-rc.1"),
            ("foo-1.0.0-alpha-2+build-7", "foo", "1.0.0-alpha-2+build-7"),
            ("md-5-0.10.6", "md-5", "0.10.6"),
            ("anyhow-1.0.99", "anyhow", "1.0.99"),
        ] {
            assert_eq!(
                super::split_package_version_component(component),
                Some((name.to_owned(), version.to_owned())),
                "{component}"
            );
        }
        assert_eq!(
            super::split_package_version_component("not-a-package"),
            None
        );
    }

    #[test]
    fn detect_registry_version_rejects_lookalike_dir_outside_registry() {
        // A `<name>-<semver>` dir that does not sit at
        // `registry/src/<index>/<pkg>` is not a package slot — a vendored
        // copy or worktree must not be read as a registry identity, whether
        // its name matches the crate name or not.
        for input_path in [
            "/Users/lexoliu/worktrees/redox_syscall-0.5.17/src/lib.rs",
            // The crate name itself matches: still not an identity.
            "/Users/lexoliu/worktrees/syscall-0.5.17/src/lib.rs",
        ] {
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "syscall",
                "--edition=2021",
                input_path,
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
            .expect("parse syscall rustc args");

            assert_eq!(
                detect_registry_crate_version(&parsed).expect("detect"),
                None,
                "{input_path} is not a registry slot"
            );
        }
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

        let identity = test_registry_identity(&parsed).expect("compute stable registry identity");

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
        assert_eq!(flagged.extra_codegen, Vec::<String>::new());

        let baseline_identity =
            test_registry_identity(&baseline).expect("compute baseline identity");
        let flagged_identity = test_registry_identity(&flagged).expect("compute flagged identity");

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

        let identity =
            |parsed: &ParsedRustcArgs| test_registry_identity(parsed).expect("compute identity");
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
            assert_eq!(parsed.extra_codegen, Vec::<String>::new());
            (
                parsed.embed_bitcode,
                test_registry_identity(&parsed).expect("compute identity"),
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

    fn shape(side: UnitSide, invocation: UnitInvocation, kind: UnitKind) -> UnitShape {
        UnitShape {
            side,
            invocation,
            kind,
        }
    }

    #[test]
    fn unit_kind_separates_linked_from_unlinked() {
        assert_eq!(
            UnitKind::from_emit(&emit(&["dep-info", "metadata", "link"])),
            UnitKind::Linked
        );
        assert_eq!(
            UnitKind::from_emit(&emit(&["dep-info", "metadata"])),
            UnitKind::Unlinked
        );
    }

    #[test]
    fn unit_shape_ints_round_trip_and_reject_legacy() {
        for side in [UnitSide::Target, UnitSide::Host] {
            assert_eq!(UnitSide::from_int(side.to_int()), Some(side));
        }
        for invocation in [UnitInvocation::Native, UnitInvocation::Target] {
            assert_eq!(
                UnitInvocation::from_int(invocation.to_int()),
                Some(invocation)
            );
        }
        for kind in [UnitKind::Unlinked, UnitKind::Linked] {
            assert_eq!(UnitKind::from_int(kind.to_int()), Some(kind));
        }
        // A `-1` leg is corruption — it decodes to nothing.
        assert_eq!(UnitSide::from_int(-1), None);
        assert_eq!(UnitInvocation::from_int(-1), None);
        assert_eq!(UnitKind::from_int(-1), None);
    }

    #[test]
    fn required_shapes_cover_both_sides_of_the_unit_graph() {
        // A host-side node serves consumers on both invocation
        // spellings, linked only: cargo links host units in every
        // phase, so check and build produce the same host shape.
        assert_eq!(
            required_unit_shapes(true, UnitInvocation::Target, ExplicitSpelling::KeysAsNative),
            vec![
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            ]
        );
        // A target-side node serves the build shape and the check shape
        // of its own invocation only.
        assert_eq!(
            required_unit_shapes(
                false,
                UnitInvocation::Native,
                ExplicitSpelling::KeysAsNative
            ),
            vec![
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Unlinked),
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Linked),
            ]
        );
        assert_eq!(
            required_unit_shapes(
                false,
                UnitInvocation::Target,
                ExplicitSpelling::KeysAsNative
            ),
            vec![
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Unlinked),
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Linked),
            ]
        );
    }

    /// stow#736: a `KeysApart` target-side node invoked `Native` owes
    /// both spellings' shapes — the explicit `--target <host>`
    /// consumer looks it up at a different key. `KeysApart` under an
    /// already-explicit invocation and `KeysAsNative` under either
    /// change nothing.
    #[test]
    fn required_shapes_add_the_explicit_spelling_for_a_flagged_native_node() {
        assert_eq!(
            required_unit_shapes(false, UnitInvocation::Native, ExplicitSpelling::KeysApart),
            vec![
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Unlinked),
                shape(UnitSide::Target, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Unlinked),
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Linked),
            ]
        );
        assert_eq!(
            required_unit_shapes(false, UnitInvocation::Target, ExplicitSpelling::KeysApart),
            vec![
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Unlinked),
                shape(UnitSide::Target, UnitInvocation::Target, UnitKind::Linked),
            ]
        );
        assert_eq!(
            required_unit_shapes(true, UnitInvocation::Native, ExplicitSpelling::KeysApart),
            vec![
                shape(UnitSide::Host, UnitInvocation::Native, UnitKind::Linked),
                shape(UnitSide::Host, UnitInvocation::Target, UnitKind::Linked),
            ]
        );
    }
}
