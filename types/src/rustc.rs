//! Parser for the rustc command line the wrapper observes, plus helpers that
//! decide cacheability and predict output paths from the parsed arguments.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use target_lexicon::{Architecture, BinaryFormat, OperatingSystem, Triple};

use crate::platform::{PanicStrategy, Profile, StripLevel};

/// One `--extern name=path` pair from a rustc invocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParsedExternCrate {
    /// Crate name as passed to `--extern` (rustc form, underscores).
    pub crate_name: String,
    /// Path to the dependency's rlib or rmeta.
    pub path: PathBuf,
}

/// The subset of a rustc command line that determines cache identity and
/// output layout.
///
/// Populated by [`ParsedRustcArgs::parse`]; fields are `Option` where the
/// corresponding flag may be absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRustcArgs {
    /// `--crate-name` value; a parse without one fails.
    pub crate_name: String,
    /// `--crate-type` list, split on `,`.
    pub crate_types: Vec<String>,
    /// `feature="…"` values collected from `--cfg` flags.
    pub features: BTreeSet<String>,
    /// Every other `--cfg` value: build-script `cargo:rustc-cfg` output and
    /// `--cfg` flags from `RUSTFLAGS`. They select code at compile time, so
    /// they are compile identity, kept separate from features because the
    /// semantic tuple registries index on is features only.
    pub cfgs: BTreeSet<String>,
    /// `--emit` kinds, deduplicated.
    pub emit: BTreeSet<String>,
    /// `--json` kinds, deduplicated.
    pub json: BTreeSet<String>,
    /// The `.rs` input file, when one was passed.
    pub input_path: Option<PathBuf>,
    /// `--target` triple, or `None` for an implicit host target.
    pub target: Option<String>,
    /// `-C metadata` value.
    pub c_metadata: Option<String>,
    /// `--out-dir` directory.
    pub out_dir: Option<PathBuf>,
    /// `-C extra-filename` suffix (empty when absent).
    pub extra_filename: String,
    /// `-C opt-level` value.
    pub opt_level: Option<String>,
    /// `-C debuginfo` value.
    pub debuginfo: Option<String>,
    /// `-C panic` value.
    pub panic_strategy: Option<String>,
    /// `-C debug-assertions` value.
    pub debug_assertions: Option<bool>,
    /// `-C overflow-checks` value.
    pub overflow_checks: Option<bool>,
    /// `-C strip` value.
    pub strip: Option<String>,
    /// `-L native=…` search paths.
    pub native_search_paths: Vec<PathBuf>,
    /// The `OUT_DIR` cargo exports to the rustc invocation of a crate that
    /// `links` — where the unit's own build script wrote. Never parsed
    /// from argv (it arrives as an environment variable): callers
    /// populating a `ParsedRustcArgs` inside a rustc-wrapper process set
    /// it from `std::env::var_os("OUT_DIR")`.
    pub build_script_out_dir: Option<PathBuf>,
    /// `--extern` pairs, sorted by crate name then path.
    pub extern_crates: Vec<ParsedExternCrate>,
    /// `-Z embed-metadata` value. Nightly cargo passes this flag on every
    /// unit, so it is toolchain identity rather than custom codegen; it
    /// changes the produced rlib, so it participates in the compile key.
    pub embed_metadata: Option<bool>,
    /// Whether the produced object files carry LLVM bitcode. rustc embeds
    /// bitcode unless `-C embed-bitcode=no`, the value cargo passes to every
    /// unit that no LTO consumer needs bitcode from; a unit compiled with
    /// bitcode is a different artifact, so it participates in the compile
    /// key.
    pub embed_bitcode: bool,
    /// The `-C` / `-Z` options the registry identity does not model,
    /// normalized to their `-C key=value` / `-Z key=value` spellings —
    /// argv only. Cargo puts every applicable `RUSTFLAGS` /
    /// `CARGO_ENCODED_RUSTFLAGS` token on the argv, and rustc never reads
    /// the variables, so argv is the one stream that says which flags the
    /// unit actually compiled with — a host unit under `--target` gets no
    /// env flags on argv precisely because cargo did not apply them.
    /// Sorted and folded into the compile key, so two invocations with the
    /// same extra options share one local identity.
    pub extra_codegen: BTreeSet<String>,
    /// The `-C` options that steer only the final link step, normalized to
    /// their `key=value` spelling and sorted. Inert for a unit that never
    /// reaches the linker, and part of the compile key for one that does —
    /// see [`ParsedRustcArgs::link_options_reaching_the_linker`]. An
    /// artifact linked with mold and one linked with lld are different
    /// bytes, so they are different keys rather than both being refused.
    pub link_options: BTreeSet<String>,
}

impl ParsedRustcArgs {
    /// Parse a captured rustc argv into `ParsedRustcArgs`.
    ///
    /// Recognizes the flags cargo passes for dependency compilations.
    /// Unknown `-C` / `-Z` options land in `extra_codegen` rather than
    /// failing, so the invocation is still parsed — they key it
    /// local-only, and the unfoldable ones classify it uncached.
    ///
    /// # Errors
    /// Returns an error when an argument is not valid UTF-8, a flag that
    /// requires a value is the last argument, an `--extern` pair or codegen
    /// boolean is malformed, or `--crate-name` is missing.
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut parsed = Self {
            crate_name: String::new(),
            crate_types: Vec::new(),
            features: BTreeSet::new(),
            cfgs: BTreeSet::new(),
            emit: BTreeSet::new(),
            json: BTreeSet::new(),
            input_path: None,
            target: None,
            c_metadata: None,
            out_dir: None,
            extra_filename: String::new(),
            opt_level: None,
            debuginfo: None,
            panic_strategy: None,
            debug_assertions: None,
            overflow_checks: None,
            strip: None,
            native_search_paths: Vec::new(),
            build_script_out_dir: None,
            extern_crates: Vec::new(),
            embed_metadata: None,
            embed_bitcode: true,
            extra_codegen: BTreeSet::new(),
            link_options: BTreeSet::new(),
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(arg) = arg.to_str() else {
                return Err(format!(
                    "rustc argument is not valid UTF-8: {}",
                    arg.display()
                ));
            };
            apply_rustc_arg(arg, &mut iter, &mut parsed)?;
        }

        if parsed.crate_name.is_empty() {
            return Err("missing --crate-name in rustc arguments".to_owned());
        }

        Ok(parsed)
    }

    /// Classify this invocation for the cache: a keyed unit — its source
    /// and its normalized extra codegen options — or the reason the
    /// cache can never hold it.
    ///
    /// `source` is the source detection's answer: the unit's immutable
    /// source identity, or the [`UncachedReason`] the detection itself
    /// settled on (no source slot, a registry that is not crates.io, a git
    /// checkout whose commit could not be verified). `primary_package` is
    /// the invocation's own `CARGO_PRIMARY_PACKAGE` fact — passed in
    /// because the deciding process's environment is not the invocation's
    /// under a supervised build.
    #[must_use]
    pub fn unit_class(
        &self,
        source: Result<crate::public_cache::UnitSource, UncachedReason>,
        primary_package: bool,
    ) -> UnitClass {
        if !(self.produces_dynamic_library() || self.produces_rlib()) {
            return UnitClass::Uncached(UncachedReason::UnrestorableCrateType(
                self.crate_types.join(","),
            ));
        }
        if self.c_metadata.is_none() || self.out_dir.is_none() {
            return UnitClass::Uncached(UncachedReason::NoMetadataOrOutDir);
        }
        if primary_package {
            return UnitClass::Uncached(UncachedReason::PrimaryPackage);
        }
        for option in &self.extra_codegen {
            if option.starts_with("-C incremental") {
                return UnitClass::Uncached(UncachedReason::Incremental);
            }
            if is_unfoldable_codegen_option(option) || option == "-C target-cpu=native" {
                return UnitClass::Uncached(UncachedReason::UnfoldableOption(option.clone()));
            }
        }
        match source {
            Err(reason) => UnitClass::Uncached(reason),
            Ok(source) => UnitClass::Keyed {
                source,
                extra_codegen: self.extra_codegen.iter().cloned().collect(),
            },
        }
    }

    /// The link-only `-C` options that actually reach a link step here,
    /// which is what the compile key has to carry.
    ///
    /// The cache stores two shapes (see [`Self::is_restorable_artifact`]):
    /// rlibs, which rustc never links, and dynamic libraries, which it
    /// does. For an rlib the options are inert — nothing in the archive
    /// depends on which linker would have been invoked — and that is where
    /// essentially all of a dependency graph lives, so an rlib's key is
    /// exactly what it was before link options were modeled.
    ///
    /// For a dynamic library they are not inert. `-C link-arg` carries
    /// arbitrary text: `-L/opt/custom/lib` changes which library is linked,
    /// `-Wl,-rpath=` changes what is found at run time, `-lfoo` links in
    /// something else entirely, and `link-self-contained` swaps the bundled
    /// runtime for the system one. Two such units are different artifacts,
    /// so they take different keys — serving one for the other would hand
    /// over a different program, and refusing to cache either would cost
    /// the cache every proc-macro in a build that chose its own linker.
    #[must_use]
    pub fn link_options_reaching_the_linker(&self) -> Vec<String> {
        if self.invokes_the_linker() {
            self.link_options.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Whether any `--crate-type` makes rustc run the linker. `lib`/`rlib`
    /// do not (rustc writes an archive of the crate's own objects and defers
    /// linking to whatever consumes it), and neither does `staticlib`; every
    /// other output is a linked image. Cargo compiles all of a lib target's
    /// declared crate types in one invocation, so a dependency declaring
    /// `crate-type = ["lib", "cdylib"]` links in the same rustc run that
    /// produces the cacheable rlib.
    #[must_use]
    fn invokes_the_linker(&self) -> bool {
        self.crate_types
            .iter()
            .any(|kind| matches!(kind.as_str(), "proc-macro" | "dylib" | "cdylib" | "bin"))
    }

    /// Whether the invocation produces an artifact stow can restore: an rlib
    /// or dynamic library with both `-C metadata` and `--out-dir` present.
    #[must_use]
    pub fn is_restorable_artifact(&self) -> bool {
        (self.produces_rlib() || self.produces_dynamic_library())
            && self.c_metadata.is_some()
            && self.out_dir.is_some()
    }

    /// Whether any `--crate-type` is `proc-macro`.
    #[must_use]
    pub fn is_proc_macro(&self) -> bool {
        self.crate_types.iter().any(|kind| kind == "proc-macro")
    }

    /// Whether any `--crate-type` is `lib` or `rlib`.
    #[must_use]
    pub fn produces_rlib(&self) -> bool {
        self.crate_types
            .iter()
            .any(|kind| kind == "lib" || kind == "rlib")
    }

    /// Whether any `--crate-type` is `proc-macro` or `dylib`.
    #[must_use]
    pub fn produces_dynamic_library(&self) -> bool {
        self.crate_types
            .iter()
            .any(|kind| kind == "proc-macro" || kind == "dylib")
    }

    /// Whether any `--crate-type` is `bin`.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        self.crate_types.iter().any(|kind| kind == "bin")
    }

    /// Whether this is the `build_script_build` binary cargo compiles for
    /// build scripts.
    #[must_use]
    pub fn is_build_script(&self) -> bool {
        self.is_binary() && self.crate_name == "build_script_build"
    }

    /// Whether `--json` includes `artifacts` (cargo's artifact-notification
    /// channel the capture wrapper relies on).
    #[must_use]
    pub fn requests_json_artifact_notifications(&self) -> bool {
        self.json.contains("artifacts")
    }

    /// Path of the emitted `.rlib` under `--out-dir`
    /// (`lib<name><extra-filename>.rlib`), or `None` when the invocation does
    /// not produce an rlib or has no `--out-dir`.
    #[must_use]
    pub fn output_rlib_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        if !self.produces_rlib() {
            return None;
        }
        Some(out_dir.join(format!(
            "lib{}{}.rlib",
            self.crate_name, self.extra_filename
        )))
    }

    /// Path of the emitted `.rmeta` under `--out-dir`
    /// (`lib<name><extra-filename>.rmeta`), or `None` without `--out-dir`.
    #[must_use]
    pub fn output_rmeta_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        Some(out_dir.join(format!(
            "lib{}{}.rmeta",
            self.crate_name, self.extra_filename
        )))
    }

    /// Path of the emitted dynamic library under `--out-dir`, named per the
    /// binary format of the triple the unit compiles for (`lib*.so` /
    /// `lib*.dylib` / `*.dll`): its `--target`, or `host` — the triple the
    /// compiling rustc reports — for a host unit that spells none.
    ///
    /// Returns `Ok(None)` when the invocation produces no dynamic library.
    ///
    /// # Errors
    /// Returns an error when a dynamic library is produced but `--out-dir` is
    /// absent, or when the triple the output is named under is unparseable or
    /// has an unsupported binary format.
    pub fn output_dynamic_library_path(&self, host: &str) -> Result<Option<PathBuf>, String> {
        if !self.produces_dynamic_library() {
            return Ok(None);
        }
        let out_dir = self
            .out_dir
            .as_ref()
            .ok_or_else(|| "dynamic library output requires --out-dir".to_owned())?;
        let (prefix, extension) = dynamic_library_naming(self.target.as_deref().unwrap_or(host))?;

        Ok(Some(out_dir.join(format!(
            "{prefix}{}{}.{}",
            self.crate_name, self.extra_filename, extension
        ))))
    }

    /// Path of the emitted dep-info file under `--out-dir`
    /// (`<name><extra-filename>.d`), or `None` without `--out-dir`.
    #[must_use]
    pub fn output_dep_info_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        Some(out_dir.join(format!("{}{}.d", self.crate_name, self.extra_filename)))
    }

    /// Path of the emitted binary under `--out-dir`
    /// (`<name><extra-filename><exe-suffix>`), or `Ok(None)` when the
    /// invocation is not a `bin` crate or has no `--out-dir`.
    ///
    /// # Errors
    /// Returns an error when the triple the output is named under — the
    /// unit's `--target`, or `host` for a host unit — is unparseable.
    pub fn output_binary_path(&self, host: &str) -> Result<Option<PathBuf>, String> {
        let Some(out_dir) = self.out_dir.as_ref() else {
            return Ok(None);
        };
        if !self.is_binary() {
            return Ok(None);
        }
        Ok(Some(out_dir.join(format!(
            "{}{}{}",
            self.crate_name,
            self.extra_filename,
            executable_suffix(self.target.as_deref().unwrap_or(host))?
        ))))
    }

    /// Path of the artifact a downstream crate would link against: the
    /// `.rlib`, then the binary, then the dynamic library.
    ///
    /// # Errors
    /// Propagates [`Self::output_binary_path`]'s and
    /// [`Self::output_dynamic_library_path`]'s errors when the triple the
    /// output is named under is unparseable or its format unsupported.
    pub fn output_link_path(&self, host: &str) -> Result<Option<PathBuf>, String> {
        if let Some(path) = self.output_rlib_path() {
            return Ok(Some(path));
        }
        if let Some(path) = self.output_binary_path(host)? {
            return Ok(Some(path));
        }
        self.output_dynamic_library_path(host)
    }

    /// The `build-script-build` alias cargo creates next to the build script
    /// binary — named per `host`, the triple the compiling rustc reports —
    /// or `Ok(None)` when this is not a build script or `--out-dir` is
    /// absent.
    ///
    /// # Errors
    /// Returns an error when `host` is unparseable.
    pub fn build_script_alias_path(&self, host: &str) -> Result<Option<PathBuf>, String> {
        let Some(out_dir) = self.out_dir.as_ref() else {
            return Ok(None);
        };
        if !self.is_build_script() {
            return Ok(None);
        }
        Ok(Some(out_dir.join(format!(
            "build-script-build{}",
            executable_suffix(self.target.as_deref().unwrap_or(host))?
        ))))
    }

    /// The cargo profile this invocation compiles with, defaulting absent
    /// flags to cargo's debug values (`opt-level=0`, debug assertions and
    /// overflow checks on, `panic=unwind`).
    ///
    /// # Errors
    /// Returns an error when `-C debuginfo`, `-C panic` or `-C strip` carry
    /// values outside the set rustc documents.
    pub fn profile(&self) -> Result<Profile, String> {
        Ok(Profile {
            opt_level: self.opt_level.clone().unwrap_or_else(|| "0".to_owned()),
            debuginfo: parse_debuginfo_level(self.debuginfo.as_deref())?,
            debug_assertions: self.debug_assertions.unwrap_or(true),
            overflow_checks: self.overflow_checks.unwrap_or(true),
            panic: parse_panic_strategy(self.panic_strategy.as_deref())?,
            strip: parse_strip_level(self.strip.as_deref())?,
        })
    }
}

/// The classification one rustc invocation gets: keyed under a source
/// identity the cache can express, or excluded with its reason, so no
/// call site can store or serve a unit the scope excludes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitClass {
    /// The unit carries an immutable source identity and a restorable
    /// shape: the cache keys it.
    Keyed {
        /// Where the unit's source of truth lives.
        source: crate::public_cache::UnitSource,
        /// The sorted, normalized `-C`/`-Z` options the registry
        /// identity does not model — folded into the compile key.
        extra_codegen: Vec<String>,
    },
    /// The cache never holds this unit — never stored, never served.
    Uncached(UncachedReason),
}

impl UnitClass {
    /// Whether the unit's own identity already forbids a remote lookup —
    /// a git source or extra codegen the builder never publishes — before
    /// its dependencies' reach is even folded in.
    #[must_use]
    pub const fn source_local_only(&self) -> bool {
        match self {
            Self::Keyed {
                source,
                extra_codegen,
                ..
            } => {
                !extra_codegen.is_empty()
                    || matches!(source, crate::public_cache::UnitSource::Git { .. })
            }
            Self::Uncached(_) => false,
        }
    }

    /// Whether this compile could have been a public-cache miss — keyed
    /// under an identity that is itself remote-lookupable. A dep-tainted
    /// unit is still missable by this measure (its own identity is a
    /// public one), which is what the local-dependency build accounting
    /// counts (stow#734); a git or codegen-keyed unit is not (stow#1006).
    #[must_use]
    pub const fn remote_missable(&self) -> bool {
        matches!(self, Self::Keyed { .. }) && !self.source_local_only()
    }
}

/// Why a unit is uncached: the reason a debug line names next to the
/// crate name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UncachedReason {
    /// The input file sits under neither a registry `src/` slot nor a
    /// cargo `git/checkouts/` slot — a path dependency, a workspace
    /// member or a vendored copy.
    PathSource,
    /// `CARGO_PRIMARY_PACKAGE` was set on the invocation — the crate the
    /// user is building is never cached.
    PrimaryPackage,
    /// `-C incremental` on the invocation: incremental objects depend on
    /// the incremental work directory, which the key cannot see.
    Incremental,
    /// A `-C`/`-Z` option whose output depends on a file or a location
    /// the key cannot see.
    UnfoldableOption(String),
    /// No crate type stow restores: `cdylib`, `staticlib`, `bin` and
    /// friends.
    UnrestorableCrateType(String),
    /// A restorable shape without `-C metadata` or `--out-dir`.
    NoMetadataOrOutDir,
    /// A registry package whose source is not crates.io — it must never
    /// take the crates.io identity of the same name and version.
    NonCratesIoRegistry,
    /// A git checkout whose resolved commit could not be read or whose
    /// `<short id>` directory is not a prefix of it — the identity the
    /// source would have keyed under cannot be verified.
    GitIdentityFailed,
}

/// Options whose output depends on a file or a location the compile key
/// cannot see — never folded, always uncached.
fn is_unfoldable_codegen_option(option: &str) -> bool {
    let name = option
        .split_once(' ')
        .map_or(option, |(_, rest)| rest)
        .split('=')
        .next()
        .unwrap_or_default();
    match option.split(' ').next().unwrap_or_default() {
        "-C" => matches!(name, "profile-use" | "profile-sample-use"),
        "-Z" => {
            matches!(name, "codegen-backend" | "llvm-plugins" | "temps-dir")
                || name.starts_with("split-dwarf")
                || name.starts_with("self-profile")
                || name.starts_with("dump-")
        }
        _ => false,
    }
}

fn apply_rustc_arg<'a>(
    arg: &str,
    iter: &mut impl Iterator<Item = &'a OsString>,
    parsed: &mut ParsedRustcArgs,
) -> Result<(), String> {
    match arg {
        "--crate-name" => apply_crate_name(next_str(iter, "--crate-name")?, parsed),
        "--crate-type" => apply_crate_types(next_str(iter, "--crate-type")?, parsed),
        "--target" => apply_target(next_str(iter, "--target")?, parsed),
        "--cfg" => apply_cfg(next_str(iter, "--cfg")?, parsed),
        "--out-dir" => parsed.out_dir = Some(PathBuf::from(next_os(iter, "--out-dir")?)),
        "--extern" => {
            parse_extern_crate(next_os(iter, "--extern")?.clone(), parsed)?;
        }
        "--emit" => {
            parse_emit_kinds(next_str(iter, "--emit")?, parsed);
        }
        "--json" => {
            parse_json_kinds(next_str(iter, "--json")?, parsed);
        }
        "-C" => {
            parse_codegen_option(next_str(iter, "-C")?, parsed)?;
        }
        "-L" => {
            parse_library_search(next_str(iter, "-L")?, parsed);
        }
        _ => apply_attached_arg(arg, iter, parsed)?,
    }
    Ok(())
}

/// Handle a flag carrying its value inline (`--flag=value` or `-Xvalue`).
///
/// Every equals spelling shares the space spelling's handler so the two
/// forms can never drift: cargo emits the space forms, but rustc accepts
/// both and a unit passed with `=` would otherwise parse as restorable-in-
/// name-only — recognized by nothing downstream.
fn apply_attached_arg<'a>(
    arg: &str,
    iter: &mut impl Iterator<Item = &'a OsString>,
    parsed: &mut ParsedRustcArgs,
) -> Result<(), String> {
    if let Some(value) = arg.strip_prefix("--crate-name=") {
        apply_crate_name(value, parsed);
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--crate-type=") {
        apply_crate_types(value, parsed);
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--target=") {
        apply_target(value, parsed);
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--cfg=") {
        apply_cfg(value, parsed);
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--out-dir=") {
        parsed.out_dir = Some(PathBuf::from(value));
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--extern=") {
        return parse_extern_crate(OsString::from(value), parsed);
    }
    if let Some(value) = arg.strip_prefix("--emit=") {
        parse_emit_kinds(value, parsed);
        return Ok(());
    }
    if let Some(value) = arg.strip_prefix("--json=") {
        parse_json_kinds(value, parsed);
        return Ok(());
    }
    if let Some(option) = arg.strip_prefix("-C") {
        return parse_codegen_option(option, parsed);
    }
    if let Some(option) = arg.strip_prefix("-L") {
        parse_library_search(option, parsed);
        return Ok(());
    }
    if arg == "-Z" {
        return parse_unstable_option(next_str(iter, "-Z")?, parsed);
    }
    if let Some(option) = arg.strip_prefix("-Z") {
        return parse_unstable_option(option, parsed);
    }
    if !arg.starts_with('-')
        && parsed.input_path.is_none()
        && std::path::Path::new(arg)
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("rs")
    {
        parsed.input_path = Some(PathBuf::from(arg));
    }
    Ok(())
}

fn apply_crate_name(value: &str, parsed: &mut ParsedRustcArgs) {
    value.clone_into(&mut parsed.crate_name);
}

/// Accumulate a `--crate-type` value. rustc takes the flag repeatedly and
/// unions the results, and cargo spells a multi-type lib target that way
/// (`--crate-type lib --crate-type cdylib`), so each occurrence extends the
/// list instead of replacing it: overwriting dropped every type but the last
/// from an identity the compile key is computed over.
fn apply_crate_types(value: &str, parsed: &mut ParsedRustcArgs) {
    for crate_type in value.split(',') {
        if !parsed.crate_types.iter().any(|seen| seen == crate_type) {
            parsed.crate_types.push(crate_type.to_owned());
        }
    }
}

fn apply_target(value: &str, parsed: &mut ParsedRustcArgs) {
    parsed.target = Some(value.to_owned());
}

fn apply_cfg(value: &str, parsed: &mut ParsedRustcArgs) {
    match parse_feature_cfg(value) {
        Some(feature) => {
            parsed.features.insert(feature);
        }
        None => {
            parsed.cfgs.insert(value.to_owned());
        }
    }
}

fn dynamic_library_naming(target: &str) -> Result<(&'static str, &'static str), String> {
    let triple: Triple = target
        .parse()
        .map_err(|error| format!("parse target triple `{target}`: {error}"))?;
    match triple.binary_format {
        BinaryFormat::Elf => Ok(("lib", "so")),
        BinaryFormat::Macho => Ok(("lib", "dylib")),
        BinaryFormat::Coff => Ok(("", "dll")),
        other => Err(format!(
            "unsupported binary format `{}` for dynamic library output",
            other.into_str()
        )),
    }
}

/// The suffix rustc gives an executable `target` compiles: `.exe` on
/// Windows, `.wasm` on a wasm triple, `.efi` on UEFI, none elsewhere.
fn executable_suffix(target: &str) -> Result<&'static str, String> {
    let triple: Triple = target
        .parse()
        .map_err(|error| format!("parse target triple `{target}`: {error}"))?;
    if matches!(
        triple.architecture,
        Architecture::Wasm32 | Architecture::Wasm64
    ) {
        return Ok(".wasm");
    }
    Ok(match triple.operating_system {
        OperatingSystem::Windows => ".exe",
        OperatingSystem::Uefi => ".efi",
        _ => "",
    })
}

fn parse_codegen_option(option: &str, parsed: &mut ParsedRustcArgs) -> Result<(), String> {
    let Some((key, value)) = option.split_once('=') else {
        match option {
            "prefer-dynamic" => {}
            _ => {
                parsed.extra_codegen.insert(format!("-C {option}"));
            }
        }
        return Ok(());
    };

    match key {
        "metadata" => parsed.c_metadata = Some(value.to_owned()),
        "extra-filename" => value.clone_into(&mut parsed.extra_filename),
        "opt-level" => parsed.opt_level = Some(value.to_owned()),
        "debuginfo" => parsed.debuginfo = Some(value.to_owned()),
        "panic" => parsed.panic_strategy = Some(value.to_owned()),
        "debug-assertions" => parsed.debug_assertions = Some(parse_bool(value)?),
        "overflow-checks" => parsed.overflow_checks = Some(parse_bool(value)?),
        "strip" => parsed.strip = Some(value.to_owned()),
        "embed-bitcode" => parsed.embed_bitcode = parse_bool(value)?,
        "codegen-units" | "split-debuginfo" => {}
        _ if is_link_only_codegen_option(option) => {
            parsed.link_options.insert(option.to_owned());
        }
        _ => {
            parsed.extra_codegen.insert(format!("-C {option}"));
        }
    }

    Ok(())
}

/// `-C` options that steer only the final link step.
///
/// They change nothing an rlib contains, because rustc never invokes a
/// linker for a unit that does not produce a linked artifact. Mold, lld and
/// alternate link drivers reach a build through exactly these flags, so
/// treating them as unmodelled codegen made a mold-configured build serve
/// nothing at all and recompile its whole dependency graph.
///
/// Inert is not the same as harmless, though: what these options mean
/// depends on whether the unit reaches the linker, which this function
/// cannot see. [`ParsedRustcArgs::link_options_reach_the_linker`] makes
/// that call.
fn is_link_only_codegen_option(option: &str) -> bool {
    let key = option.split_once('=').map_or(option, |(key, _)| key);
    matches!(
        key,
        "linker" | "linker-flavor" | "link-arg" | "link-args" | "link-self-contained"
    )
}

/// Handle a `-Z` option. `embed-metadata` is the flag nightly cargo emits on
/// every unit and is modeled as compile identity; every other `-Z` option
/// joins the normalized extra-codegen set the compile key folds.
fn parse_unstable_option(option: &str, parsed: &mut ParsedRustcArgs) -> Result<(), String> {
    match option.split_once('=') {
        Some(("embed-metadata", value)) => {
            parsed.embed_metadata = Some(parse_bool(value)?);
        }
        _ => {
            parsed.extra_codegen.insert(format!("-Z {option}"));
        }
    }
    Ok(())
}

fn parse_library_search(option: &str, parsed: &mut ParsedRustcArgs) {
    if let Some(path) = option.strip_prefix("native=") {
        parsed.native_search_paths.push(PathBuf::from(path));
    }
}

fn parse_extern_crate(arg: OsString, parsed: &mut ParsedRustcArgs) -> Result<(), String> {
    let arg = arg.into_string().map_err(|value| {
        format!(
            "rustc --extern argument is not valid UTF-8: {}",
            value.display()
        )
    })?;
    let Some((crate_name, path)) = arg.split_once('=') else {
        return Ok(());
    };
    if crate_name.is_empty() || path.is_empty() {
        return Err(format!("invalid rustc --extern argument: {arg}"));
    }
    parsed.extern_crates.push(ParsedExternCrate {
        crate_name: crate_name.to_owned(),
        path: PathBuf::from(path),
    });
    parsed.extern_crates.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.path.cmp(&right.path))
    });
    Ok(())
}

fn parse_emit_kinds(value: &str, parsed: &mut ParsedRustcArgs) {
    parsed.emit.extend(
        value
            .split(',')
            .filter(|emit| !emit.is_empty())
            .map(str::to_owned),
    );
}

fn parse_json_kinds(value: &str, parsed: &mut ParsedRustcArgs) {
    parsed.json.extend(
        value
            .split(',')
            .filter(|json| !json.is_empty())
            .map(str::to_owned),
    );
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "yes" | "true" | "on" => Ok(true),
        "no" | "false" | "off" => Ok(false),
        _ => Err(format!("invalid boolean rustc codegen value: {value}")),
    }
}

fn parse_feature_cfg(cfg: &str) -> Option<String> {
    let feature = cfg.strip_prefix("feature=\"")?;
    let feature = feature.strip_suffix('"')?;
    Some(feature.to_owned())
}

fn parse_debuginfo_level(value: Option<&str>) -> Result<u32, String> {
    match value {
        None | Some("none") => Ok(0),
        Some("line-directives-only" | "line-tables-only" | "limited") => Ok(1),
        Some("full") => Ok(2),
        Some(raw) => raw
            .parse::<u32>()
            .map_err(|error| format!("invalid debuginfo rustc codegen value `{raw}`: {error}")),
    }
}

fn parse_strip_level(value: Option<&str>) -> Result<StripLevel, String> {
    match value.unwrap_or("none") {
        "none" => Ok(StripLevel::None),
        "debuginfo" => Ok(StripLevel::Debuginfo),
        "symbols" => Ok(StripLevel::Symbols),
        other => Err(format!("invalid strip rustc codegen value `{other}`")),
    }
}

fn parse_panic_strategy(value: Option<&str>) -> Result<PanicStrategy, String> {
    match value.unwrap_or("unwind") {
        "unwind" => Ok(PanicStrategy::Unwind),
        "abort" => Ok(PanicStrategy::Abort),
        raw => Err(format!("invalid panic rustc codegen value: {raw}")),
    }
}

fn next_os<'a>(
    iter: &mut impl Iterator<Item = &'a OsString>,
    flag: &str,
) -> Result<&'a OsString, String> {
    iter.next()
        .ok_or_else(|| format!("missing value after {flag}"))
}

fn next_str<'a>(
    iter: &mut impl Iterator<Item = &'a OsString>,
    flag: &str,
) -> Result<&'a str, String> {
    next_os(iter, flag)?
        .to_str()
        .ok_or_else(|| format!("value after {flag} is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::{ParsedRustcArgs, UncachedReason, UnitClass};
    use crate::platform::StripLevel;

    fn args(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    /// A crates.io source for classification assertions — the source
    /// detection itself lives in the wrapper, which owns the filesystem
    /// probes.
    fn test_source() -> crate::public_cache::UnitSource {
        crate::public_cache::UnitSource::CratesIo {
            package: "itoa".to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    /// Whether the invocation classifies as a keyed unit.
    fn keyed(parsed: &ParsedRustcArgs) -> bool {
        matches!(
            parsed.unit_class(Ok(test_source()), false),
            UnitClass::Keyed { .. }
        )
    }

    #[test]
    fn parses_debug_rlib_invocation() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--cfg",
            "feature=\"default\"",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-abc123",
            "-C",
            "opt-level=0",
            "-C",
            "debug-assertions=yes",
        ]))
        .expect("parser should succeed");

        assert_eq!(parsed.crate_name, "itoa");
        assert_eq!(parsed.target.as_deref(), Some("aarch64-apple-darwin"));
        assert_eq!(parsed.c_metadata.as_deref(), Some("abc123"));
        assert!(keyed(&parsed));
        assert!(parsed.features.contains("default"));
        assert!(
            parsed
                .output_rlib_path()
                .expect("rlib path")
                .ends_with("libitoa-abc123.rlib")
        );
    }

    #[test]
    fn parses_the_equals_spellings_of_every_flag_cargo_can_emit() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name=itoa",
            "--crate-type=rlib",
            "--target=aarch64-apple-darwin",
            "--cfg=feature=\"default\"",
            "--out-dir=/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-abc123",
            "-C",
            "opt-level=0",
            "-C",
            "debug-assertions=yes",
        ]))
        .expect("parser should succeed");

        assert_eq!(parsed.crate_name, "itoa");
        assert_eq!(parsed.crate_types, vec!["rlib"]);
        assert_eq!(parsed.target.as_deref(), Some("aarch64-apple-darwin"));
        assert_eq!(parsed.c_metadata.as_deref(), Some("abc123"));
        assert_eq!(
            parsed.out_dir.as_deref(),
            Some(std::path::Path::new("/tmp/out"))
        );
        assert!(keyed(&parsed));
        assert!(parsed.features.contains("default"));
        assert!(
            parsed
                .output_rlib_path()
                .expect("rlib path")
                .ends_with("libitoa-abc123.rlib")
        );
    }

    #[test]
    fn equals_and_space_spellings_produce_the_same_parse() {
        let space = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--crate-type",
            "cdylib",
            "--target",
            "aarch64-apple-darwin",
            "--cfg",
            "feature=\"serde\"",
            "--cfg",
            "unix",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-abc123",
        ]))
        .expect("space spelling parses");
        let equals = ParsedRustcArgs::parse(&args(&[
            "--crate-name=itoa",
            "--crate-type=rlib",
            "--crate-type=cdylib",
            "--target=aarch64-apple-darwin",
            "--cfg=feature=\"serde\"",
            "--cfg=unix",
            "--out-dir=/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-abc123",
        ]))
        .expect("equals spelling parses");

        assert_eq!(space.crate_name, equals.crate_name);
        assert_eq!(space.crate_types, equals.crate_types);
        assert_eq!(space.target, equals.target);
        assert_eq!(space.features, equals.features);
        assert_eq!(space.cfgs, equals.cfgs);
        assert_eq!(space.cfgs, BTreeSet::from(["unix".to_owned()]));
        assert_eq!(space.out_dir, equals.out_dir);
        assert_eq!(space.c_metadata, equals.c_metadata);
        assert_eq!(space.extra_filename, equals.extra_filename);
    }

    #[test]
    fn rejects_custom_codegen() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "target-cpu=native",
        ]))
        .expect("parser should succeed");

        assert!(!keyed(&parsed));
    }

    #[test]
    fn proc_macro_is_cacheable_without_debug_profile() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde_derive",
            "--crate-type",
            "proc-macro",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=pm123",
            "-C",
            "opt-level=3",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        assert!(parsed.is_proc_macro());
    }

    #[test]
    fn release_profile_is_cacheable_because_the_profile_is_identity() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "opt-level=3",
            "-C",
            "debug-assertions=no",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        let profile = parsed.profile().expect("profile");
        assert_eq!(profile.opt_level, "3");
        assert!(!profile.debug_assertions);
    }

    #[test]
    fn primary_package_is_never_locally_cacheable() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        assert_eq!(
            parsed.unit_class(Ok(test_source()), true),
            UnitClass::Uncached(UncachedReason::PrimaryPackage)
        );
    }

    #[test]
    fn an_unresolved_native_target_cpu_is_never_cached() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "target-cpu=native",
        ]))
        .expect("parser should succeed");

        // `native` is still keyed: the wrapper resolves it to the
        // concrete CPU before classifying. A `native` that survives to
        // the classifier means resolution failed — never cached.
        assert_eq!(
            parsed.extra_codegen.iter().next().map(String::as_str),
            Some("-C target-cpu=native")
        );
        assert_eq!(
            parsed.unit_class(Ok(test_source()), false),
            UnitClass::Uncached(UncachedReason::UnfoldableOption(
                "-C target-cpu=native".to_owned()
            ))
        );
    }

    #[test]
    fn link_only_codegen_options_stay_cacheable_for_an_rlib() {
        for option in [
            "link-arg=-fuse-ld=mold",
            "link-args=-fuse-ld=mold -Wl,--as-needed",
            "linker=clang",
            "linker-flavor=gcc",
            "link-self-contained=y",
        ] {
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "itoa",
                "--crate-type",
                "rlib",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
                "-C",
                option,
            ]))
            .expect("parser should succeed");

            assert!(parsed.extra_codegen.is_empty(), "{option} marked custom");
            assert!(keyed(&parsed), "{option} made unit uncacheable");
        }
    }

    #[test]
    fn link_options_key_a_unit_that_links_instead_of_disqualifying_it() {
        // An rlib is never linked, so these options cannot change it and
        // never reach its key. A proc-macro or dylib IS linked, and
        // `-C link-arg` carries arbitrary text — a different `-L`, `-rpath`
        // or `-l` produces a different `.so`. That makes it a different
        // artifact, which is a different key, not a refusal.
        for crate_type in ["proc-macro", "dylib"] {
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "serde_derive",
                "--crate-type",
                crate_type,
                "--target",
                "x86_64-unknown-linux-gnu",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
                "-C",
                "link-arg=-L/opt/custom/lib",
            ]))
            .expect("parser should succeed");

            assert_eq!(
                parsed.link_options_reaching_the_linker(),
                vec!["link-arg=-L/opt/custom/lib".to_owned()],
                "{crate_type} lost the link option the key needs"
            );
            assert!(
                parsed.extra_codegen.is_empty(),
                "{crate_type} was misfiled as custom codegen"
            );
            assert!(
                keyed(&parsed),
                "{crate_type} with a link option was refused instead of keyed"
            );
            assert!(
                keyed(&parsed),
                "{crate_type} with a link option was refused by the local cache"
            );
        }
    }

    #[test]
    fn an_rlib_never_carries_link_options_into_its_key() {
        // The options are inert for an archive rustc never links, and that
        // is where a dependency graph lives: keying on them would change
        // every existing rlib's identity for nothing.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde",
            "--crate-type",
            "lib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "link-arg=-fuse-ld=mold",
        ]))
        .expect("parser should succeed");

        assert_eq!(
            parsed.link_options,
            BTreeSet::from(["link-arg=-fuse-ld=mold".to_owned()]),
            "the option was not parsed"
        );
        assert!(
            parsed.link_options_reaching_the_linker().is_empty(),
            "an rlib reported a link option as reaching the linker"
        );
        assert!(keyed(&parsed), "a mold-built rlib stopped serving");
    }
    #[test]
    fn repeated_crate_type_flags_union_into_one_identity() {
        // rustc accepts `--crate-type` more than once and cargo spells a
        // multi-type lib target that way. The compile key is computed over
        // this list, so dropping all but the last flag both lost the rlib
        // and let two different units agree on one key.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "ffi_thing",
            "--crate-type",
            "lib",
            "--crate-type",
            "cdylib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
        ]))
        .expect("parser should succeed");

        assert_eq!(parsed.crate_types, vec!["lib", "cdylib"]);
    }

    #[test]
    fn a_lib_that_also_produces_a_cdylib_is_a_unit_that_links() {
        // Cargo compiles every crate type a lib target declares in one rustc
        // invocation, so `crate-type = ["lib", "cdylib"]` — the usual shape
        // of an FFI crate — produces the rlib stow would cache in the same
        // run that links the `.so`. The link options are not inert there, so
        // they enter the key rather than being ignored as they are for a
        // pure rlib.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "ffi_thing",
            "--crate-type",
            "lib",
            "--crate-type",
            "cdylib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "link-arg=-L/opt/custom/lib",
        ]))
        .expect("parser should succeed");

        assert!(parsed.produces_rlib(), "the rlib output is what is cached");
        assert_eq!(
            parsed.link_options_reaching_the_linker(),
            vec!["link-arg=-L/opt/custom/lib".to_owned()],
            "a lib+cdylib unit dropped the link option from its key"
        );
        assert!(keyed(&parsed), "a lib+cdylib unit stopped serving");
    }

    #[test]
    fn link_flags_on_argv_key_a_unit_that_links() {
        // `-C link-arg` on argv keys only a unit that invokes the linker:
        // the proc-macro carries the option into its key; the rlib does
        // not see it at all.
        let linked = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde_derive",
            "--crate-type",
            "proc-macro",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "link-arg=-fuse-ld=mold",
        ]))
        .expect("parser should succeed");
        let rlib = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde",
            "--crate-type",
            "rlib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
        ]))
        .expect("parser should succeed");

        assert_eq!(
            linked.link_options_reaching_the_linker(),
            vec!["link-arg=-fuse-ld=mold".to_owned()],
            "a linked unit lost the link option from its key"
        );
        assert!(keyed(&linked), "a mold-linked proc-macro stopped serving");
        assert!(
            rlib.link_options_reaching_the_linker().is_empty(),
            "an rlib took a link option into its key"
        );
        assert!(keyed(&rlib), "the rlib stopped being cacheable");
    }

    #[test]
    fn foldable_codegen_flags_key_the_unit_local_only() {
        // Foldable options key into extra-codegen: the unit stays a
        // cache unit, local-only by reach (stow#1006).
        for option in ["linker-plugin-lto", "link-dead-code=y"] {
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "itoa",
                "--crate-type",
                "rlib",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
                "-C",
                option,
            ]))
            .expect("parser should succeed");

            let UnitClass::Keyed {
                ref extra_codegen, ..
            } = parsed.unit_class(Ok(test_source()), false)
            else {
                panic!("{option} should key into extra-codegen");
            };
            assert!(
                extra_codegen.contains(&format!("-C {option}")),
                "{option} lost its marking"
            );
        }

        // A `target-cpu=native` that survives the wrapper's
        // resolution is not deterministically representable —
        // uncached, never keyed.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "target-cpu=native",
        ]))
        .expect("parser should succeed");
        assert!(!keyed(&parsed));
    }

    #[test]
    fn options_the_key_cannot_see_stay_uncached() {
        // Each of these depends on a file or a location the compile
        // key cannot see: the unit is uncached, never keyed.
        for (flag, option) in [
            ("-C", "profile-use=/tmp/merged.profdata"),
            ("-C", "profile-sample-use=/tmp/sample.prof"),
            ("-Z", "codegen-backend=cranelift"),
            ("-Z", "llvm-plugins=/tmp/plugin.so"),
            ("-Z", "temps-dir=/tmp/temps"),
            ("-Z", "split-dwarf-kind=split"),
            ("-Z", "self-profile=/tmp/profile"),
            ("-Z", "dump-mir=all"),
        ] {
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "itoa",
                "--crate-type",
                "rlib",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
                flag,
                option,
            ]))
            .expect("parser should succeed");
            assert!(
                matches!(
                    parsed.unit_class(Ok(test_source()), false),
                    UnitClass::Uncached(UncachedReason::UnfoldableOption(_))
                ),
                "{flag} {option} was keyed"
            );
        }
    }

    #[test]
    fn nightly_cargo_embed_metadata_is_not_custom_codegen() {
        for spelling in ["-Z embed-metadata=no", "-Zembed-metadata=no"] {
            let mut invocation = vec![
                "--crate-name",
                "itoa",
                "--crate-type",
                "rlib",
                "--target",
                "aarch64-apple-darwin",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
            ];
            invocation.extend(spelling.split(' '));
            let parsed = ParsedRustcArgs::parse(&args(&invocation)).expect("parser should succeed");

            assert_eq!(parsed.embed_metadata, Some(false));
            assert!(parsed.extra_codegen.is_empty());
            assert!(keyed(&parsed));
        }
    }

    #[test]
    fn parses_embed_metadata_yes() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-Z",
            "embed-metadata=yes",
        ]))
        .expect("parser should succeed");

        assert_eq!(parsed.embed_metadata, Some(true));
        assert!(parsed.extra_codegen.is_empty());
    }

    #[test]
    fn other_unstable_options_still_count_as_custom_codegen() {
        for spelling in ["-Z some-other-flag", "-Zsome-other-flag"] {
            let mut invocation = vec![
                "--crate-name",
                "itoa",
                "--crate-type",
                "rlib",
                "--target",
                "aarch64-apple-darwin",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=abc123",
            ];
            invocation.extend(spelling.split(' '));
            let parsed = ParsedRustcArgs::parse(&args(&invocation)).expect("parser should succeed");

            assert_eq!(parsed.embed_metadata, None);
            assert!(keyed(&parsed));
            assert!(!parsed.extra_codegen.is_empty());
        }
    }

    #[test]
    fn malformed_embed_metadata_value_is_a_parse_error() {
        let error = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "-Z",
            "embed-metadata=banana",
        ]))
        .expect_err("malformed embed-metadata value must fail parsing");

        assert!(error.contains("invalid boolean rustc codegen value"));
    }

    #[test]
    fn accepts_common_codegen_flag_without_value() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "zerocopy_derive",
            "--crate-type",
            "proc-macro",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=pm123",
            "-C",
            "prefer-dynamic",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        assert!(parsed.is_proc_macro());
        assert!(parsed.extra_codegen.is_empty());
    }

    #[test]
    fn unknown_codegen_flag_without_value_is_not_cacheable() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "mystery-flag",
        ]))
        .expect("parser should succeed");

        // An unknown codegen flag is byte-representable: it keys
        // into extra-codegen and the unit is local-only (stow#1006).
        assert!(keyed(&parsed));
        assert!(parsed.extra_codegen.contains("-C mystery-flag"));
    }

    #[test]
    fn debug_profile_defaults_are_cacheable() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--crate-type",
            "lib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=fd828ed38da2eccd",
            "-C",
            "extra-filename=-d1c4311f6644f7fa",
            "-C",
            "split-debuginfo=unpacked",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        assert!(parsed.extra_codegen.is_empty());
    }

    #[test]
    fn implicit_host_target_is_cacheable() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "byteorder",
            "--crate-type",
            "lib",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=979b12f2cebb9d65",
            "-C",
            "extra-filename=-9c7162ae9201c5e4",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
    }

    #[test]
    fn optimized_dependency_is_still_restorable_for_ci_capture() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "regex",
            "--crate-type",
            "lib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "--json",
            "diagnostic-rendered-ansi,artifacts,future-incompat",
            "-C",
            "metadata=regex123",
            "-C",
            "extra-filename=-regex123",
            "-C",
            "opt-level=3",
            "-C",
            "debug-assertions=yes",
        ]))
        .expect("parser should succeed");

        assert!(parsed.is_restorable_artifact());
        assert!(keyed(&parsed));
        assert!(parsed.requests_json_artifact_notifications());
    }

    #[test]
    fn dylib_invocation_is_cacheable_in_debug_profile() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "bevy_dylib",
            "--crate-type",
            "dylib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=dylib123",
            "-C",
            "extra-filename=-dylib123",
            "-C",
            "opt-level=0",
            "-C",
            "debug-assertions=yes",
        ]))
        .expect("parser should succeed");

        assert!(keyed(&parsed));
        assert_eq!(
            parsed
                .output_dynamic_library_path("x86_64-unknown-linux-gnu")
                .expect("dylib path")
                .expect("dynamic library output"),
            PathBuf::from("/tmp/out/libbevy_dylib-dylib123.dylib")
        );
    }

    /// A host unit — a proc macro, a `dylib` — spells no `--target`; its
    /// dynamic library takes the compiling rustc's host naming, which a
    /// mock-compile run reports as the task's runner host (stow#773).
    #[test]
    fn a_target_less_dylib_is_named_for_the_compiling_host() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "pest_derive",
            "--crate-type",
            "proc-macro",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=pm123",
            "-C",
            "extra-filename=-pm123",
        ]))
        .expect("parser should succeed");

        for (host, expected) in [
            (
                "x86_64-unknown-linux-gnu",
                "/tmp/out/libpest_derive-pm123.so",
            ),
            ("x86_64-pc-windows-msvc", "/tmp/out/pest_derive-pm123.dll"),
            (
                "aarch64-apple-darwin",
                "/tmp/out/libpest_derive-pm123.dylib",
            ),
        ] {
            assert_eq!(
                parsed
                    .output_dynamic_library_path(host)
                    .expect("dylib path")
                    .expect("dynamic library output"),
                PathBuf::from(expected),
                "{host}"
            );
        }
    }

    #[test]
    fn proc_macro_metadata_output_uses_rmeta_path() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "pest_derive",
            "--crate-type",
            "proc-macro",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "--emit",
            "dep-info,metadata",
            "-C",
            "metadata=pm123",
            "-C",
            "extra-filename=-pm123",
        ]))
        .expect("parser should succeed");

        assert_eq!(
            parsed.output_rmeta_path().expect("proc-macro rmeta path"),
            PathBuf::from("/tmp/out/libpest_derive-pm123.rmeta")
        );
    }

    #[test]
    fn static_lib_crate_types_do_not_report_dynamic_library_output() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--crate-type",
            "lib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=lib123",
            "-C",
            "extra-filename=-lib123",
        ]))
        .expect("parser should succeed");

        assert!(parsed.produces_rlib());
        assert!(!parsed.produces_dynamic_library());
        assert_eq!(
            parsed
                .output_dynamic_library_path("aarch64-apple-darwin")
                .expect("dynamic library path"),
            None
        );
        assert_eq!(
            parsed
                .output_link_path("aarch64-apple-darwin")
                .expect("link path"),
            Some(PathBuf::from("/tmp/out/libunicode_ident-lib123.rlib"))
        );
    }

    #[test]
    fn build_script_paths_match_cargo_naming() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "build_script_build",
            "--crate-type",
            "bin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=e8a2e5854cc9f44b",
            "-C",
            "extra-filename=-fbf81822541b190b",
        ]))
        .expect("parser should succeed");

        assert!(parsed.is_build_script());
        assert_eq!(
            parsed
                .output_binary_path("aarch64-apple-darwin")
                .expect("build script output"),
            Some(PathBuf::from(
                "/tmp/out/build_script_build-fbf81822541b190b"
            ))
        );
        assert_eq!(
            parsed
                .build_script_alias_path("aarch64-apple-darwin")
                .expect("build script alias"),
            Some(PathBuf::from("/tmp/out/build-script-build"))
        );
    }

    /// A build script binary is named for the host the compiling rustc
    /// reports — `.exe` on a Windows runner — not for the machine stow
    /// happens to run on (stow#773).
    #[test]
    fn a_build_script_is_named_for_the_compiling_host() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "build_script_build",
            "--crate-type",
            "bin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=e8a2e5854cc9f44b",
            "-C",
            "extra-filename=-fbf81822541b190b",
        ]))
        .expect("parser should succeed");

        assert_eq!(
            parsed
                .output_binary_path("x86_64-pc-windows-msvc")
                .expect("build script output"),
            Some(PathBuf::from(
                "/tmp/out/build_script_build-fbf81822541b190b.exe"
            ))
        );
        assert_eq!(
            parsed
                .build_script_alias_path("x86_64-pc-windows-msvc")
                .expect("build script alias"),
            Some(PathBuf::from("/tmp/out/build-script-build.exe"))
        );
        assert_eq!(
            parsed
                .output_binary_path("x86_64-unknown-linux-gnu")
                .expect("build script output"),
            Some(PathBuf::from(
                "/tmp/out/build_script_build-fbf81822541b190b"
            ))
        );
    }

    #[test]
    #[serial_test::serial]
    fn env_remap_rustflags_do_not_enter_the_key() {
        // `--remap-path-prefix` on argv is ignored by the parser, and in
        // env it is not the invocation's: either way nothing keys.
        unsafe {
            std::env::set_var(
                "RUSTFLAGS",
                "--remap-path-prefix=/tmp/work=stow-ci://workspace",
            );
        }
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "cfg_if",
            "--crate-type",
            "lib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=cfgif123",
        ]))
        .expect("parser should succeed");
        unsafe {
            std::env::remove_var("RUSTFLAGS");
        }

        assert!(keyed(&parsed));
        assert!(parsed.extra_codegen.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn env_link_rustflags_do_not_enter_the_key() {
        // Cargo puts env rustflags on the argv of every unit they apply
        // to — an env-only flag was not applied to this unit (a host
        // unit under --target), so keying on it would collide this unit
        // with a target unit that compiled with the flag (stow#1006).
        for value in [
            "-C link-arg=-fuse-ld=mold",
            "-Clink-arg=-fuse-ld=mold",
            "--codegen=link-arg=-fuse-ld=mold",
            "--remap-path-prefix=/tmp/work=stow-ci://workspace -C linker=clang",
        ] {
            unsafe {
                std::env::set_var("RUSTFLAGS", value);
            }
            let parsed = ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "cfg_if",
                "--crate-type",
                "lib",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--out-dir",
                "/tmp/out",
                "-C",
                "metadata=cfgif123",
            ]))
            .expect("parser should succeed");
            unsafe {
                std::env::remove_var("RUSTFLAGS");
            }

            assert!(keyed(&parsed), "{value} made unit uncacheable");
            assert!(
                parsed.extra_codegen.is_empty(),
                "{value} entered the key without being on argv"
            );
            assert!(
                parsed.link_options.is_empty(),
                "{value} entered link options without being on argv"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn env_rustflags_with_link_and_codegen_do_not_enter_the_key() {
        unsafe {
            std::env::set_var(
                "RUSTFLAGS",
                "-C link-arg=-fuse-ld=mold -C target-cpu=native",
            );
        }
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "cfg_if",
            "--crate-type",
            "lib",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=cfgif123",
        ]))
        .expect("parser should succeed");
        unsafe {
            std::env::remove_var("RUSTFLAGS");
        }

        assert!(keyed(&parsed));
        assert!(parsed.extra_codegen.is_empty());
        assert!(parsed.link_options.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn env_target_cpu_native_does_not_enter_the_key() {
        unsafe {
            std::env::set_var("RUSTFLAGS", "-C target-cpu=native");
        }
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "cfg_if",
            "--crate-type",
            "lib",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=cfgif123",
        ]))
        .expect("parser should succeed");
        unsafe {
            std::env::remove_var("RUSTFLAGS");
        }

        assert!(keyed(&parsed));
        assert!(parsed.extra_codegen.is_empty());
    }

    #[test]
    fn parses_json_artifact_requests() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "lib",
            "--out-dir",
            "/tmp/out",
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
            "-C",
            "metadata=json123",
        ]))
        .expect("parser should succeed");

        assert!(parsed.requests_json_artifact_notifications());
        assert!(parsed.json.contains("diagnostic-rendered-ansi"));
        assert!(parsed.json.contains("future-incompat"));
    }

    #[test]
    fn parses_extern_crates() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "grep_searcher",
            "--crate-type",
            "lib",
            "--out-dir",
            "/tmp/out",
            "--extern",
            "memchr=/tmp/deps/libmemchr-aaaaaaaaaaaaaaaa.rmeta",
            "--extern=regex_automata=/tmp/deps/libregex_automata-bbbbbbbbbbbbbbbb.rmeta",
            "-C",
            "metadata=grepsearcher123",
        ]))
        .expect("parser should succeed");

        assert_eq!(parsed.extern_crates.len(), 2);
        assert_eq!(parsed.extern_crates[0].crate_name, "memchr");
        assert_eq!(
            parsed.extern_crates[0].path,
            PathBuf::from("/tmp/deps/libmemchr-aaaaaaaaaaaaaaaa.rmeta")
        );
        assert_eq!(parsed.extern_crates[1].crate_name, "regex_automata");
    }

    #[test]
    fn strip_level_is_part_of_the_profile() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "itoa",
            "--crate-type",
            "rlib",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "strip=debuginfo",
        ]))
        .expect("parser should succeed");
        assert!(parsed.extra_codegen.is_empty());
        assert_eq!(parsed.strip.as_deref(), Some("debuginfo"));
        assert_eq!(
            parsed.profile().expect("profile").strip,
            StripLevel::Debuginfo
        );

        let error = ParsedRustcArgs::parse(&args(&["--crate-name", "itoa", "-C", "strip=all"]))
            .expect("parser should succeed")
            .profile()
            .expect_err("unknown strip level must fail");
        assert!(error.contains("strip"), "{error}");
    }
}
