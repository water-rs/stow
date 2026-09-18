//! Parser for the rustc command line the wrapper observes, plus helpers that
//! decide cacheability and predict output paths from the parsed arguments.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use target_lexicon::{BinaryFormat, Triple};

use crate::platform::{PanicStrategy, Profile};

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
    /// `-L native=…` search paths.
    pub native_search_paths: Vec<PathBuf>,
    /// `--extern` pairs, sorted by crate name then path.
    pub extern_crates: Vec<ParsedExternCrate>,
    /// Whether the invocation (or `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS`)
    /// carries codegen flags stow does not model; such builds are never
    /// served from the public cache.
    pub has_custom_codegen: bool,
}

impl ParsedRustcArgs {
    /// Parse a captured rustc argv into `ParsedRustcArgs`.
    ///
    /// Recognizes the flags cargo passes for dependency compilations. Unknown
    /// `-C` / `-Z` options set `has_custom_codegen` rather than failing, so
    /// the invocation is still parsed — it just will not be cacheable.
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
            native_search_paths: Vec::new(),
            extern_crates: Vec::new(),
            has_custom_codegen: env_has_custom_codegen_flags(),
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

    /// Whether this invocation may be served from the public cache.
    ///
    /// Requires a restorable artifact, no custom codegen flags, and no
    /// `CARGO_PRIMARY_PACKAGE` (workspace crates are never cached). Proc
    /// macros are cacheable in any profile; other crates only in the debug
    /// shape (`opt-level=0` with debug assertions not explicitly disabled).
    #[must_use]
    pub fn is_cacheable(&self) -> bool {
        if !self.is_restorable_artifact() {
            return false;
        }
        if self.has_custom_codegen {
            return false;
        }
        if std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some() {
            return false;
        }

        if self.is_proc_macro() {
            return true;
        }

        self.opt_level.as_deref().unwrap_or("0") == "0" && self.debug_assertions != Some(false)
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
    /// target's binary format (`lib*.so` / `lib*.dylib` / `*.dll`).
    ///
    /// Returns `Ok(None)` when the invocation produces no dynamic library.
    ///
    /// # Errors
    /// Returns an error when a dynamic library is produced but `--out-dir` is
    /// absent, or when the `--target` triple is unparseable or has an
    /// unsupported binary format.
    pub fn output_dynamic_library_path(&self) -> Result<Option<PathBuf>, String> {
        if !self.produces_dynamic_library() {
            return Ok(None);
        }
        let out_dir = self
            .out_dir
            .as_ref()
            .ok_or_else(|| "dynamic library output requires --out-dir".to_owned())?;
        let (prefix, extension) = match self.target.as_deref() {
            Some(target) => dynamic_library_naming(target)?,
            None => (
                std::env::consts::DLL_PREFIX,
                std::env::consts::DLL_SUFFIX
                    .strip_prefix('.')
                    .unwrap_or(std::env::consts::DLL_SUFFIX),
            ),
        };

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
    /// (`<name><extra-filename><exe-suffix>`), or `None` when the invocation
    /// is not a `bin` crate or has no `--out-dir`.
    #[must_use]
    pub fn output_binary_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        if !self.is_binary() {
            return None;
        }
        Some(out_dir.join(format!(
            "{}{}{}",
            self.crate_name,
            self.extra_filename,
            std::env::consts::EXE_SUFFIX
        )))
    }

    /// Path of the artifact a downstream crate would link against: the
    /// `.rlib`, then the binary, then the dynamic library.
    ///
    /// # Errors
    /// Propagates [`Self::output_dynamic_library_path`]'s error when the
    /// invocation produces a dynamic library without `--out-dir` or with an
    /// unparseable target.
    pub fn output_link_path(&self) -> Result<Option<PathBuf>, String> {
        if let Some(path) = self.output_rlib_path() {
            return Ok(Some(path));
        }
        if let Some(path) = self.output_binary_path() {
            return Ok(Some(path));
        }
        self.output_dynamic_library_path()
    }

    /// The `build-script-build` alias cargo creates next to the build script
    /// binary, or `None` when this is not a build script or `--out-dir` is
    /// absent.
    #[must_use]
    pub fn build_script_alias_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        if !self.is_build_script() {
            return None;
        }
        Some(out_dir.join(format!(
            "build-script-build{}",
            std::env::consts::EXE_SUFFIX
        )))
    }

    /// The cargo profile this invocation compiles with, defaulting absent
    /// flags to cargo's debug values (`opt-level=0`, debug assertions and
    /// overflow checks on, `panic=unwind`).
    ///
    /// # Errors
    /// Returns an error when `-C debuginfo` or `-C panic` carry values
    /// outside the set rustc documents.
    pub fn profile(&self) -> Result<Profile, String> {
        Ok(Profile {
            opt_level: self.opt_level.clone().unwrap_or_else(|| "0".to_owned()),
            debuginfo: parse_debuginfo_level(self.debuginfo.as_deref())?,
            debug_assertions: self.debug_assertions.unwrap_or(true),
            overflow_checks: self.overflow_checks.unwrap_or(true),
            panic: parse_panic_strategy(self.panic_strategy.as_deref())?,
        })
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
    if arg == "-Z" || arg.starts_with("-Z") {
        parsed.has_custom_codegen = true;
        if arg == "-Z" {
            let _ = next_str(iter, "-Z")?;
        }
        return Ok(());
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

fn apply_crate_types(value: &str, parsed: &mut ParsedRustcArgs) {
    parsed.crate_types = value.split(',').map(str::to_owned).collect();
}

fn apply_target(value: &str, parsed: &mut ParsedRustcArgs) {
    parsed.target = Some(value.to_owned());
}

fn apply_cfg(value: &str, parsed: &mut ParsedRustcArgs) {
    if let Some(feature) = parse_feature_cfg(value) {
        parsed.features.insert(feature);
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

fn parse_codegen_option(option: &str, parsed: &mut ParsedRustcArgs) -> Result<(), String> {
    let Some((key, value)) = option.split_once('=') else {
        match option {
            "prefer-dynamic" => {}
            _ => parsed.has_custom_codegen = true,
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
        "embed-bitcode" | "codegen-units" | "split-debuginfo" => {}
        // `strip=none` is the default and changes nothing; any real strip
        // level alters the emitted artifact and disqualifies the invocation
        // from the public cache (CI never builds stripped variants).
        "strip" if value == "none" => {}
        _ => parsed.has_custom_codegen = true,
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

fn env_has_custom_codegen_flags() -> bool {
    let has_encoded = std::env::var_os("CARGO_ENCODED_RUSTFLAGS").is_some();
    let has_rustflags = std::env::var_os("RUSTFLAGS").is_some();
    if !has_encoded && !has_rustflags {
        return false;
    }

    env_rustflags_are_custom()
}

fn env_rustflags_are_custom() -> bool {
    let mut flags = encoded_rustflags();
    match split_rustflags_env() {
        Ok(extra) => flags.extend(extra),
        Err(error) => {
            tracing::warn!(
                %error,
                "RUSTFLAGS could not be parsed — treating as custom codegen (cache disabled)"
            );
            return true;
        }
    }
    if flags.is_empty() {
        return false;
    }

    let mut iter = flags.into_iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--remap-path-prefix" => {
                if iter.next().is_none() {
                    return true;
                }
            }
            _ if flag.starts_with("--remap-path-prefix=") => {}
            _ => return true,
        }
    }

    false
}

fn encoded_rustflags() -> Vec<String> {
    std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .ok()
        .into_iter()
        .flat_map(|value| value.split('\x1f').map(str::to_owned).collect::<Vec<_>>())
        .filter(|value| !value.is_empty())
        .collect()
}

fn split_rustflags_env() -> Result<Vec<String>, shell_words::ParseError> {
    std::env::var("RUSTFLAGS").map_or_else(|_| Ok(Vec::new()), |value| shell_words::split(&value))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    fn with_clean_rustc_env<T>(f: impl FnOnce() -> T) -> T {
        let encoded = std::env::var_os("CARGO_ENCODED_RUSTFLAGS");
        let rustflags = std::env::var_os("RUSTFLAGS");
        let primary = std::env::var_os("CARGO_PRIMARY_PACKAGE");
        unsafe {
            std::env::remove_var("CARGO_ENCODED_RUSTFLAGS");
            std::env::remove_var("RUSTFLAGS");
            std::env::remove_var("CARGO_PRIMARY_PACKAGE");
        }
        let result = f();
        unsafe {
            match encoded {
                Some(value) => std::env::set_var("CARGO_ENCODED_RUSTFLAGS", value),
                None => std::env::remove_var("CARGO_ENCODED_RUSTFLAGS"),
            }
            match rustflags {
                Some(value) => std::env::set_var("RUSTFLAGS", value),
                None => std::env::remove_var("RUSTFLAGS"),
            }
            match primary {
                Some(value) => std::env::set_var("CARGO_PRIMARY_PACKAGE", value),
                None => std::env::remove_var("CARGO_PRIMARY_PACKAGE"),
            }
        }
        result
    }

    #[test]
    #[serial_test::serial]
    fn parses_debug_rlib_invocation() {
        with_clean_rustc_env(|| {
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
            assert!(parsed.is_cacheable());
            assert!(parsed.features.contains("default"));
            assert!(
                parsed
                    .output_rlib_path()
                    .expect("rlib path")
                    .ends_with("libitoa-abc123.rlib")
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn parses_the_equals_spellings_of_every_flag_cargo_can_emit() {
        with_clean_rustc_env(|| {
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
            assert!(parsed.is_cacheable());
            assert!(parsed.features.contains("default"));
            assert!(
                parsed
                    .output_rlib_path()
                    .expect("rlib path")
                    .ends_with("libitoa-abc123.rlib")
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn equals_and_space_spellings_produce_the_same_parse() {
        with_clean_rustc_env(|| {
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
            assert_eq!(space.out_dir, equals.out_dir);
            assert_eq!(space.c_metadata, equals.c_metadata);
            assert_eq!(space.extra_filename, equals.extra_filename);
        });
    }

    #[test]
    #[serial_test::serial]
    fn rejects_custom_codegen() {
        with_clean_rustc_env(|| {
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

            assert!(!parsed.is_cacheable());
        });
    }

    #[test]
    #[serial_test::serial]
    fn proc_macro_is_cacheable_without_debug_profile() {
        with_clean_rustc_env(|| {
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

            assert!(parsed.is_cacheable());
            assert!(parsed.is_proc_macro());
        });
    }

    #[test]
    #[serial_test::serial]
    fn accepts_common_codegen_flag_without_value() {
        with_clean_rustc_env(|| {
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

            assert!(parsed.is_cacheable());
            assert!(parsed.is_proc_macro());
            assert!(!parsed.has_custom_codegen);
        });
    }

    #[test]
    #[serial_test::serial]
    fn unknown_codegen_flag_without_value_is_not_cacheable() {
        with_clean_rustc_env(|| {
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

            assert!(!parsed.is_cacheable());
            assert!(parsed.has_custom_codegen);
        });
    }

    #[test]
    #[serial_test::serial]
    fn debug_profile_defaults_are_cacheable() {
        with_clean_rustc_env(|| {
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

            assert!(parsed.is_cacheable());
            assert!(!parsed.has_custom_codegen);
        });
    }

    #[test]
    #[serial_test::serial]
    fn implicit_host_target_is_cacheable() {
        with_clean_rustc_env(|| {
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

            assert!(parsed.is_cacheable());
        });
    }

    #[test]
    #[serial_test::serial]
    fn optimized_dependency_is_still_restorable_for_ci_capture() {
        with_clean_rustc_env(|| {
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
            assert!(!parsed.is_cacheable());
            assert!(parsed.requests_json_artifact_notifications());
        });
    }

    #[test]
    #[serial_test::serial]
    fn dylib_invocation_is_cacheable_in_debug_profile() {
        with_clean_rustc_env(|| {
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

            assert!(parsed.is_cacheable());
            assert_eq!(
                parsed
                    .output_dynamic_library_path()
                    .expect("dylib path")
                    .expect("dynamic library output"),
                PathBuf::from("/tmp/out/libbevy_dylib-dylib123.dylib")
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn proc_macro_metadata_output_uses_rmeta_path() {
        with_clean_rustc_env(|| {
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
        });
    }

    #[test]
    #[serial_test::serial]
    fn static_lib_crate_types_do_not_report_dynamic_library_output() {
        with_clean_rustc_env(|| {
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
                    .output_dynamic_library_path()
                    .expect("dynamic library path"),
                None
            );
            assert_eq!(
                parsed.output_link_path().expect("link path"),
                Some(PathBuf::from("/tmp/out/libunicode_ident-lib123.rlib"))
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn build_script_paths_match_cargo_naming() {
        with_clean_rustc_env(|| {
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
                parsed.output_binary_path().expect("build script output"),
                PathBuf::from("/tmp/out/build_script_build-fbf81822541b190b")
            );
            assert_eq!(
                parsed
                    .build_script_alias_path()
                    .expect("build script alias"),
                PathBuf::from("/tmp/out/build-script-build")
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn remap_rustflags_do_not_disable_cacheability() {
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

        assert!(parsed.is_cacheable());
        assert!(!parsed.has_custom_codegen);
    }

    #[test]
    #[serial_test::serial]
    fn custom_env_rustflags_disable_cacheability() {
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

        assert!(!parsed.is_cacheable());
        assert!(parsed.has_custom_codegen);
    }

    #[test]
    #[serial_test::serial]
    fn parses_json_artifact_requests() {
        with_clean_rustc_env(|| {
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
        });
    }

    #[test]
    #[serial_test::serial]
    fn parses_extern_crates() {
        with_clean_rustc_env(|| {
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
        });
    }
}
