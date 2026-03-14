use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRustcArgs {
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub features: BTreeSet<String>,
    pub target: Option<String>,
    pub c_metadata: Option<String>,
    pub out_dir: Option<PathBuf>,
    pub extra_filename: String,
    pub opt_level: Option<String>,
    pub debuginfo: Option<String>,
    pub panic_strategy: Option<String>,
    pub debug_assertions: Option<bool>,
    pub overflow_checks: Option<bool>,
    pub has_custom_codegen: bool,
}

impl ParsedRustcArgs {
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut parsed = ParsedRustcArgs {
            crate_name: String::new(),
            crate_types: Vec::new(),
            features: BTreeSet::new(),
            target: None,
            c_metadata: None,
            out_dir: None,
            extra_filename: String::new(),
            opt_level: None,
            debuginfo: None,
            panic_strategy: None,
            debug_assertions: None,
            overflow_checks: None,
            has_custom_codegen: env_has_custom_codegen_flags(),
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(arg) = arg.to_str() else {
                return Err(format!("rustc argument is not valid UTF-8: {arg:?}"));
            };

            match arg {
                "--crate-name" => {
                    parsed.crate_name = next_str(&mut iter, "--crate-name")?.to_owned();
                }
                "--crate-type" => {
                    parsed.crate_types = next_str(&mut iter, "--crate-type")?
                        .split(',')
                        .map(str::to_owned)
                        .collect();
                }
                "--target" => {
                    parsed.target = Some(next_str(&mut iter, "--target")?.to_owned());
                }
                "--cfg" => {
                    let cfg = next_str(&mut iter, "--cfg")?;
                    if let Some(feature) = parse_feature_cfg(cfg) {
                        parsed.features.insert(feature);
                    }
                }
                "--out-dir" => {
                    parsed.out_dir = Some(PathBuf::from(next_os(&mut iter, "--out-dir")?));
                }
                "-C" => {
                    parse_codegen_option(next_str(&mut iter, "-C")?, &mut parsed)?;
                }
                value if value.starts_with("-C") => {
                    let option = value
                        .strip_prefix("-C")
                        .expect("prefix checked above");
                    parse_codegen_option(option, &mut parsed)?;
                }
                value if value == "-Z" || value.starts_with("-Z") => {
                    parsed.has_custom_codegen = true;
                    if value == "-Z" {
                        let _ = next_str(&mut iter, "-Z")?;
                    }
                }
                _ => {}
            }
        }

        if parsed.crate_name.is_empty() {
            return Err("missing --crate-name in rustc arguments".to_owned());
        }

        Ok(parsed)
    }

    pub fn is_cacheable(&self) -> bool {
        if self.has_custom_codegen {
            return false;
        }
        if std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some() {
            return false;
        }

        let is_proc_macro = self.crate_types.iter().any(|kind| kind == "proc-macro");
        let is_rlib = self
            .crate_types
            .iter()
            .any(|kind| kind == "lib" || kind == "rlib");
        if !(is_proc_macro || is_rlib) {
            return false;
        }

        if self.c_metadata.is_none() || self.out_dir.is_none() || self.target.is_none() {
            return false;
        }

        if is_proc_macro {
            return true;
        }

        self.opt_level.as_deref() == Some("0") && self.debug_assertions != Some(false)
    }

    pub fn is_proc_macro(&self) -> bool {
        self.crate_types.iter().any(|kind| kind == "proc-macro")
    }

    pub fn output_rlib_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        if self.is_proc_macro() {
            return None;
        }
        Some(out_dir.join(format!(
            "lib{}{}.rlib",
            self.crate_name, self.extra_filename
        )))
    }

    pub fn output_rmeta_path(&self) -> Option<PathBuf> {
        let out_dir = self.out_dir.as_ref()?;
        if self.is_proc_macro() {
            return None;
        }
        Some(out_dir.join(format!(
            "lib{}{}.rmeta",
            self.crate_name, self.extra_filename
        )))
    }
}

fn parse_codegen_option(option: &str, parsed: &mut ParsedRustcArgs) -> Result<(), String> {
    let (key, value) = option
        .split_once('=')
        .ok_or_else(|| format!("unsupported -C option without value: {option}"))?;

    match key {
        "metadata" => parsed.c_metadata = Some(value.to_owned()),
        "extra-filename" => parsed.extra_filename = value.to_owned(),
        "opt-level" => parsed.opt_level = Some(value.to_owned()),
        "debuginfo" => parsed.debuginfo = Some(value.to_owned()),
        "panic" => parsed.panic_strategy = Some(value.to_owned()),
        "debug-assertions" => parsed.debug_assertions = Some(parse_bool(value)?),
        "overflow-checks" => parsed.overflow_checks = Some(parse_bool(value)?),
        "embed-bitcode" | "codegen-units" => {}
        "target-cpu" | "target-feature" => parsed.has_custom_codegen = true,
        _ => parsed.has_custom_codegen = true,
    }

    Ok(())
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
    std::env::var_os("RUSTFLAGS").is_some() || std::env::var_os("CARGO_ENCODED_RUSTFLAGS").is_some()
}

#[cfg(test)]
mod tests {
    use super::ParsedRustcArgs;

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
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
        assert!(parsed.is_cacheable());
        assert!(parsed.features.contains("default"));
        assert!(parsed
            .output_rlib_path()
            .expect("rlib path")
            .ends_with("libitoa-abc123.rlib"));
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

        assert!(!parsed.is_cacheable());
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

        assert!(parsed.is_cacheable());
        assert!(parsed.is_proc_macro());
    }
}
