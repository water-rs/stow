use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use async_process::Command;
use sha2::{Digest, Sha256};
use stow_types::error::Context;

use crate::config::StowConfig;

// The compiler-resolution half lives in `stow_facade` — the `stow cc`
// facades' cold path resolves the toolchain there too (stow#347).
pub use stow_facade::cc::ResolvedCompiler;
#[cfg(test)]
pub use stow_facade::cc::{CcKind, resolve_compiler};

const PROBE_FLAGS: &[&str] = &[
    "--version",
    "-v",
    "-V",
    "-dumpversion",
    "-dumpmachine",
    "-print-search-dirs",
];
const FLAGS_WITH_VALUE: &[&str] = &[
    "-I",
    "-isystem",
    "-include",
    "-imacros",
    "-iquote",
    "-idirafter",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-x",
    "-std",
    "-target",
    "-arch",
    "-D",
    "-U",
    "-Xpreprocessor",
    "-Xclang",
    "-Xlinker",
    "-Xassembler",
];

/// Which header set the requested depfile must record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepfileMode {
    /// `-MMD`: user headers only.
    UserHeadersOnly,
    /// `-MD`: all headers, including system headers.
    AllHeaders,
}

/// A depfile rule target requested via `-MT` or `-MQ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepfileTarget {
    /// `-MT`: target name used verbatim.
    Plain(OsString),
    /// `-MQ`: target name the compiler make-quotes when emitting the rule.
    Quoted(OsString),
}

/// A `-MD`/`-MMD` depfile request extracted from the compiler invocation.
#[derive(Debug, Clone)]
pub struct DepfileRequest {
    pub mode: DepfileMode,
    pub path: PathBuf,
    pub targets: Vec<DepfileTarget>,
    pub phony_headers: bool,
}

impl DepfileRequest {
    /// Append the equivalent depfile flags to a compiler command so the
    /// preprocessor pass writes the requested depfile as a side effect.
    fn append_compiler_args(&self, command: &mut Command) {
        command.arg(match self.mode {
            DepfileMode::UserHeadersOnly => "-MMD",
            DepfileMode::AllHeaders => "-MD",
        });
        command.arg("-MF").arg(&self.path);
        for target in &self.targets {
            match target {
                DepfileTarget::Plain(value) => command.arg("-MT").arg(value),
                DepfileTarget::Quoted(value) => command.arg("-MQ").arg(value),
            };
        }
        if self.phony_headers {
            command.arg("-MP");
        }
    }
}

/// How a `-M`-family argument was handled while scanning the command line.
enum DepfileArg {
    /// Not a depfile flag; the main parser handles the argument.
    Unrelated,
    /// A depfile option was recorded.
    Consumed,
    /// A dependency mode that produces no cacheable object (`-M`, `-MM`,
    /// `-MG`, `-MJ`); the invocation must pass through to the real compiler.
    Passthrough,
}

/// Accumulates `-M`-family depfile options while scanning a compile command
/// line.
#[derive(Default)]
struct DepfileOptions {
    mode: Option<DepfileMode>,
    path: Option<PathBuf>,
    targets: Vec<DepfileTarget>,
    phony_headers: bool,
}

impl DepfileOptions {
    fn consume(
        &mut self,
        arg: &str,
        iter: &mut std::slice::Iter<'_, OsString>,
    ) -> stow_types::error::Result<DepfileArg> {
        match arg {
            "-MD" => self.mode = Some(DepfileMode::AllHeaders),
            "-MMD" => self.mode = Some(DepfileMode::UserHeadersOnly),
            "-MP" => self.phony_headers = true,
            "-M" | "-MM" | "-MG" | "-MJ" => return Ok(DepfileArg::Passthrough),
            "-MF" | "-MT" | "-MQ" => {
                let Some(value) = iter.next() else {
                    return Err(stow_types::stow_error!("missing value after {arg}"));
                };
                self.apply(arg, value);
            }
            _ if arg.starts_with("-MJ") => return Ok(DepfileArg::Passthrough),
            _ => {
                if arg.len() <= 3 {
                    return Ok(DepfileArg::Unrelated);
                }
                let (flag, value) = arg.split_at(3);
                if !matches!(flag, "-MF" | "-MT" | "-MQ") {
                    return Ok(DepfileArg::Unrelated);
                }
                self.apply(flag, OsStr::new(value));
            }
        }
        Ok(DepfileArg::Consumed)
    }

    fn apply(&mut self, flag: &str, value: &OsStr) {
        match flag {
            "-MF" => self.path = Some(PathBuf::from(value)),
            "-MT" => self.targets.push(DepfileTarget::Plain(value.to_owned())),
            "-MQ" => self.targets.push(DepfileTarget::Quoted(value.to_owned())),
            _ => unreachable!("depfile value flag {flag}"),
        }
    }

    /// Whether depfile side-options (`-MF`, `-MT`, `-MQ`, `-MP`) were given
    /// without a `-MD`/`-MMD` mode — a shape stow does not reproduce.
    const fn side_options_without_mode(&self) -> bool {
        self.mode.is_none()
            && (self.path.is_some() || !self.targets.is_empty() || self.phony_headers)
    }

    fn build(self, output_path: &Path) -> Option<DepfileRequest> {
        self.mode.map(|mode| DepfileRequest {
            mode,
            path: self.path.unwrap_or_else(|| output_path.with_extension("d")),
            targets: if self.targets.is_empty() {
                vec![DepfileTarget::Plain(output_path.as_os_str().to_owned())]
            } else {
                self.targets
            },
            phony_headers: self.phony_headers,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedCcInvocation {
    pub output_path: PathBuf,
    pub depfile: Option<DepfileRequest>,
    pub preprocess_args: Vec<OsString>,
    pub compile_hash_args: Vec<OsString>,
}

pub async fn try_compile(
    config: &StowConfig,
    compiler: &ResolvedCompiler,
    compiler_args: &[OsString],
) -> stow_types::error::Result<CcOutcome> {
    let expanded_args = expand_response_args(compiler_args)?;
    let Some(parsed) = ParsedCcInvocation::parse(&expanded_args)? else {
        return Ok(CcOutcome::Passthrough);
    };
    let compiler_fingerprint = compiler_fingerprint(compiler).await?;
    if let Some(depfile) = parsed.depfile.as_ref()
        && let Some(parent) = depfile.path.parent()
        && !parent.as_os_str().is_empty()
    {
        // clang creates the depfile's parent directory while gcc errors on a
        // missing one; stow follows clang.
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create C depfile directory {}", parent.display()))?;
    }
    let preprocessed = preprocess_source(compiler, &parsed).await?;
    let cache_key = cache_key(&compiler_fingerprint, &parsed, &preprocessed);
    let cache_path = cc_cache_path(config, &cache_key);

    if let Some(parent) = cache_path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create C cache directory {}", parent.display()))?;
    }

    if cache_path.exists() {
        let object = async_fs::read(&cache_path)
            .await
            .wrap_err_with(|| format!("read cached object {}", cache_path.display()))?;
        if let Some(parent) = parsed.output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            async_fs::create_dir_all(parent)
                .await
                .wrap_err_with(|| format!("create C output directory {}", parent.display()))?;
        }
        async_fs::write(&parsed.output_path, object)
            .await
            .wrap_err_with(|| format!("write cached object {}", parsed.output_path.display()))?;
        return Ok(CcOutcome::Hit {
            cache_key,
            output_path: parsed.output_path,
        });
    }

    Ok(CcOutcome::Miss {
        cache_key,
        cache_path,
        output_path: parsed.output_path,
    })
}

pub fn expand_response_args(args: &[OsString]) -> stow_types::error::Result<Vec<OsString>> {
    let mut expanded = Vec::with_capacity(args.len());
    for arg in args {
        expand_response_arg(arg, 0, &mut expanded)?;
    }
    Ok(expanded)
}

fn expand_response_arg(
    arg: &OsString,
    depth: usize,
    output: &mut Vec<OsString>,
) -> stow_types::error::Result<()> {
    if depth > 8 {
        return Err(stow_types::stow_error!(
            "C compiler response file nesting exceeds maximum depth"
        ));
    }
    let Some(raw) = arg.to_str() else {
        output.push(arg.clone());
        return Ok(());
    };
    let Some(path) = raw.strip_prefix('@') else {
        output.push(arg.clone());
        return Ok(());
    };
    if path.is_empty() {
        return Err(stow_types::stow_error!(
            "invalid empty C compiler response file argument"
        ));
    }
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read C compiler response file {path}"))?;
    let tokens = shell_words::split(&contents).map_err(|error| {
        stow_types::stow_error!("parse C compiler response file {path}: {error}")
    })?;
    for token in tokens {
        let nested = OsString::from(token);
        expand_response_arg(&nested, depth + 1, output)?;
    }
    Ok(())
}

pub async fn store_compiled_object(
    cache_path: &Path,
    output_path: &Path,
) -> stow_types::error::Result<()> {
    let object = async_fs::read(output_path)
        .await
        .wrap_err_with(|| format!("read compiled object {}", output_path.display()))?;
    async_fs::write(cache_path, object)
        .await
        .wrap_err_with(|| format!("write compiled object cache {}", cache_path.display()))
}

fn cc_cache_path(config: &StowConfig, cache_key: &str) -> PathBuf {
    config.cache_dir.join("cc").join(format!("{cache_key}.o"))
}

/// The directory every cached C object lands in — the once-per-build
/// cold check reads its emptiness to decide the cc facades' path
/// (stow#347).
pub fn cache_root(config: &StowConfig) -> PathBuf {
    config.cache_dir.join("cc")
}

pub async fn compiler_fingerprint(
    compiler: &ResolvedCompiler,
) -> stow_types::error::Result<Vec<u8>> {
    let output = Command::new(&compiler.program)
        .arg("--version")
        .envs(compiler.env.iter().cloned())
        .output()
        .await
        .wrap_err("spawn compiler --version")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "compiler --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

pub async fn preprocess_source(
    compiler: &ResolvedCompiler,
    parsed: &ParsedCcInvocation,
) -> stow_types::error::Result<Vec<u8>> {
    let mut command = Command::new(&compiler.program);
    command
        .args(&parsed.preprocess_args)
        .envs(compiler.env.iter().cloned());
    if let Some(depfile) = parsed.depfile.as_ref() {
        depfile.append_compiler_args(&mut command);
    }
    let output = command.output().await.wrap_err("spawn C preprocessor")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "C preprocessing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

pub fn cache_key(
    compiler_fingerprint: &[u8],
    parsed: &ParsedCcInvocation,
    preprocessed: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"stow-cc-v1");
    hasher.update(compiler_fingerprint);
    for arg in &parsed.compile_hash_args {
        hash_os_string(&mut hasher, arg);
    }
    hasher.update(preprocessed);
    hex::encode(hasher.finalize())
}

fn hash_os_string(hasher: &mut Sha256, value: &OsStr) {
    let encoded = value.to_string_lossy();
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded.as_bytes());
}

impl ParsedCcInvocation {
    pub fn parse(args: &[OsString]) -> stow_types::error::Result<Option<Self>> {
        if args.is_empty() {
            return Ok(None);
        }
        if args
            .iter()
            .filter_map(|arg| arg.to_str())
            .any(|arg| PROBE_FLAGS.contains(&arg))
        {
            return Ok(None);
        }

        let mut source_path = None;
        let mut output_path = None;
        let mut depfile_options = DepfileOptions::default();
        let mut preprocess_args = Vec::new();
        let mut compile_hash_args = Vec::new();
        let mut iter = args.iter();
        let mut seen_compile_flag = false;

        while let Some(arg) = iter.next() {
            let Some(arg_str) = arg.to_str() else {
                return Ok(None);
            };

            match depfile_options.consume(arg_str, &mut iter)? {
                DepfileArg::Consumed => continue,
                DepfileArg::Passthrough => return Ok(None),
                DepfileArg::Unrelated => {}
            }

            match arg_str {
                "-c" => {
                    seen_compile_flag = true;
                }
                "-o" => {
                    let Some(path) = iter.next() else {
                        return Err(stow_types::stow_error!("missing value after -o"));
                    };
                    output_path = Some(PathBuf::from(path));
                }
                flag if FLAGS_WITH_VALUE.contains(&flag) => {
                    let Some(value) = iter.next() else {
                        return Err(stow_types::stow_error!("missing value after {arg_str}"));
                    };
                    preprocess_args.push(arg.clone());
                    preprocess_args.push(value.clone());
                    compile_hash_args.push(arg.clone());
                    compile_hash_args.push(value.clone());
                }
                value if value.starts_with("-o") && value.len() > 2 => {
                    output_path = Some(PathBuf::from(&value[2..]));
                }
                value
                    if value.starts_with("-I")
                        || value.starts_with("-D")
                        || value.starts_with("-U")
                        || value.starts_with("-std=")
                        || value.starts_with("-isystem")
                        || value.starts_with("-include")
                        || value.starts_with("-imacros")
                        || value.starts_with("-iquote")
                        || value.starts_with("-target")
                        || value.starts_with("-arch") =>
                {
                    preprocess_args.push(arg.clone());
                    compile_hash_args.push(arg.clone());
                }
                value if value.starts_with('-') => {
                    preprocess_args.push(arg.clone());
                    compile_hash_args.push(arg.clone());
                }
                _ => {
                    if source_path.is_some() {
                        return Ok(None);
                    }
                    source_path = Some(PathBuf::from(arg));
                    preprocess_args.push(arg.clone());
                }
            }
        }

        if !seen_compile_flag {
            return Ok(None);
        }

        let Some(_source_path) = source_path else {
            return Ok(None);
        };
        let Some(output_path) = output_path else {
            return Ok(None);
        };

        if depfile_options.side_options_without_mode() {
            return Ok(None);
        }
        let depfile = depfile_options.build(&output_path);

        preprocess_args.push(OsString::from("-E"));
        preprocess_args.push(OsString::from("-P"));

        Ok(Some(Self {
            output_path,
            depfile,
            preprocess_args,
            compile_hash_args,
        }))
    }
}

#[derive(Debug, Clone)]
pub enum CcOutcome {
    Passthrough,
    Hit {
        cache_key: String,
        output_path: PathBuf,
    },
    Miss {
        cache_key: String,
        cache_path: PathBuf,
        output_path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use super::CcOutcome;
    use super::{DepfileMode, DepfileTarget, ParsedCcInvocation};
    #[cfg(unix)]
    use crate::config::{StowConfig, VerifyMode};

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[cfg(unix)]
    fn test_config(cache_dir: PathBuf) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787/v2/water-rs/stow-cache".to_owned(),
            cache_dir,
            request_timeout: Duration::from_secs(15),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            build_state: None,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: Duration::from_mins(1),
            verify_mode: VerifyMode::GithubCi,
            state_db_pool: StowConfig::default_state_db_pool(),
            trust_material: std::sync::Arc::default(),
        }
    }

    /// With no MSVC toolchain needed — a non-msvc target or a POSIX host —
    /// the resolution is the plain `cc`/`c++` driver name.
    #[test]
    fn non_msvc_targets_resolve_to_the_platform_driver() {
        #[cfg(not(windows))]
        let cases = [
            ("x86_64-unknown-linux-gnu", "cc"),
            ("x86_64-pc-windows-msvc", "cc"), // unreachable on POSIX
        ];
        #[cfg(windows)]
        let cases = [
            ("x86_64-pc-windows-gnu", "cc"),
            ("wasm32-unknown-unknown", "cc"),
        ];
        for (target, expected) in cases {
            let resolved = super::resolve_compiler(super::CcKind::C, Some(target));
            #[cfg(windows)]
            let resolved = resolved.expect("resolve");
            assert_eq!(resolved.program, OsString::from(expected));
            assert!(resolved.env.is_empty(), "env leaked for {target}");
        }
    }

    #[test]
    fn expands_response_file_arguments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rsp = dir.path().join("args.rsp");
        std::fs::write(&rsp, "-I include -DNAME=VALUE -c source.c -o source.o")
            .expect("write response file");
        let values = vec![OsString::from(format!("@{}", rsp.display()))];
        let expanded = super::expand_response_args(&values).expect("expand response args");
        assert_eq!(
            expanded,
            vec![
                OsString::from("-I"),
                OsString::from("include"),
                OsString::from("-DNAME=VALUE"),
                OsString::from("-c"),
                OsString::from("source.c"),
                OsString::from("-o"),
                OsString::from("source.o"),
            ]
        );
    }

    #[test]
    fn parses_basic_compile_invocation() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-O2",
            "-Wall",
            "-I",
            "include",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(parsed.output_path, std::path::PathBuf::from("out/foo.o"));
        assert!(parsed.preprocess_args.iter().any(|arg| arg == "-E"));
    }

    #[test]
    fn treats_version_probe_as_passthrough() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["--version"])).expect("parse should succeed");
        assert!(parsed.is_none());
    }

    #[test]
    fn parses_mmd_depfile_with_defaults_from_output_path() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["-MMD", "-c", "src/foo.c", "-o", "out/foo.o"]))
                .expect("parse should succeed")
                .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::UserHeadersOnly);
        assert_eq!(depfile.path, PathBuf::from("out/foo.d"));
        assert_eq!(
            depfile.targets,
            vec![DepfileTarget::Plain(OsString::from("out/foo.o"))]
        );
        assert!(!depfile.phony_headers);
    }

    #[test]
    fn parses_md_depfile_with_explicit_options() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MD",
            "-MF",
            "deps/x.d",
            "-MT",
            "x.o",
            "-MP",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::AllHeaders);
        assert_eq!(depfile.path, PathBuf::from("deps/x.d"));
        assert_eq!(
            depfile.targets,
            vec![DepfileTarget::Plain(OsString::from("x.o"))]
        );
        assert!(depfile.phony_headers);
    }

    #[test]
    fn parses_attached_depfile_option_forms() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MMD",
            "-MFfoo.d",
            "-MTfoo.o",
            "-MQbar.o",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::UserHeadersOnly);
        assert_eq!(depfile.path, PathBuf::from("foo.d"));
        assert_eq!(
            depfile.targets,
            vec![
                DepfileTarget::Plain(OsString::from("foo.o")),
                DepfileTarget::Quoted(OsString::from("bar.o")),
            ]
        );
        assert!(!depfile.phony_headers);
    }

    #[test]
    fn xpreprocessor_value_is_not_a_depfile_flag() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-Xpreprocessor",
            "-MD",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert!(parsed.depfile.is_none());
        assert_eq!(parsed.compile_hash_args, args(&["-Xpreprocessor", "-MD"]));
        assert_eq!(
            parsed.preprocess_args,
            args(&["-Xpreprocessor", "-MD", "src/foo.c", "-E", "-P"])
        );
    }

    #[test]
    fn xclang_value_is_not_a_depfile_flag() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["-Xclang", "-MF", "x.d", "-c", "-o", "out/foo.o"]))
                .expect("parse should succeed")
                .expect("compile should be cacheable");

        assert!(parsed.depfile.is_none());
        assert_eq!(parsed.compile_hash_args, args(&["-Xclang", "-MF"]));
        assert_eq!(
            parsed.preprocess_args,
            args(&["-Xclang", "-MF", "x.d", "-E", "-P"])
        );
    }

    #[test]
    fn repeated_mf_last_wins() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MD",
            "-MF",
            "first.d",
            "-MF",
            "second.d",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(
            parsed.depfile.expect("depfile request").path,
            PathBuf::from("second.d")
        );
    }

    #[test]
    fn repeated_md_mmd_last_wins() {
        for (flags, expected) in [
            (&["-MD", "-MMD"][..], DepfileMode::UserHeadersOnly),
            (&["-MMD", "-MD"][..], DepfileMode::AllHeaders),
        ] {
            let mut argv = flags.to_vec();
            argv.extend(["-c", "src/foo.c", "-o", "out/foo.o"]);
            let parsed = ParsedCcInvocation::parse(&args(&argv))
                .expect("parse should succeed")
                .expect("compile should be cacheable");
            assert_eq!(
                parsed.depfile.expect("depfile request").mode,
                expected,
                "mode for {argv:?}"
            );
        }
    }

    #[test]
    fn repeated_mt_accumulates_in_order() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MMD",
            "-MT",
            "a.o",
            "-MT",
            "b.o",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(
            parsed.depfile.expect("depfile request").targets,
            vec![
                DepfileTarget::Plain(OsString::from("a.o")),
                DepfileTarget::Plain(OsString::from("b.o")),
            ]
        );
    }

    #[test]
    fn depfile_options_without_md_or_mmd_pass_through() {
        for invocation in [
            &["-MF", "x.d"][..],
            &["-MT", "x.o"][..],
            &["-MQ", "x.o"][..],
            &["-MP"][..],
        ] {
            let mut argv = vec!["-c", "src/foo.c", "-o", "out/foo.o"];
            argv.extend_from_slice(invocation);
            let parsed = ParsedCcInvocation::parse(&args(&argv)).expect("parse should succeed");
            assert!(parsed.is_none(), "expected passthrough for {argv:?}");
        }
    }

    #[test]
    fn non_compile_dependency_modes_pass_through() {
        for invocation in [
            &["-M"][..],
            &["-MM"][..],
            &["-MG"][..],
            &["-MJ", "x.json"][..],
            &["-MJx.json"][..],
        ] {
            let mut argv = vec!["-c", "src/foo.c", "-o", "out/foo.o"];
            argv.extend_from_slice(invocation);
            let parsed = ParsedCcInvocation::parse(&args(&argv)).expect("parse should succeed");
            assert!(parsed.is_none(), "expected passthrough for {argv:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_hit_writes_requested_depfile() {
        let cc = super::ResolvedCompiler::explicit(OsString::from("cc"));
        if let Err(error) = async_process::Command::new(&cc.program)
            .arg("--version")
            .output()
            .await
        {
            if error.kind() == std::io::ErrorKind::NotFound {
                return;
            }
            panic!("spawn cc --version: {error}");
        }
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path();
        std::fs::write(dir.join("value.h"), "#define VALUE 1\n").expect("write header");
        std::fs::write(
            dir.join("demo.c"),
            "#include \"value.h\"\nint demo(void) { return VALUE; }\n",
        )
        .expect("write source");
        let build = dir.join("build");
        std::fs::create_dir_all(&build).expect("create build dir");
        let object = build.join("demo.o");
        let config = test_config(dir.join("stow-cache"));

        let compiler_args = vec![
            OsString::from("-MMD"),
            OsString::from("-c"),
            dir.join("demo.c").into_os_string(),
            OsString::from("-o"),
            object.clone().into_os_string(),
        ];

        let first = super::try_compile(&config, &cc, &compiler_args)
            .await
            .expect("first try_compile");
        let CcOutcome::Miss {
            cache_path,
            output_path,
            ..
        } = first
        else {
            panic!("first compile must be a cache miss");
        };
        let status = async_process::Command::new(&cc.program)
            .args(&compiler_args)
            .status()
            .await
            .expect("spawn cc");
        assert!(status.success());
        super::store_compiled_object(&cache_path, &output_path)
            .await
            .expect("store compiled object");

        std::fs::remove_dir_all(&build).expect("remove build dir");

        let second = super::try_compile(&config, &cc, &compiler_args)
            .await
            .expect("second try_compile");
        assert!(matches!(second, CcOutcome::Hit { .. }));
        assert!(object.exists());
        let depfile = std::fs::read_to_string(build.join("demo.d")).expect("read depfile");
        assert!(depfile.contains("value.h"), "depfile contents: {depfile}");
        assert!(
            depfile.contains(&format!("{}:", object.display())),
            "depfile contents: {depfile}"
        );
    }
}
