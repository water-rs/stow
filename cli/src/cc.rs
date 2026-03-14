use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use async_process::Command;
use eyre::Context;
use sha2::{Digest, Sha256};

use crate::config::StowConfig;

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
];

#[derive(Debug, Clone)]
pub struct ParsedCcInvocation {
    pub output_path: PathBuf,
    pub preprocess_args: Vec<OsString>,
    pub compile_hash_args: Vec<OsString>,
}

pub async fn try_compile(
    config: &StowConfig,
    compiler: &OsStr,
    compiler_args: &[OsString],
) -> eyre::Result<CcOutcome> {
    let Some(parsed) = ParsedCcInvocation::parse(compiler_args)? else {
        return Ok(CcOutcome::Passthrough);
    };
    let compiler_fingerprint = compiler_fingerprint(compiler).await?;
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

pub async fn store_compiled_object(
    cache_path: &Path,
    output_path: &Path,
) -> eyre::Result<()> {
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

async fn compiler_fingerprint(compiler: &OsStr) -> eyre::Result<Vec<u8>> {
    let output = Command::new(compiler)
        .arg("--version")
        .output()
        .await
        .wrap_err("spawn compiler --version")?;
    if !output.status.success() {
        return Err(eyre::eyre!(
            "compiler --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

async fn preprocess_source(
    compiler: &OsStr,
    parsed: &ParsedCcInvocation,
) -> eyre::Result<Vec<u8>> {
    let mut command = Command::new(compiler);
    command.args(&parsed.preprocess_args);
    let output = command
        .output()
        .await
        .wrap_err("spawn C preprocessor")?;
    if !output.status.success() {
        return Err(eyre::eyre!(
            "C preprocessing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn cache_key(
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
    pub fn parse(args: &[OsString]) -> eyre::Result<Option<Self>> {
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
        let mut preprocess_args = Vec::new();
        let mut compile_hash_args = Vec::new();
        let mut iter = args.iter().peekable();
        let mut seen_compile_flag = false;

        while let Some(arg) = iter.next() {
            let Some(arg_str) = arg.to_str() else {
                return Ok(None);
            };

            match arg_str {
                "-c" => {
                    seen_compile_flag = true;
                }
                "-o" => {
                    let Some(path) = iter.next() else {
                        return Err(eyre::eyre!("missing value after -o"));
                    };
                    output_path = Some(PathBuf::from(path));
                }
                "-MF" | "-MT" | "-MQ" => {
                    if iter.next().is_none() {
                        return Err(eyre::eyre!("missing value after {arg_str}"));
                    }
                }
                flag if FLAGS_WITH_VALUE.contains(&flag) => {
                    let Some(value) = iter.next() else {
                        return Err(eyre::eyre!("missing value after {arg_str}"));
                    };
                    preprocess_args.push(arg.clone());
                    preprocess_args.push(value.clone());
                    compile_hash_args.push(arg.clone());
                    compile_hash_args.push(value.clone());
                }
                value if value.starts_with("-o") && value.len() > 2 => {
                    output_path = Some(PathBuf::from(&value[2..]));
                }
                value if value.starts_with("-MF") && value.len() > 3 => {}
                value if value.starts_with("-MT") && value.len() > 3 => {}
                value if value.starts_with("-MQ") && value.len() > 3 => {}
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
                "-MD" | "-MMD" | "-MP" | "-MG" | "-MJ" => {}
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

        preprocess_args.push(OsString::from("-E"));
        preprocess_args.push(OsString::from("-P"));

        Ok(Some(Self {
            output_path,
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
    use super::ParsedCcInvocation;

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
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
        assert!(parsed
            .preprocess_args
            .iter()
            .any(|arg| arg == "-E"));
    }

    #[test]
    fn treats_version_probe_as_passthrough() {
        let parsed = ParsedCcInvocation::parse(&args(&["--version"]))
            .expect("parse should succeed");
        assert!(parsed.is_none());
    }
}
