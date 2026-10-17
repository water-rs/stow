//! The mock compiler behind the `Preheat cost` lane (stow#773).
//!
//! Compiled only with the `mock-compile` feature and active only when
//! `STOW_BUILD_MOCK_COMPILE=1` reaches the capture wrapper, so no
//! production `stow-build` can stand in for rustc. Everything around the
//! compile stays the real pipeline: cargo resolves, fetches and plans the
//! unit graph, runs every phase in the sandbox and invokes the capture
//! wrapper per unit; the wrapper captures, serves consumed units from the
//! verified store and records identities. Only the step where rustc
//! turns sources into bytes is replaced: the mock writes the files that
//! invocation would have produced — at the paths cargo and the scan
//! expect, for the `--emit` kinds it asked for — empty, and prints the
//! artifact notifications cargo's pipelining reads.
//!
//! Probes stay real. An invocation that prints (`--print`), reads its
//! source from stdin, or names no `--out-dir` is cargo or a build script
//! asking rustc a question, and its answer is read, not written to disk.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use stow_types::rustc::ParsedRustcArgs;

/// The switch the local CI sets for a mock-compile run. The build stage
/// inherits it, and the sandboxed phases receive it explicitly.
pub const STOW_BUILD_MOCK_COMPILE_ENV: &str = "STOW_BUILD_MOCK_COMPILE";

/// What a build script's mock binary runs: a successful exit with no
/// `cargo:` directives, so cargo proceeds to the unit it gates. An empty
/// file is not executable, and cargo runs the build script.
const BUILD_SCRIPT_STUB: &str = "#!/bin/sh\nexit 0\n";

/// Whether this process compiles through the mock.
#[must_use]
pub fn enabled() -> bool {
    std::env::var_os(STOW_BUILD_MOCK_COMPILE_ENV).is_some_and(|value| value == "1")
}

/// Whether `args` is a compile the mock stands in for: an input source
/// file and an `--out-dir` to write into, and nothing printed back.
fn replaces(args: &[OsString], parsed: &ParsedRustcArgs) -> bool {
    let prints = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| arg == "--print" || arg.starts_with("--print="))
    });
    let from_stdin = args.iter().any(|arg| arg == "-");
    !prints && !from_stdin && parsed.out_dir.is_some() && parsed.input_path.is_some()
}

/// The mock's answer to one rustc invocation: `None` when the mock does
/// not apply and the real rustc must run, else the stderr bytes the
/// compile emitted — the artifact notifications, one JSON line each.
///
/// # Errors
/// Returns an error when an output cannot be written, or a requested
/// output has no name the invocation determines.
pub fn compile(args: &[OsString]) -> stow_types::error::Result<Option<Vec<u8>>> {
    if !enabled() {
        return Ok(None);
    }
    let Ok(parsed) = ParsedRustcArgs::parse(args) else {
        return Ok(None);
    };
    if !replaces(args, &parsed) {
        return Ok(None);
    }
    let outputs = planned_outputs(&parsed)?;
    let mut stderr = Vec::new();
    for output in &outputs {
        write_output(output, &parsed)?;
        if parsed.requests_json_artifact_notifications() {
            serde_json::to_writer(
                &mut stderr,
                &serde_json::json!({
                    "$message_type": "artifact",
                    "artifact": output.path,
                    "emit": output.emit,
                }),
            )?;
            stderr.push(b'\n');
        }
    }
    Ok(Some(stderr))
}

/// One file the invocation emits, and which `--emit` kind names it.
struct PlannedOutput {
    path: PathBuf,
    emit: &'static str,
    kind: OutputKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputKind {
    DepInfo,
    Data,
    Executable,
}

/// Every file rustc writes for `parsed`, in rustc's emission order:
/// dep-info, metadata, then each crate type's link output.
fn planned_outputs(parsed: &ParsedRustcArgs) -> stow_types::error::Result<Vec<PlannedOutput>> {
    let out_dir = parsed
        .out_dir
        .as_deref()
        .ok_or_else(|| stow_types::stow_error!("mock compile of {} has no --out-dir", parsed.crate_name))?;
    let stem = format!("{}{}", parsed.crate_name, parsed.extra_filename);
    let mut outputs = Vec::new();
    if parsed.emit.contains("dep-info") {
        outputs.push(PlannedOutput {
            path: out_dir.join(format!("{stem}.d")),
            emit: "dep-info",
            kind: OutputKind::DepInfo,
        });
    }
    if parsed.emit.contains("metadata") {
        outputs.push(PlannedOutput {
            path: out_dir.join(format!("lib{stem}.rmeta")),
            emit: "metadata",
            kind: OutputKind::Data,
        });
    }
    if parsed.emit.contains("link") {
        let naming = Naming::of(parsed.target.as_deref());
        for crate_type in &parsed.crate_types {
            let (file_name, kind) = match crate_type.as_str() {
                "lib" | "rlib" => (format!("lib{stem}.rlib"), OutputKind::Data),
                "proc-macro" | "dylib" | "cdylib" => (naming.dynamic(&stem), OutputKind::Data),
                "staticlib" => (naming.static_lib(&stem), OutputKind::Data),
                "bin" => (format!("{stem}{}", naming.exe_suffix), OutputKind::Executable),
                other => {
                    return Err(stow_types::stow_error!(
                        "mock compile of {} has crate type {other} with no known output",
                        parsed.crate_name
                    ));
                }
            };
            outputs.push(PlannedOutput {
                path: out_dir.join(file_name),
                emit: "link",
                kind,
            });
        }
    }
    Ok(outputs)
}

/// The platform naming rustc applies to a link output, from the unit's
/// `--target` (or the host, for a unit compiled without one).
struct Naming {
    dll_prefix: &'static str,
    dll_suffix: &'static str,
    static_prefix: &'static str,
    static_suffix: &'static str,
    exe_suffix: &'static str,
}

impl Naming {
    fn of(target: Option<&str>) -> Self {
        let Some(target) = target else {
            return Self {
                dll_prefix: std::env::consts::DLL_PREFIX,
                dll_suffix: std::env::consts::DLL_SUFFIX,
                static_prefix: if cfg!(windows) { "" } else { "lib" },
                static_suffix: if cfg!(windows) { ".lib" } else { ".a" },
                exe_suffix: std::env::consts::EXE_SUFFIX,
            };
        };
        if target.contains("-windows-") {
            Self {
                dll_prefix: "",
                dll_suffix: ".dll",
                static_prefix: "",
                static_suffix: ".lib",
                exe_suffix: ".exe",
            }
        } else if target.contains("-apple-") {
            Self {
                dll_prefix: "lib",
                dll_suffix: ".dylib",
                static_prefix: "lib",
                static_suffix: ".a",
                exe_suffix: "",
            }
        } else if target.starts_with("wasm32-") {
            Self {
                dll_prefix: "",
                dll_suffix: ".wasm",
                static_prefix: "lib",
                static_suffix: ".a",
                exe_suffix: ".wasm",
            }
        } else {
            Self {
                dll_prefix: "lib",
                dll_suffix: ".so",
                static_prefix: "lib",
                static_suffix: ".a",
                exe_suffix: "",
            }
        }
    }

    fn dynamic(&self, stem: &str) -> String {
        format!("{}{stem}{}", self.dll_prefix, self.dll_suffix)
    }

    fn static_lib(&self, stem: &str) -> String {
        format!("{}{stem}{}", self.static_prefix, self.static_suffix)
    }
}

/// Write one planned output: empty for data, a no-op script for an
/// executable, and for dep-info the one rule cargo's fingerprint reads —
/// the source the unit was "compiled" from.
fn write_output(output: &PlannedOutput, parsed: &ParsedRustcArgs) -> stow_types::error::Result<()> {
    if let Some(parent) = output.path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(&output.path).map_err(|error| {
        stow_types::stow_error!("mock compile: create {}: {error}", output.path.display())
    })?;
    match output.kind {
        OutputKind::Data => {}
        OutputKind::DepInfo => {
            let input = parsed.input_path.as_deref().unwrap_or_else(|| Path::new(""));
            writeln!(file, "{}: {}", output.path.display(), input.display())?;
            writeln!(file)?;
            writeln!(file, "{}:", input.display())?;
        }
        OutputKind::Executable => {
            file.write_all(BUILD_SCRIPT_STUB.as_bytes())?;
            make_executable(&output.path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> stow_types::error::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(path: &Path) -> stow_types::error::Result<()> {
    Err(stow_types::stow_error!(
        "mock compile cannot write a runnable build script at {} on this platform",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use stow_types::rustc::ParsedRustcArgs;

    use super::{OutputKind, planned_outputs, replaces};

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_pipelined_lib_unit_plans_dep_info_rmeta_and_rlib() {
        let argv = args(&[
            "--crate-name",
            "serde",
            "--edition=2021",
            "src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "-C",
            "metadata=0123456789abcdef",
            "-C",
            "extra-filename=-0123456789abcdef",
            "--out-dir",
            "/t/deps",
        ]);
        let parsed = ParsedRustcArgs::parse(&argv).expect("parse");
        assert!(replaces(&argv, &parsed));
        let outputs = planned_outputs(&parsed).expect("plan");
        let names = outputs
            .iter()
            .map(|output| output.path.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "/t/deps/serde-0123456789abcdef.d",
                "/t/deps/libserde-0123456789abcdef.rmeta",
                "/t/deps/libserde-0123456789abcdef.rlib",
            ]
        );
    }

    #[test]
    fn a_build_script_plans_an_executable() {
        let argv = args(&[
            "--crate-name",
            "build_script_build",
            "build.rs",
            "--crate-type",
            "bin",
            "--emit=dep-info,link",
            "-C",
            "extra-filename=-aa",
            "--out-dir",
            "/t/build/x",
        ]);
        let parsed = ParsedRustcArgs::parse(&argv).expect("parse");
        let outputs = planned_outputs(&parsed).expect("plan");
        let link = outputs.last().expect("link output");
        assert!(link.kind == OutputKind::Executable);
        assert!(
            link.path
                .to_string_lossy()
                .starts_with("/t/build/x/build_script_build-aa")
        );
    }

    #[test]
    fn probes_stay_with_the_real_rustc() {
        let argv = args(&[
            "-",
            "--crate-name",
            "___",
            "--print=file-names",
            "--crate-type",
            "bin",
        ]);
        let parsed = ParsedRustcArgs::parse(&argv).expect("parse");
        assert!(!replaces(&argv, &parsed));
    }
}
