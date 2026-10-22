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
//!
//! The mock also stands in for the runner a task is dispatched to. A
//! production build runs on the runner its target's `build-crate` job
//! names, so its host units — build scripts, proc macros, the whole of a
//! host-side node — compile for that runner's host triple. One machine
//! hosting every target's builds must answer as each of those hosts: the
//! host is [`runner_host`] of the task's target — the runner mapping the
//! scheduler dispatches by — and every place a build learns its host from
//! rustc (`rustc -vV`, the target-info probes cargo sends without a
//! `--target`, the triple a target-less unit is keyed and named under)
//! answers with it. The real rustc still answers each probe, asked about
//! that triple.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use stow_types::rustc::ParsedRustcArgs;

/// The switch the local CI sets for a mock-compile run. The build stage
/// inherits it, and the sandboxed phases receive it explicitly.
pub const STOW_BUILD_MOCK_COMPILE_ENV: &str = "STOW_BUILD_MOCK_COMPILE";

/// The host triple the capture wrapper answers as — [`runner_host`] of
/// the task's target, set by the build stage on every process that
/// reaches the wrapper (the sandboxed phases, the unit-graph resolves).
/// The wrapper has no task of its own to derive it from.
pub const STOW_BUILD_MOCK_HOST_ENV: &str = "STOW_BUILD_MOCK_HOST";

/// What a build script's mock binary runs: a successful exit with no
/// `cargo:` directives, so cargo proceeds to the unit it gates. An empty
/// file is not executable, and cargo runs the build script.
const BUILD_SCRIPT_STUB: &str = "#!/bin/sh\nexit 0\n";

/// Whether this process compiles through the mock.
#[must_use]
pub fn enabled() -> bool {
    std::env::var_os(STOW_BUILD_MOCK_COMPILE_ENV).is_some_and(|value| value == "1")
}

/// The host triple a build for `target` runs on: the host of the runner
/// family `build-crate.yml` dispatches the target to
/// ([`stow_types::api::runner_family`]), the same mapping the scheduler's
/// dispatch caps and the publish validation read.
///
/// # Errors
/// Returns an error when no runner family builds `target`.
pub fn runner_host(target: &str) -> stow_types::error::Result<&'static str> {
    stow_types::api::runner_family(target)
        .map(stow_types::api::RunnerFamily::host_triple)
        .ok_or_else(|| {
            stow_types::stow_error!("mock compile: no runner family builds target {target}")
        })
}

/// The host this wrapper process answers as, from
/// [`STOW_BUILD_MOCK_HOST_ENV`] — required whenever the mock is on: a
/// wrapper that fell back to the machine's own host would key every host
/// unit under a runner the task is not dispatched to.
///
/// # Errors
/// Returns an error when the variable is unset or not UTF-8.
pub fn emulated_host() -> stow_types::error::Result<String> {
    std::env::var(STOW_BUILD_MOCK_HOST_ENV).map_err(|error| {
        stow_types::stow_error!(
            "mock compile is on but {STOW_BUILD_MOCK_HOST_ENV} is not usable: {error}"
        )
    })
}

/// A question cargo asks rustc about its host, and how the mock has the
/// real rustc answer it.
#[derive(Debug, PartialEq, Eq)]
pub enum HostProbe {
    /// `rustc -vV`: run as asked, then report `host` as the emulated
    /// triple ([`rewrite_version_host`]).
    Version,
    /// A target-less `--print` / stdin probe: run with `--target` set to
    /// the emulated host — the answer cargo reads as its host's.
    Print(Vec<OsString>),
}

/// Whether `args` asks rustc about the host, and the invocation that
/// answers it as `host`. A probe that names a `--target` asks about that
/// target and passes through untouched, as does every compile.
#[must_use]
pub fn host_probe(args: &[OsString], host: &str) -> Option<HostProbe> {
    if args.iter().any(|arg| arg == "-vV") {
        return Some(HostProbe::Version);
    }
    let prints = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| arg == "--print" || arg.starts_with("--print="))
    });
    let from_stdin = args.iter().any(|arg| arg == "-");
    let names_target = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| arg == "--target" || arg.starts_with("--target="))
    });
    if !(prints || from_stdin) || names_target {
        return None;
    }
    let mut probe = args.to_vec();
    probe.push(OsString::from("--target"));
    probe.push(OsString::from(host));
    Some(HostProbe::Print(probe))
}

/// `rustc -vV`'s answer with its `host:` line naming `host`.
///
/// # Errors
/// Returns an error when the output is not UTF-8 or has no `host:` line.
pub fn rewrite_version_host(stdout: &[u8], host: &str) -> stow_types::error::Result<Vec<u8>> {
    let text = std::str::from_utf8(stdout)
        .map_err(|error| stow_types::stow_error!("rustc -vV output is not UTF-8: {error}"))?;
    let mut found = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.starts_with("host: ") {
            found = true;
            out.push_str("host: ");
            out.push_str(host);
            out.push('\n');
        } else {
            out.push_str(line);
        }
    }
    if !found {
        return Err(stow_types::stow_error!("rustc -vV output has no host line"));
    }
    Ok(out.into_bytes())
}

/// The `build.rustc-wrapper` a unit-graph resolve runs under, so the
/// cargo that plans the build sees the same host the sandboxed phases'
/// cargo does: a script in `dir` that enters this executable's capture
/// wrapper with the mock switched on and `host` emulated. A resolve only
/// probes rustc, which the wrapper answers before any capture.
///
/// # Errors
/// Returns an error when the script cannot be written.
pub async fn unit_graph_wrapper(dir: &Path, host: &str) -> stow_types::error::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let path = dir.join("stow-mock-host-rustc");
    let script = format!(
        "#!/bin/sh\nexec env {STOW_BUILD_MOCK_COMPILE_ENV}=1 {STOW_BUILD_MOCK_HOST_ENV}={} {} rustc \"$@\"\n",
        shell_quote(host),
        shell_quote(&exe.to_string_lossy()),
    );
    async_fs::write(&path, script).await?;
    make_executable(&path)?;
    Ok(path)
}

/// `value` as one single-quoted POSIX shell word.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
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
    let host = emulated_host()?;
    let outputs = planned_outputs(&parsed, &host)?;
    if let Some(alias) = build_script_run_path(&parsed, &host) {
        write_output(&alias, &parsed)?;
    }
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
fn planned_outputs(
    parsed: &ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<Vec<PlannedOutput>> {
    let out_dir = parsed.out_dir.as_deref().ok_or_else(|| {
        stow_types::stow_error!("mock compile of {} has no --out-dir", parsed.crate_name)
    })?;
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
        let naming = Naming::of(parsed.target.as_deref().unwrap_or(host));
        for crate_type in &parsed.crate_types {
            let (file_name, kind) = match crate_type.as_str() {
                "lib" | "rlib" => (format!("lib{stem}.rlib"), OutputKind::Data),
                "proc-macro" | "dylib" | "cdylib" => (naming.dynamic(&stem), OutputKind::Data),
                "staticlib" => (naming.static_lib(&stem), OutputKind::Data),
                "bin" => (
                    format!("{stem}{}", naming.exe_suffix),
                    OutputKind::Executable,
                ),
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

/// Where cargo will execute a build script the mock compiled for an
/// emulated host whose executables are named differently from this
/// machine's. Cargo names a build script's outputs from the host rustc
/// reports — `build_script_build-<hash>.exe` for a Windows runner, which
/// it hard-links to `build-script-build.exe` — but runs it under the
/// executable suffix cargo itself was built with. On the runner the two
/// agree; here the stub must also sit where cargo runs it. `None` when
/// they already agree or `parsed` is no build script.
fn build_script_run_path(parsed: &ParsedRustcArgs, host: &str) -> Option<PlannedOutput> {
    let built_for_host = parsed.target.is_none();
    let is_build_script = parsed.crate_name.starts_with("build_script_")
        && parsed
            .crate_types
            .iter()
            .any(|crate_type| crate_type == "bin")
        && parsed.emit.contains("link");
    let host_suffix = Naming::of(host).exe_suffix;
    if !built_for_host || !is_build_script || host_suffix == std::env::consts::EXE_SUFFIX {
        return None;
    }
    let out_dir = parsed.out_dir.as_deref()?;
    Some(PlannedOutput {
        path: out_dir.join(format!(
            "{}{}",
            parsed.crate_name.replace('_', "-"),
            std::env::consts::EXE_SUFFIX
        )),
        emit: "link",
        kind: OutputKind::Executable,
    })
}

/// The platform naming rustc applies to a link output, from the unit's
/// `--target` (or the emulated host, for a unit compiled without one).
struct Naming {
    dll_prefix: &'static str,
    dll_suffix: &'static str,
    static_prefix: &'static str,
    static_suffix: &'static str,
    exe_suffix: &'static str,
}

impl Naming {
    fn of(target: &str) -> Self {
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
            let input = parsed
                .input_path
                .as_deref()
                .unwrap_or_else(|| Path::new(""));
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

    use super::{
        HostProbe, OutputKind, build_script_run_path, host_probe, planned_outputs, replaces,
        rewrite_version_host, runner_host,
    };

    const LINUX_HOST: &str = "x86_64-unknown-linux-gnu";

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
        let outputs = planned_outputs(&parsed, LINUX_HOST).expect("plan");
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
        let outputs = planned_outputs(&parsed, LINUX_HOST).expect("plan");
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

    /// Every CI target answers as its runner family's host — the
    /// `build-crate.yml` runner map — and a target no runner builds is
    /// refused rather than given the machine's own host.
    #[test]
    fn each_ci_target_runs_on_its_runner_family_host() {
        let expected = [
            ("aarch64-apple-darwin", "aarch64-apple-darwin"),
            ("aarch64-apple-ios", "aarch64-apple-darwin"),
            ("aarch64-apple-ios-sim", "aarch64-apple-darwin"),
            ("aarch64-linux-android", LINUX_HOST),
            ("x86_64-unknown-linux-gnu", LINUX_HOST),
            ("aarch64-unknown-linux-gnu", LINUX_HOST),
            ("x86_64-pc-windows-msvc", "x86_64-pc-windows-msvc"),
            ("aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc"),
            ("wasm32-unknown-unknown", LINUX_HOST),
        ];
        assert_eq!(
            expected.map(|(target, _)| target).as_slice(),
            stow_types::api::CI_TARGET_TRIPLES
        );
        for (target, host) in expected {
            assert_eq!(runner_host(target).expect("CI target"), host, "{target}");
        }
        assert!(runner_host("x86_64-apple-darwin").is_err());
    }

    #[test]
    fn version_probe_reports_the_emulated_host() {
        assert_eq!(
            host_probe(&args(&["-vV"]), LINUX_HOST),
            Some(HostProbe::Version)
        );
        let real = b"rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.99.0\n";
        let rewritten = rewrite_version_host(real, "x86_64-pc-windows-msvc").expect("rewrite");
        assert_eq!(
            String::from_utf8(rewritten).expect("utf8"),
            "rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\nhost: x86_64-pc-windows-msvc\nrelease: 1.99.0\n"
        );
        assert!(rewrite_version_host(b"rustc 1.99.0\n", LINUX_HOST).is_err());
    }

    #[test]
    fn a_targetless_probe_asks_about_the_emulated_host() {
        let probe = args(&[
            "-",
            "--crate-name",
            "___",
            "--print=file-names",
            "--crate-type",
            "bin",
            "--print=cfg",
        ]);
        let Some(HostProbe::Print(asked)) = host_probe(&probe, "x86_64-pc-windows-msvc") else {
            panic!("a target-less probe is a host probe");
        };
        assert_eq!(
            &asked[asked.len() - 2..],
            args(&["--target", "x86_64-pc-windows-msvc"]).as_slice()
        );
        let targeted = args(&["-", "--print=cfg", "--target", "aarch64-apple-ios"]);
        assert_eq!(host_probe(&targeted, LINUX_HOST), None);
        let compile = args(&["--crate-name", "serde", "src/lib.rs", "--out-dir", "/t"]);
        assert_eq!(host_probe(&compile, LINUX_HOST), None);
    }

    /// A target-less unit — a build script — is named for the emulated
    /// host, so cargo finds the `.exe` it planned for a Windows runner.
    #[test]
    fn a_host_unit_is_named_for_the_emulated_host() {
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
        let outputs = planned_outputs(&parsed, "x86_64-pc-windows-msvc").expect("plan");
        let link = outputs.last().expect("link output");
        assert_eq!(
            link.path.to_string_lossy(),
            "/t/build/x/build_script_build-aa.exe"
        );
        // Cargo runs it under its own executable suffix, not the
        // emulated host's: the stub sits there too.
        let run = build_script_run_path(&parsed, "x86_64-pc-windows-msvc");
        if std::env::consts::EXE_SUFFIX == ".exe" {
            assert!(run.is_none());
        } else {
            let run = run.expect("a run path for a foreign suffix");
            assert_eq!(run.path.to_string_lossy(), "/t/build/x/build-script-build");
            assert!(run.kind == OutputKind::Executable);
        }
        assert!(build_script_run_path(&parsed, LINUX_HOST).is_none() || cfg!(windows));
    }
}
