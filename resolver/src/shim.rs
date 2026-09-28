//! The rustc shim a resolve probes through: one executable cargo
//! invokes as `build.rustc-wrapper`.
//!
//! `argv[1]` is then the real rustc path (cargo resolves
//! `build.rustc` into it), and the runner family's host triple rides
//! in the shim's own file stem, `rustc-shim-<host>` — no env var and
//! no generated script.
//!
//! The shim answers for the family, not this machine: a `-vV` /
//! `--version` / `-V` probe returns the real rustc's output with the
//! `host:` line rewritten to the family triple (so `Rustc::host` — the
//! `CompileKind::Host` target — is the family triple), and a `--print`
//! probe that passes no `--target` gets `--target <host>` injected (so
//! host cfg / file-name probing answers for the family). Every other
//! invocation is the real rustc verbatim, and the child's exit status
//! is propagated.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::Context as _;

/// The `argv[0]` file stem prefix carrying the family host triple —
/// `rustc-shim-<host>`.
pub const STEM_PREFIX: &str = "rustc-shim-";

/// What one rustc invocation through the shim needs.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// A version probe: run the real rustc with the args verbatim, then
    /// rewrite the `host:` line of its stdout to the family triple.
    Version,
    /// Any other invocation: run the real rustc with these args,
    /// `--target <host>` first when a `--print` probe lacks one.
    Exec(Vec<OsString>),
}

/// Classify the rustc args after `argv[1]`: a version flag anywhere
/// makes it a version probe, a `--print` probe with no `--target`
/// gets the family target injected, anything else passes through.
fn plan(args: &[OsString], host: &str) -> Plan {
    if args
        .iter()
        .any(|arg| matches!(arg.to_str(), Some("-vV" | "--version" | "-V")))
    {
        return Plan::Version;
    }
    let has_print = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| arg == "--print" || arg.starts_with("--print="))
    });
    let has_target = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| arg == "--target" || arg.starts_with("--target="))
    });
    let mut rewritten = Vec::with_capacity(args.len() + 2);
    if has_print && !has_target {
        rewritten.push(OsString::from("--target"));
        rewritten.push(OsString::from(host));
    }
    rewritten.extend(args.iter().cloned());
    Plan::Exec(rewritten)
}

/// Rewrite the `host: ` line of `rustc -vV` stdout to the family
/// triple, line endings preserved.
fn rewrite_host(stdout: &str, host: &str) -> String {
    let mut rewritten = String::with_capacity(stdout.len() + host.len());
    for line in stdout.split_inclusive('\n') {
        if line.starts_with("host: ") {
            rewritten.push_str("host: ");
            rewritten.push_str(host);
            if line.ends_with('\n') {
                rewritten.push('\n');
            }
        } else {
            rewritten.push_str(line);
        }
    }
    rewritten
}

/// A child's exit code; a signal-terminated child reports
/// `128 + signal`.
fn status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            status.signal().map_or(1, |signal| 128 + signal)
        }
        #[cfg(not(unix))]
        {
            1
        }
    })
}

fn entry() -> anyhow::Result<i32> {
    let mut raw = std::env::args_os();
    let exe = raw.next().context("shim argv[0] missing")?;
    let stem = Path::new(&exe)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("shim argv[0] has no UTF-8 file stem")?;
    let host = stem
        .strip_prefix(STEM_PREFIX)
        .with_context(|| format!("shim file stem `{stem}` is not `{STEM_PREFIX}<host>`"))?;
    let rustc = raw
        .next()
        .context("rustc-wrapper argv[1] is the rustc path")?;
    let args: Vec<OsString> = raw.collect();
    match plan(&args, host) {
        Plan::Version => {
            let output = Command::new(&rustc)
                .args(&args)
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .with_context(|| format!("run {}", Path::new(&rustc).display()))?;
            let stdout = String::from_utf8(output.stdout).context("rustc stdout is not UTF-8")?;
            let mut out = std::io::stdout().lock();
            out.write_all(rewrite_host(&stdout, host).as_bytes())
                .and_then(|()| out.flush())
                .context("write stdout")?;
            Ok(status_code(output.status))
        }
        Plan::Exec(exec_args) => {
            let status = Command::new(&rustc)
                .args(&exec_args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .with_context(|| format!("run {}", Path::new(&rustc).display()))?;
            Ok(status_code(status))
        }
    }
}

/// Shim entry point: dispatch from `argv[0]`'s file stem
/// (`rustc-shim-<host>`), run the real rustc at `argv[1]`, propagate
/// its exit status. Shim failures report on stderr and exit 1.
pub fn run() -> ! {
    let code = entry().unwrap_or_else(|error| {
        eprintln!("stow rustc-shim: {error:#}");
        1
    });
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(arg: &str) -> OsString {
        OsString::from(arg)
    }

    #[test]
    fn version_probes_rewrite_the_host_line() {
        let host = "x86_64-pc-windows-msvc";
        for flag in ["-vV", "--version", "-V"] {
            assert_eq!(plan(&[os(flag)], host), Plan::Version, "{flag}");
        }
        let stdout = "rustc 1.98.1 (abc1234 2026-09-01)\nbinary: rustc\ncommit-hash: abc1234\ncommit-date: 2026-09-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.98.1\nLLVM version: 21.1.0\n";
        let rewritten = rewrite_host(stdout, host);
        assert!(rewritten.contains("host: x86_64-pc-windows-msvc\n"));
        assert!(!rewritten.contains("x86_64-unknown-linux-gnu"));
        assert!(rewritten.contains("release: 1.98.1\n"));
    }

    #[test]
    fn print_without_target_gets_the_family_target() {
        let host = "aarch64-apple-darwin";
        for args in [
            vec![os("--print"), os("cfg")],
            vec![os("--print=cfg")],
            vec![os("--print"), os("target-libdir"), os("--edition=2021")],
        ] {
            let Plan::Exec(got) = plan(&args, host) else {
                panic!("--print args must exec");
            };
            let mut expected = vec![os("--target"), os(host)];
            expected.extend(args);
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn print_with_target_is_untouched() {
        let host = "x86_64-pc-windows-msvc";
        let args = [
            os("--print"),
            os("cfg"),
            os("--target"),
            os("wasm32-unknown-unknown"),
        ];
        let Plan::Exec(got) = plan(&args, host) else {
            panic!("--print args must exec");
        };
        assert_eq!(got, args);
    }

    #[test]
    fn anything_else_passes_through_verbatim() {
        let args = [
            os("--crate-name"),
            os("itoa"),
            os("--crate-type"),
            os("lib"),
            os("-o"),
            os("/tmp/out.rlib"),
        ];
        let Plan::Exec(got) = plan(&args, "x86_64-unknown-linux-gnu") else {
            panic!("compile args must exec");
        };
        assert_eq!(got, args);
    }
}
