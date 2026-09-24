//! `stow-facade` — the executable the `stow-rustc-wrapper`/`stow-cc`/
//! `stow-cxx`/`stow-cc-launcher` shims actually are.
//!
//! Startup cost is the whole product: cargo spawns one of these per
//! compiler invocation, hundreds per build, so the binary stays small —
//! std I/O and JSON, no runtime, no config, no network. An invocation the
//! build's own serve map answers never leaves this process; one it cannot
//! (a covered unit, a probe) pays the single plan frame that may block
//! the compiler's start; one with no supervisor environment at all
//! delegates to the `stow-runtime` executable placed beside it — the full
//! CLI, which keeps the ordinary wrapper path working (stow#347).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use stow_facade::wrapper::STOW_CLI_BINARY_ENV;
use stow_shim::WrapperRole;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    std::process::exit(run(&args));
}

fn run(args: &[OsString]) -> i32 {
    let Some((program, wrapped)) = args.split_first() else {
        return delegate_or_fail(args);
    };
    let program = Path::new(program);
    let Some(role) = WrapperRole::from_program(program) else {
        return direct_subcommand_or_delegate(args);
    };
    // Inside a trusted build sandbox the rustc role belongs to the
    // capture executable, not the facade — same delegation the runtime
    // performs when the wrapper name resolves to it.
    if role.delegates_to_capture() {
        let capture = stow_shim::capture_executable_beside(program);
        let mut command = std::process::Command::new(&capture);
        command.arg("rustc").args(wrapped);
        return match command.status() {
            Ok(status) => status.code().unwrap_or(1),
            Err(error) => {
                eprintln!("stow: run capture wrapper {}: {error}", capture.display());
                1
            }
        };
    }
    let mut expanded = Vec::with_capacity(wrapped.len() + 2);
    expanded.push(program.as_os_str().to_owned());
    expanded.extend(role.runtime_args(wrapped));
    match stow_facade::wrapper::try_fast_wrapper_path(&expanded, &|_| {}) {
        Ok(Some(status)) => status,
        Ok(None) => delegate_to_runtime(&expanded, program),
        Err(error) => {
            eprintln!("stow: {error}");
            1
        }
    }
}

/// A facade invoked under its own name (`stow-facade rustc ...`) —
/// tests and manual runs only: the argv is already in the runtime's
/// subcommand shape, so the fast path can read it directly.
fn direct_subcommand_or_delegate(args: &[OsString]) -> i32 {
    let is_wrapper_subcommand = matches!(
        args.get(1).map(OsString::as_os_str),
        Some(arg) if arg == "rustc" || arg == "cc"
    );
    if is_wrapper_subcommand {
        match stow_facade::wrapper::try_fast_wrapper_path(args, &|_| {}) {
            Ok(Some(status)) => return status,
            Ok(None) => {}
            Err(error) => {
                eprintln!("stow: {error}");
                return 1;
            }
        }
    }
    let program = args.first().map_or_else(|| Path::new(""), Path::new);
    delegate_to_runtime(args, program)
}

fn delegate_or_fail(args: &[OsString]) -> i32 {
    let program = args.first().map_or_else(|| Path::new(""), Path::new);
    delegate_to_runtime(args, program)
}

/// The invocation needs the full runtime — an old supervisor with no
/// serve map, or no supervisor at all. The runtime sits beside this
/// facade (`stow-runtime`, which `stow setup` materializes next to the
/// wrappers), or wherever [`STOW_CLI_BINARY_ENV`] points, or on `PATH`.
fn delegate_to_runtime(args: &[OsString], program: &Path) -> i32 {
    let runtime = resolve_runtime(program);
    let mut command = std::process::Command::new(&runtime);
    // `args[0]` is this facade's own name; the runtime parses only the
    // subcommand line, so hand it everything after the program word.
    command.args(args.get(1..).unwrap_or_default());
    match command.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!(
                "stow: the facade could not reach the runtime at {}: {error}",
                runtime.display()
            );
            1
        }
    }
}

/// Where the full runtime lives relative to this facade, in order of
/// preference: the build's own `STOW_CLI_BINARY`, the `stow-runtime`
/// sibling `stow setup` materializes beside every wrapper, then `stow`
/// on `PATH` for a hand-placed facade.
fn resolve_runtime(program: &Path) -> PathBuf {
    if let Some(explicit) = std::env::var_os(STOW_CLI_BINARY_ENV).map(PathBuf::from)
        && explicit.exists()
    {
        return explicit;
    }
    let sibling = program
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(format!("stow-runtime{}", std::env::consts::EXE_SUFFIX));
    if sibling.exists() {
        return sibling;
    }
    PathBuf::from(format!("stow-cli{}", std::env::consts::EXE_SUFFIX))
}
