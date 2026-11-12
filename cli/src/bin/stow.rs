//! Short alias for the stow CLI; resolves to `stow_cli::run()` like the
//! canonical `stow-cli` binary.

fn main() -> std::process::ExitCode {
    stow_cli::run()
}
