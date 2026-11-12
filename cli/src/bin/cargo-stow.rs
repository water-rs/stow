//! stow exposed as a `cargo` subcommand: `cargo stow <args>` invokes this
//! binary as `cargo-stow stow <args>`, and `stow_cli::run()` strips the
//! repeated subcommand word so both forms parse identically.

fn main() -> std::process::ExitCode {
    stow_cli::run()
}
