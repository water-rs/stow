//! stow exposed as a `cargo` subcommand: `cargo stow <args>` invokes this
//! binary as `cargo-stow stow <args>`, and `stow_cli::run()` strips the
//! repeated subcommand word so both forms parse identically.

fn main() -> stow_types::error::Result<()> {
    stow_cli::run()
}
