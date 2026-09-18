//! Short alias for the stow CLI; resolves to `stow_cli::run()` like the
//! canonical `stow-cli` binary.

fn main() -> stow_types::error::Result<()> {
    stow_cli::run()
}
