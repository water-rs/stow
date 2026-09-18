//! The canonical stow entrypoint installed on user machines; all behavior
//! lives in `stow_cli::run()`.

fn main() -> stow_types::error::Result<()> {
    stow_cli::run()
}
