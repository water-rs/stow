//! The canonical stow entrypoint installed on user machines; all behavior
//! lives in `stow_cli::run()`.

fn main() -> std::process::ExitCode {
    stow_cli::run()
}
