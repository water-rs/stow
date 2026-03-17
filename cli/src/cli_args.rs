use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "stow", disable_help_subcommand = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Check(CargoCommandArgs),
    Build(CargoCommandArgs),
    Test(CargoCommandArgs),
    Predict(CargoCommandArgs),
    Setup,
    Status,
    Clean,
    CheckArtifact(CheckArtifactArgs),
    FetchArtifact(FetchArtifactArgs),
    #[command(name = "__purge-cache-dir", hide = true)]
    PurgeCacheDir(PurgeCacheDirArgs),
}

#[derive(Debug, Clone, Args)]
pub(crate) struct CargoCommandArgs {
    #[arg(long)]
    pub silent_compatible_upgrades: bool,
    #[arg(
        value_name = "CARGO_ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub cargo_args: Vec<OsString>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct CheckArtifactArgs {
    pub target: String,
    pub rustc_version: String,
    pub c_metadata: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct FetchArtifactArgs {
    pub target: String,
    pub rustc_version: String,
    pub c_metadata: String,
    pub output_path: PathBuf,
    pub crate_name: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct PurgeCacheDirArgs {
    #[arg(value_name = "PATH", num_args = 1..)]
    pub paths: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_check_command_with_passthrough_cargo_args() {
        let cli = Cli::try_parse_from([
            "stow",
            "check",
            "--silent-compatible-upgrades",
            "--target",
            "aarch64-apple-darwin",
            "--manifest-path",
            "Cargo.toml",
        ])
        .expect("parse check command");

        let Command::Check(args) = cli.command else {
            panic!("expected check command");
        };
        assert!(args.silent_compatible_upgrades);
        assert_eq!(
            args.cargo_args,
            vec![
                OsString::from("--target"),
                OsString::from("aarch64-apple-darwin"),
                OsString::from("--manifest-path"),
                OsString::from("Cargo.toml"),
            ]
        );
    }

    #[test]
    fn parses_fetch_artifact_command() {
        let cli = Cli::try_parse_from([
            "stow",
            "fetch-artifact",
            "aarch64-apple-darwin",
            "1.91.1",
            "abc123",
            "/tmp/out.tar",
            "aho-corasick",
        ])
        .expect("parse fetch-artifact command");

        let Command::FetchArtifact(args) = cli.command else {
            panic!("expected fetch-artifact command");
        };
        assert_eq!(args.target, "aarch64-apple-darwin");
        assert_eq!(args.rustc_version, "1.91.1");
        assert_eq!(args.c_metadata, "abc123");
        assert_eq!(args.output_path, PathBuf::from("/tmp/out.tar"));
        assert_eq!(args.crate_name, "aho-corasick");
    }
}
