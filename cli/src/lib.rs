use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_process::Command;
use eyre::WrapErr;
use toml_edit::{DocumentMut, Item, Table, Value};
use tracing_subscriber::EnvFilter;
use zenwave::Client;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";

pub fn run() -> eyre::Result<()> {
    install_tracing();
    smol::block_on(async_main())
}

async fn async_main() -> eyre::Result<()> {
    let args = std::env::args_os().collect::<Vec<_>>();
    match detect_mode(&args) {
        Mode::RustcWrapper | Mode::CcWrapper => run_passthrough(&args).await,
        Mode::CargoSubcommand => handle_subcommand(&args).await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    RustcWrapper,
    CcWrapper,
    CargoSubcommand,
}

fn detect_mode(args: &[std::ffi::OsString]) -> Mode {
    let Some(argv1) = args.get(1) else {
        return Mode::CargoSubcommand;
    };

    if is_rustc_path(argv1) {
        return Mode::RustcWrapper;
    }
    if is_c_compiler(argv1) {
        return Mode::CcWrapper;
    }

    Mode::CargoSubcommand
}

async fn run_passthrough(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let executable = args
        .get(1)
        .ok_or_else(|| eyre::eyre!("wrapper mode requires the real compiler path as argv[1]"))?;
    let status = Command::new(executable)
        .args(&args[2..])
        .status()
        .await
        .wrap_err("failed to spawn wrapped compiler")?;

    std::process::exit(status.code().unwrap_or(1));
}

async fn handle_subcommand(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let Some(command) = args.get(1).and_then(|arg| arg.to_str()) else {
        return Err(eyre::eyre!("missing subcommand: expected `setup` or `status`"));
    };

    match command {
        "setup" => setup_project().await,
        "status" => status_project().await,
        "check-artifact" => check_artifact(args).await,
        other => Err(eyre::eyre!("unsupported subcommand `{other}`")),
    }
}

async fn setup_project() -> eyre::Result<()> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_dir = current_dir.join(".cargo");
    let config_path = cargo_dir.join("config.toml");
    let wrapper_command = detect_wrapper_command()?;

    std::fs::create_dir_all(&cargo_dir).wrap_err("create .cargo directory")?;

    let mut document = if config_path.exists() {
        std::fs::read_to_string(&config_path)
            .wrap_err("read existing .cargo/config.toml")?
            .parse::<DocumentMut>()
            .wrap_err("parse existing .cargo/config.toml")?
    } else {
        DocumentMut::new()
    };

    set_build_wrapper(&mut document, &wrapper_command);
    set_env_wrapper(&mut document, "CC", &format!("{wrapper_command} cc"));
    set_env_wrapper(&mut document, "CXX", &format!("{wrapper_command} c++"));
    set_env_wrapper(&mut document, "CMAKE_C_COMPILER_LAUNCHER", &wrapper_command);
    set_env_wrapper(&mut document, "CMAKE_CXX_COMPILER_LAUNCHER", &wrapper_command);

    std::fs::write(&config_path, document.to_string()).wrap_err("write .cargo/config.toml")?;

    tracing::info!(path = %config_path.display(), wrapper = %wrapper_command, "configured project for stow");
    write_stdout(&format!(
        "configured {}\nwrapper: {}\n",
        config_path.display(),
        wrapper_command
    ))?;

    Ok(())
}

async fn status_project() -> eyre::Result<()> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let config_path = current_dir.join(".cargo").join("config.toml");

    if !config_path.exists() {
        write_stdout("not configured: .cargo/config.toml is missing\n")?;
        return Ok(());
    }

    let document = std::fs::read_to_string(&config_path)
        .wrap_err("read .cargo/config.toml")?
        .parse::<DocumentMut>()
        .wrap_err("parse .cargo/config.toml")?;

    let rustc_wrapper = document
        .get("build")
        .and_then(Item::as_table)
        .and_then(|table| table.get("rustc-wrapper"))
        .and_then(Item::as_str)
        .unwrap_or("<missing>");

    let cc = env_value(&document, "CC").unwrap_or("<missing>");
    let cxx = env_value(&document, "CXX").unwrap_or("<missing>");
    let edge_url = load_edge_url().unwrap_or_else(|| "<missing>".to_owned());

    write_stdout(&format!(
        "config: {}\nrustc-wrapper: {}\nCC: {}\nCXX: {}\nedge-url: {}\n",
        config_path.display(),
        rustc_wrapper,
        cc,
        cxx,
        edge_url,
    ))?;

    Ok(())
}

async fn check_artifact(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let target = args
        .get(2)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <target> for check-artifact"))?;
    let rustc_version = args
        .get(3)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <rustc_version> for check-artifact"))?;
    let c_metadata = args
        .get(4)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <c_metadata> for check-artifact"))?;
    let edge_url = load_edge_url()
        .ok_or_else(|| eyre::eyre!("missing edge URL; set {STOW_EDGE_URL_ENV} or ~/.config/stow/config.toml"))?;

    let url = format!(
        "{}/api/v1/artifacts/{}/{}/{}",
        edge_url.trim_end_matches('/'),
        target,
        rustc_version,
        c_metadata
    );

    let mut client = zenwave::client();
    let response = client
        .method(zenwave::Method::HEAD, &url)
        .await?;

    write_stdout(&format!("status: {}\nurl: {}\n", response.status(), url))?;
    Ok(())
}

fn set_build_wrapper(document: &mut DocumentMut, wrapper_command: &str) {
    let build = ensure_table(document, "build");
    build["rustc-wrapper"] = Item::Value(Value::from(wrapper_command));
}

fn set_env_wrapper(document: &mut DocumentMut, key: &str, value: &str) {
    let env = ensure_table(document, "env");
    let mut table = Table::new();
    table["value"] = Item::Value(Value::from(value));
    table["force"] = Item::Value(Value::from(true));
    env[key] = Item::Table(table);
}

fn ensure_table<'a>(document: &'a mut DocumentMut, key: &str) -> &'a mut Table {
    if !document.get(key).is_some_and(Item::is_table) {
        document.insert(key, Item::Table(Table::new()));
    }
    document
        .get_mut(key)
        .expect("table inserted above must exist")
        .as_table_mut()
        .expect("table inserted above must exist")
}

fn env_value<'a>(document: &'a DocumentMut, key: &str) -> Option<&'a str> {
    document
        .get("env")
        .and_then(Item::as_table)
        .and_then(|table| table.get(key))
        .and_then(Item::as_table_like)
        .and_then(|entry| entry.get("value"))
        .and_then(Item::as_str)
}

fn detect_wrapper_command() -> eyre::Result<String> {
    if let Ok(wrapper) = std::env::var("STOW_WRAPPER_PATH") {
        return Ok(wrapper);
    }

    let current_exe = std::env::current_exe().wrap_err("resolve current executable")?;
    let file_name = current_exe.file_name().and_then(OsStr::to_str).unwrap_or_default();
    if file_name == "stow-cli" {
        return Ok(current_exe.display().to_string());
    }

    let sibling = sibling_binary(&current_exe, "stow-cli");
    if sibling.exists() {
        return Ok(sibling.display().to_string());
    }

    Ok("stow-cli".to_owned())
}

fn load_edge_url() -> Option<String> {
    if let Ok(edge_url) = std::env::var(STOW_EDGE_URL_ENV) {
        return Some(edge_url);
    }

    let config_path = dirs::config_dir()?.join("stow").join("config.toml");
    let contents = std::fs::read_to_string(config_path).ok()?;
    let config = toml::from_str::<StowUserConfig>(&contents).ok()?;
    config.edge_url
}

fn sibling_binary(current_exe: &Path, name: &str) -> PathBuf {
    current_exe
        .parent()
        .map(|parent| parent.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn is_rustc_path(path: &OsStr) -> bool {
    file_name(path).is_some_and(|name| name.starts_with("rustc"))
}

fn is_c_compiler(path: &OsStr) -> bool {
    matches!(
        file_name(path),
        Some("cc" | "c++" | "gcc" | "g++" | "clang" | "clang++" | "cl" | "cl.exe")
    )
}

fn file_name(path: &OsStr) -> Option<&str> {
    Path::new(path)
        .file_name()
        .and_then(OsStr::to_str)
}

fn write_stdout(message: &str) -> eyre::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[derive(Debug, serde::Deserialize)]
struct StowUserConfig {
    edge_url: Option<String>,
}
