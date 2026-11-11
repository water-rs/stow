//! The `--isolation` contract, end to end on this machine (stow#779, stow#1000).
//!
//! A fixture workspace depends on a crate whose build script — and, for
//! the second fixture, a crate whose proc-macro — attempts each action
//! the issue calls forbidden: reading a file under the home directory,
//! reading a token variable, writing to the workspace sources and to the
//! home directory, reading the clipboard, and opening a network
//! connection. Every attempt lands in a temporary HOME with temporary
//! files; the real home directory is never touched.
//!
//! Each probe reports its attempt's outcome; when anything is refused
//! the fixture panics, and the test reads the `PROBE-DENIED:` line out
//! of cargo's stderr — a build that fails with it is a build the sandbox
//! held, and the `succeeded` list names any hole.

mod build_fixture;
mod support;

use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use build_fixture::stow_setup_in;

/// The token the `read-env` probe tries to read — never part of the
/// sandbox's environment allowlist, so the probe must come up empty.
const SECRET_ENV: &str = "STOW_SANDBOX_SECRET_TOKEN";

/// The probe crate's build script: read `probe.conf` beside the
/// manifest, attempt each listed action, and panic — `PROBE-DENIED:` —
/// when any is refused. All of them succeeding is the unsandboxed
/// control's exit 0.
const PROBE_BUILD_RS: &str = r"fn main() {
    stow_probe::run();
}
";

/// The proc-macro fixture: the same attempts run at expansion time,
/// inside the sandboxed rustc — proof the sandbox reaches proc-macro
/// descendants, not only build-script ones.
const PROBE_MACRO_RS: &str = r#"extern crate proc_macro;

#[proc_macro]
pub fn sandbox_probe(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    stow_probe::run_at(std::path::Path::new(&dir).join("probe-macro.conf"), "PROBE-MACRO-DENIED");
    "()".parse().expect("unit tokens")
}
"#;

/// The probe logic the build script and the proc-macro share, as a
/// plain dependency of both.
const PROBE_LIB_RS: &str = r#"use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

/// `probe.conf` in the calling crate's manifest dir: `probes=a,b` plus
/// `key=value` inputs the actions need.
pub fn run() {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    run_at(Path::new(&dir).join("probe.conf"), "PROBE-DENIED");
}

pub fn run_at(conf_path: impl AsRef<Path>, marker: &str) {
    let conf = conf(std::fs::read_to_string(conf_path).expect("read probe.conf"));
    let mut refused = Vec::new();
    let mut succeeded = Vec::new();
    for probe in conf["probes"].split(',').filter(|probe| !probe.is_empty()) {
        let ok = attempt(probe, &conf);
        (if ok { &mut succeeded } else { &mut refused }).push(probe.to_owned());
    }
    if !refused.is_empty() {
        panic!("{marker}: refused={refused:?} succeeded={succeeded:?}");
    }
}

fn conf(text: String) -> BTreeMap<String, String> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn attempt(probe: &str, conf: &BTreeMap<String, String>) -> bool {
    match probe {
        "read-home" => report("read-home", std::fs::read_to_string(&conf["home_file"]).map(|_| ())),
        "read-env" => report(
            "read-env",
            std::env::var("STOW_SANDBOX_SECRET_TOKEN").map(|_| ()),
        ),
        "write-workspace" => report(
            "write-workspace",
            std::fs::write(&conf["workspace_write"], "pwned\n"),
        ),
        "write-home" => report("write-home", std::fs::write(&conf["home_write"], "pwned\n")),
        "clipboard" => report(
            "clipboard",
            std::process::Command::new("pbpaste")
                .output()
                .and_then(|output| {
                    output
                        .status
                        .success()
                        .then_some(())
                        .ok_or_else(|| std::io::Error::other("pasteboard read denied"))
                }),
        ),
        "read-credential" => report(
            "read-credential",
            std::fs::read_to_string(&conf["credential_file"]).map(|_| ()),
        ),
        "write-persistence" => report(
            "write-persistence",
            std::fs::write(&conf["persistence_file"], "pwned\n"),
        ),
        "network" => network(&conf["net_target"]),
        "reach-daemon" => report(
            "reach-daemon",
            reach_daemon(&conf["daemon_endpoint"], &conf["daemon_dir"]),
        ),
        other => panic!("unknown probe {other}"),
    }
}

/// The daemon's two doors: its socket, and its runtime directory, where
/// the session tables and the log live. Either one open is a way in.
#[cfg(unix)]
fn reach_daemon(endpoint: &str, dir: &str) -> Result<(), String> {
    let connected = std::os::unix::net::UnixStream::connect(endpoint);
    let written = std::fs::write(Path::new(dir).join("planted"), "pwned\n");
    match (connected, written) {
        (Err(connect), Err(write)) => Err(format!("connect: {connect}; write: {write}")),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn reach_daemon(_endpoint: &str, _dir: &str) -> Result<(), String> {
    unreachable!("the reach-daemon probe is listed on Unix only")
}

fn report<E: std::fmt::Display>(probe: &str, result: Result<(), E>) -> bool {
    if let Err(error) = &result {
        println!("cargo:warning=probe {probe} refused: {error}");
    }
    result.is_ok()
}

/// The network probe: with heel's proxy environment present, CONNECT
/// through it to the test's listener — the only outbound channel a
/// network-allowed sandbox leaves; without it, attempt a direct
/// connection, which is what `--isolation offline` must refuse.
fn network(target: &str) -> bool {
    let proxy = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|name| std::env::var(name).ok());
    println!("cargo:warning=probe network: proxy env {proxy:?}");
    match proxy {
        Some(proxy) => {
            let addr = proxy
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_owned();
            let Ok(mut stream) = TcpStream::connect(&addr) else {
                println!("cargo:warning=probe network: connect to proxy {addr} failed");
                return false;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
            if let Err(error) = stream.write_all(
                format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
            ) {
                println!("cargo:warning=probe network: CONNECT write: {error}");
                return false;
            }
            let mut reader = BufReader::new(stream);
            let mut status = String::new();
            if reader.read_line(&mut status).is_err() || !status.contains(" 200") {
                println!("cargo:warning=probe network: CONNECT status {status:?}");
                return false;
            }
            // The rest of the CONNECT response's headers still sit in the
            // stream; the tunnel starts after the blank line.
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header) {
                    Ok(_) if header.trim().is_empty() => break,
                    Ok(_) => continue,
                    Err(error) => {
                        println!("cargo:warning=probe network: header read: {error}");
                        return false;
                    }
                }
            }
            // Read through the tunnel: the listener's PONG proves the
            // CONNECT, not just the proxy handshake, succeeded.
            if writeln!(reader.get_mut(), "PING").is_err() || reader.get_mut().flush().is_err() {
                println!("cargo:warning=probe network: write PING failed");
                return false;
            }
            let mut pong = String::new();
            match reader.read_line(&mut pong) {
                Ok(_) if pong.trim() == "PONG" => true,
                Ok(_) => {
                    println!("cargo:warning=probe network: unexpected pong {pong:?}");
                    false
                }
                Err(error) => {
                    println!("cargo:warning=probe network: read pong: {error}");
                    false
                }
            }
        }
        None => report(
            "network",
            TcpStream::connect_timeout(
                &target
                    .parse()
                    .expect("net_target is a socket address"),
                Duration::from_secs(5),
            )
            .map(|_| ()),
        ),
    }
}
"#;

/// One crate per fixture role: `stow-probe` holds the shared logic so
/// the build script and the proc-macro attempt the identical actions.
fn write_probe_crate(dir: &Path, name: &str, deps: &str, lib: &str) {
    let root = dir.join(name);
    std::fs::create_dir_all(root.join("src")).expect("crate dir");
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{deps}\n"
        ),
    )
    .expect("crate manifest");
    std::fs::write(root.join("src").join("lib.rs"), lib).expect("crate source");
}

/// The fixture workspace: `probe`, a binary depending on `sandbox-probe`
/// (whose build script runs the attempts) and, when `with_macro`, on
/// `probe-macro` (whose `sandbox_probe!` runs them during expansion).
/// The conf files are written by `write_conf` per test.
fn write_fixture(dir: &Path, with_macro: bool) {
    let deps = dir.join("deps");
    write_probe_crate(&deps, "stow-probe", "", PROBE_LIB_RS);
    // The build script's helper is a build dependency — `cargo` links
    // `[build-dependencies]` into build.rs, not `[dependencies]`.
    {
        let root = deps.join("sandbox-probe");
        std::fs::create_dir_all(root.join("src")).expect("probe dir");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"sandbox-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [build-dependencies]\nstow-probe = { path = \"../stow-probe\" }\n",
        )
        .expect("probe manifest");
        std::fs::write(root.join("src").join("lib.rs"), "").expect("probe lib");
    }
    let probe_src = if with_macro {
        "probe_macro::sandbox_probe!();\nfn main() {}\n"
    } else {
        "fn main() {}\n"
    };
    if with_macro {
        let root = deps.join("probe-macro");
        std::fs::create_dir_all(root.join("src")).expect("macro dir");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"probe-macro\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [lib]\nproc-macro = true\n\n\
             [dependencies]\nstow-probe = { path = \"../stow-probe\" }\n",
        )
        .expect("macro manifest");
        std::fs::write(root.join("src").join("lib.rs"), PROBE_MACRO_RS).expect("macro source");
    }
    std::fs::create_dir_all(dir.join("src")).expect("src");
    std::fs::write(dir.join("src").join("main.rs"), probe_src).expect("main.rs");
    // The build script lives beside its own manifest in the usual place.
    std::fs::write(
        dir.join("deps").join("sandbox-probe").join("build.rs"),
        PROBE_BUILD_RS,
    )
    .expect("build.rs");
    let dependency_lines = [
        "sandbox-probe = { path = \"deps/sandbox-probe\" }",
        if with_macro {
            "probe-macro = { path = \"deps/probe-macro\" }"
        } else {
            ""
        },
    ]
    .join("\n");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dependency_lines}\n"
        ),
    )
    .expect("write manifest");
    // Fetch now so nothing under test needs the network — the probes are
    // path dependencies, so this is a lockfile write, not a download.
    let fetched = Command::new("cargo")
        .args(["fetch", "--offline"])
        .current_dir(dir)
        .output()
        .expect("cargo fetch");
    assert!(
        fetched.status.success(),
        "cargo fetch failed:\n{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
}

/// The conf both fixtures read — one per test — naming the probes to run
/// and the temporary files each action targets.
fn conf_text(home: &Path, workspace: &Path, net_target: &str) -> String {
    let mut probes = vec![
        "read-home",
        "read-env",
        "write-workspace",
        "write-home",
        "network",
        "read-credential",
        "write-persistence",
    ];
    // The clipboard probe uses pbpaste; only macOS has one to deny.
    if cfg!(target_os = "macos") {
        probes.push("clipboard");
    }
    // The pipe a Windows daemon listens on is guarded by its DACL, which
    // no probe here can exercise.
    if cfg!(unix) {
        probes.push("reach-daemon");
    }
    // The run directory the hermetic build gives its daemon.
    let daemon_dir = workspace.join("stow-home").join("run");
    format!(
        "probes={}\n\
         daemon_dir={}\n\
         daemon_endpoint={}\n\
         home_file={}\n\
         home_write={}\n\
         workspace_write={}\n\
         credential_file={}\n\
         persistence_file={}\n\
         net_target={net_target}\n",
        probes.join(","),
        daemon_dir.display(),
        daemon_dir.join("daemon.sock").display(),
        home.join("secret-token.txt").display(),
        home.join("pwned.txt").display(),
        workspace.join("planted.txt").display(),
        home.join(".ssh").join("id_ed25519").display(),
        home.join(".zshrc").display(),
    )
}

fn write_conf(path: &Path, home: &Path, workspace: &Path, net_target: &str) {
    std::fs::write(path, conf_text(home, workspace, net_target)).expect("write probe conf");
}

/// A local listener the network probe CONNECTs to through heel's proxy:
/// it answers the post-tunnel PING with PONG so the test distinguishes a
/// real connection from a proxy that merely answered. heel's proxy
/// refuses host-local upstreams, so the listener binds every interface
/// and the target is the machine's own non-loopback address — a connect
/// that still stays on this machine.
fn spawn_pong_listener() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("0.0.0.0:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    // The machine's primary address, without sending a packet: a UDP
    // socket's connect resolves the route to a public address and names
    // the interface it would leave through.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("udp probe");
    probe.connect("8.8.8.8:80").expect("udp connect");
    let local_ip = probe.local_addr().expect("local addr").ip();
    assert!(
        !local_ip.is_loopback(),
        "no non-loopback address for the network probe"
    );
    let thread = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read ping");
        reader.get_mut().write_all(b"PONG\n").expect("write pong");
    });
    (format!("{local_ip}:{port}"), thread)
}

struct ProbeEnv {
    _dir: support::TempDir,
    _home: support::TempDir,
    _cargo_home: support::TempDir,
    _cache: support::TempDir,
    _target: support::TempDir,
    dir: PathBuf,
    home: PathBuf,
    cargo_home: PathBuf,
    cache: PathBuf,
    target: PathBuf,
}

/// The fixture and its isolated filesystem: temporary HOME with the
/// secret file the `read-home` probe wants, an isolated cargo home,
/// cache and target dir — nothing real of the user's machine is read or
/// written.
fn probe_env(with_macro: bool, net_target: &str) -> ProbeEnv {
    sandbox_env(|dir, home| {
        write_fixture(dir, with_macro);
        // An empty `probes=` line makes the build-script probe inert so the
        // proc-macro probe is the only actor under test.
        std::fs::write(
            dir.join("deps").join("sandbox-probe").join("probe.conf"),
            if with_macro {
                "probes=
"
                .to_owned()
            } else {
                conf_text(home, dir, net_target)
            },
        )
        .expect("write build-script probe conf");
        write_conf(&dir.join("probe-macro.conf"), home, dir, net_target);
    })
}

/// The isolated filesystem every sandbox fixture builds in; `write` lays
/// the fixture out in the workspace directory (given with the temporary
/// HOME) before `stow setup` runs.
fn sandbox_env(write: impl FnOnce(&Path, &Path)) -> ProbeEnv {
    let dir = support::tempdir().expect("workspace dir");
    let home = support::tempdir().expect("home dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let cache = support::tempdir().expect("cache dir");
    let target = support::tempdir().expect("target dir");
    std::fs::write(home.path().join("secret-token.txt"), "hunter2\n").expect("home secret");
    std::fs::create_dir_all(home.path().join(".ssh")).expect("ssh dir");
    std::fs::write(home.path().join(".ssh").join("id_ed25519"), "fake key\n")
        .expect("fake credential");
    std::fs::write(home.path().join(".zshrc"), "# startup\n").expect("fake startup file");
    write(dir.path(), home.path());
    stow_setup_in(dir.path(), cargo_home.path());
    ProbeEnv {
        dir: dir.path().to_path_buf(),
        home: home.path().to_path_buf(),
        cargo_home: cargo_home.path().to_path_buf(),
        cache: cache.path().to_path_buf(),
        target: target.path().to_path_buf(),
        _dir: dir,
        _home: home,
        _cargo_home: cargo_home,
        _cache: cache,
        _target: target,
    }
}

/// `stow-cli build` in the fixture with the probe's environment: the
/// temporary HOME, the secret token the `read-env` probe must not see,
/// and a `RUSTUP_HOME` so the toolchain resolves despite the moved HOME.
/// Write the `[cache]` table with every layer off into the global config the probe build reads.
fn turn_cache_off(env: &ProbeEnv) {
    support::write_global_config(
        &[&env.home, &env.dir.join("stow-home")],
        "[cache]\nremote = false\nlocal_crates_io = false\nlocal_git = false\n",
    );
}

fn run_build(env: &ProbeEnv, args: &[&str]) -> std::process::Output {
    run_build_on_path(env, args, None)
}

/// [`run_build`] with `PATH` replaced by `path` when given.
fn run_build_on_path(env: &ProbeEnv, args: &[&str], path: Option<&str>) -> std::process::Output {
    let rustup_home = std::env::var("RUSTUP_HOME")
        .ok()
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|home| format!("{home}/.rustup"))
        })
        .filter(|path| Path::new(path).is_dir());
    let mut extra: Vec<(&str, String)> = vec![
        ("HOME", env.home.display().to_string()),
        (SECRET_ENV, "hunter2".to_owned()),
    ];
    if let Some(home) = rustup_home {
        extra.push(("RUSTUP_HOME", home));
    }
    if let Some(path) = path {
        extra.push(("PATH", path.to_owned()));
    }
    let extra: Vec<(&str, &str)> = extra
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    build_fixture::stow_build_in_default_isolation(
        &env.dir,
        args,
        &build_fixture::refused_url(),
        &build_fixture::refused_url(),
        &env.cache,
        &env.cargo_home,
        &env.target,
        &extra,
    )
}

/// The `PROBE-DENIED:` / `PROBE-MACRO-DENIED:` line from cargo's stderr —
/// the assertion the whole suite reads.
fn denial(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find(|line| line.contains("PROBE-DENIED:") || line.contains("PROBE-MACRO-DENIED:"))
        .map(str::to_owned)
}

/// With the network denied, every forbidden attempt must be refused:
/// file reads and writes to the home dir and workspace, the token
/// variable, the clipboard, and the connection — the build fails with
/// the probe's denial line naming each one.
#[test]
fn denied_sandbox_refuses_every_forbidden_action() {
    let env = probe_env(false, "127.0.0.1:9");
    let output = run_build(&env, &["build", "--isolation", "offline", "--offline"]);
    assert!(
        !output.status.success(),
        "sandboxed build unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let denial =
        denial(&stderr).unwrap_or_else(|| panic!("no probe denial in failing build:\n{stderr}"));
    for probe in [
        "read-home",
        "read-env",
        "write-workspace",
        "write-home",
        "network",
    ] {
        assert!(
            denial.contains(probe),
            "{probe} missing from denial: {denial}"
        );
    }
    if cfg!(target_os = "macos") {
        assert!(
            denial.contains("clipboard"),
            "clipboard probe missing: {denial}"
        );
    }
    if cfg!(unix) {
        assert!(
            denial.contains("reach-daemon"),
            "the daemon was reachable: {denial}"
        );
    }
    assert!(
        denial.contains("succeeded=[]"),
        "a forbidden action leaked through: {denial}"
    );
}

/// With `--isolation strict` the build's outbound traffic rides heel's proxy, so
/// the CONNECT to the test listener succeeds — and everything else is
/// still refused.
#[test]
fn allowed_network_sandbox_refuses_everything_but_the_connection() {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    let output = run_build(&env, &["build", "--isolation", "strict", "--offline"]);
    assert!(
        !output.status.success(),
        "sandboxed build unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let denial =
        denial(&stderr).unwrap_or_else(|| panic!("no probe denial in failing build:\n{stderr}"));
    assert!(
        denial.contains("succeeded=[\"network\"]"),
        "expected only the network attempt to succeed:\n{stderr}"
    );
    if cfg!(unix) {
        assert!(
            denial.contains("reach-daemon"),
            "the daemon was reachable: {denial}"
        );
    }
}

/// The proc-macro runs inside the sandboxed rustc — the same denials
/// must reach it, proving the sandbox covers every descendant of cargo,
/// not only build-script ones.
#[test]
fn denied_sandbox_reaches_proc_macro_expansion() {
    let env = probe_env(true, "127.0.0.1:9");
    let output = run_build(&env, &["build", "--isolation", "offline", "--offline"]);
    assert!(
        !output.status.success(),
        "sandboxed build unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let denial = denial(&stderr)
        .unwrap_or_else(|| panic!("no proc-macro denial in failing build:\n{stderr}"));
    assert!(
        denial.contains("PROBE-MACRO-DENIED"),
        "expected the proc-macro denial marker: {denial}"
    );
    assert!(
        denial.contains("succeeded=[]"),
        "a forbidden action leaked through the proc-macro: {denial}"
    );
}

/// The control: unsandboxed, every attempt succeeds — the probes are
/// real, and a passing build here is what makes a denial above mean
/// anything.
#[test]
fn unsandboxed_build_lets_the_same_actions_through() {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    // The unsandboxed probe reads its token and connects directly — the
    // proxy env isn't needed, so unset it for the direct-connect path.
    let output = run_build(&env, &["build", "--isolation", "off", "--offline"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "unsandboxed control build failed:\n{stderr}"
    );
}

/// stow#823: a fresh checkout or a `cargo clean` leaves no target
/// directory, and every grant is canonicalized before the sandbox
/// starts — the grant setup must create it itself. The probes are
/// beside the point here, so the build-script conf is the inert one.
#[test]
fn sandboxed_build_creates_its_missing_target_directory() {
    let env = probe_env(false, "127.0.0.1:9");
    std::fs::remove_dir(&env.target).expect("remove the fixture's target dir");
    std::fs::write(
        env.dir
            .join("deps")
            .join("sandbox-probe")
            .join("probe.conf"),
        "probes=\n",
    )
    .expect("inert probe conf");
    let output = run_build(&env, &["build", "--isolation", "offline", "--offline"]);
    assert!(
        output.status.success(),
        "sandboxed build without a target directory failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        env.target.is_dir(),
        "the target directory {} was not created",
        env.target.display()
    );
}

/// The probes the build script reported refused and succeeded, read out of
/// the `PROBE-DENIED:` line (`refused=["a", "b"] succeeded=["c"]`).
fn outcome(stderr: &str) -> (Vec<String>, Vec<String>) {
    let line =
        denial(stderr).unwrap_or_else(|| panic!("no probe denial in failing build:\n{stderr}"));
    let list = |key: &str| -> Vec<String> {
        let start = line
            .find(key)
            .unwrap_or_else(|| panic!("no {key} in {line}"))
            + key.len();
        let rest = &line[start..];
        let end = rest.find(']').expect("closing bracket");
        rest[..end]
            .split('"')
            .enumerate()
            .filter(|(index, _)| index % 2 == 1)
            .map(|(_, name)| name.to_owned())
            .collect()
    };
    (list("refused=["), list("succeeded=["))
}

/// Run the probe build at `level` and return what it refused and what it
/// let through. `cache_off` runs it with every cache layer off in the global
/// config: the boundary must not depend on the cache (stow#1059).
fn probe_level(level: &str, cache_off: bool) -> (Vec<String>, Vec<String>) {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    if cache_off {
        turn_cache_off(&env);
    }
    let mut args = vec!["build", "--isolation", level];
    // `protect` runs cargo online; the fixture has only path dependencies,
    // so nothing needs the network, and `--offline` would be a second,
    // unrelated restriction on what is being tested.
    if level != "protect" {
        args.push("--offline");
    }
    let output = run_build(&env, &args);
    assert!(
        !output.status.success(),
        "a build with refused probes unexpectedly succeeded at {level}:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    outcome(&String::from_utf8_lossy(&output.stderr))
}

fn assert_contains_all(actual: &[String], expected: &[&str], what: &str) {
    for name in expected {
        assert!(
            actual.iter().any(|actual| actual == name),
            "{name} missing from {what}: {actual:?}"
        );
    }
}

#[cfg(not(windows))]
fn assert_protect(cache_off: bool) {
    let (refused, succeeded) = probe_level("protect", cache_off);
    assert_contains_all(
        &refused,
        &[
            "read-credential",
            "write-persistence",
            "read-env",
            "reach-daemon",
        ],
        "refused",
    );
    // The machine is otherwise open, and the build still downloads.
    assert_contains_all(
        &succeeded,
        &["read-home", "write-home", "write-workspace", "network"],
        "succeeded",
    );
}

/// The default level: a build script cannot read a credential store or
/// write a persistence location, and still reads and writes the rest of the
/// machine and reaches the network through the audited proxy.
#[cfg(not(windows))]
#[test]
fn protect_refuses_credentials_and_persistence_but_still_downloads() {
    assert_protect(false);
}

/// Isolation does not depend on cache mode: the same refusals hold with
/// the public cache off.
#[cfg(not(windows))]
#[test]
fn protect_holds_with_the_cache_off() {
    assert_protect(true);
}

/// No flag and no config means `protect`.
#[cfg(not(windows))]
#[test]
fn protect_is_the_default_level() {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    let output = run_build(&env, &["build"]);
    assert!(!output.status.success());
    let (refused, succeeded) = outcome(&String::from_utf8_lossy(&output.stderr));
    assert_contains_all(
        &refused,
        &["read-credential", "write-persistence"],
        "refused",
    );
    assert_contains_all(&succeeded, &["read-home", "write-home"], "succeeded");
}

/// On Windows no flag and no config means `strict`: heel cannot enforce
/// `protect` there, and the allowlist keeps credentials unreachable.
#[cfg(windows)]
#[test]
fn strict_is_the_default_level_on_windows() {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    let output = run_build(&env, &["build", "--offline"]);
    assert!(!output.status.success());
    let (refused, succeeded) = outcome(&String::from_utf8_lossy(&output.stderr));
    assert_contains_all(
        &refused,
        &["read-home", "read-credential", "write-persistence"],
        "refused",
    );
    assert_eq!(succeeded, ["network"], "strict leaves only the proxy");
}

/// An explicit `protect` on Windows fails naming the level; it is never
/// replaced by `strict`.
#[cfg(windows)]
#[test]
fn explicit_protect_is_refused_on_windows() {
    let env = probe_env(false, "127.0.0.1:9");
    let output = run_build(&env, &["build", "--isolation", "protect"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`protect`") && stderr.contains("cannot be enforced"),
        "the error should name the level and say it cannot be enforced:\n{stderr}"
    );
    assert!(
        denial(&stderr).is_none(),
        "no build may have run at another level:\n{stderr}"
    );
}

fn assert_strict(cache_off: bool) {
    let (refused, succeeded) = probe_level("strict", cache_off);
    if cfg!(unix) {
        assert_contains_all(&refused, &["reach-daemon"], "refused");
    }
    assert_contains_all(
        &refused,
        &[
            "read-home",
            "read-env",
            "write-workspace",
            "write-home",
            "read-credential",
            "write-persistence",
        ],
        "refused",
    );
    assert_eq!(succeeded, ["network"], "strict leaves only the proxy");
}

/// `strict` is the allowlist: everything but the proxied network is
/// refused.
#[test]
fn strict_refuses_everything_but_the_connection() {
    assert_strict(false);
}

#[test]
fn strict_holds_with_the_cache_off() {
    assert_strict(true);
}

fn assert_offline(cache_off: bool) {
    let (_, succeeded) = probe_level("offline", cache_off);
    assert!(
        succeeded.is_empty(),
        "offline let an action through: {succeeded:?}"
    );
}

/// `offline` is `strict` without the network.
#[test]
fn offline_refuses_everything() {
    assert_offline(false);
}

#[test]
fn offline_holds_with_the_cache_off() {
    assert_offline(true);
}

/// `off` is the unconfined control: every attempt succeeds.
#[test]
fn off_lets_everything_through() {
    let (target, _pong) = spawn_pong_listener();
    let env = probe_env(false, &target);
    turn_cache_off(&env);
    let output = run_build(&env, &["build", "--isolation", "off", "--offline"]);
    assert!(
        output.status.success(),
        "an `off` build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An unknown level is an error, never a fallback to another level.
#[test]
fn an_unknown_level_fails() {
    let env = probe_env(false, "127.0.0.1:9");
    let output = run_build(&env, &["build", "--isolation", "loose"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("loose") && stderr.contains("protect"),
        "the error should name the bad value and the valid levels:\n{stderr}"
    );
}

/// The build script of the C fixture: compile C through the `CC` shim
/// `stow setup` wired — the wrapper process the sandbox confines — and
/// check, from inside the sandbox, that the driver's SQLite locks on the
/// state database's `-shm` survived it (stow#1442).
///
/// SQLite's WAL locking is POSIX record locks, which a process loses when
/// it closes *any* descriptor of the file; heel's file broker serves a
/// sandboxed open of the state database by opening it in the driver and
/// closing its own copy there. A wrapper that opens the database therefore
/// strips the driver of its locks, and the next wrapper takes itself for
/// the first connection and truncates `-shm` under the driver's mapping.
/// `/proc/locks` lists the driver's lock on the dead-man-switch byte
/// without opening the file, so the check cannot disturb what it reads.
#[cfg(target_os = "linux")]
const C_BUILD_RS: &str = r#"use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The byte SQLite's unix VFS takes its dead-man-switch lock on in `-shm`.
const DEAD_MAN_SWITCH_BYTE: u64 = 128;

fn dead_man_switch_held(shm: &Path) -> bool {
    let inode = std::fs::metadata(shm)
        .unwrap_or_else(|error| panic!("stat {}: {error}", shm.display()))
        .ino();
    let locks = std::fs::read_to_string("/proc/locks").expect("read /proc/locks");
    // `1: POSIX  ADVISORY  READ  4242 08:02:131077 128 128`
    locks.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, "POSIX", _, _, _, id, start, end] = fields[..] else {
            return false;
        };
        let on_shm = id
            .rsplit(':')
            .next()
            .and_then(|node| node.parse::<u64>().ok())
            == Some(inode);
        let start = start.parse::<u64>().expect("lock start");
        let end = end.parse::<u64>().unwrap_or(u64::MAX);
        on_shm && start <= DEAD_MAN_SWITCH_BYTE && DEAD_MAN_SWITCH_BYTE <= end
    })
}

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let shm = PathBuf::from(
        std::fs::read_to_string(manifest.join("shm.path")).expect("read shm.path"),
    );
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let target = std::env::var("TARGET").expect("TARGET");
    let cc_key = format!("CC_{}", target.replace(['-', '.'], "_"));
    let cc = std::env::var(&cc_key).unwrap_or_else(|_| panic!("{cc_key} is not set"));

    assert!(
        dead_man_switch_held(&shm),
        "STATE-DB-LOCK-LOST: the driver does not hold {} before any C compile",
        shm.display()
    );
    // Two sources, one compiled twice: whatever each invocation decides
    // — a miss that compiles, a hit that serves — the wrapper process
    // must leave the driver's locks alone.
    for (name, body) in [("a", "int a(void) { return 1; }\n"), ("b", "int b(void) { return 2; }\n")] {
        std::fs::write(out.join(format!("{name}.c")), body).expect("write C source");
    }
    for name in ["a", "b", "a"] {
        let status = Command::new(&cc)
            .current_dir(&out)
            .args(["-c", &format!("{name}.c"), "-o", &format!("{name}.o")])
            .status()
            .expect("run the CC shim");
        assert!(status.success(), "the CC shim failed to compile {name}.c");
        assert!(out.join(format!("{name}.o")).is_file(), "no {name}.o");
        assert!(
            dead_man_switch_held(&shm),
            "STATE-DB-LOCK-LOST: the driver lost its lock on {} after compiling {name}.c",
            shm.display()
        );
    }
}
"#;

/// A binary whose build script compiles C: the sandboxed process that
/// used to open the state database.
#[cfg(target_os = "linux")]
fn write_c_fixture(dir: &Path, shm: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("main.rs");
    std::fs::write(dir.join("build.rs"), C_BUILD_RS).expect("build.rs");
    std::fs::write(dir.join("shm.path"), shm.display().to_string()).expect("shm.path");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    )
    .expect("manifest");
}

/// stow#1442: under the default isolation a build script's C compile
/// goes through the `CC` shim inside the sandbox, and that process must
/// not open the state database — only the driving process does. The build
/// script fails with `STATE-DB-LOCK-LOST` when the driver's `-shm` lock
/// disappears, which is deterministic on the cause (an open of the
/// database from the sandbox) rather than on a race between a truncation
/// and a read. The compiled objects must still land in the C object cache:
/// the daemon stores them.
#[cfg(target_os = "linux")]
#[test]
fn a_sandboxed_c_wrapper_never_opens_the_state_database() {
    let cache = support::tempdir().expect("cache dir");
    let shm = cache.path().join("state-v3.sqlite3-shm");
    let mut env = sandbox_env(|dir, _home| write_c_fixture(dir, &shm));
    // The fixture's cache is the one the shm path names.
    env.cache = cache.path().to_path_buf();
    let output = run_build(&env, &["build"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the sandboxed C build failed:\n{stderr}"
    );
    assert!(
        !stderr.contains("STATE-DB-LOCK-LOST"),
        "a sandboxed process disturbed the driver's state database:\n{stderr}"
    );
    let stored = std::fs::read_dir(cache.path().join("cc"))
        .expect("the daemon created the C object cache")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "o"))
        .count();
    assert!(
        stored >= 2,
        "the daemon stored {stored} C objects; the wrapper's compiles never reached it:\n{stderr}"
    );
}

/// A `cargo` launcher script on `PATH`, in front of a copy of the real
/// `cargo` proxy kept in a directory no sandbox grant covers: the layout
/// of a host whose `/usr/local/bin/cargo` execs a rustup proxy elsewhere
/// (stow#1441).
#[cfg(target_os = "linux")]
struct LauncherToolchain {
    launcher_dir: support::TempDir,
    proxy_dir: support::TempDir,
}

#[cfg(target_os = "linux")]
impl LauncherToolchain {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::var_os("PATH").expect("PATH");
        let real_cargo = std::env::split_paths(&path)
            .map(|dir| dir.join("cargo"))
            .find(|candidate| candidate.is_file())
            .expect("a cargo on PATH");
        // The copy has to be the toolchain's own entry point: a host whose
        // `cargo` is already a launcher script would only copy the script.
        let magic = std::fs::read(&real_cargo).expect("read the cargo on PATH");
        assert!(
            magic.starts_with(b"\x7fELF"),
            "{} is not a native executable; run this test with the real cargo first on PATH",
            real_cargo.display()
        );
        let proxy_dir = support::tempdir().expect("proxy dir");
        // A copy, not a link: the sandbox checks the path that is executed,
        // and a link would execute the real file in the user's toolchain.
        std::fs::copy(&real_cargo, proxy_dir.path().join("cargo")).expect("copy the cargo proxy");
        let launcher_dir = support::tempdir().expect("launcher dir");
        let launcher = launcher_dir.path().join("cargo");
        std::fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nexec {} \"$@\"\n",
                proxy_dir.path().join("cargo").display()
            ),
        )
        .expect("write the launcher");
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
            .expect("make the launcher executable");
        Self {
            launcher_dir,
            proxy_dir,
        }
    }
}

/// The inherited `PATH` behind the given directories.
#[cfg(target_os = "linux")]
fn path_after(dirs: &[&Path]) -> String {
    let inherited = std::env::var_os("PATH").expect("PATH");
    std::env::join_paths(
        dirs.iter()
            .map(|dir| dir.to_path_buf())
            .chain(std::env::split_paths(&inherited)),
    )
    .expect("join PATH")
    .into_string()
    .expect("UTF-8 PATH")
}

/// The default sandbox cannot execute what a launcher `cargo` runs when
/// that lies outside the granted trees, and stow says so — naming the
/// `cargo` it resolved and what to set — instead of leaving the shell's
/// bare "Permission denied" (stow#1441).
#[cfg(target_os = "linux")]
#[test]
fn a_launcher_cargo_the_sandbox_cannot_execute_is_reported() {
    let env = probe_env(false, "127.0.0.1:9");
    std::fs::write(
        env.dir
            .join("deps")
            .join("sandbox-probe")
            .join("probe.conf"),
        "probes=\n",
    )
    .expect("inert probe conf");
    let toolchain = LauncherToolchain::new();
    let path = path_after(&[toolchain.launcher_dir.path()]);
    let output = run_build_on_path(&env, &["build", "--offline"], Some(&path));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a build whose cargo the sandbox cannot execute succeeded:\n{stderr}"
    );
    let launcher = toolchain.launcher_dir.path().join("cargo");
    for needle in [
        "the sandbox refused what",
        &launcher.display().to_string(),
        "RUSTUP_HOME",
        "PATH",
    ] {
        assert!(
            stderr.contains(needle),
            "`{needle}` missing from the failure:\n{stderr}"
        );
    }
}

/// Naming the real toolchain on `PATH` — the directory the launcher
/// execs — makes the same build pass: the sandbox grants the directory
/// `PATH` resolves `cargo` from (stow#1441).
#[cfg(target_os = "linux")]
#[test]
fn a_toolchain_named_on_path_builds_where_its_launcher_could_not() {
    let env = probe_env(false, "127.0.0.1:9");
    std::fs::write(
        env.dir
            .join("deps")
            .join("sandbox-probe")
            .join("probe.conf"),
        "probes=\n",
    )
    .expect("inert probe conf");
    let toolchain = LauncherToolchain::new();
    let path = path_after(&[toolchain.proxy_dir.path(), toolchain.launcher_dir.path()]);
    let output = run_build_on_path(&env, &["build", "--offline"], Some(&path));
    assert!(
        output.status.success(),
        "the build with the toolchain named on PATH failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
