---
name: stow
description: >
  Install, configure, and drive stow — the signed public prebuilt cache and
  shared CoW local compilation cache for Rust (`cargo` / C / C++). Load whenever
  setting up Rust build acceleration on a user's machine or CI, running `stow`
  commands (`stow setup`, `stow check|build|test|run|clippy|doc|bench|nextest`, `stow predict`, `stow status`,
  `stow stats`, `stow update`, `stow index`, `stow clean`), diagnosing cache
  misses or `stow-daemon` sandbox errors during `cargo` builds, configuring
  `heel` build-isolation grants, or adding `water-rs/stow@main` to GitHub Actions.
---

# Using and Configuring `stow`

`stow` accelerates Rust builds in two layers:
1. **Signed public prebuilt cache (`stow.waterui.dev` + GHCR):** downloads Sigstore-verified rlibs, proc-macros, dylibs, and reusable build-script binaries so `rustc` never compiles covered dependencies.
2. **Shared local CoW cache (`~/.stow`):** deduplicates downloaded and locally compiled `crates.io`, `git`, and C/C++ units across every workspace and git worktree on the machine via copy-on-write clones (APFS, Btrfs, reflink XFS, ReFS Dev Drive).

## 1. Install, Update, and Machine Setup

Install with the official release script (automatically runs `stow setup`):

```sh
# macOS and Linux
curl -fsSL https://stow.waterui.dev/install.sh | sh
```

```powershell
# Windows
irm https://stow.waterui.dev/install.ps1 | iex
```

- **Updating:** run `stow update` (reads the cargo-dist receipt, updates the binary, refreshes wrapper shims, and drains/restarts the running daemon). Never overwrite an installer-managed `stow` with `cargo install`, which lacks an install receipt.
- **Global Cargo wiring only — never pollute project repos:** `stow setup` is idempotent and writes only into `$CARGO_HOME/config.toml` (`~/.cargo/config.toml` by default): `build.rustc-wrapper`, host-scoped `CC_<triple>` / `CXX_<triple>`, `CMAKE_C_COMPILER_LAUNCHER` / `CMAKE_CXX_COMPILER_LAUNCHER`, `build.build-dir` (unless the user already configured one or `--no-build-dir` was passed), and on Linux a managed `mold` install (`-fuse-ld=mold` + `COMPILER_PATH`). On interactive terminals where `~/.claude` or `~/.agents` exists, `stow setup` also offers to install/update this `stow` skill (`--install-skill` / `--no-install-skill` for non-interactive control). **Never write `stow` wrapper paths into a project's `.cargo/config.toml`.**
- **`build.build-dir` & integration test binaries:** on developer machines where `stow setup` sets `build.build-dir = "<cache_dir>/build-dir/{workspace-path-hash}"` (so idle/deleted worktrees can be swept), Cargo still copies final `[[bin]]` / `cdylib` / `staticlib` outputs to `target/<profile>/`, while `deps/` intermediates (including integration test executables) live under `<build-dir>/<profile>/deps/`. Discover test executable paths from `cargo test --no-run --message-format=json` (`executable` field), or pass `CARGO_BUILD_BUILD_DIR=target` (or `stow setup --no-build-dir` on ephemeral CI runners) when a script requires `target/<profile>/deps/`.

## 2. Running Builds and Maximizing Hit Rate

- **After `stow setup`:** ordinary `cargo check`, `cargo build`, and `cargo test` automatically route through the per-user `stow` daemon.
- **Driver commands (with or without `stow setup`):** `stow check`, `stow build`, and `stow test` accept Cargo flags (`--release`, `--manifest-path`, `--target`, `-p`, `--bin`), synthesize a cache-pinned `Cargo.lock` in a persistent per-workspace mirror, warm covered bundles asynchronously inside the daemon while Cargo runs, confine build scripts/proc-macros under `heel`, and fall back to plain Cargo if the toolchain is unsupported (e.g. nightly) or the edge is unreachable.
- **Non-interactive compatible upgrades:** the public cache builds the latest patch on each semver-compatible line. In agent sessions and CI, pass `--silent-compatible-upgrades` (`stow check --silent-compatible-upgrades`) so recommended patch upgrades apply in a workspace mirror without blocking on an interactive prompt. Pass `--no-stow-resolver` when Cargo must use the exact unmodified `Cargo.lock` without lockfile synthesis.
- **Check coverage first (read-only, zero network posts, evaluates `stow-resolver` synthesis unless `--no-stow-resolver` is passed):**
  ```sh
  stow predict --manifest-path Cargo.toml
  ```
- **Profile & toolchain caveats:**
  - Public prebuilts target the two most recent **stable** Rust releases (`rustup run stable ...`).
  - `[profile.dev] lto = true` forces `-C linker-plugin-lto` on every dependency and disables public hits; set `lto = false` (or `"off"`) on `profile.dev` if fast dev builds are wanted.
  - On Linux, `mold` is required on both sides of the cache for linked units (proc-macros, dylibs); `stow setup` and `stow build` provision a pinned `mold` automatically without root.

## 3. Agent Sandboxes and the `stow` Daemon (Critical)

Every `rustc` / `cc` wrapper invoked by plain `cargo` is a thin client of the per-user daemon. **Wrappers never fall back to running `rustc` directly.** If a coding agent's own filesystem/IPC sandbox blocks the wrapper from reaching or starting the daemon, `cargo` fails on its first compiler probe naming the daemon endpoint and log.

- **Never "work around" a sandbox block by setting `RUSTC_WRAPPER=""` or editing/deleting `$CARGO_HOME/config.toml`.** That silently destroys the user's build cache and leaves multi-minute cold compiles.
- **Fix the sandbox permission instead:**
  - Grant read/write/connect access to the daemon runtime directory: `$STOW_DAEMON_DIR` when set, otherwise `<per-user cache dir>/stow/run` (contains `daemon.sock`, `daemon.lock`, `start.lock`, `daemon.log`), plus `~/.stow` (`$STOW_CACHE_DIR`) and `$CARGO_HOME`.
  - On Windows, `stow setup` registers a per-user Scheduled Task `stow-daemon-<hash>` to launch the daemon outside Cargo's job object; if missing, run `stow setup` (with the same `STOW_DAEMON_DIR`, if set).
  - If a build fails with `the stow daemon restarted during this cargo build` (for example right after an upgrade), simply re-run the `cargo` command.

## 4. Configuring `stow` (`config.toml`), Cache Layers, and Isolation

`stow` reads its OS-standard config path — **not** `~/.config` on macOS. Unknown keys fail fast:
- **macOS:** `~/Library/Application Support/stow/config.toml`
- **Linux:** `$XDG_CONFIG_HOME/stow/config.toml` (when absolute) or `~/.config/stow/config.toml`
- **Windows:** `%APPDATA%\stow\config.toml`

### Cache layers & privacy
- Disable telemetry while keeping full public + local caching: set `STOW_NO_ANALYTICS=1` in the environment.
- Toggle layers persistently in `config.toml` or per invocation:
  ```toml
  [cache]
  remote = true           # --no-remote-cache: zero edge/GHCR requests or miss reports
  local_crates_io = true  # --no-local-crates-io-cache
  local_git = true        # --no-local-git-cache (use if a git dep reads files outside its package)
  ```

### Build isolation (`heel`) and grants
`stow check|build|test` confine Cargo, `rustc`, build scripts, and proc-macros at four levels (`--isolation <level>` or `[isolation] level = "..."` in `config.toml`):
- `protect` (default on macOS/Linux; requires Linux kernel >= 6.7 and `kernel.yama.ptrace_scope <= 1`): open machine minus credential stores (SSH/GPG, cloud/forge tokens, browser cookies, macOS Keychain) and persistence paths (`~/.ssh`, shell rc files, `.git/hooks`, launchd/systemd).
- `strict` (default on Windows; `protect` is unsupported on Windows and never falls back): filesystem and env allowlist + audited network proxy.
- `offline`: `strict` with network cut off.
- `off`: unconfined.

When a crate's `build.rs` (e.g. `openssl-sys`, `pkg-config` consumers) fails under `strict` or `offline`, inspect `<local data dir>/stow/audit/denied-access.<date>.jsonl` and add a targeted grant in `config.toml` rather than disabling caching:

```toml
[[isolation.grant]]
crate = "openssl-sys"
read = ["/opt/homebrew/opt/openssl"]
write = []
exec = []
env = ["OPENSSL_DIR"]
```

## 5. GitHub Actions Setup

Two composite actions are provided. **Always use the networked default `water-rs/stow@main` unless the user explicitly forbids remote cache connections** — running local-only drops all public prebuilt acceleration on cold caches.

### Default (recommended): public prebuilt cache + local cache
Needs zero secrets or special permissions, verifies release SHA-256 and Sigstore bundle signatures, installs managed `mold` on Linux, and replaces dependency-caching setups such as `Swatinem/rust-cache`:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - uses: water-rs/stow@main
  - run: cargo test
```

Optional inputs on `water-rs/stow@main`: `version` (default `latest`, or e.g. `0.21.9`), `edge-url` (default `https://stow.waterui.dev`), `verify-mode` (default `github-ci`).

### Air-gapped / strict local-only policy: `water-rs/stow/local@main`
Use **only** when policy prohibits querying the public cache or sending anonymous miss proofs. Writes `[cache] remote = false` before `stow setup`; pair with `actions/cache` on `~/.stow` so subsequent runs reuse locally compiled dependencies:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: dtolnay/rust-toolchain@stable
  - uses: actions/cache@v4
    with:
      path: ~/.stow
      key: stow-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
      restore-keys: stow-${{ runner.os }}-
  - uses: water-rs/stow/local@main
  - run: cargo test
```

## 6. Diagnostics & Maintenance Commands

- `stow status` — active Cargo wrapper paths, stale per-project configs detected, and rolling `rust-cache` / `cc-cache` hit/miss/error counts.
- `stow stats` (`--json`) — local hits, misses, bytes downloaded, and compile CPU time saved.
- `stow index status` / `stow index refresh` — inspect or force-revalidate cached `(target, rustc)` signed index slices (`~/.stow/index/`).
- `STOW_IDENTITY_TRACE=/tmp/stow-trace cargo check` — writes per-invocation JSON identity records to diagnose why a specific unit missed an index row.
- `stow clean` — deletes cached artifacts and build directories under `~/.stow` (`$STOW_CACHE_DIR`, resetting `state-v3.sqlite3` if its schema mismatches) while preserving verified index slices (`~/.stow/index/`), local stats, and wrapper shims; pass `stow clean --all` to wipe `~/.stow` completely.
