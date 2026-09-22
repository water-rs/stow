//! The one-time mold recommendation for Linux builds.
//!
//! Serving removes compile time, so linking dominates a warm stow build —
//! and mold links far faster than the default GNU linker. When a Linux
//! build's effective linker configuration does not already use mold, the
//! CLI says so once, recording in stow's local state that it was said.
//!
//! Detection inspects the configuration cargo actually resolves — env
//! rustflags and `CARGO_TARGET_*_LINKER` ahead of the `.cargo/config.toml`
//! chain — never guesses from a missing variable, and runs only in the CLI
//! paths that report a finished build, so the rustc wrapper hot path never
//! pays for it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::StowConfig;
use crate::{log_nonfatal_result, stats, write_stdout};

/// Emit the mold recommendation the first time a Linux build is seen
/// without mold. Best-effort throughout: no persisted state, an unreadable
/// cargo config or a missing rustc quietly skips the message rather than
/// interrupting a build.
pub async fn maybe_recommend(config: &StowConfig, target: &str, cargo_dir: &Path) {
    if !cfg!(target_os = "linux") || !target.contains("linux") {
        return;
    }
    if uses_mold(target, cargo_dir).await {
        return;
    }
    match stats::mold_recommendation_shown(config).await {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            tracing::debug!(%error, "failed to read the mold recommendation marker");
            return;
        }
    }
    if write_stdout(&recommendation_message(target, mold_on_path())).is_err() {
        return;
    }
    log_nonfatal_result(
        "failed to record the mold recommendation",
        stats::record_mold_recommendation_shown(config)
            .await
            .map(drop),
    );
}

/// The user-facing message: the recommendation plus how to enable it.
fn recommendation_message(target: &str, mold_installed: bool) -> String {
    let install = if mold_installed {
        String::new()
    } else {
        " Install mold first (e.g. `apt install mold`, or see https://github.com/rui314/mold)."
            .to_owned()
    };
    format!(
        "stow: mold is recommended as the linker on Linux — serving removes \
         dependency compile time, so linking dominates a warm build.{install} \
         Enable it in .cargo/config.toml:\n\
         [target.{target}]\n\
         rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]"
    )
}

/// Whether `target`'s effective linker configuration already uses mold:
/// the linker cargo selects for the triple, or any `-C` link option in the
/// effective rustflags.
async fn uses_mold(target: &str, cargo_dir: &Path) -> bool {
    let config = CargoConfig::load(cargo_dir).await;
    let tables = config.matching_target_tables(target).await;
    if let Some(linker) = effective_linker(target, &tables)
        && linker.contains("mold")
    {
        return true;
    }
    effective_rustflags(&config, &tables)
        .iter()
        .any(|flag| flag_mentions_mold(flag))
}

/// A rustflag selects mold when a `-C` link option's value names it —
/// `-C link-arg=-fuse-ld=mold`, `-C linker=mold`, a `-C link-args` bundle
/// carrying `-fuse-ld=mold`, and so on.
fn flag_mentions_mold(flag: &str) -> bool {
    let option = flag
        .strip_prefix("--codegen=")
        .or_else(|| flag.strip_prefix("-C"))
        .unwrap_or(flag);
    let Some((key, value)) = option.split_once('=') else {
        return false;
    };
    matches!(key, "linker" | "linker-flavor" | "link-arg" | "link-args") && value.contains("mold")
}

/// The rustflags cargo resolves for `target`, honoring cargo's precedence:
/// `CARGO_ENCODED_RUSTFLAGS`, then `RUSTFLAGS`, then — only when neither env
/// source exists — the config `build.rustflags` joined with every matching
/// `target.*` table's `rustflags`.
fn effective_rustflags(
    config: &CargoConfig,
    tables: &[(String, &toml_edit::Table)],
) -> Vec<String> {
    if let Some(encoded) = std::env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        return encoded
            .to_string_lossy()
            .split('\x1f')
            .filter(|flag| !flag.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Ok(flags) = std::env::var("RUSTFLAGS") {
        return shell_words::split(&flags).unwrap_or_default();
    }
    config.rustflags(tables)
}

/// The linker cargo selects for `target`: `CARGO_TARGET_<TRIPLE>_LINKER`,
/// then `target.<triple>.linker`, then a matching `target.<cfg>.linker`.
fn effective_linker(target: &str, tables: &[(String, &toml_edit::Table)]) -> Option<String> {
    let env_key = format!(
        "CARGO_TARGET_{}_LINKER",
        target.to_uppercase().replace('-', "_")
    );
    if let Some(linker) = std::env::var_os(&env_key) {
        return Some(linker.to_string_lossy().into_owned());
    }
    let mut cfg_linker = None;
    for (key, table) in tables {
        let Some(linker) = table.get("linker").and_then(toml_edit::Item::as_str) else {
            continue;
        };
        if key == target {
            return Some(linker.to_owned());
        }
        cfg_linker = Some(linker.to_owned());
    }
    cfg_linker
}

/// Whether a `mold` executable exists anywhere on `PATH`.
fn mold_on_path() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable(&dir.join("mold")))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// The cargo config files that apply to a cargo invocation at `cargo_dir`,
/// ordered lowest → highest precedence: `$CARGO_HOME/config.toml` first,
/// then every `.cargo/config` and `.cargo/config.toml` from the filesystem
/// root down to `cargo_dir` (the same walk cargo performs).
fn cargo_config_paths(cargo_dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".cargo")))
    {
        paths.push(cargo_home.join("config.toml"));
    }
    let ancestors: Vec<PathBuf> = cargo_dir.ancestors().map(Path::to_path_buf).collect();
    for dir in ancestors.into_iter().rev() {
        paths.push(dir.join(".cargo").join("config"));
        paths.push(dir.join(".cargo").join("config.toml"));
    }
    paths
}

/// The parsed cargo config chain, kept per-file because cargo resolves each
/// key from its highest-precedence definer rather than merging whole files.
struct CargoConfig {
    files: Vec<toml_edit::DocumentMut>,
}

impl CargoConfig {
    async fn load(cargo_dir: &Path) -> Self {
        let mut files = Vec::new();
        for path in cargo_config_paths(cargo_dir) {
            let Ok(contents) = async_fs::read_to_string(&path).await else {
                continue;
            };
            match contents.parse::<toml_edit::DocumentMut>() {
                Ok(document) => files.push(document),
                Err(error) => {
                    tracing::debug!(path = %path.display(), %error, "ignoring unparseable cargo config file");
                }
            }
        }
        Self { files }
    }

    /// `build.rustflags` plus every matching `target.*` table's `rustflags`,
    /// each key resolved to its highest-precedence definer.
    fn rustflags(&self, tables: &[(String, &toml_edit::Table)]) -> Vec<String> {
        let mut flags = self
            .lookup(&["build", "rustflags"])
            .into_iter()
            .flat_map(rustflags_value)
            .collect::<Vec<_>>();
        for (_, table) in tables {
            flags.extend(table.get("rustflags").into_iter().flat_map(rustflags_value));
        }
        flags
    }

    /// The last definition of `path` across the precedence-ordered files —
    /// the one cargo would resolve.
    fn lookup(&self, path: &[&str]) -> Option<&toml_edit::Item> {
        self.files.iter().rev().find_map(|file| {
            let mut value = file.as_item();
            for key in path {
                value = value.get(*key)?;
            }
            Some(value)
        })
    }

    /// Every `target.*` table matching `target` across the chain —
    /// `(table key, table)` pairs in precedence order, so later entries are
    /// the higher-precedence definers.
    async fn matching_target_tables<'a>(
        &'a self,
        target: &str,
    ) -> Vec<(String, &'a toml_edit::Table)> {
        let cfgs = rustc_target_cfgs(target).await;
        // Keyed by table name so the nearest definer of each table wins;
        // position records first appearance so entries stay in
        // precedence order.
        let mut order: Vec<String> = Vec::new();
        let mut by_key: std::collections::HashMap<String, &toml_edit::Table> =
            std::collections::HashMap::new();
        for file in &self.files {
            let Some(target_tables) = file.get("target").and_then(toml_edit::Item::as_table) else {
                continue;
            };
            for (key, value) in target_tables {
                let Some(table) = value.as_table() else {
                    continue;
                };
                let matches = if key == target {
                    true
                } else if let Some(predicate) = key
                    .strip_prefix("cfg(")
                    .and_then(|key| key.strip_suffix(')'))
                {
                    cfg_matches(predicate, cfgs.as_ref())
                } else {
                    false
                };
                if matches {
                    if !by_key.contains_key(key) {
                        order.push(key.to_owned());
                    }
                    by_key.insert(key.to_owned(), table);
                }
            }
        }
        order
            .into_iter()
            .filter_map(|key| by_key.get(&key).map(|table| (key, *table)))
            .collect()
    }
}

/// `rustc --print cfg --target <triple>` — the truth about which `cfg()`
/// predicates match. `None` when rustc cannot answer, in which case every
/// cfg table stays a candidate (favoring a missed recommendation over a
/// wrong one).
async fn rustc_target_cfgs(target: &str) -> Option<HashSet<String>> {
    let output = async_process::Command::new("rustc")
        .args(["--print", "cfg", "--target", target])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// A `rustflags` config value as individual flags: an array stays an array,
/// a string splits on whitespace like cargo does.
fn rustflags_value(item: &toml_edit::Item) -> Vec<String> {
    if let Some(array) = item.as_array() {
        return array
            .iter()
            .filter_map(|flag| flag.as_str())
            .map(str::to_owned)
            .collect();
    }
    item.as_str()
        .map(|flags| flags.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Evaluate a `cfg(...)` predicate body against rustc's printed cfg set.
/// Unknown cfgs (`None`) keep the table a candidate.
fn cfg_matches(predicate: &str, cfgs: Option<&HashSet<String>>) -> bool {
    cfgs.is_none_or(|cfgs| eval_cfg(predicate, cfgs))
}

fn eval_cfg(text: &str, cfgs: &HashSet<String>) -> bool {
    let text = text.trim();
    if let Some(inner) = strip_cfg_fn(text, "all") {
        return split_cfg_args(inner).all(|part| eval_cfg(part, cfgs));
    }
    if let Some(inner) = strip_cfg_fn(text, "any") {
        return split_cfg_args(inner).any(|part| eval_cfg(part, cfgs));
    }
    if let Some(inner) = strip_cfg_fn(text, "not") {
        return !eval_cfg(inner, cfgs);
    }
    match text.split_once('=') {
        Some((key, value)) => {
            let leaf = format!("{}={}", key.trim(), value.trim());
            cfgs.contains(&leaf)
        }
        None => cfgs.contains(text),
    }
}

/// The argument list of `name(...)` — `text` with the function stripped —
/// only when `text` is exactly that call.
fn strip_cfg_fn<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.strip_prefix(name)
        .and_then(|rest| rest.trim_start().strip_prefix('('))
        .and_then(|rest| rest.strip_suffix(')'))
}

/// Split `a, b, c` at top level — commas inside nested parentheses are not
/// separators.
fn split_cfg_args(inner: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&inner[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_mentions_mold_covers_the_ways_users_select_it() {
        for flag in [
            "link-arg=-fuse-ld=mold",
            "-Clink-arg=-fuse-ld=mold",
            "--codegen=link-arg=-fuse-ld=mold",
            "link-args=-Wl,-plugin -fuse-ld=mold",
            "linker=/usr/local/bin/mold",
            "linker=mold",
        ] {
            assert!(flag_mentions_mold(flag), "{flag} should select mold");
        }
    }

    #[test]
    fn non_mold_flags_do_not_read_as_mold() {
        for flag in [
            "link-arg=-fuse-ld=lld",
            "link-arg=-fuse-ld=gold",
            "linker=lld",
            "opt-level=3",
            "-Ctarget-cpu=x86-64-v3",
            "remap-path-prefix=/ci=/local",
        ] {
            assert!(!flag_mentions_mold(flag), "{flag} is not mold");
        }
    }

    #[test]
    fn eval_cfg_handles_predicates() {
        let cfgs: HashSet<String> = ["target_os=\"linux\"", "target_arch=\"x86_64\"", "unix"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(eval_cfg("target_os=\"linux\"", &cfgs));
        assert!(eval_cfg("unix", &cfgs));
        assert!(!eval_cfg("target_os=\"macos\"", &cfgs));
        assert!(eval_cfg("not(target_os=\"macos\")", &cfgs));
        assert!(eval_cfg(
            "all(target_os=\"linux\", target_arch=\"x86_64\")",
            &cfgs
        ));
        assert!(!eval_cfg(
            "all(target_os=\"linux\", target_arch=\"aarch64\")",
            &cfgs
        ));
        assert!(eval_cfg(
            "any(target_os=\"macos\", target_arch=\"x86_64\")",
            &cfgs
        ));
        assert!(eval_cfg(
            "all(unix, any(target_os=\"linux\", target_os=\"macos\"))",
            &cfgs
        ));
    }

    #[test]
    fn cfg_matches_defaults_to_candidate_when_cfgs_unknown() {
        assert!(cfg_matches("target_os=\"anything\"", None));
        let cfgs: HashSet<String> = HashSet::new();
        assert!(!cfg_matches("unix", Some(&cfgs)));
    }

    #[test]
    fn split_cfg_args_splits_at_top_level_commas() {
        let parts: Vec<&str> =
            split_cfg_args("target_os=\"linux\", any(unix, target_family=\"gnu\")").collect();
        assert_eq!(
            parts,
            vec!["target_os=\"linux\"", "any(unix, target_family=\"gnu\")"]
        );
    }
}
