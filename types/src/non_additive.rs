//! Source-level detection of non-additive Cargo features (stow#1668).
//!
//! Cargo's superset-serving rule assumes enabling an additional feature only
//! adds items. Crates that gate public symbols behind negated `cfg` checks
//! (`#[cfg(not(feature = "dlopen"))]`, `!cfg!(feature = "dlopen")`,
//! `dlib::external_library!`), mutual-exclusion `compile_error!` guards, or
//! feature-switched `build.rs` scripts break that assumption: adding such a
//! feature removes items or changes native link inputs. Both CI submission
//! and the CLI exclude non-additive features from superset substitution.

use std::collections::{BTreeMap, BTreeSet};

/// Declared features and `dlib` usage extracted from a crate's `Cargo.toml`.
struct ManifestFeatures {
    /// Declared feature name -> intra-package features it directly activates.
    declared: BTreeMap<String, Vec<String>>,
    /// Whether any dependency table pulls in the `dlib` macro crate.
    uses_dlib: bool,
    /// Explicit `package.build` path, if not disabled (`build = false`).
    #[cfg(not(target_arch = "wasm32"))]
    build_script_rel: Option<String>,
}

/// Compute the set of non-additive features of a crate from its manifest text,
/// build-script sources, and library/target Rust sources.
#[must_use]
pub fn non_additive_features_in_sources(
    manifest_toml: &str,
    build_script_sources: &[&str],
    rust_sources: &[&str],
) -> BTreeSet<String> {
    let Some(manifest) = parse_manifest_features(manifest_toml) else {
        return BTreeSet::new();
    };
    if manifest.declared.is_empty() {
        return BTreeSet::new();
    }
    let mut direct = BTreeSet::new();
    if manifest.uses_dlib && manifest.declared.contains_key("dlopen") {
        direct.insert("dlopen".to_owned());
    }
    let env_to_feature: BTreeMap<String, String> = manifest
        .declared
        .keys()
        .map(|feat| {
            (
                format!(
                    "CARGO_FEATURE_{}",
                    feat.to_ascii_uppercase().replace('-', "_")
                ),
                feat.clone(),
            )
        })
        .collect();

    for source in build_script_sources {
        let stripped = strip_rust_comments(source);
        scan_rust_source(&stripped, &manifest.declared, &mut direct);
        collect_feature_literals(&stripped, &manifest.declared, &mut direct);
        for (env_key, feat) in &env_to_feature {
            if stripped.contains(env_key.as_str()) {
                direct.insert(feat.clone());
            }
        }
    }
    for source in rust_sources {
        let stripped = strip_rust_comments(source);
        scan_rust_source(&stripped, &manifest.declared, &mut direct);
    }
    transitive_activating_closure(&manifest.declared, direct)
}

fn parse_manifest_features(manifest_toml: &str) -> Option<ManifestFeatures> {
    let value: toml::Value = toml::from_str(manifest_toml).ok()?;
    let table = value.as_table()?;
    let mut raw_features: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut explicit_dep_triggers = BTreeSet::new();
    if let Some(features) = table.get("features").and_then(toml::Value::as_table) {
        for (name, list) in features {
            let mut items = Vec::new();
            if let Some(arr) = list.as_array() {
                for entry in arr.iter().filter_map(toml::Value::as_str) {
                    if let Some(dep_name) = entry.strip_prefix("dep:") {
                        explicit_dep_triggers.insert(dep_name.to_owned());
                    } else if !entry.contains('/') {
                        items.push(entry.to_owned());
                    }
                }
            }
            raw_features.insert(name.clone(), items);
        }
    }
    let mut uses_dlib = false;
    collect_dep_tables(table, &mut |dep_key, dep_val| {
        let pkg_name = dep_val
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(dep_key);
        if pkg_name == "dlib" {
            uses_dlib = true;
        }
        let optional = dep_val
            .as_table()
            .and_then(|t| t.get("optional"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if optional && !explicit_dep_triggers.contains(dep_key) {
            raw_features.entry(dep_key.to_owned()).or_default();
        }
    });
    let known: BTreeSet<String> = raw_features.keys().cloned().collect();
    let declared = raw_features
        .into_iter()
        .map(|(k, vals)| (k, vals.into_iter().filter(|v| known.contains(v)).collect()))
        .collect();
    #[cfg(not(target_arch = "wasm32"))]
    let build_script_rel = match table.get("package").and_then(|p| p.get("build")) {
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::String(path)) => Some(path.clone()),
        _ => Some("build.rs".to_owned()),
    };
    Some(ManifestFeatures {
        declared,
        uses_dlib,
        #[cfg(not(target_arch = "wasm32"))]
        build_script_rel,
    })
}

fn collect_dep_tables(
    root: &toml::map::Map<String, toml::Value>,
    visit: &mut impl FnMut(&str, &toml::Value),
) {
    for section in ["dependencies", "build-dependencies"] {
        if let Some(deps) = root.get(section).and_then(toml::Value::as_table) {
            for (k, v) in deps {
                visit(k, v);
            }
        }
    }
    if let Some(targets) = root.get("target").and_then(toml::Value::as_table) {
        for target_cfg in targets.values().filter_map(toml::Value::as_table) {
            for section in ["dependencies", "build-dependencies"] {
                if let Some(deps) = target_cfg.get(section).and_then(toml::Value::as_table) {
                    for (k, v) in deps {
                        visit(k, v);
                    }
                }
            }
        }
    }
}

fn transitive_activating_closure(
    declared: &BTreeMap<String, Vec<String>>,
    mut marked: BTreeSet<String>,
) -> BTreeSet<String> {
    let mut changed = !marked.is_empty();
    while changed {
        changed = false;
        for (feature, activates) in declared {
            if !marked.contains(feature) && activates.iter().any(|dep| marked.contains(dep)) {
                marked.insert(feature.clone());
                changed = true;
            }
        }
    }
    marked
}

/// Replace line comments and nested block comments with spaces while keeping
/// normal and raw string literals intact.
fn strip_rust_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        if bytes[i] == b'r'
            && let Some((end, raw)) = consume_raw_string(&source[i..])
        {
            out.push_str(raw);
            i += end;
            continue;
        }
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            out.push_str(&source[start..i]);
            continue;
        }
        let ch = source[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn consume_raw_string(rest: &str) -> Option<(usize, &str)> {
    let after_r = rest.strip_prefix('r')?;
    let hashes = after_r.bytes().take_while(|&b| b == b'#').count();
    let after_hashes = &after_r[hashes..];
    if !after_hashes.starts_with('"') {
        return None;
    }
    let mut close = String::with_capacity(1 + hashes);
    close.push('"');
    for _ in 0..hashes {
        close.push('#');
    }
    let body_end = after_hashes[1..].find(&close)?;
    let total = 1 + hashes + 1 + body_end + close.len();
    Some((total, &rest[..total]))
}

fn scan_rust_source(
    stripped: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // 1. `not(...)` inside cfg predicates / `cfg!`.
        if starts_ident_at(stripped, i, "not")
            && let Some((inner, _)) = paren_group_after(stripped, i + 3)
        {
            collect_feature_literals(inner, declared, out);
        }
        // 2. `external_library!(...)` from `dlib`.
        if starts_ident_at(stripped, i, "external_library")
            && let Some((inner, _)) = macro_group_after(stripped, i + "external_library".len())
        {
            let before = out.len();
            collect_feature_literals(inner, declared, out);
            if out.len() == before && declared.contains_key("dlopen") {
                out.insert("dlopen".to_owned());
            }
        }
        // 3. Negated `!cfg!(...)` or `!(... cfg!(...) ...)`.
        if bytes[i] == b'!' && bytes.get(i + 1) != Some(&b'=') && !preceded_by_ident(bytes, i) {
            let after_bang = skip_ws(stripped, i + 1);
            if starts_ident_at(stripped, after_bang, "cfg")
                && let Some((inner, _)) = macro_group_after(stripped, after_bang + 3)
            {
                collect_feature_literals(inner, declared, out);
            } else if let Some((inner, _)) = paren_group_after(stripped, after_bang) {
                scan_cfg_macros_in(inner, declared, out);
            }
        }
        // 4. `#[cfg(...)]` guarding `compile_error!(...)`.
        if stripped[i..].starts_with("#[")
            && let Some((attr_inner, after_attr)) = bracket_group_after(stripped, i + 1)
        {
            let trimmed = attr_inner.trim_start();
            if starts_ident_at(trimmed, 0, "cfg") && follows_compile_error(stripped, after_attr) {
                collect_feature_literals(trimmed, declared, out);
            }
        }
        let step = stripped[i..].chars().next().map_or(1, char::len_utf8);
        i += step;
    }
}

fn scan_cfg_macros_in(
    segment: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let mut i = 0;
    while i < segment.len() {
        if starts_ident_at(segment, i, "cfg")
            && let Some((inner, end)) = macro_group_after(segment, i + 3)
        {
            collect_feature_literals(inner, declared, out);
            i = end;
            continue;
        }
        i += segment[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn follows_compile_error(source: &str, mut pos: usize) -> bool {
    loop {
        pos = skip_ws(source, pos);
        if source[pos..].starts_with("#[")
            && let Some((_, next)) = bracket_group_after(source, pos + 1)
        {
            pos = next;
            continue;
        }
        break;
    }
    if !starts_ident_at(source, pos, "compile_error") {
        return false;
    }
    let after = skip_ws(source, pos + "compile_error".len());
    source.as_bytes().get(after) == Some(&b'!')
}

fn collect_feature_literals(
    segment: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let mut i = 0;
    while i < segment.len() {
        if starts_ident_at(segment, i, "feature") {
            let eq = skip_ws(segment, i + "feature".len());
            if segment.as_bytes().get(eq) == Some(&b'=') {
                let lit = skip_ws(segment, eq + 1);
                if let Some(name) = parse_string_literal(&segment[lit..])
                    && declared.contains_key(&name)
                {
                    out.insert(name);
                }
            }
        }
        i += segment[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn parse_string_literal(rest: &str) -> Option<String> {
    let body = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next()?);
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

const fn preceded_by_ident(bytes: &[u8], pos: usize) -> bool {
    pos > 0 && is_ident_byte(bytes[pos - 1])
}

fn starts_ident_at(s: &str, pos: usize, ident: &str) -> bool {
    let bytes = s.as_bytes();
    if preceded_by_ident(bytes, pos) || !s[pos..].starts_with(ident) {
        return false;
    }
    bytes
        .get(pos + ident.len())
        .is_none_or(|&b| !is_ident_byte(b))
}

const fn skip_ws(s: &str, mut pos: usize) -> usize {
    let bytes = s.as_bytes();
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn macro_group_after(s: &str, pos: usize) -> Option<(&str, usize)> {
    let bang = skip_ws(s, pos);
    if s.as_bytes().get(bang) != Some(&b'!') {
        return None;
    }
    let open = skip_ws(s, bang + 1);
    match s.as_bytes().get(open)? {
        b'(' => balanced_slice(s, open, b'(', b')'),
        b'{' => balanced_slice(s, open, b'{', b'}'),
        b'[' => balanced_slice(s, open, b'[', b']'),
        _ => None,
    }
}

fn paren_group_after(s: &str, pos: usize) -> Option<(&str, usize)> {
    let open = skip_ws(s, pos);
    balanced_slice(s, open, b'(', b')')
}

fn bracket_group_after(s: &str, pos: usize) -> Option<(&str, usize)> {
    let open = skip_ws(s, pos);
    balanced_slice(s, open, b'[', b']')
}

fn balanced_slice(s: &str, open_pos: usize, open: u8, close: u8) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    if bytes.get(open_pos) != Some(&open) {
        return None;
    }
    let mut depth = 1usize;
    let mut i = open_pos + 1;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if bytes[i] == open {
            depth += 1;
        } else if bytes[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some((&s[open_pos + 1..i], i + 1));
            }
        }
        i += 1;
    }
    None
}

/// Inspect an unpacked Cargo package directory on disk and return its
/// non-additive features. Returns an empty set when the directory or
/// `Cargo.toml` cannot be read.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn non_additive_features_in_package_dir(package_dir: &std::path::Path) -> BTreeSet<String> {
    let Ok(manifest_toml) = std::fs::read_to_string(package_dir.join("Cargo.toml")) else {
        return BTreeSet::new();
    };
    let Some(manifest) = parse_manifest_features(&manifest_toml) else {
        return BTreeSet::new();
    };
    if manifest.declared.is_empty() {
        return BTreeSet::new();
    }
    let build_canon = manifest
        .build_script_rel
        .as_deref()
        .map(|rel| package_dir.join(rel))
        .and_then(|p| std::fs::canonicalize(&p).ok().or(Some(p)));
    let mut build_sources = Vec::new();
    if let Some(path) = &build_canon
        && let Ok(text) = std::fs::read_to_string(path)
    {
        build_sources.push(text);
    }
    let mut rust_sources = Vec::new();
    collect_rs_files(package_dir, build_canon.as_deref(), &mut rust_sources);
    let build_refs: Vec<&str> = build_sources.iter().map(String::as_str).collect();
    let rust_refs: Vec<&str> = rust_sources.iter().map(String::as_str).collect();
    non_additive_features_in_sources(&manifest_toml, &build_refs, &rust_refs)
}

#[cfg(not(target_arch = "wasm32"))]
fn collect_rs_files(
    dir: &std::path::Path,
    skip_file: Option<&std::path::Path>,
    out: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            if matches!(
                name.to_str(),
                Some("target" | ".git" | "tests" | "benches" | "examples")
            ) {
                continue;
            }
            collect_rs_files(&path, skip_file, out);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            let canon = std::fs::canonicalize(&path).ok();
            let same_as_skip =
                skip_file.is_some_and(|skip| skip == path || canon.as_deref() == Some(skip));
            if !same_as_skip && let Ok(text) = std::fs::read_to_string(&path) {
                out.push(text);
            }
        }
    }
}

/// Resolve unpacked `<cargo_home>/registry/src/*/<name>-<version>` directories
/// for `packages` and return the non-empty non-additive feature sets.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn non_additive_features_in_cargo_home(
    cargo_home: &std::path::Path,
    packages: &BTreeSet<(crate::identity::CrateName, crate::identity::CrateVersion)>,
) -> BTreeMap<(crate::identity::CrateName, crate::identity::CrateVersion), BTreeSet<String>> {
    let mut out = BTreeMap::new();
    if packages.is_empty() {
        return out;
    }
    let src_root = cargo_home.join("registry").join("src");
    let Ok(registries) = std::fs::read_dir(&src_root) else {
        return out;
    };
    let registry_dirs: Vec<_> = registries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    for (name, version) in packages {
        let dir_name = format!("{name}-{version}");
        for reg_dir in &registry_dirs {
            let candidate = reg_dir.join(&dir_name);
            if candidate.is_dir() {
                let found = non_additive_features_in_package_dir(&candidate);
                if !found.is_empty() {
                    out.insert((name.clone(), version.clone()), found);
                }
                break;
            }
        }
    }
    out
}

/// Find the enclosing Cargo package root of `source_file` by walking upward to
/// the nearest `Cargo.toml`.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn enclosing_package_dir(source_file: &std::path::Path) -> Option<std::path::PathBuf> {
    let start = if source_file.is_dir() {
        source_file
    } else {
        source_file.parent()?
    };
    for ancestor in start.ancestors() {
        if ancestor.join("Cargo.toml").is_file() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_yeslogic_fontconfig_sys_dlopen_pattern() {
        let cargo_toml = r#"
[package]
name = "yeslogic-fontconfig-sys"
version = "6.0.1"

[features]
dlopen = []

[dependencies.dlib]
version = "0.5.0"
"#;
        let build_rs = r#"
fn main() {
    let dlopen = std::env::var_os("RUST_FONTCONFIG_DLOPEN").is_some();
    if !(dlopen || cfg!(feature = "dlopen")) {
        println!("cargo:rustc-link-lib=fontconfig");
    }
}
"#;
        let lib_rs = r#"
dlib::external_library!(Fc, "fontconfig",
    functions:
        fn FcFontSetDestroy(*mut ()) -> ()
);
"#;
        assert_eq!(
            non_additive_features_in_sources(cargo_toml, &[build_rs], &[lib_rs]),
            BTreeSet::from(["dlopen".to_owned()])
        );
    }

    #[test]
    fn detects_negated_cfg_compile_error_and_transitive_default() {
        let cargo_toml = r#"
[package]
name = "sample"
version = "1.0.0"

[features]
default = ["dlopen"]
dlopen = []
pure_add = []
backend_a = []
backend_b = []
"#;
        let lib_rs = r##"
// #[cfg(not(feature = "pure_add"))] in a comment is ignored
const DOC: &str = "#[cfg(not(feature = \"pure_add\"))]";

#[cfg(not(feature = "dlopen"))]
pub fn linked_only() {}

#[cfg(all(feature = "backend_a", feature = "backend_b"))]
compile_error!("cannot enable both backends");

#[cfg(feature = "pure_add")]
pub fn extra_helper() {}
"##;
        assert_eq!(
            non_additive_features_in_sources(cargo_toml, &[], &[lib_rs]),
            BTreeSet::from([
                "backend_a".to_owned(),
                "backend_b".to_owned(),
                "default".to_owned(),
                "dlopen".to_owned(),
            ])
        );
    }
}
