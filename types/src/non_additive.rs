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
        if build_script_switches_native_link(&stripped) {
            scan_build_script_features(&stripped, &manifest.declared, &env_to_feature, &mut direct);
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

fn build_script_switches_native_link(stripped: &str) -> bool {
    [
        "rustc-link-lib",
        "rustc-link-arg",
        "pkg_config",
        "find_library",
        "vcpkg",
        "cc::Build",
        "cmake::Config",
    ]
    .iter()
    .any(|needle| stripped.contains(needle))
}

fn scan_build_script_features(
    stripped: &str,
    declared: &BTreeMap<String, Vec<String>>,
    env_to_feature: &BTreeMap<String, String>,
    out: &mut BTreeSet<String>,
) {
    collect_feature_literals(stripped, declared, out);
    for (env_key, feat) in env_to_feature {
        if stripped.contains(env_key.as_str()) {
            out.insert(feat.clone());
        }
    }
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
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
        i += stripped[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn scan_rust_source(
    stripped: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let mut positive_pub_items = BTreeSet::new();
    let mut negated_pub_items: Vec<(String, BTreeSet<String>)> = Vec::new();
    scan_module_items(
        stripped,
        declared,
        out,
        &mut positive_pub_items,
        &mut negated_pub_items,
    );
    for (item_name, feats) in negated_pub_items {
        if item_name.is_empty() || !positive_pub_items.contains(&item_name) {
            out.extend(feats);
        }
    }
}

fn scan_module_items(
    stripped: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
    positive_pub_items: &mut BTreeSet<String>,
    negated_pub_items: &mut Vec<(String, BTreeSet<String>)>,
) {
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip private `mod foo { ... }` bodies: `pub use` inside a private
        // facade module (e.g. `serde`'s `mod lib`) is not public crate API.
        if starts_ident_at(stripped, i, "mod") && !preceded_by_pub(stripped, i) {
            let after_mod = skip_ws(stripped, i + 3);
            let ident_end = consume_ident(stripped, after_mod);
            if ident_end > after_mod {
                let brace = skip_ws(stripped, ident_end);
                if let Some((_, after_body)) = balanced_slice(stripped, brace, b'{', b'}') {
                    i = after_body;
                    continue;
                }
            }
        }
        // 1. `external_library!(...)` from `dlib`.
        if starts_ident_at(stripped, i, "external_library")
            && let Some((inner, _)) = macro_group_after(stripped, i + "external_library".len())
        {
            let before = out.len();
            collect_feature_literals(inner, declared, out);
            if out.len() == before && declared.contains_key("dlopen") {
                out.insert("dlopen".to_owned());
            }
        }
        // 2. Consecutive outer `#[...]` attribute block on an item.
        if stripped[i..].starts_with("#[") {
            let (cfg_preds, saw_macro_export, after_attrs) = consume_outer_attrs(stripped, i);
            if !cfg_preds.is_empty() {
                if starts_compile_error_at(stripped, after_attrs) {
                    for pred in &cfg_preds {
                        if cfg_is_pure_feature_formula(pred) {
                            collect_positive_features_in_cfg(pred, declared, out);
                        }
                    }
                } else if let Some(item_name) =
                    public_item_name_at(stripped, after_attrs, saw_macro_export)
                {
                    let mut neg = BTreeSet::new();
                    for pred in &cfg_preds {
                        collect_negated_features_in_cfg(pred, declared, &mut neg);
                    }
                    if neg.is_empty() {
                        if !item_name.is_empty() {
                            positive_pub_items.insert(item_name);
                        }
                    } else {
                        negated_pub_items.push((item_name, neg));
                    }
                    i = (after_attrs + 3).min(bytes.len());
                    continue;
                }
                i = after_attrs.max(i + 2);
                continue;
            }
        }
        // Record unattributed `pub` item names so a negated fallback paired
        // with an unconditional or positive sibling knows the symbol stays.
        if starts_ident_at(stripped, i, "pub")
            && let Some(name) = public_item_name_at(stripped, i, false)
            && !name.is_empty()
        {
            positive_pub_items.insert(name);
        }
        i += stripped[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn consume_outer_attrs(source: &str, mut pos: usize) -> (Vec<String>, bool, usize) {
    let mut cfg_preds = Vec::new();
    let mut saw_macro_export = false;
    loop {
        let cur = skip_ws(source, pos);
        if source[cur..].starts_with("#[")
            && let Some((inner, next)) = bracket_group_after(source, cur + 1)
        {
            let trimmed = inner.trim_start();
            if starts_ident_at(trimmed, 0, "cfg")
                && let Some((pred, _)) = paren_group_after(trimmed, 3)
            {
                cfg_preds.push(pred.to_owned());
            } else if starts_ident_at(trimmed, 0, "macro_export") {
                saw_macro_export = true;
            }
            pos = next;
            continue;
        }
        return (cfg_preds, saw_macro_export, cur);
    }
}

fn starts_compile_error_at(source: &str, pos: usize) -> bool {
    if !starts_ident_at(source, pos, "compile_error") {
        return false;
    }
    let after = skip_ws(source, pos + "compile_error".len());
    source.as_bytes().get(after) == Some(&b'!')
}

fn cfg_is_pure_feature_formula(pred: &str) -> bool {
    let mut i = 0;
    while i < pred.len() {
        let b = pred.as_bytes()[i];
        if b.is_ascii_whitespace() || matches!(b, b'(' | b')' | b',') {
            i += 1;
            continue;
        }
        if starts_ident_at(pred, i, "all")
            || starts_ident_at(pred, i, "any")
            || starts_ident_at(pred, i, "not")
        {
            i = consume_ident(pred, i);
            continue;
        }
        if starts_ident_at(pred, i, "feature") {
            let eq = skip_ws(pred, i + "feature".len());
            if pred.as_bytes().get(eq) == Some(&b'=') {
                let lit = skip_ws(pred, eq + 1);
                if let Some(val) = parse_string_literal(&pred[lit..]) {
                    i = lit + val.len() + 2;
                    continue;
                }
            }
        }
        return false;
    }
    true
}

fn collect_positive_features_in_cfg(
    cfg_pred: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let mut i = 0;
    while i < cfg_pred.len() {
        if starts_ident_at(cfg_pred, i, "not")
            && let Some((_, end)) = paren_group_after(cfg_pred, i + 3)
        {
            i = end;
            continue;
        }
        if starts_ident_at(cfg_pred, i, "feature") {
            let eq = skip_ws(cfg_pred, i + "feature".len());
            if cfg_pred.as_bytes().get(eq) == Some(&b'=') {
                let lit = skip_ws(cfg_pred, eq + 1);
                if let Some(name) = parse_string_literal(&cfg_pred[lit..])
                    && declared.contains_key(&name)
                {
                    out.insert(name);
                }
            }
        }
        i += cfg_pred[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn collect_negated_features_in_cfg(
    cfg_attr: &str,
    declared: &BTreeMap<String, Vec<String>>,
    out: &mut BTreeSet<String>,
) {
    let mut i = 0;
    while i < cfg_attr.len() {
        if starts_ident_at(cfg_attr, i, "not")
            && let Some((inner, _)) = paren_group_after(cfg_attr, i + 3)
        {
            collect_feature_literals(inner, declared, out);
        }
        i += cfg_attr[i..].chars().next().map_or(1, char::len_utf8);
    }
}

fn preceded_by_pub(source: &str, mod_pos: usize) -> bool {
    let before = source[..mod_pos].trim_end();
    before.len() >= 3 && starts_ident_at(before, before.len() - 3, "pub")
}

const fn consume_ident(source: &str, mut pos: usize) -> usize {
    let bytes = source.as_bytes();
    while pos < bytes.len() && is_ident_byte(bytes[pos]) {
        pos += 1;
    }
    pos
}

fn public_item_name_at(source: &str, pos: usize, saw_macro_export: bool) -> Option<String> {
    if saw_macro_export && starts_ident_at(source, pos, "macro_rules") {
        let bang = skip_ws(source, pos + "macro_rules".len());
        if source.as_bytes().get(bang) == Some(&b'!') {
            let name_start = skip_ws(source, bang + 1);
            let name_end = consume_ident(source, name_start);
            return Some(source[name_start..name_end].to_owned());
        }
        return Some(String::new());
    }
    if starts_ident_at(source, pos, "pub") {
        let mut cur = skip_ws(source, pos + 3);
        if source.as_bytes().get(cur) == Some(&b'(') {
            return None;
        }
        for kw in ["unsafe", "async", "const"] {
            if starts_ident_at(source, cur, kw) {
                cur = skip_ws(source, cur + kw.len());
            }
        }
        if starts_ident_at(source, cur, "extern") {
            cur = skip_ws(source, cur + "extern".len());
            if let Some(abi) = parse_string_literal(&source[cur..]) {
                cur = skip_ws(source, cur + abi.len() + 2);
            }
        }
        if starts_ident_at(source, cur, "use") {
            return Some(extract_pub_use_leaf(&source[cur + 3..]));
        }
        for kw in [
            "fn", "struct", "enum", "trait", "type", "const", "static", "mod", "union",
        ] {
            if starts_ident_at(source, cur, kw) {
                let name_start = skip_ws(source, cur + kw.len());
                let name_end = consume_ident(source, name_start);
                return Some(source[name_start..name_end].to_owned());
            }
        }
        return Some(String::new());
    }
    None
}

fn extract_pub_use_leaf(after_use: &str) -> String {
    let stmt_end = after_use.find(';').unwrap_or(after_use.len());
    let stmt = after_use[..stmt_end].trim();
    if stmt.contains('{') || stmt.ends_with('*') {
        return String::new();
    }
    if let Some((_, alias)) = stmt.rsplit_once(" as ") {
        let alias = alias.trim();
        let end = consume_ident(alias, 0);
        if end > 0 && alias != "_" {
            return alias[..end].to_owned();
        }
    }
    let tail = stmt.rsplit("::").next().unwrap_or(stmt).trim();
    let end = consume_ident(tail, 0);
    tail[..end].to_owned()
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

    #[test]
    fn keeps_private_no_std_fallbacks_and_cfg_only_build_scripts_additive() {
        let once_cell_toml = r#"
[package]
name = "once_cell"
version = "1.21.4"

[features]
default = ["std"]
std = ["alloc"]
alloc = ["race"]
race = []
critical-section = []
parking_lot = []
portable-atomic = []
"#;
        let once_cell_lib = r#"
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "critical-section", not(feature = "std")))]
#[path = "imp_cs.rs"]
mod imp;

#[cfg(all(feature = "std", not(feature = "parking_lot")))]
#[path = "imp_std.rs"]
mod imp;

#[cfg(not(feature = "portable-atomic"))]
use core::sync::atomic;

#[cfg(not(feature = "std"))]
pub(crate) fn internal_helper() {}
"#;
        assert!(
            non_additive_features_in_sources(once_cell_toml, &[], &[once_cell_lib]).is_empty(),
            "once_cell's no_std and private-module fallbacks are additive"
        );

        let proc_macro2_toml = r#"
[package]
name = "proc-macro2"
version = "1.0.107"

[features]
default = ["proc-macro"]
proc-macro = []
span-locations = []
"#;
        let proc_macro2_build = r#"
fn main() {
    if cfg!(feature = "span-locations") {
        println!("cargo:rustc-cfg=span_locations");
    }
    if !cfg!(feature = "proc-macro") {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }
    println!("cargo:rustc-cfg=wrap_proc_macro");
}
"#;
        assert!(
            non_additive_features_in_sources(proc_macro2_toml, &[proc_macro2_build], &[""])
                .is_empty(),
            "cfg-only build scripts without native link directives remain additive"
        );

        let paired_pub_lib = r#"
#[cfg(feature = "std")]
pub struct IndexMap<K, V, S = ()>(core::marker::PhantomData<(K, V, S)>);
#[cfg(not(feature = "std"))]
pub struct IndexMap<K, V, S>(core::marker::PhantomData<(K, V, S)>);

#[cfg(feature = "std")]
#[macro_export]
macro_rules! helper_macro { () => { 1 }; }
#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! helper_macro { () => { 0 }; }
"#;
        assert!(
            non_additive_features_in_sources(once_cell_toml, &[], &[paired_pub_lib]).is_empty(),
            "paired positive/negated definitions of the same public symbol remain additive"
        );
    }
}
