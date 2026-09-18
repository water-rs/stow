//! Workspace-level guard for the public cache's canonical build profile.
//!
//! The trusted CI builds every artifact with cargo's default `dev` profile.
//! A workspace that overrides identity-relevant `[profile.dev]` knobs (or
//! per-package overrides like `[profile.dev.package."*"] debug = false`)
//! produces dependency artifacts whose compile identities can never match
//! the cache — every lookup would miss by construction. Detecting that up
//! front lets stow degrade to a transparent cargo passthrough instead of
//! paying resolver/analysis/prefetch overhead for zero hits.

use std::path::Path;

use stow_types::error::Context;

/// Identity-relevant profile keys and the values cargo defaults to for
/// `dev`. Keys absent from this table (`codegen-units`, `incremental`,
/// `split-debuginfo`, `build-override`, …) do not participate in the cache
/// identity and never disqualify a workspace.
const RELEVANT_KEYS: &[(&str, CanonicalValue)] = &[
    ("opt-level", CanonicalValue::IntOrStr(0, "0")),
    ("debug", CanonicalValue::DebugDefault),
    ("strip", CanonicalValue::StripNone),
    ("debug-assertions", CanonicalValue::Bool(true)),
    ("overflow-checks", CanonicalValue::Bool(true)),
    ("panic", CanonicalValue::Str("unwind")),
    ("lto", CanonicalValue::LtoOff),
];

#[derive(Debug, Clone, Copy)]
enum CanonicalValue {
    Bool(bool),
    Str(&'static str),
    IntOrStr(i64, &'static str),
    /// `debug = true` / `2` / `"full"` are all cargo's dev default.
    DebugDefault,
    /// `strip = false` / `"none"` are equivalent to not stripping.
    StripNone,
    /// `lto = false` / `"off"` are the dev default.
    LtoOff,
}

impl CanonicalValue {
    fn matches(self, value: &toml::Value) -> bool {
        match self {
            Self::Bool(expected) => value.as_bool() == Some(expected),
            Self::Str(expected) => value.as_str() == Some(expected),
            Self::IntOrStr(int, string) => {
                value.as_integer() == Some(int) || value.as_str() == Some(string)
            }
            Self::DebugDefault => {
                value.as_bool() == Some(true)
                    || value.as_integer() == Some(2)
                    || value.as_str() == Some("full")
            }
            Self::StripNone => value.as_bool() == Some(false) || value.as_str() == Some("none"),
            Self::LtoOff => value.as_bool() == Some(false) || value.as_str() == Some("off"),
        }
    }
}

/// Why a workspace's dev profile diverges from the cache's canonical one,
/// for operator-facing logging.
#[derive(Debug)]
pub struct ProfileDivergence {
    /// Human-readable location, e.g. `profile.dev` or `profile.dev.package."*"`.
    pub section: String,
    /// The offending key.
    pub key: String,
}

impl std::fmt::Display for ProfileDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] sets `{}`", self.section, self.key)
    }
}

/// Inspect the workspace root manifest's `[profile.dev]` (including
/// per-package overrides) and report the first identity-relevant divergence
/// from cargo's defaults, or `None` when the cache can apply.
pub async fn dev_profile_divergence(
    workspace_root: &Path,
) -> stow_types::error::Result<Option<ProfileDivergence>> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let contents = async_fs::read_to_string(&manifest_path)
        .await
        .wrap_err_with(|| format!("read workspace manifest {}", manifest_path.display()))?;
    let manifest: toml::Value = toml::from_str(&contents)
        .wrap_err_with(|| format!("parse workspace manifest {}", manifest_path.display()))?;

    let Some(dev) = manifest
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .and_then(toml::Value::as_table)
    else {
        return Ok(None);
    };

    if let Some(divergence) = table_divergence(dev, "profile.dev") {
        return Ok(Some(divergence));
    }
    // Only the wildcard override rewrites every dependency's identity. A
    // named-package override (`[profile.dev.package.insta]`) diverges just
    // that package — its artifacts miss individually while the rest of the
    // workspace still hits, so it must not disqualify the whole build.
    if let Some(wildcard) = dev
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|packages| packages.get("*"))
        .and_then(toml::Value::as_table)
        && let Some(divergence) = table_divergence(wildcard, "profile.dev.package.\"*\"")
    {
        return Ok(Some(divergence));
    }
    Ok(None)
}

fn table_divergence(
    table: &toml::map::Map<String, toml::Value>,
    section: &str,
) -> Option<ProfileDivergence> {
    for (key, canonical) in RELEVANT_KEYS {
        if let Some(value) = table.get(*key)
            && !canonical.matches(value)
        {
            return Some(ProfileDivergence {
                section: section.to_owned(),
                key: (*key).to_owned(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::table_divergence;

    fn table(source: &str) -> toml::map::Map<String, toml::Value> {
        toml::from_str::<toml::Value>(source)
            .unwrap()
            .as_table()
            .unwrap()
            .clone()
    }

    #[test]
    fn canonical_values_do_not_diverge() {
        let dev = table(
            r#"
            opt-level = 0
            debug = true
            strip = "none"
            debug-assertions = true
            overflow-checks = true
            panic = "unwind"
            codegen-units = 16
            incremental = true
            "#,
        );
        assert!(table_divergence(&dev, "profile.dev").is_none());
    }

    #[test]
    fn identity_relevant_overrides_diverge() {
        let dev = table(r#"debug = "line-tables-only""#);
        let divergence = table_divergence(&dev, "profile.dev").expect("divergent");
        assert_eq!(divergence.key, "debug");

        let dev = table("opt-level = 1");
        assert!(table_divergence(&dev, "profile.dev").is_some());

        let dev = table(r#"strip = "debuginfo""#);
        assert!(table_divergence(&dev, "profile.dev").is_some());
    }

    #[test]
    fn named_package_overrides_do_not_disqualify_the_workspace() {
        let manifest: toml::Value = toml::from_str(
            r"
            [profile.dev.package.insta]
            opt-level = 3
            ",
        )
        .unwrap();
        let dev = manifest["profile"]["dev"].as_table().unwrap();
        assert!(table_divergence(dev, "profile.dev").is_none());
        let wildcard = dev
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|packages| packages.get("*"));
        assert!(wildcard.is_none());
    }

    #[test]
    fn neutral_keys_are_ignored() {
        let dev = table(
            r#"codegen-units = 1
incremental = false
split-debuginfo = "packed""#,
        );
        assert!(table_divergence(&dev, "profile.dev").is_none());
    }
}
