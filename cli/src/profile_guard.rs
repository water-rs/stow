//! Workspace-level guard for profile settings the public cache can never
//! serve.
//!
//! Every profile knob rustc sees (`opt-level`, `debuginfo`, debug
//! assertions, overflow checks, `panic`, `strip`) is part of the compile
//! identity (`stow_types::platform::Profile`), so a workspace that tunes
//! `[profile.dev]` — or every dependency through
//! `[profile.dev.package."*"]` — is not disqualified: its lookups carry the
//! tuned profile and hit whenever the pool holds artifacts built under it,
//! which is what project-source seeding produces. The one knob no identity
//! can express is `lto`: cargo then compiles every dependency with
//! `-C linker-plugin-lto`, which `stow_types::rustc` treats as custom
//! codegen, so every unit is ineligible and stow degrades to a transparent
//! cargo passthrough instead of paying analysis overhead for zero hits.

use std::path::Path;

use stow_types::error::Context;

/// Why a workspace's dev profile can never be served, for operator-facing
/// logging.
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

/// Inspect the workspace root manifest's `[profile.dev]` (including the
/// wildcard package override) and report the first setting that makes
/// every dependency unit ineligible, or `None` when the cache can apply.
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
    // Only the wildcard override reaches every dependency. A named-package
    // override (`[profile.dev.package.insta]`) affects just that package —
    // its artifacts miss individually while the rest of the workspace still
    // hits, so it must not disqualify the whole build.
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

/// `lto = false` and `lto = "off"` are cargo's dev default; anything else
/// turns on linker-plugin LTO for every dependency.
fn table_divergence(
    table: &toml::map::Map<String, toml::Value>,
    section: &str,
) -> Option<ProfileDivergence> {
    let lto = table.get("lto")?;
    let default = lto.as_bool() == Some(false) || lto.as_str() == Some("off");
    (!default).then(|| ProfileDivergence {
        section: section.to_owned(),
        key: "lto".to_owned(),
    })
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
    fn identity_expressible_knobs_do_not_diverge() {
        let dev = table(
            r#"
            opt-level = 2
            debug = "line-tables-only"
            strip = "debuginfo"
            debug-assertions = false
            overflow-checks = false
            panic = "abort"
            codegen-units = 1
            incremental = false
            split-debuginfo = "packed"
            lto = false
            "#,
        );
        assert!(table_divergence(&dev, "profile.dev").is_none());
        let dev = table(r#"lto = "off""#);
        assert!(table_divergence(&dev, "profile.dev").is_none());
    }

    #[test]
    fn lto_diverges() {
        for source in ["lto = true", r#"lto = "fat""#, r#"lto = "thin""#] {
            let dev = table(source);
            let divergence = table_divergence(&dev, "profile.dev").expect("divergent");
            assert_eq!(divergence.key, "lto");
        }
    }

    #[test]
    fn named_package_overrides_do_not_disqualify_the_workspace() {
        let manifest: toml::Value = toml::from_str(
            r"
            [profile.dev.package.insta]
            lto = true
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
}
