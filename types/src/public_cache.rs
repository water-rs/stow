use crate::artifact::{ArtifactKind, RustCrateType};
use crate::platform::Profile;
use crate::rustc::ParsedRustcArgs;
use crate::upload_plan::compute_compile_key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableRegistryArtifactIdentity {
    pub compile_key: String,
    pub c_metadata: String,
    pub extra_filename: String,
    pub crate_name: String,
    pub version: String,
}

pub fn canonical_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

pub fn detect_registry_crate_version(
    parsed: &ParsedRustcArgs,
) -> crate::error::Result<Option<(String, String)>> {
    let Some(input_path) = parsed.input_path.as_ref() else {
        return Ok(None);
    };
    let crate_name = canonical_crate_name(&parsed.crate_name);
    for ancestor in input_path.ancestors() {
        let Some(component) = ancestor.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if let Some((package_name, version)) =
            split_registry_package_component(component, &crate_name)
        {
            return Ok(Some((package_name, version)));
        }
    }
    Ok(None)
}

pub fn stable_registry_artifact_identity(
    parsed: &ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
    features_json: &str,
    dependency_c_metadata_json: &str,
) -> crate::error::Result<Option<StableRegistryArtifactIdentity>> {
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    let profile = normalized_cache_profile(parsed)?;
    let kind = parsed_artifact_kind(parsed)?;
    let crate_types = parsed_crate_types(parsed)?;
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
    let compile_key = compute_compile_key(
        &crate_name,
        &version,
        target,
        rustc_version,
        &profile,
        &crate_types,
        &emit,
        features_json,
        dependency_c_metadata_json,
        &kind,
    )?;
    let c_metadata = stable_c_metadata_for_compile_key(&compile_key)?;
    Ok(Some(StableRegistryArtifactIdentity {
        compile_key,
        extra_filename: format!("-{c_metadata}"),
        c_metadata,
        crate_name,
        version,
    }))
}

pub fn stable_c_metadata_for_compile_key(compile_key: &str) -> crate::error::Result<String> {
    const STABLE_METADATA_HEX_LEN: usize = 16;
    if compile_key.len() < STABLE_METADATA_HEX_LEN
        || !compile_key.chars().all(|value| value.is_ascii_hexdigit())
    {
        return Err(crate::stow_error!(
            "compile key `{compile_key}` is not valid hex for stable c_metadata"
        ));
    }
    Ok(compile_key[..STABLE_METADATA_HEX_LEN].to_owned())
}

fn split_registry_package_component(
    component: &str,
    expected_crate_name: &str,
) -> Option<(String, String)> {
    for (index, _) in component.match_indices('-').rev() {
        let crate_name = &component[..index];
        let version = &component[index + 1..];
        if canonical_crate_name(crate_name) != expected_crate_name {
            continue;
        }
        if semver::Version::parse(version).is_err() {
            continue;
        }
        return Some((crate_name.to_owned(), version.to_owned()));
    }
    None
}

pub fn normalized_cache_profile(parsed: &ParsedRustcArgs) -> crate::error::Result<Profile> {
    let mut profile = parsed.profile().map_err(crate::error::Error::msg)?;
    if parsed.debuginfo.is_none() || !parsed.emit.iter().any(|entry| entry == "link") {
        profile.debuginfo = 1;
    }
    Ok(profile)
}

fn parsed_artifact_kind(parsed: &ParsedRustcArgs) -> crate::error::Result<ArtifactKind> {
    let crate_types = parsed_crate_types(parsed)?;
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::ProcMacro))
    {
        return Ok(ArtifactKind::ProcMacro);
    }
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::Dylib))
    {
        return Ok(ArtifactKind::Dylib);
    }
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, RustCrateType::Lib | RustCrateType::Rlib))
    {
        return Ok(ArtifactKind::Rlib);
    }
    Err(crate::stow_error!(
        "unsupported artifact kind for crate types {:?}",
        parsed.crate_types
    ))
}

fn parsed_crate_types(parsed: &ParsedRustcArgs) -> crate::error::Result<Vec<RustCrateType>> {
    parsed
        .crate_types
        .iter()
        .map(|crate_type| match crate_type.as_str() {
            "lib" => Ok(RustCrateType::Lib),
            "rlib" => Ok(RustCrateType::Rlib),
            "dylib" => Ok(RustCrateType::Dylib),
            "cdylib" => Ok(RustCrateType::Cdylib),
            "staticlib" => Ok(RustCrateType::Staticlib),
            "proc-macro" => Ok(RustCrateType::ProcMacro),
            other => Err(crate::stow_error!("unsupported crate type `{other}`")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{normalized_cache_profile, stable_registry_artifact_identity};
    use crate::rustc::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn cache_profile_defaults_missing_debuginfo_to_line_tables() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let profile = normalized_cache_profile(&parsed).expect("normalize cache profile");

        assert_eq!(profile.debuginfo, 1);
    }

    #[test]
    fn cache_profile_preserves_explicit_debuginfo_zero() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "debuginfo=0",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let profile = normalized_cache_profile(&parsed).expect("normalize cache profile");

        assert_eq!(profile.debuginfo, 0);
    }

    #[test]
    fn unicode_ident_host_invocation_maps_to_ci_stable_identity() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "unicode_ident",
            "--edition=2021",
            "/Users/lexoliu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/unicode-ident-1.0.24/src/lib.rs",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/tmp/out",
        ]))
        .expect("parse unicode-ident rustc args");

        let identity = stable_registry_artifact_identity(
            &parsed,
            "aarch64-apple-darwin",
            "1.91.1",
            "[]",
            "[]",
        )
        .expect("compute stable registry identity")
        .expect("registry crate identity");

        assert_eq!(identity.c_metadata, "0e63365407e7f07c");
    }
}
