//! Schema/identity validation for assembled artifact bundles.
//!
//! The trusted publish stage assembles the bundle tar the edge later streams
//! byte-for-byte; before the tar is pushed it must prove to be a well-formed
//! stow bundle whose embedded config matches the stable public-cache identity,
//! because nothing between GHCR and the CLI inspects it again.

use std::io::Cursor;

use crate::bundle::{
    ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH,
    STOW_DYLIB_MEDIA_TYPE, STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE,
};
use crate::public_cache::stable_c_metadata_for_compile_key;

/// An assembled bundle failed schema or identity validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid bundle: {0}")]
pub struct BundleSchemaError(pub String);

/// Validate an assembled bundle tar: it must carry a `manifest.json` whose
/// config names a stable public-cache identity and canonical output files.
///
/// # Errors
/// Returns [`BundleSchemaError`] when the tar cannot be read, the manifest is
/// missing or malformed, or the config's identity is inconsistent.
pub fn validate_bundle_schema(bytes: &[u8]) -> Result<(), BundleSchemaError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut manifest_bytes = None::<Vec<u8>>;
    for entry in archive
        .entries()
        .map_err(|error| BundleSchemaError(format!("read bundle entries: {error}")))?
    {
        let mut entry =
            entry.map_err(|error| BundleSchemaError(format!("read bundle entry: {error}")))?;
        let path = entry
            .path()
            .map_err(|error| BundleSchemaError(format!("read bundle path: {error}")))?
            .to_string_lossy()
            .to_string();
        if path != STOW_BUNDLE_MANIFEST_PATH {
            continue;
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes)
            .map_err(|error| BundleSchemaError(format!("read bundle manifest payload: {error}")))?;
        manifest_bytes = Some(bytes);
        break;
    }
    let manifest_bytes = manifest_bytes
        .ok_or_else(|| BundleSchemaError("bundle is missing manifest.json".to_owned()))?;
    let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&manifest_bytes)
        .map_err(|error| BundleSchemaError(format!("parse bundle manifest json: {error}")))?;
    validate_bundle_config_identity(&manifest.config)?;
    Ok(())
}

fn validate_bundle_config_identity(config: &ArtifactBlobConfig) -> Result<(), BundleSchemaError> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&config.compile_key).map_err(|error| {
            BundleSchemaError(format!(
                "bundle compile_key {} is not a valid stable public-cache identity: {error}",
                config.compile_key
            ))
        })?;
    if stable_c_metadata != config.c_metadata.as_str() {
        return Err(BundleSchemaError(format!(
            "bundle c_metadata {} does not match stable compile_key prefix {}",
            config.c_metadata, stable_c_metadata
        )));
    }

    // The lib name — rustc's `--crate-name`, the stem every artifact file
    // is named after — is not `config.crate_name` underscored: `[lib]
    // name = "…"` names a lib target nothing like the package, and the
    // package is all the config carries (stow#578). Derive it from the
    // outputs instead: every artifact rustc writes is
    // `lib?<name>-<metadata>.<ext>`, so the outputs themselves name the
    // one lib name a bundle may hold.
    let mut lib_name = None::<String>;
    let mut saw_canonical_rlib = false;
    let mut saw_canonical_rmeta = false;
    let mut saw_canonical_dynamic = false;

    for output in &config.outputs {
        let (stem, kind) = classify_bundle_output(config, output)?;
        match &lib_name {
            Some(name) if *name != stem => {
                return Err(BundleSchemaError(format!(
                    "bundle outputs {} name two different lib stems ({name} and {stem})",
                    output.file_name
                )));
            }
            Some(_) => {}
            None => lib_name = Some(stem.clone()),
        }
        let canonical_stem = format!("lib{stem}{extra}", extra = config.extra_filename);
        match kind {
            BundleOutputKind::Rlib => {
                saw_canonical_rlib |= output.file_name == format!("{canonical_stem}.rlib");
            }
            BundleOutputKind::Rmeta => {
                saw_canonical_rmeta |= output.file_name == format!("{canonical_stem}.rmeta");
            }
            BundleOutputKind::Dynamic => {
                // Dynamic output names are platform-shaped: unix takes
                // `lib<crate><extra>.{so,dylib}`, Windows takes
                // `<crate><extra>.dll` with no `lib` prefix.
                let prefix = if config.target.is_windows() {
                    format!("{stem}{extra}.dll", extra = config.extra_filename)
                } else {
                    format!("{canonical_stem}.")
                };
                saw_canonical_dynamic |= output.file_name.starts_with(&prefix);
            }
        }
    }

    if config
        .outputs
        .iter()
        .any(|output| output.media_type == STOW_RLIB_MEDIA_TYPE)
        && !saw_canonical_rlib
    {
        return Err(BundleSchemaError(format!(
            "bundle is missing canonical rlib output for stable metadata {}",
            config.c_metadata
        )));
    }
    if config
        .outputs
        .iter()
        .any(|output| output.media_type == STOW_RMETA_MEDIA_TYPE)
        && !saw_canonical_rmeta
    {
        return Err(BundleSchemaError(format!(
            "bundle is missing canonical rmeta output for stable metadata {}",
            config.c_metadata
        )));
    }
    if config.outputs.iter().any(|output| {
        output.media_type == STOW_DYLIB_MEDIA_TYPE
            || output.media_type == STOW_PROC_MACRO_MEDIA_TYPE
    }) && !saw_canonical_dynamic
    {
        return Err(BundleSchemaError(format!(
            "bundle is missing canonical dynamic output for stable metadata {}",
            config.c_metadata
        )));
    }

    Ok(())
}

/// Which canonical check a bundle output participates in.
enum BundleOutputKind {
    Rlib,
    Rmeta,
    Dynamic,
}

/// Read one bundle output: its lib stem and which canonical kind it is,
/// or the schema violation the name carries.
fn classify_bundle_output(
    config: &ArtifactBlobConfig,
    output: &ArtifactBundleFile,
) -> Result<(String, BundleOutputKind), BundleSchemaError> {
    let file_name = std::path::Path::new(&output.file_name);
    if file_name.components().count() != 1 {
        return Err(BundleSchemaError(format!(
            "bundle output {} is not a single path component",
            output.file_name
        )));
    }
    let stem = match output.media_type.as_str() {
        STOW_RLIB_MEDIA_TYPE => {
            return Ok((
                output_lib_stem(&output.file_name, "rlib")?,
                BundleOutputKind::Rlib,
            ));
        }
        STOW_RMETA_MEDIA_TYPE => {
            return Ok((
                output_lib_stem(&output.file_name, "rmeta")?,
                BundleOutputKind::Rmeta,
            ));
        }
        STOW_DYLIB_MEDIA_TYPE | STOW_PROC_MACRO_MEDIA_TYPE => {
            if config.target.is_windows() {
                output_windows_dynamic_stem(&output.file_name)?
            } else {
                output_dynamic_stem(&output.file_name)?
            }
        }
        other => {
            return Err(BundleSchemaError(format!(
                "bundle output {} has unsupported media type {}",
                output.file_name, other
            )));
        }
    };
    Ok((stem, BundleOutputKind::Dynamic))
}

/// The error an output name that names no rustc artifact shape raises.
fn malformed_output(file_name: &str) -> BundleSchemaError {
    BundleSchemaError(format!(
        "bundle output {file_name} does not match `lib?<crate>-<metadata>` artifact name shape"
    ))
}

/// Parse `<name>-<metadata>` from an artifact body: `<name>` is the lib
/// name (rustc's `--crate-name`, a crate identifier), `<metadata>` the
/// 16-hex `-C metadata` of whichever identity cargo handed that
/// invocation — the stable identity on the canonical outputs, cargo's
/// ephemeral one on the aliased copies shipped beside them.
fn artifact_stem(body: &str, file_name: &str) -> Result<String, BundleSchemaError> {
    let (name, metadata) = body
        .rsplit_once('-')
        .ok_or_else(|| malformed_output(file_name))?;
    // A crate identifier is letters, digits and `_` and never opens with
    // a digit; rustc's metadata is 16 lowercase hex digits.
    let crate_identifier = !name.is_empty()
        && !name.as_bytes()[0].is_ascii_digit()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    let metadata_suffix = metadata.len() == 16
        && metadata
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !crate_identifier || !metadata_suffix {
        return Err(malformed_output(file_name));
    }
    Ok(name.to_owned())
}

/// The lib stem of a `lib<crate>-<metadata>.<ext>` output.
fn output_lib_stem(file_name: &str, ext: &str) -> Result<String, BundleSchemaError> {
    let body = file_name
        .strip_prefix("lib")
        .and_then(|rest| rest.strip_suffix(&format!(".{ext}")))
        .ok_or_else(|| malformed_output(file_name))?;
    artifact_stem(body, file_name)
}

/// The lib stem of a unix dynamic output — `lib<crate>-<metadata>.<ext>`
/// with the extension whatever rustc emitted (`so`, `dylib`, …).
fn output_dynamic_stem(file_name: &str) -> Result<String, BundleSchemaError> {
    let body = file_name
        .strip_prefix("lib")
        .and_then(|rest| rest.split_once('.'))
        .map(|(body, _ext)| body)
        .ok_or_else(|| malformed_output(file_name))?;
    artifact_stem(body, file_name)
}

/// The lib stem of a Windows dynamic output — `<crate>-<metadata>.dll`
/// (and the `.dll.*` companions rustc writes beside it, like the
/// import library). Windows dynamic artifacts take no `lib` prefix, so
/// a name carrying one is not a stem the shape can ever have meant —
/// it is the unix spelling on the wrong platform.
fn output_windows_dynamic_stem(file_name: &str) -> Result<String, BundleSchemaError> {
    if file_name.starts_with("lib") {
        return Err(malformed_output(file_name));
    }
    let body = file_name
        .split_once(".dll")
        .map(|(body, _ext)| body)
        .ok_or_else(|| malformed_output(file_name))?;
    artifact_stem(body, file_name)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::validate_bundle_schema;
    use crate::artifact::{ArtifactKind, RustCrateType};
    use crate::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH,
        STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE,
    };
    use crate::identity::{
        CMetadata, CrateName, DependencyCMetadataIdentity, DependencyCMetadataJson, FeaturesJson,
        TargetTriple, WireRustcVersion,
    };
    use crate::platform::{PanicStrategy, Profile, StripLevel};
    use tar::{Builder, Header};

    fn profile() -> Profile {
        Profile {
            opt_level: "0".to_owned(),
            debuginfo: 1,
            debug_assertions: true,
            overflow_checks: true,
            panic: PanicStrategy::Unwind,
            strip: StripLevel::None,
        }
    }

    fn bundle_file(file_name: &str, media_type: &str) -> ArtifactBundleFile {
        ArtifactBundleFile {
            file_name: file_name.to_owned(),
            media_type: media_type.to_owned(),
            sha256: "deadbeef".to_owned(),
        }
    }

    fn stable_config(outputs: Vec<ArtifactBundleFile>) -> ArtifactBlobConfig {
        let dependency_identity = DependencyCMetadataIdentity {
            crate_name: CrateName::parse("unicode_ident").unwrap(),
            c_metadata: CMetadata::parse(
                "0e63365407e7f07c2be3d7da23fc1e46fdf371b2b1e7030e54325461657e757f",
            )
            .unwrap(),
        };
        ArtifactBlobConfig {
            compile_key: "df1c5df8d44a9ede068e852b56a99270d4d6b905ee849e7f4861e2c13699f43e"
                .to_owned(),
            crate_name: CrateName::parse("proc-macro2").unwrap(),
            crate_version: "1.0.106".parse().unwrap(),
            c_metadata: CMetadata::parse("df1c5df8d44a9ede").unwrap(),
            extra_filename: "-df1c5df8d44a9ede".to_owned(),
            target: TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            features_json: FeaturesJson::canonicalize(vec![
                "default".to_owned(),
                "proc-macro".to_owned(),
            ])
            .unwrap(),
            dependency_compile_keys_json: DependencyCMetadataJson::from_sorted(vec![
                dependency_identity.clone(),
            ])
            .unwrap()
            .raw(),
            dependency_c_metadata_json: DependencyCMetadataJson::from_sorted(vec![
                dependency_identity,
            ])
            .unwrap(),
            profile: profile(),
            emit: vec![
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ],
            artifact_size: 1,
            compile_millis: 0,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs,
            native: None,
            native_archive: None,
        }
    }

    fn bundle_bytes(config: ArtifactBlobConfig) -> Vec<u8> {
        let manifest = ArtifactBundleManifest {
            oci_reference: "ghcr.io/water-rs/stow-cache:proc-macro2.test".to_owned(),
            oci_digest: "sha256:test".to_owned(),
            config,
            sigstore_signatures: Vec::new(),
        };
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let mut tar = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_size(manifest_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(
            &mut header,
            STOW_BUNDLE_MANIFEST_PATH,
            Cursor::new(manifest_json),
        )
        .unwrap();
        tar.into_inner().unwrap()
    }

    #[test]
    fn validate_bundle_schema_rejects_stable_bundle_without_canonical_output_names() {
        let bytes = bundle_bytes(stable_config(vec![
            bundle_file("libproc_macro2-68afcc2f66100859.rlib", STOW_RLIB_MEDIA_TYPE),
            bundle_file(
                "libproc_macro2-68afcc2f66100859.rmeta",
                STOW_RMETA_MEDIA_TYPE,
            ),
        ]));

        assert!(validate_bundle_schema(&bytes).is_err());
    }

    #[test]
    fn validate_bundle_schema_accepts_windows_proc_macro_without_lib_prefix() {
        // Windows dynamic artifacts are `<crate><extra>.dll` — no `lib`
        // prefix — so a windows-target proc-macro bundle must not be held
        // to the unix stem (stow#431).
        let mut config = stable_config(vec![bundle_file(
            "dyn_stack_macros-df1c5df8d44a9ede.dll",
            crate::bundle::STOW_PROC_MACRO_MEDIA_TYPE,
        )]);
        config.crate_name = CrateName::parse("dyn-stack-macros").unwrap();
        config.target = TargetTriple::parse("x86_64-pc-windows-msvc").unwrap();
        config.kind = ArtifactKind::ProcMacro;
        config.crate_types = vec![RustCrateType::ProcMacro];

        validate_bundle_schema(&bundle_bytes(config)).unwrap();
    }

    #[test]
    fn validate_bundle_schema_rejects_windows_proc_macro_with_lib_prefix() {
        let mut config = stable_config(vec![bundle_file(
            "libdyn_stack_macros-df1c5df8d44a9ede.dll",
            crate::bundle::STOW_PROC_MACRO_MEDIA_TYPE,
        )]);
        config.crate_name = CrateName::parse("dyn-stack-macros").unwrap();
        config.target = TargetTriple::parse("x86_64-pc-windows-msvc").unwrap();
        config.kind = ArtifactKind::ProcMacro;
        config.crate_types = vec![RustCrateType::ProcMacro];

        assert!(validate_bundle_schema(&bundle_bytes(config)).is_err());
    }

    #[test]
    fn validate_bundle_schema_accepts_stable_bundle_with_canonical_output_names() {
        let bytes = bundle_bytes(stable_config(vec![
            bundle_file("libproc_macro2-57f123ce754eb51b.rlib", STOW_RLIB_MEDIA_TYPE),
            bundle_file("libproc_macro2-df1c5df8d44a9ede.rlib", STOW_RLIB_MEDIA_TYPE),
            bundle_file(
                "libproc_macro2-57f123ce754eb51b.rmeta",
                STOW_RMETA_MEDIA_TYPE,
            ),
            bundle_file(
                "libproc_macro2-df1c5df8d44a9ede.rmeta",
                STOW_RMETA_MEDIA_TYPE,
            ),
        ]));

        validate_bundle_schema(&bytes).unwrap();
    }

    #[test]
    fn validate_bundle_schema_accepts_a_lib_name_that_is_not_the_package_name() {
        // `new_debug_unreachable` declares `[lib] name = "debug_unreachable"`,
        // so rustc names the outputs after the lib target — the package
        // name in `config.crate_name` never enters the file names (stow#578).
        let mut config = stable_config(vec![
            bundle_file(
                "libdebug_unreachable-df1c5df8d44a9ede.rlib",
                STOW_RLIB_MEDIA_TYPE,
            ),
            bundle_file(
                "libdebug_unreachable-df1c5df8d44a9ede.rmeta",
                STOW_RMETA_MEDIA_TYPE,
            ),
        ]);
        config.crate_name = CrateName::parse("new_debug_unreachable").unwrap();

        validate_bundle_schema(&bundle_bytes(config)).unwrap();
    }

    #[test]
    fn validate_bundle_schema_rejects_outputs_naming_two_lib_stems() {
        let bytes = bundle_bytes(stable_config(vec![
            bundle_file(
                "libdebug_unreachable-df1c5df8d44a9ede.rlib",
                STOW_RLIB_MEDIA_TYPE,
            ),
            bundle_file("libitoa-df1c5df8d44a9ede.rmeta", STOW_RMETA_MEDIA_TYPE),
        ]));

        let error = validate_bundle_schema(&bytes).expect_err("mixed stems must fail");
        assert!(
            error.to_string().contains("two different lib stems"),
            "{error}"
        );
    }

    #[test]
    fn validate_bundle_schema_rejects_a_wrong_extra_filename() {
        // The outputs share a stem but carry a metadata suffix that is not
        // the config's `extra_filename` — no canonical output exists for
        // the identity the bundle claims.
        let bytes = bundle_bytes(stable_config(vec![
            bundle_file("libproc_macro2-68afcc2f66100859.rlib", STOW_RLIB_MEDIA_TYPE),
            bundle_file(
                "libproc_macro2-68afcc2f66100859.rmeta",
                STOW_RMETA_MEDIA_TYPE,
            ),
        ]));

        let error = validate_bundle_schema(&bytes).expect_err("a wrong extra_filename must fail");
        assert!(
            error.to_string().contains("missing canonical rlib output"),
            "{error}"
        );
    }
}
