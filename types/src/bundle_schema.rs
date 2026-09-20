//! Schema/identity validation for assembled artifact bundles.
//!
//! The trusted publish stage assembles the bundle tar the edge later streams
//! byte-for-byte; before the tar is pushed it must prove to be a well-formed
//! stow bundle whose embedded config matches the stable public-cache identity,
//! because nothing between GHCR and the CLI inspects it again.

use std::io::Cursor;

use crate::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH, STOW_DYLIB_MEDIA_TYPE,
    STOW_PROC_MACRO_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE, STOW_RMETA_MEDIA_TYPE,
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

    let canonical_crate_name = config.crate_name.as_str().replace('-', "_");
    let canonical_stem = format!(
        "lib{}{extra}",
        canonical_crate_name,
        extra = config.extra_filename
    );
    let mut saw_canonical_rlib = false;
    let mut saw_canonical_rmeta = false;
    let mut saw_canonical_dynamic = false;

    for output in &config.outputs {
        let file_name = std::path::Path::new(&output.file_name);
        if file_name.components().count() != 1 {
            return Err(BundleSchemaError(format!(
                "bundle output {} is not a single path component",
                output.file_name
            )));
        }
        match output.media_type.as_str() {
            STOW_RLIB_MEDIA_TYPE => {
                saw_canonical_rlib |= output.file_name == format!("{canonical_stem}.rlib");
            }
            STOW_RMETA_MEDIA_TYPE => {
                saw_canonical_rmeta |= output.file_name == format!("{canonical_stem}.rmeta");
            }
            STOW_DYLIB_MEDIA_TYPE | STOW_PROC_MACRO_MEDIA_TYPE => {
                saw_canonical_dynamic |=
                    output.file_name.starts_with(&format!("{canonical_stem}."));
            }
            other => {
                return Err(BundleSchemaError(format!(
                    "bundle output {} has unsupported media type {}",
                    output.file_name, other
                )));
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
}
