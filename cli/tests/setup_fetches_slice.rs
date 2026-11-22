//! `stow setup` leaves the host index slice in the local cache: a plain
//! `cargo build` right after — with no `stow` command in between —
//! serves the units the slice covers (stow#1032).
//!
//! The stack is the mock's shape in miniature: one loopback server
//! answers the OCI requests `ensure_slice` makes (the anonymous token
//! exchange, the slice manifest and its blobs, and the cosign-shaped
//! signature image) plus the `/api/v1/bundles/` byte path the wrapper's
//! download reads. Everything is signed with a throwaway P-256 key and
//! verified under `STOW_VERIFY_MODE=mock-key`, so the test exists only
//! in a `mock-verify` build — the feature the mock end-to-end lane
//! compiles the CLI with.
//!
//! The slice's row and bundle come from a real compile: a fill build on
//! a scratch cache compiles `cfg-if` through the wrapper, and the local
//! store's entry (`manifest.json`, `oci/`, `files/`) supplies every
//! identity field and output byte the published row would carry. The
//! build under test then uses a *fresh* cache, so the only way `cfg-if`
//! can serve is through the slice setup fetched.

#![cfg(feature = "mock-verify")]

mod build_fixture;
mod support;

use std::collections::BTreeMap;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use build_fixture::write_fixture;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::crypto::SigningScheme;
use sigstore::crypto::signing_key::SigStoreKeyPair;
use sigstore::crypto::signing_key::ecdsa::{ECDSAKeys, EllipticCurve};
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleFile, BundleParts, BundleSignatureMaterial,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, STOW_ARTIFACT_CONFIG_MEDIA_TYPE, STOW_PACK_MEDIA_TYPE,
    assemble_bundle, sigstore_payload_path, sigstore_signature_tag,
};
use stow_types::identity::{DependencyIdentity, TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
    STOW_INDEX_CONFIG_MEDIA_TYPE, STOW_INDEX_MEDIA_TYPE, index_tag,
};
use stow_types::public_cache::{UnitInvocation, UnitKind, UnitShape, UnitSide};
use stow_types::registry::{cache_repository, sha256_digest};
use support::{denied_registry, hermetic_stow_env};

const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
/// The certificate slot of a mock signature: `mock-key` verification
/// checks this literal, the way `stow-mock-registry` writes it.
const MOCK_CERTIFICATE: &str = "mock-local";

/// What the fill build's local store recorded for the served unit — the
/// identity columns `artifact_cache_entries` carries.
#[derive(sqlx::FromRow)]
struct StoredUnit {
    rustc_version: String,
    relative_dir: String,
    crate_name: String,
    crate_version: String,
    c_metadata: String,
    compile_key: String,
    features_json: String,
    dependency_c_metadata_json: String,
    dependency_compile_keys_json: String,
    target: String,
    profile_json: String,
    emit_json: String,
    kind_json: String,
    crate_types_json: String,
}

fn stored_unit(cache_dir: &Path, crate_name: &str) -> StoredUnit {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            for tier in ["crates-io", "local-crates-io", "local"] {
                let db = cache_dir.join(tier).join("catalog-v1.sqlite3");
                if !db.exists() {
                    continue;
                }
                let options = sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&db)
                    .read_only(true);
                let pool = sqlx::SqlitePool::connect_with(options)
                    .await
                    .expect("open the tier catalog read-only");
                let unit: Option<StoredUnit> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                    "SELECT rustc_version, relative_dir, crate_name, crate_version, \
                     c_metadata, compile_key, features_json, dependency_c_metadata_json, \
                     dependency_compile_keys_json, target, profile_json, emit_json, kind_json, crate_types_json \
                     FROM artifact_cache_entries WHERE crate_name = '{crate_name}'"
                )))
                .fetch_optional(&pool)
                .await
                .expect("query stored unit");
                pool.close().await;
                if let Some(unit) = unit {
                    return unit;
                }
            }
            panic!("the fill build stored no {crate_name} unit across tiers");
        })
}

/// A column holding the JSON text of a type whose wire shape is itself a
/// JSON-encoded string.
fn wire_string<T: serde::de::DeserializeOwned>(text: &str) -> T {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .unwrap_or_else(|error| panic!("decode wire string {text}: {error}"))
}

/// The unit's recorded output files, in cache order: name, media type,
/// SHA-256 of the uncompressed bytes.
fn stored_outputs(cache_dir: &Path, unit: &StoredUnit) -> Vec<ArtifactBundleFile> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            for tier in ["crates-io", "local-crates-io", "local"] {
                let db = cache_dir.join(tier).join("catalog-v1.sqlite3");
                if !db.exists() {
                    continue;
                }
                let options = sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&db)
                    .read_only(true);
                let pool = sqlx::SqlitePool::connect_with(options)
                    .await
                    .expect("open the tier catalog read-only");
                let rows: Vec<(String, String, String)> = sqlx::query_as(
                    "SELECT o.file_name, o.media_type, o.sha256 \
                     FROM artifact_cache_outputs o \
                     JOIN artifact_cache_entries e \
                       ON e.rustc_version = o.rustc_version AND e.cache_key = o.cache_key \
                     WHERE e.rustc_version = ? AND e.c_metadata = ? ORDER BY o.ordinal",
                )
                .bind(&unit.rustc_version)
                .bind(&unit.c_metadata)
                .fetch_all(&pool)
                .await
                .expect("the fill build recorded the unit's outputs");
                pool.close().await;
                if !rows.is_empty() {
                    return rows
                        .into_iter()
                        .map(|(file_name, media_type, sha256)| ArtifactBundleFile {
                            file_name,
                            media_type,
                            sha256,
                        })
                        .collect();
                }
            }
            panic!("the fill build recorded no outputs for {}", unit.crate_name);
        })
}

/// The local store's entry directory for `relative_dir` — wherever the
/// cache layout nests it.
fn entry_dir(cache_dir: &Path, relative_dir: &str) -> PathBuf {
    let tail = Path::new(relative_dir);
    let mut candidates = vec![cache_dir.to_path_buf()];
    while let Some(dir) = candidates.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                candidates.push(path);
            }
        }
        if dir.ends_with(tail) && dir.join("files").is_dir() {
            return dir;
        }
    }
    panic!(
        "no cache entry dir ending in {relative_dir} under {}",
        cache_dir.display()
    );
}

/// One TCP listener answering the whole mock stack: the OCI registry
/// requests a slice fetch makes and the edge byte path a serve reads.
struct MockStack {
    url: String,
}

impl MockStack {
    /// `manifests` keys the `<ref>` a `/manifests/<ref>` GET names —
    /// tags and digests alike; `blobs` keys `sha256:` digests.
    fn serve(manifests: BTreeMap<String, Vec<u8>>, blobs: BTreeMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock stack");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let realm = url.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                Self::serve_one(stream, &realm, &manifests, &blobs);
            }
        });
        Self { url }
    }

    fn serve_one(
        mut stream: std::net::TcpStream,
        realm: &str,
        manifests: &BTreeMap<String, Vec<u8>>,
        blobs: &BTreeMap<String, Vec<u8>>,
    ) {
        let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        // Headers give the bearer check; the body is consumed so a reply
        // is not reset by unread request bytes.
        let mut content_length = 0_u64;
        let mut authorized = false;
        loop {
            let mut header = String::new();
            match reader.read_line(&mut header) {
                Ok(0) | Err(_) => return,
                _ => {}
            }
            if header == "\r\n" {
                break;
            }
            let lowered = header.to_ascii_lowercase();
            if lowered.starts_with("authorization:") && lowered.contains("bearer") {
                authorized = true;
            }
            if let Some(value) = lowered.strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let _ = std::io::copy(&mut reader.take(content_length), &mut std::io::sink());

        let mut respond = |status: &str, content_type: &str, body: &[u8]| {
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(body);
        };

        if path.starts_with("/token") {
            respond(
                "200 OK",
                "application/json",
                br#"{"token":"mock","access_token":"mock","expires_in":300}"#,
            );
            return;
        }
        if path.contains("/api/v1/bundles/") {
            let digest = path.rsplit('/').next().unwrap_or_default();
            let Some(bytes) = blobs.get(digest) else {
                respond("404 Not Found", "text/plain", b"");
                return;
            };
            respond("200 OK", "application/octet-stream", bytes);
            return;
        }
        if path.contains("/v2") {
            if !authorized {
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{realm}/token\",service=\"mock\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
                return;
            }
            if let Some(reference) = path.split("/manifests/").nth(1) {
                let Some(bytes) = manifests.get(reference) else {
                    respond("404 Not Found", "text/plain", b"");
                    return;
                };
                respond(
                    "200 OK",
                    "application/vnd.oci.image.manifest.v1+json",
                    bytes,
                );
                return;
            }
            if let Some(digest) = path.split("/blobs/").nth(1) {
                let Some(bytes) = blobs.get(digest) else {
                    respond("404 Not Found", "text/plain", b"");
                    return;
                };
                respond("200 OK", "application/octet-stream", bytes);
                return;
            }
            respond("200 OK", "application/json", b"{}");
            return;
        }
        respond("404 Not Found", "text/plain", b"");
    }
}

/// The wrapper shim `cargo` invokes for rustc — the `stow-rustc-wrapper`
/// name pointing at this binary, the same layout `install_wrapper_shim`
/// in `enqueue_admission` builds.
fn wrapper_shim(tools: &Path) -> PathBuf {
    let exe = env!("CARGO_BIN_EXE_stow-cli");
    let shim = tools.join(format!(
        "stow-rustc-wrapper{}",
        std::env::consts::EXE_SUFFIX
    ));
    let runtime = tools.join(format!("stow-runtime{}", std::env::consts::EXE_SUFFIX));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(exe, &shim).expect("symlink shim");
        std::os::unix::fs::symlink(exe, &runtime).expect("symlink runtime");
    }
    #[cfg(windows)]
    {
        std::fs::copy(exe, &shim).expect("copy shim");
        std::fs::copy(exe, &runtime).expect("copy runtime");
    }
    shim
}

/// A plain `cargo build` through the wrapper shim: no `stow` parent, so
/// the daemon serves it a session of its cargo — exactly the post-setup
/// consumer. Returns once that session has ended, so the cache holds
/// everything the build stored.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one distinct build input"
)]
fn plain_build(
    dir: &Path,
    cargo_home: &Path,
    shim: &Path,
    edge_url: &str,
    cache_dir: &Path,
    home: &Path,
    target_dir: &Path,
    envs: &[(&str, &Path)],
) -> std::process::Output {
    let mut build = support::cargo_command(home);
    hermetic_stow_env(&mut build, edge_url, cache_dir, home);
    build
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTC_WRAPPER", shim)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_BUILD_BUILD_DIR", target_dir)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_INCREMENTAL", "0")
        .env("NO_COLOR", "1")
        .env("CARGO_TERM_COLOR", "never");
    for (key, value) in envs {
        build.env(key, value);
    }
    support::output_after_session(&mut build, home)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one linear narrative: fill, sign, serve, setup, build"
)]
fn setup_fetches_the_host_slice_and_plain_cargo_serves_through_it() {
    let dir = support::tempdir().expect("temp dir");
    let cargo_home = support::tempdir().expect("cargo home");
    let fill_cache = support::tempdir().expect("fill cache");
    let tools = support::tempdir().expect("tools dir");
    write_fixture(dir.path(), cargo_home.path(), "cfg-if = \"1\"\n");
    let shim = wrapper_shim(tools.path());
    // The wrapper starts the daemon under the build's home; it is stopped
    // with the test.
    let _daemon = support::PrivateDaemon::in_home(&dir.path().join("stow-home"));

    // Fill: an all-miss build on a scratch cache compiles `cfg-if`
    // through the wrapper, which stores the artifact bundle locally —
    // the signed row's identity and bytes in test-readable form.
    let home = dir.path().join("stow-home");
    let fill = plain_build(
        dir.path(),
        cargo_home.path(),
        &shim,
        &denied_registry(),
        fill_cache.path(),
        &home,
        &dir.path().join("fill-target"),
        &[],
    );
    assert!(
        fill.status.success(),
        "fill build failed:\n{}",
        String::from_utf8_lossy(&fill.stderr)
    );

    let unit = stored_unit(fill_cache.path(), "cfg-if");
    let entry = entry_dir(fill_cache.path(), &unit.relative_dir);
    let outputs = stored_outputs(fill_cache.path(), &unit);
    assert!(!outputs.is_empty(), "the fill build stored no output files");
    let wire_rustc = WireRustcVersion::parse(&unit.rustc_version).expect("rustc version");
    let repository = cache_repository(&wire_rustc);
    let oci_reference = repository.reference("test.bundle");

    // The published artifact: the config the trusted build would write
    // (identity from the local row, `cfg-if` being a leaf), the outputs
    // packed as one layer, and the OCI manifest over it.
    let config = ArtifactBlobConfig {
        compile_key: unit.compile_key.clone(),
        crate_name: unit.crate_name.parse().expect("crate name"),
        crate_version: unit.crate_version.parse().expect("crate version"),
        c_metadata: unit.c_metadata.parse().expect("c_metadata"),
        extra_filename: format!("-{}", unit.c_metadata),
        target: TargetTriple::parse(&unit.target).expect("target"),
        rustc_version: wire_rustc.clone(),
        features_json: wire_string(&unit.features_json),
        dependency_c_metadata_json: wire_string(&unit.dependency_c_metadata_json),
        dependency_identity: DependencyIdentity::leaf().expect("leaf identity"),
        dependency_compile_keys_json: unit.dependency_compile_keys_json.clone(),
        profile: serde_json::from_str(&unit.profile_json).expect("profile"),
        emit: serde_json::from_str(&unit.emit_json).expect("emit"),
        artifact_size: 0,
        compile_millis: 0,
        kind: serde_json::from_str(&unit.kind_json).expect("artifact kind"),
        crate_types: serde_json::from_str(&unit.crate_types_json).expect("crate types"),
        outputs: outputs.clone(),
        native: None,
        native_archive: None,
    };
    let oci_config_bytes = serde_json::to_vec(&config).expect("config bytes");
    let oci_config_digest = sha256_digest(&oci_config_bytes);
    let raw: Vec<Vec<u8>> = outputs
        .iter()
        .map(|file| {
            std::fs::read(entry.join("files").join(&file.file_name))
                .unwrap_or_else(|error| panic!("read output {}: {error}", file.file_name))
        })
        .collect();
    let named: Vec<(&str, &[u8])> = outputs
        .iter()
        .zip(&raw)
        .map(|(file, bytes)| (file.file_name.as_str(), bytes.as_slice()))
        .collect();
    let pack = stow_shim::pack(&named).expect("pack outputs");
    let oci_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_ARTIFACT_CONFIG_MEDIA_TYPE,
            "digest": oci_config_digest,
            "size": oci_config_bytes.len(),
        },
        "layers": [{
            "mediaType": STOW_PACK_MEDIA_TYPE,
            "digest": sha256_digest(&pack),
            "size": pack.len(),
        }],
    }))
    .expect("oci manifest");
    let oci_digest = sha256_digest(&oci_manifest_bytes);

    // A throwaway P-256 key signs every artifact; its public half is
    // what `STOW_VERIFY_MODE=mock-key` verifies against.
    let key_pair = SigStoreKeyPair::ECDSA(
        ECDSAKeys::new(EllipticCurve::P256).expect("generate mock key pair"),
    );
    let signer = key_pair
        .to_sigstore_signer(&SigningScheme::ECDSA_P256_SHA256_ASN1)
        .expect("mock signer");
    let public_key_path = dir.path().join("mock.pub");
    std::fs::write(
        &public_key_path,
        key_pair.public_key_to_pem().expect("public key pem"),
    )
    .expect("write public key");

    let sign = |reference: &str, digest: &str| -> BundleSignatureMaterial {
        let payload = SimpleSigning::new(&reference.parse().expect("oci reference"), digest);
        let payload_bytes = serde_json::to_vec(&payload).expect("payload bytes");
        let signature = signer.sign(&payload_bytes).expect("sign payload");
        BundleSignatureMaterial {
            payload_path: sigstore_payload_path(0),
            payload_bytes,
            signature: base64::engine::general_purpose::STANDARD.encode(signature),
            certificate_pem: MOCK_CERTIFICATE.to_owned(),
            rekor_bundle_json: None,
        }
    };

    // The bundle the edge byte path streams: manifest, config, mock
    // signature and the pack.
    let material = sign(&oci_reference, &oci_digest);
    let signatures = [material];
    let bundle_bytes = assemble_bundle(&BundleParts {
        oci_reference: &oci_reference,
        oci_digest: &oci_digest,
        manifest_bytes: &oci_manifest_bytes,
        config_bytes: &oci_config_bytes,
        config: &config,
        signatures: &signatures,
        pack: &pack,
    })
    .expect("assemble bundle");
    let bundle_digest = sha256_digest(&bundle_bytes);

    // The index row: the unit's recorded identity, addressed by the
    // exact `c_metadata` the wrapper looks up.
    let row = ArtifactIndexRow {
        crate_name: unit.crate_name.parse().expect("crate name"),
        version: unit.crate_version.parse().expect("crate version"),
        features_json: wire_string(&unit.features_json),
        dependency_c_metadata_json: wire_string(&unit.dependency_c_metadata_json),
        dependency_task_ids: Vec::new(),
        c_metadata: unit.c_metadata.parse().expect("c_metadata"),
        compile_key: unit.compile_key.clone(),
        bundle_digest: bundle_digest.clone(),
        bundle_size: u64::try_from(bundle_bytes.len()).expect("bundle size"),
        artifact_kind: serde_json::from_str(&unit.kind_json).expect("artifact kind"),
        crate_types: serde_json::from_str(&unit.crate_types_json).expect("crate types"),
        node_profile: stow_types::node_profile::NodeProfile::Dev,
        profile: serde_json::from_str(&unit.profile_json).expect("profile"),
        emit: serde_json::from_str(&unit.emit_json).expect("emit"),
        unit_shape: UnitShape {
            side: UnitSide::Target,
            invocation: UnitInvocation::Native,
            kind: UnitKind::Linked,
        },
        min_glibc: None,
    };
    let index = ArtifactIndex {
        header: ArtifactIndexHeader {
            format_version: ARTIFACT_INDEX_FORMAT_VERSION,
            target: TargetTriple::parse(&unit.target).expect("target"),
            rustc_version: WireRustcVersion::parse(&unit.rustc_version).expect("rustc version"),
            generated_at: "2026-10-28T00:00:00Z".to_owned(),
            generation: 1,
            row_count: 1,
        },
        rows: vec![row],
        build_scripts: Vec::new(),
        local_programs: Vec::new(),
    };
    let index_blob = stow_shim::encode_index(&index).expect("encode index");
    let index_blob_digest = sha256_digest(&index_blob);

    // The OCI manifest/signature pair the slice fetch pulls — the same
    // shape `stow-admin index publish` writes (mock-registry's
    // `write_signed_index` mirrors it for `populate`).
    let empty = b"{}".to_vec();
    let empty_digest = sha256_digest(&empty);
    let index_manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_INDEX_CONFIG_MEDIA_TYPE,
            "digest": empty_digest,
            "size": empty.len(),
        },
        "layers": [{
            "mediaType": STOW_INDEX_MEDIA_TYPE,
            "digest": index_blob_digest,
            "size": index_blob.len(),
        }],
    }))
    .expect("index manifest");
    let index_manifest_digest = sha256_digest(&index_manifest);
    let tag = index_tag(&unit.target, &unit.rustc_version);
    let index_reference = repository.reference(&tag);
    let index_material = sign(&index_reference, &index_manifest_digest);
    let index_payload_digest = sha256_digest(&index_material.payload_bytes);
    let signature_manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "digest": empty_digest,
            "size": empty.len(),
        },
        "layers": [{
            "mediaType": SIGSTORE_OCI_MEDIA_TYPE,
            "digest": index_payload_digest,
            "size": index_material.payload_bytes.len(),
            "annotations": {
                SIGSTORE_CERT_ANNOTATION: MOCK_CERTIFICATE,
                SIGSTORE_SIGNATURE_ANNOTATION: index_material.signature,
            },
        }],
    }))
    .expect("signature manifest");

    let stack = MockStack::serve(
        BTreeMap::from([
            (tag, index_manifest),
            (
                sigstore_signature_tag(&index_manifest_digest),
                signature_manifest,
            ),
        ]),
        BTreeMap::from([
            (empty_digest, empty),
            (index_blob_digest, index_blob),
            (index_payload_digest, index_material.payload_bytes),
            (bundle_digest, bundle_bytes),
        ]),
    );

    // `stow setup` against the mock stack: writes the cargo wiring and
    // ends by fetching the host slice — the fetch must succeed.
    let cache = support::tempdir().expect("serving cache");
    let mut setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    setup
        .arg("setup")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path());
    hermetic_stow_env(&mut setup, &stack.url, cache.path(), &home);
    let setup = setup
        .env("STOW_VERIFY_MODE", "mock-key")
        .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
        .output()
        .expect("run stow-cli setup");
    assert!(
        setup.status.success(),
        "stow setup failed:\n{}",
        String::from_utf8_lossy(&setup.stderr)
    );

    // The slice is committed under the cache's index dir — the wrapper's
    // read-only `cached_slice` source.
    let slice_dir = cache
        .path()
        .join("index")
        .join(&unit.target)
        .join(&unit.rustc_version);
    assert!(
        slice_dir.join("current.json").is_file(),
        "setup must leave a verified slice pointer under {}",
        slice_dir.display()
    );

    // First run `stow build` + `stow status` on `dir` (same as `itoa-consumer` in mock-e2e.sh)
    // so the daemon already holds open `CacheDirHandles` + `StateDb` on `cache`!
    {
        let mut first_check = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        first_check
            .arg("build")
            .current_dir(dir.path())
            .env("CARGO_HOME", cargo_home.path())
            .env_remove("CARGO_PROFILE_DEV_DEBUG")
            .env_remove("CARGO_TARGET_DIR");
        hermetic_stow_env(&mut first_check, &stack.url, cache.path(), &home);
        let first_out = first_check
            .env("STOW_VERIFY_MODE", "mock-key")
            .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
            .output()
            .expect("first stow build");
        assert!(
            String::from_utf8_lossy(&first_out.stdout).contains("served 1 of 1"),
            "first stow build failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&first_out.stdout),
            String::from_utf8_lossy(&first_out.stderr),
        );

        let mut status_cmd = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        status_cmd
            .arg("status")
            .current_dir(dir.path())
            .env("CARGO_HOME", cargo_home.path());
        hermetic_stow_env(&mut status_cmd, &stack.url, cache.path(), &home);
        assert!(
            status_cmd
                .env("STOW_VERIFY_MODE", "mock-key")
                .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
                .output()
                .expect("stow status")
                .status
                .success()
        );
    }

    // Also verify stow#881 superset serve through `stow check` on `once_cell`:
    // publish `once_cell 1.21.4` built with `["default"]` (`["alloc","default","race","std"]`),
    // then run `stow check` on a `--lib` consumer requesting `default-features = false, features = ["alloc"]`.
    {
        let oc_fill_dir = support::tempdir().expect("once_cell fill dir");
        std::fs::write(
            oc_fill_dir.path().join("Cargo.toml"),
            "[package]\nname = \"oc-fill\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\npath = \"src/lib.rs\"\n[dependencies]\nonce_cell = \"=1.21.4\"\n",
        )
        .expect("oc fill manifest");
        std::fs::create_dir_all(oc_fill_dir.path().join("src")).expect("oc fill src");
        std::fs::write(oc_fill_dir.path().join("src/lib.rs"), "pub fn f() {}\n").expect("oc lib");
        let mut fetch_cmd = support::cargo_command(&home);
        fetch_cmd
            .arg("fetch")
            .current_dir(oc_fill_dir.path())
            .env("CARGO_HOME", cargo_home.path());
        assert!(
            fetch_cmd
                .output()
                .expect("cargo fetch once_cell")
                .status
                .success()
        );

        let oc_fill_cache = support::tempdir().expect("oc fill cache");
        let mut oc_check = support::cargo_command(&home);
        hermetic_stow_env(
            &mut oc_check,
            &denied_registry(),
            oc_fill_cache.path(),
            &home,
        );
        let oc_fill = support::output_after_session(
            oc_check
                .arg("check")
                .current_dir(oc_fill_dir.path())
                .env("CARGO_HOME", cargo_home.path())
                .env("RUSTC_WRAPPER", &shim)
                .env("CARGO_TARGET_DIR", oc_fill_dir.path().join("target"))
                .env("CARGO_BUILD_BUILD_DIR", oc_fill_dir.path().join("target"))
                .env("CARGO_NET_OFFLINE", "true")
                .env("CARGO_INCREMENTAL", "0"),
            &home,
        );
        assert!(
            oc_fill.status.success(),
            "oc fill failed: {}",
            String::from_utf8_lossy(&oc_fill.stderr)
        );
        let oc_unit = stored_unit(oc_fill_cache.path(), "once_cell");
        let oc_entry = entry_dir(oc_fill_cache.path(), &oc_unit.relative_dir);
        let oc_outputs = stored_outputs(oc_fill_cache.path(), &oc_unit);
        let oc_raw: Vec<Vec<u8>> = oc_outputs
            .iter()
            .map(|f| std::fs::read(oc_entry.join("files").join(&f.file_name)).expect("read oc out"))
            .collect();
        let oc_named: Vec<(&str, &[u8])> = oc_outputs
            .iter()
            .zip(&oc_raw)
            .map(|(f, b)| (f.file_name.as_str(), b.as_slice()))
            .collect();
        let oc_pack = stow_shim::pack(&oc_named).expect("pack oc");
        let superset_config = ArtifactBlobConfig {
            compile_key: oc_unit.compile_key.clone(),
            crate_name: oc_unit.crate_name.parse().expect("crate name"),
            crate_version: oc_unit.crate_version.parse().expect("crate version"),
            c_metadata: oc_unit.c_metadata.parse().expect("c_metadata"),
            extra_filename: format!("-{}", oc_unit.c_metadata),
            target: TargetTriple::parse(&oc_unit.target).expect("target"),
            rustc_version: wire_rustc.clone(),
            features_json: wire_string(&oc_unit.features_json),
            dependency_c_metadata_json: wire_string(&oc_unit.dependency_c_metadata_json),
            dependency_identity: DependencyIdentity::leaf().expect("leaf identity"),
            dependency_compile_keys_json: oc_unit.dependency_compile_keys_json.clone(),
            profile: serde_json::from_str(&oc_unit.profile_json).expect("profile"),
            emit: serde_json::from_str(&oc_unit.emit_json).expect("emit"),
            artifact_size: 0,
            compile_millis: 0,
            kind: serde_json::from_str(&oc_unit.kind_json).expect("artifact kind"),
            crate_types: serde_json::from_str(&oc_unit.crate_types_json).expect("crate types"),
            outputs: oc_outputs,
            native: None,
            native_archive: None,
        };
        let superset_config_bytes =
            serde_json::to_vec(&superset_config).expect("superset config bytes");
        let superset_manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": STOW_ARTIFACT_CONFIG_MEDIA_TYPE,
                "digest": sha256_digest(&superset_config_bytes),
                "size": superset_config_bytes.len(),
            },
            "layers": [{
                "mediaType": STOW_PACK_MEDIA_TYPE,
                "digest": sha256_digest(&oc_pack),
                "size": oc_pack.len(),
            }],
        }))
        .expect("superset oci manifest");
        let superset_oci_digest = sha256_digest(&superset_manifest_bytes);
        let superset_sig = sign(&oci_reference, &superset_oci_digest);
        let superset_sigs = [superset_sig];
        let superset_bundle_bytes = assemble_bundle(&BundleParts {
            oci_reference: &oci_reference,
            oci_digest: &superset_oci_digest,
            manifest_bytes: &superset_manifest_bytes,
            config_bytes: &superset_config_bytes,
            config: &superset_config,
            signatures: &superset_sigs,
            pack: &oc_pack,
        })
        .expect("assemble superset bundle");
        let superset_bundle_digest = sha256_digest(&superset_bundle_bytes);
        let superset_row = ArtifactIndexRow {
            crate_name: oc_unit.crate_name.parse().expect("crate name"),
            version: oc_unit.crate_version.parse().expect("crate version"),
            features_json: wire_string(&oc_unit.features_json),
            dependency_c_metadata_json: wire_string(&oc_unit.dependency_c_metadata_json),
            dependency_task_ids: Vec::new(),
            c_metadata: oc_unit.c_metadata.parse().expect("c_metadata"),
            compile_key: oc_unit.compile_key.clone(),
            bundle_digest: superset_bundle_digest.clone(),
            bundle_size: u64::try_from(superset_bundle_bytes.len()).expect("bundle size"),
            artifact_kind: serde_json::from_str(&oc_unit.kind_json).expect("artifact kind"),
            crate_types: serde_json::from_str(&oc_unit.crate_types_json).expect("crate types"),
            node_profile: stow_types::node_profile::NodeProfile::Dev,
            profile: serde_json::from_str(&oc_unit.profile_json).expect("profile"),
            emit: serde_json::from_str(&oc_unit.emit_json).expect("emit"),
            unit_shape: UnitShape {
                side: UnitSide::Target,
                invocation: UnitInvocation::Native,
                kind: UnitKind::Linked,
            },
            min_glibc: None,
        };
        let superset_index = ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse(&oc_unit.target).expect("target"),
                rustc_version: WireRustcVersion::parse(&oc_unit.rustc_version)
                    .expect("rustc version"),
                generated_at: "2026-10-28T00:00:00Z".to_owned(),
                generation: 2,
                row_count: 1,
            },
            rows: vec![superset_row],
            build_scripts: Vec::new(),
            local_programs: Vec::new(),
        };
        let s_blob = stow_shim::encode_index(&superset_index).expect("encode superset index");
        let s_blob_digest = sha256_digest(&s_blob);
        let empty = b"{}".to_vec();
        let empty_digest = sha256_digest(&empty);
        let s_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": STOW_INDEX_CONFIG_MEDIA_TYPE,
                "digest": empty_digest,
                "size": empty.len(),
            },
            "layers": [{
                "mediaType": STOW_INDEX_MEDIA_TYPE,
                "digest": s_blob_digest,
                "size": s_blob.len(),
            }],
        }))
        .expect("s manifest");
        let s_manifest_digest = sha256_digest(&s_manifest);
        let s_tag = index_tag(&oc_unit.target, &oc_unit.rustc_version);
        let s_ref = repository.reference(&s_tag);
        let s_mat = sign(&s_ref, &s_manifest_digest);
        let s_payload_digest = sha256_digest(&s_mat.payload_bytes);
        let s_sig_manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": empty_digest,
                "size": empty.len(),
            },
            "layers": [{
                "mediaType": SIGSTORE_OCI_MEDIA_TYPE,
                "digest": s_payload_digest,
                "size": s_mat.payload_bytes.len(),
                "annotations": {
                    SIGSTORE_CERT_ANNOTATION: MOCK_CERTIFICATE,
                    SIGSTORE_SIGNATURE_ANNOTATION: s_mat.signature,
                },
            }],
        }))
        .expect("s sig manifest");
        let s_stack = MockStack::serve(
            BTreeMap::from([
                (s_tag, s_manifest),
                (sigstore_signature_tag(&s_manifest_digest), s_sig_manifest),
            ]),
            BTreeMap::from([
                (empty_digest, empty),
                (s_blob_digest, s_blob),
                (s_payload_digest, s_mat.payload_bytes),
                (superset_bundle_digest, superset_bundle_bytes),
            ]),
        );

        let mut s_refresh = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        s_refresh
            .args(["index", "refresh"])
            .current_dir(dir.path())
            .env("CARGO_HOME", cargo_home.path());
        hermetic_stow_env(&mut s_refresh, &s_stack.url, cache.path(), &home);
        let s_refresh_out = s_refresh
            .env("STOW_VERIFY_MODE", "mock-key")
            .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
            .output()
            .expect("superset index refresh");
        assert!(s_refresh_out.status.success());

        let subset_dir = support::tempdir().expect("subset consumer");
        std::fs::write(
            subset_dir.path().join("Cargo.toml"),
            "[package]\nname = \"once_cell-subset-consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nonce_cell = { version = \"=1.21.4\", default-features = false, features = [\"alloc\"] }\n",
        )
        .expect("subset manifest");
        std::fs::create_dir_all(subset_dir.path().join("src")).expect("subset src");
        std::fs::write(
            subset_dir.path().join("src/lib.rs"),
            "pub fn add(a: u64, b: u64) -> u64 { a + b }\n",
        )
        .expect("subset lib");

        let mut sub_fetch = support::cargo_command(&home);
        sub_fetch
            .arg("fetch")
            .current_dir(subset_dir.path())
            .env("CARGO_HOME", cargo_home.path());
        assert!(
            sub_fetch
                .output()
                .expect("subset cargo fetch")
                .status
                .success()
        );

        let mut sub_setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        sub_setup
            .arg("setup")
            .current_dir(subset_dir.path())
            .env("CARGO_HOME", cargo_home.path());
        hermetic_stow_env(&mut sub_setup, &s_stack.url, cache.path(), &home);
        assert!(
            sub_setup
                .env("STOW_VERIFY_MODE", "mock-key")
                .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
                .output()
                .expect("subset stow setup")
                .status
                .success()
        );

        let mut s_check = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        s_check
            .arg("check")
            .current_dir(subset_dir.path())
            .env("CARGO_HOME", cargo_home.path())
            .env_remove("CARGO_PROFILE_DEV_DEBUG")
            .env_remove("CARGO_TARGET_DIR");
        hermetic_stow_env(&mut s_check, &s_stack.url, cache.path(), &home);
        let s_check_out = s_check
            .env("STOW_VERIFY_MODE", "mock-key")
            .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
            .output()
            .expect("superset check");
        assert!(
            String::from_utf8_lossy(&s_check_out.stdout).contains("served 1 of 1"),
            "once_cell subset check failed to serve:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&s_check_out.stdout),
            String::from_utf8_lossy(&s_check_out.stderr),
        );

        // Restore original slice on `cache` for the remaining assertions below.
        let mut restore_refresh = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        restore_refresh
            .args(["index", "refresh"])
            .current_dir(dir.path())
            .env("CARGO_HOME", cargo_home.path());
        hermetic_stow_env(&mut restore_refresh, &stack.url, cache.path(), &home);
        assert!(
            restore_refresh
                .env("STOW_VERIFY_MODE", "mock-key")
                .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
                .output()
                .expect("restore refresh")
                .status
                .success()
        );
    }

    // A fresh cargo build on a fresh target dir, still pointed at the
    // serving cache: `cfg-if` is the slice's row, so it serves remotely
    // — cargo never compiles it.
    let build = plain_build(
        dir.path(),
        cargo_home.path(),
        &shim,
        &stack.url,
        cache.path(),
        &home,
        &dir.path().join("serve-target"),
        &[
            ("STOW_VERIFY_MODE", Path::new("mock-key")),
            ("STOW_MOCK_PUBLIC_KEY_PATH", public_key_path.as_path()),
        ],
    );
    let stderr = String::from_utf8_lossy(&build.stderr);
    assert!(build.status.success(), "served build failed:\n{stderr}");
    assert!(
        stderr.contains("Compiling probe"),
        "the fixture's own crate still compiles:\n{stderr}"
    );
    // Cargo announces `Compiling` for a unit the wrapper serves, so the
    // proof is the serving cache: it was fresh (setup only fetched the
    // slice) and the only way `cfg-if` lands there is the wrapper
    // downloading the slice row's bundle — a downloaded entry carries the
    // verified bundle manifest a local store never writes.
    let served = entry_dir(cache.path(), &unit.relative_dir);
    assert!(
        served.starts_with(cache.path().join("crates-io")),
        "remote download must land under crates-io/: {}",
        served.display()
    );
    assert!(
        served.join("manifest.json").is_file(),
        "cfg-if must be served from the slice setup fetched, not compiled:\n{stderr}"
    );

    // When `fill_cache` already holds a transitional `local-crates-io/` entry
    // for `cfg-if` and the public slice later covers it, an online build
    // downloads the signed bundle into `crates-io/` and retires the
    // superseded `local-crates-io/` entry.
    assert!(
        entry.starts_with(fill_cache.path().join("local-crates-io")),
        "offline fill must store public crates.io units under local-crates-io/: {}",
        entry.display()
    );
    let mut refresh = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    refresh
        .arg("setup")
        .arg("--no-install-skill")
        .current_dir(dir.path())
        .env("CARGO_HOME", cargo_home.path());
    hermetic_stow_env(&mut refresh, &stack.url, fill_cache.path(), &home);
    let refresh = refresh
        .env("STOW_VERIFY_MODE", "mock-key")
        .env("STOW_MOCK_PUBLIC_KEY_PATH", &public_key_path)
        .output()
        .expect("refresh fill_cache slice");
    assert!(
        refresh.status.success(),
        "fill_cache setup failed:\n{}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    let supersede = plain_build(
        dir.path(),
        cargo_home.path(),
        &shim,
        &stack.url,
        fill_cache.path(),
        &home,
        &dir.path().join("supersede-target"),
        &[
            ("STOW_VERIFY_MODE", Path::new("mock-key")),
            ("STOW_MOCK_PUBLIC_KEY_PATH", public_key_path.as_path()),
        ],
    );
    assert!(
        supersede.status.success(),
        "supersede build failed:\n{}",
        String::from_utf8_lossy(&supersede.stderr)
    );
    assert!(
        !entry.exists(),
        "transitional local-crates-io/ entry must be retired once crates-io/ serves it"
    );
    let promoted = entry_dir(&fill_cache.path().join("crates-io"), &unit.relative_dir);
    assert!(promoted.join("manifest.json").is_file());
}
