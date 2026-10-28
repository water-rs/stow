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
    ArtifactBlobConfig, ArtifactBundleFile, BundleLayer, BundleParts, BundleSignatureMaterial,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, STOW_ARTIFACT_CONFIG_MEDIA_TYPE, assemble_bundle,
    sigstore_payload_path, sigstore_signature_tag,
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
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(cache_dir.join("state-v3.sqlite3"))
                .read_only(true);
            let pool = sqlx::SqlitePool::connect_with(options)
                .await
                .expect("open the state db read-only");
            let unit: StoredUnit = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT rustc_version, relative_dir, crate_name, crate_version, \
                 c_metadata, compile_key, features_json, dependency_c_metadata_json, \
                 dependency_compile_keys_json, target, profile_json, emit_json, kind_json, crate_types_json \
                 FROM artifact_cache_entries WHERE crate_name = '{crate_name}'"
            )))
            .fetch_one(&pool)
            .await
            .expect("the fill build stored the unit");
            pool.close().await;
            unit
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
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(cache_dir.join("state-v3.sqlite3"))
                .read_only(true);
            let pool = sqlx::SqlitePool::connect_with(options)
                .await
                .expect("open the state db read-only");
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
            rows.into_iter()
                .map(|(file_name, media_type, sha256)| ArtifactBundleFile {
                    file_name,
                    media_type,
                    sha256,
                })
                .collect()
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
    #[cfg(unix)]
    std::os::unix::fs::symlink(exe, &shim).expect("symlink shim");
    #[cfg(windows)]
    std::fs::copy(exe, &shim).expect("copy shim");
    shim
}

/// A plain `cargo build` through the wrapper shim: no `stow` parent, so
/// the wrapper runs standalone — exactly the post-setup consumer.
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
    let mut build = Command::new("cargo");
    hermetic_stow_env(&mut build, edge_url, cache_dir, home);
    build
        .arg("build")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTC_WRAPPER", shim)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_INCREMENTAL", "0")
        .env("NO_COLOR", "1")
        .env("CARGO_TERM_COLOR", "never");
    for (key, value) in envs {
        build.env(key, value);
    }
    build.output().expect("run cargo build")
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one linear narrative: fill, sign, serve, setup, build"
)]
fn setup_fetches_the_host_slice_and_plain_cargo_serves_through_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let fill_cache = tempfile::tempdir().expect("fill cache");
    let tools = tempfile::tempdir().expect("tools dir");
    write_fixture(dir.path(), cargo_home.path(), "cfg-if = \"1\"\n");
    let shim = wrapper_shim(tools.path());

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
    // (identity from the local row, `cfg-if` being a leaf), each output
    // zstd-compressed as one layer, and the OCI manifest over them.
    let config = ArtifactBlobConfig {
        compile_key: unit.compile_key.clone(),
        crate_name: unit.crate_name.parse().expect("crate name"),
        crate_version: unit.crate_version.parse().expect("crate version"),
        c_metadata: unit.c_metadata.parse().expect("c_metadata"),
        extra_filename: format!("-{}", unit.c_metadata),
        target: TargetTriple::parse(&unit.target).expect("target"),
        rustc_version: wire_rustc,
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
    let compressed: Vec<Vec<u8>> = outputs
        .iter()
        .map(|file| {
            let raw = std::fs::read(entry.join("files").join(&file.file_name))
                .unwrap_or_else(|error| panic!("read output {}: {error}", file.file_name));
            zstd::bulk::compress(&raw, 3).expect("compress output")
        })
        .collect();
    let oci_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_ARTIFACT_CONFIG_MEDIA_TYPE,
            "digest": oci_config_digest,
            "size": oci_config_bytes.len(),
        },
        "layers": outputs.iter().zip(&compressed).map(|(file, bytes)| serde_json::json!({
            "mediaType": file.storage_media_type(),
            "digest": sha256_digest(bytes),
            "size": bytes.len(),
        })).collect::<Vec<_>>(),
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
    // signature and the layers.
    let material = sign(&oci_reference, &oci_digest);
    let media_types: Vec<String> = outputs
        .iter()
        .map(ArtifactBundleFile::storage_media_type)
        .collect();
    let layers: Vec<BundleLayer<'_>> = media_types
        .iter()
        .zip(&compressed)
        .map(|(media_type, bytes)| BundleLayer { media_type, bytes })
        .collect();
    let signatures = [material];
    let bundle_bytes = assemble_bundle(&BundleParts {
        oci_reference: &oci_reference,
        oci_digest: &oci_digest,
        manifest_bytes: &oci_manifest_bytes,
        config_bytes: &oci_config_bytes,
        config: &config,
        signatures: &signatures,
        layers: &layers,
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
        compile_key: unit.compile_key,
        bundle_digest: bundle_digest.clone(),
        bundle_size: u64::try_from(bundle_bytes.len()).expect("bundle size"),
        artifact_kind: serde_json::from_str(&unit.kind_json).expect("artifact kind"),
        crate_types: serde_json::from_str(&unit.crate_types_json).expect("crate types"),
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
    };
    let index_blob = stow_types::index::encode(&index).expect("encode index");
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
    let cache = tempfile::tempdir().expect("serving cache");
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
        served.join("manifest.json").is_file(),
        "cfg-if must be served from the slice setup fetched, not compiled:\n{stderr}"
    );
}
