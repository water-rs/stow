//! Every network entry point refuses a cache mode that does not reach the
//! network (stow#1059).
//!
//! The registry and the edge both point at a listener that counts the
//! connections it is offered; each entry point runs under `local` and `off`,
//! and the count must stay zero.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{CacheMode, StowConfig, VerifyMode};
use crate::fetch::BundleRef;

/// A loopback listener that counts the connections it accepts, so a
/// request that was made shows up even though nothing answers it.
struct Tripwire {
    url: String,
    connections: Arc<AtomicUsize>,
}

impl Tripwire {
    fn set() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the tripwire");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("tripwire address")
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        Self { url, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn config(cache_dir: &Path, cache_mode: CacheMode, tripwire: &Tripwire) -> StowConfig {
    StowConfig {
        cache_mode,
        edge_url: tripwire.url.clone(),
        registry_base_url: tripwire.url.clone(),
        cache_dir: cache_dir.to_path_buf(),
        request_timeout: std::time::Duration::from_secs(5),
        negative_cache_ttl: std::time::Duration::from_mins(5),
        circuit_reset_after: std::time::Duration::from_mins(1),
        circuit_trip_threshold: 5,
        artifact_cache_max_bytes: 1024,
        index_refresh_interval: std::time::Duration::from_mins(10),
        verify_mode: VerifyMode::GithubCi,
        state_db: crate::state_db::StateDb::default(),
        trust_material: Arc::default(),
        registry_http: Arc::default(),
        artifact_cache_staging: Arc::default(),
    }
}

#[tokio::test]
async fn no_entry_point_reaches_the_network_outside_the_public_mode() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tripwire = Tripwire::set();
    for mode in [CacheMode::Local, CacheMode::Off] {
        let dir = tempfile::tempdir().expect("cache dir");
        let config = config(dir.path(), mode, &tripwire);
        let bundle = BundleRef {
            target: "x86_64-unknown-linux-gnu",
            rustc_version: "1.91.1",
            c_metadata: "0123456789abcdef",
            bundle_digest: "sha256:deadbeef",
        };

        assert!(
            config.registry_http().await.is_err(),
            "{mode:?}: registry client"
        );
        assert!(
            crate::edge_client::client(&config).is_err(),
            "{mode:?}: edge client"
        );
        assert!(
            crate::index::ensure_slice(&config, bundle.target, bundle.rustc_version)
                .await
                .is_err(),
            "{mode:?}: index pull"
        );
        assert!(
            crate::index::refresh_slice(&config, bundle.target, bundle.rustc_version)
                .await
                .is_err(),
            "{mode:?}: index refresh"
        );
        assert!(
            crate::index::confirmed_slice(&config, bundle.target, bundle.rustc_version)
                .await
                .is_err(),
            "{mode:?}: confirmed index pull"
        );
        assert!(
            crate::fetch::download_bundle_bytes(&config, &bundle)
                .await
                .is_err(),
            "{mode:?}: bundle download"
        );
        assert!(
            !crate::report::report_due_today(&config).await,
            "{mode:?}: report due"
        );
        crate::report::maybe_report(&config).await;
        crate::report::bump_build(&config).await;
    }
    assert_eq!(
        tripwire.connections(),
        0,
        "a network entry point made a request outside the public cache mode"
    );
}

#[tokio::test]
async fn the_public_mode_reaches_the_network() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tripwire = Tripwire::set();
    let dir = tempfile::tempdir().expect("cache dir");
    let config = config(dir.path(), CacheMode::Public, &tripwire);
    assert!(config.registry_http().await.is_ok());
    assert!(crate::edge_client::client(&config).is_ok());
}

#[test]
fn the_cache_mode_is_read_from_the_config_file_spelling() {
    #[derive(serde::Deserialize)]
    struct File {
        cache_mode: CacheMode,
    }
    for (spelled, mode) in [
        ("public", CacheMode::Public),
        ("local", CacheMode::Local),
        ("off", CacheMode::Off),
    ] {
        let file: File = toml::from_str(&format!("cache_mode = \"{spelled}\"")).expect("parse");
        assert_eq!(file.cache_mode, mode);
        assert_eq!(mode.as_str(), spelled);
    }
    assert!(toml::from_str::<File>("cache_mode = \"remote\"").is_err());
    assert_eq!(CacheMode::default(), CacheMode::Public);
}
