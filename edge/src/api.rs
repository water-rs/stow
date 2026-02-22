use std::collections::BTreeMap;

use skyzen::{Body, extract::Query};

// Request to `/get` endpoint, sending from our `stow` CLI.
struct CacheReq {
    name: String,
    version: String,
    arch: String,
    rustc_version: String,
    features: Vec<String>,
    flags: Vec<String>,
    env: BTreeMap<String, String>,
}

pub async fn check(query: Query<CacheReq>) {}

impl CacheReq {
    pub fn hash(&self) -> String {
        todo!()
    }
}

pub enum GetCacheError {}

pub async fn get() {}
