use std::collections::BTreeMap;

struct CacheReq {
    name: String,
    version: String,
    arch: String,
    rustc_version: String,
    features: Vec<String>,
    flags: Vec<String>,
    env: BTreeMap<String, String>,
}

impl CacheReq {
    pub fn hash(&self) -> String {
        todo!()
    }
}

pub async fn get() {}
