//! crates.io API for fetching latest updated crate

use worker::{D1Database, KvStore};

pub struct Crates {
    kv: KvStore,
}
type CrateName = String;

pub struct SubscribedCrates {
    d1: D1Database,
}

type Hash = String;

pub struct SubscribedCrate {
    name: String,
    caches: Vec<Hash>,
    
}

impl SubscribedCrates {
    pub fn new(d1: D1Database) -> Self {
        Self { d1 }
    }

    /// Get the subscribed crates by us
    pub async fn get(&self) -> Vec<CrateName> {
        // Get the subscribed crates from D1 database
        todo!()
    }
}

impl Crates {
    pub fn new(kv: KvStore) -> Self {
        Self { kv }
    }

    /// Fetch the latest updated crates from crates.io API
    ///
    /// Tip: We only aware subscribed crates by us.
    pub async fn next_updates(&self) -> Vec<CrateName> {
        // Get the latest updated crates from crates.io API
        //
        // We would storage `last_seen_id` in KV so that we can only fetch the crates updated after `last_seen_id`
        todo!()
    }
}
