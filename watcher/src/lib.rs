//! Tick will be called per minute to update the status
//!
//! This program would run on the cloudflare worker

mod crates_api;
use worker::{Env, ScheduleContext, ScheduledEvent, event};

use crate::crates_api::Crates;

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    entry(env).await;
}

async fn entry(env: Env) {
    let crates = Crates::new(env.kv("CRATES_KV").expect("failed to get KV store"));
    let updates = crates.next_updates().await;
    for crate_name in updates {}
}
