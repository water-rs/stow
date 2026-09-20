//! `stow-admin cache …` — GitHub Actions cache usage and eviction for
//! `water-rs/stow`.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::stow_error;

use crate::github;
use crate::render::{self, Output, Table};

/// GitHub's per-repository Actions cache quota.
const QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Subcommand)]
pub enum CacheCommand {
    /// Cache usage vs the repository's 10 GiB quota.
    Stats,
    /// Delete every cache entry whose key starts with `--prefix`.
    Clear(ClearArgs),
}

#[derive(Args)]
pub struct ClearArgs {
    /// Key prefix to evict (`stow-bins-build-` covers every workflow's
    /// binary cache, `build-crate-` the rust-cache lane).
    #[arg(long)]
    pub prefix: String,
    /// Delete the entries. Without it the command prints the plan and
    /// exits 0 without touching the cache.
    #[arg(long)]
    pub yes: bool,
}

// ===== GitHub REST shapes =====

/// `GET …/actions/cache/usage`.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct CacheUsage {
    full_name: String,
    active_caches_count: u64,
    active_caches_size_in_bytes: u64,
}

/// The `cache stats` payload — usage plus the quota math.
#[derive(Debug, serde::Serialize)]
struct CacheStats {
    repo: String,
    active_caches: u64,
    used_bytes: u64,
    quota_bytes: u64,
}

/// `GET …/actions/caches` page.
#[derive(Debug, serde::Deserialize)]
struct CachesPage {
    actions_caches: Vec<CacheEntry>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct CacheEntry {
    id: u64,
    key: String,
    #[serde(rename = "ref")]
    reference: String,
    size_in_bytes: u64,
    created_at: String,
    last_accessed_at: String,
}

/// The plan a `cache clear` prints.
#[derive(Debug, serde::Serialize)]
struct ClearPlan {
    prefix: String,
    entries: Vec<CacheEntry>,
    total_bytes: u64,
}

/// What a `cache clear` apply reports back.
#[derive(Debug, serde::Serialize)]
struct ClearResult {
    deleted: u32,
}

pub async fn run(token: &str, args: CacheArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        CacheCommand::Stats => stats(token, output).await,
        CacheCommand::Clear(args) => clear(token, args, output).await,
    }
}

async fn stats(token: &str, output: Output) -> stow_types::error::Result<()> {
    let usage: CacheUsage = github::get(token, "actions/cache/usage").await?;
    let stats = CacheStats {
        repo: usage.full_name,
        active_caches: usage.active_caches_count,
        used_bytes: usage.active_caches_size_in_bytes,
        quota_bytes: QUOTA_BYTES,
    };
    render::emit(output, &stats, |stats| {
        #[allow(clippy::cast_precision_loss)]
        let pct = stats.used_bytes as f64 / stats.quota_bytes as f64 * 100.0;
        format!(
            "repo            {}\nactive caches   {}\nused            {} of {} ({pct:.1}%)",
            stats.repo,
            stats.active_caches,
            render::size(stats.used_bytes),
            render::size(stats.quota_bytes),
        )
    })
}

/// Every cache entry whose key starts with `prefix`, paginated.
async fn caches_with_prefix(
    token: &str,
    prefix: &str,
) -> stow_types::error::Result<Vec<CacheEntry>> {
    let mut entries = Vec::new();
    let mut page = 1u32;
    loop {
        let page_body: CachesPage = github::get(
            token,
            &format!(
                "actions/caches?key={prefix}&sort=created_at&direction=asc&per_page=100&page={page}"
            ),
        )
        .await?;
        let count = page_body.actions_caches.len();
        entries.extend(page_body.actions_caches);
        if count < 100 {
            break;
        }
        page += 1;
    }
    Ok(entries)
}

async fn clear(token: &str, args: ClearArgs, output: Output) -> stow_types::error::Result<()> {
    if args.prefix.is_empty() {
        return Err(stow_error!("--prefix must not be empty"));
    }
    let entries = caches_with_prefix(token, &args.prefix).await?;
    let plan = ClearPlan {
        prefix: args.prefix.clone(),
        total_bytes: entries.iter().map(|entry| entry.size_in_bytes).sum(),
        entries,
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<ClearPlan, ClearResult>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "evict {} cache entr{} matching `{}` ({})\n",
                plan.entries.len(),
                if plan.entries.len() == 1 { "y" } else { "ies" },
                plan.prefix,
                render::size(plan.total_bytes),
            );
            let mut table = Table::new(&["id", "key", "ref", "size", "created"]);
            for entry in &plan.entries {
                table.push([
                    entry.id.to_string(),
                    entry.key.clone(),
                    entry.reference.clone(),
                    render::size(entry.size_in_bytes),
                    entry.created_at.clone(),
                ]);
            }
            if !table.is_empty() {
                let _ = write!(out, "{}", table.render());
            }
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "\ndeleted {} entr{}",
                    result.deleted,
                    if result.deleted == 1 { "y" } else { "ies" }
                );
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |plan: &ClearPlan| {
            let mut deleted = 0u32;
            for entry in &plan.entries {
                github::delete(token, &format!("actions/caches/{}", entry.id)).await?;
                deleted += 1;
            }
            Ok(ClearResult { deleted })
        },
    )
    .await
}
