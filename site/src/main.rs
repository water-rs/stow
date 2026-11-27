//! Renders the `stow.waterui.dev` site into `site/dist/` for Cloudflare
//! Pages: the askama templates in `site/templates/` become static HTML —
//! every value a page needs is baked here, so a page edit is a site
//! deploy and never touches the edge Worker — and the verbatim files in
//! `site/static/` (install scripts, `_headers`, `_redirects`) are copied
//! alongside. Dynamic pages (`/stats`, `/requests/{id}`) ship as shells
//! whose scripts read the same JSON the API serves.
//!
//! Usage: `cargo run -p stow-site [-- <out dir>]` — default `site/dist`.

use std::path::{Path, PathBuf};

use askama::Template;
use stow_types::api::CI_TARGET_TRIPLES;

/// Page stylesheet, embedded into each template's `<style>` block — the
/// site keeps one request of markup per page, no asset fetches.
const SITE_CSS: &str = include_str!("../templates/site.css");

/// Landing-page client script, embedded into `index.html`.
const SITE_JS: &str = include_str!("../templates/site.js");

/// Stats-page client script — fetches `GET /api/v1/stats` and renders it.
const STATS_JS: &str = include_str!("../templates/stats.js");

/// Request-status client script — fetches `GET /api/v1/requests/{id}`
/// and polls it while the record is unsettled.
const REQUEST_JS: &str = include_str!("../templates/request.js");

/// The project repository every documentation link points into.
const REPOSITORY_URL: &str = "https://github.com/water-rs/stow";

/// The audit the numbers section cites, pinned to `main`.
const AUDIT_URL: &str = "https://github.com/water-rs/stow/blob/main/docs/acceleration-audit.md";

/// The target the cache lookup picker selects by default — a visitor's
/// own platform cannot be guessed reliably, so the picker defaults to
/// the most common CI target.
const DEFAULT_LOOKUP_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Public Turnstile site key rendered into the request widget's
/// `data-sitekey`. It is site data — the matching secret stays an edge
/// secret — so the production value lives here and `TURNSTILE_SITE_KEY`
/// overrides it for a build against another deployment (the mock's
/// always-pass test key `1x00000000000000000000AA`).
const TURNSTILE_SITE_KEY: &str = "0x4AAAAAAE8LjhnMsqdVhiSp";

/// Files copied verbatim into `dist/` — the Pages configuration files
/// and the one-line installers.
const STATIC_FILES: &[&str] = &["_headers", "_redirects", "install.sh", "install.ps1"];

/// Askama context for `templates/index.html` — every variable is baked
/// at render time; the deployed page is plain HTML.
#[derive(Debug, Template)]
#[template(path = "index.html")]
struct IndexPage {
    turnstile_site_key: &'static str,
    targets: &'static [&'static str],
    /// Position of the lookup picker's default target inside `targets`
    /// (`loop.index0` comparisons — askama cannot compare `&&str` to a
    /// literal).
    default_target_index: usize,
    repository_url: &'static str,
    audit_url: &'static str,
    version: &'static str,
    css: &'static str,
    js: &'static str,
}

impl IndexPage {
    /// Build the render context; `site_key` is [`TURNSTILE_SITE_KEY`] or
    /// the `TURNSTILE_SITE_KEY` environment override.
    fn new(site_key: &'static str) -> Self {
        Self {
            turnstile_site_key: site_key,
            targets: CI_TARGET_TRIPLES,
            default_target_index: CI_TARGET_TRIPLES
                .iter()
                .position(|target| *target == DEFAULT_LOOKUP_TARGET)
                .expect("default lookup target is a CI target"),
            repository_url: REPOSITORY_URL,
            audit_url: AUDIT_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
            js: SITE_JS,
        }
    }
}

/// Askama context for `templates/stats.html` — the figures and
/// leaderboards are elements `stats.js` fills from `GET /api/v1/stats`.
#[derive(Debug, Template)]
#[template(path = "stats.html")]
struct StatsPage {
    repository_url: &'static str,
    version: &'static str,
    css: &'static str,
    js: &'static str,
}

/// Askama context for `templates/request.html` — served for every
/// `/requests/{id}` through the `_redirects` rewrite; `request.js`
/// reads the id off the path and renders the API's record.
#[derive(Debug, Template)]
#[template(path = "request.html")]
struct RequestPage {
    repository_url: &'static str,
    version: &'static str,
    css: &'static str,
    js: &'static str,
}

/// Write `rendered` to `dist/<path>`, creating parent directories.
fn write_page(out: &Path, path: &str, rendered: &str) -> std::io::Result<()> {
    let target = out.join(path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, rendered)
}

fn main() {
    let out = std::env::args().nth(1).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("dist"),
        PathBuf::from,
    );
    let site_key = std::env::var("TURNSTILE_SITE_KEY").map_or(TURNSTILE_SITE_KEY, |key| {
        Box::leak(key.into_boxed_str()) as &str
    });

    let (repository_url, version, css) = (REPOSITORY_URL, env!("CARGO_PKG_VERSION"), SITE_CSS);
    let pages: &[(&str, String)] = &[
        (
            "index.html",
            IndexPage::new(site_key)
                .render()
                .expect("index page renders"),
        ),
        (
            "stats.html",
            StatsPage {
                repository_url,
                version,
                css,
                js: STATS_JS,
            }
            .render()
            .expect("stats page renders"),
        ),
        (
            "request.html",
            RequestPage {
                repository_url,
                version,
                css,
                js: REQUEST_JS,
            }
            .render()
            .expect("request page renders"),
        ),
    ];
    for (path, html) in pages {
        write_page(&out, path, html)
            .unwrap_or_else(|error| panic!("write {}: {error}", out.join(path).display()));
    }
    for file in STATIC_FILES {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("static")
            .join(file);
        let target = out.join(file);
        std::fs::copy(&source, &target).unwrap_or_else(|error| {
            panic!("copy {} to {}: {error}", source.display(), target.display())
        });
    }
    eprintln!(
        "stow-site: rendered {} pages + {} files into {}",
        pages.len(),
        STATIC_FILES.len(),
        out.display()
    );
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use stow_types::api::CI_TARGET_TRIPLES;

    use super::{
        AUDIT_URL, IndexPage, REPOSITORY_URL, SITE_CSS, STATS_JS, StatsPage, TURNSTILE_SITE_KEY,
    };

    fn render() -> String {
        IndexPage::new(TURNSTILE_SITE_KEY)
            .render()
            .expect("index page renders")
    }

    #[test]
    fn index_page_renders_site_key_and_targets() {
        let html = render();
        assert!(html.contains(&format!(r#"data-sitekey="{TURNSTILE_SITE_KEY}""#)));
        for target in CI_TARGET_TRIPLES {
            assert!(html.contains(target), "rendered page lists {target}");
        }
    }

    #[test]
    fn index_page_cites_the_audit_for_its_numbers() {
        let html = render();
        assert!(html.contains(AUDIT_URL));
        for figure in ["2.88×", "4.76×", "234 s", "433 s", "61 s floor"] {
            assert!(html.contains(figure), "rendered page shows {figure}");
        }
    }

    #[test]
    fn index_page_offers_search_version_and_feature_controls() {
        let html = render();
        assert!(html.contains(r#"role="combobox""#));
        assert!(html.contains(r#"<ul id="crate-options" class="combobox-list" role="listbox""#));
        assert!(html.contains(r#"<select id="crate-version" name="version" disabled>"#));
        assert!(
            html.contains(r#"<fieldset class="field feature-set" id="feature-field" disabled>"#)
        );
        assert!(!html.contains(r#"id="crate-features""#));
        for endpoint in ["/api/v1/crates/search", "/versions", "/features"] {
            assert!(html.contains(endpoint), "script calls {endpoint}");
        }
    }

    #[test]
    fn index_page_links_results_to_the_status_page_not_the_json_route() {
        let html = render();
        assert!(html.contains("`/requests/${encodeURIComponent(outcome.request_id)}`"));
        assert!(!html.contains("`/api/v1/requests/${encodeURIComponent(entry.task_id)}`"));
    }

    #[test]
    fn index_page_carries_the_cache_lookup_controls() {
        let html = render();
        assert!(html.contains(r#"<select id="lookup-target">"#));
        for target in CI_TARGET_TRIPLES {
            assert!(
                html.contains(&format!(r#"<option value="{target}""#)),
                "lookup picker lists {target}"
            );
        }
        assert!(html.contains(
            r#"<option value="x86_64-unknown-linux-gnu" selected>x86_64-unknown-linux-gnu</option>"#
        ));
    }

    #[test]
    fn index_page_offers_both_install_lines_with_posix_as_the_default() {
        let html = render();
        assert!(html.contains(r#"<code id="install-posix-command">curl -fsSL https://stow.waterui.dev/install.sh | sh"#));
        assert!(html.contains(r#"<code id="install-windows-command" hidden>irm https://stow.waterui.dev/install.ps1 | iex"#));
        assert!(html.contains(r#"id="install-posix""#));
        assert!(html.contains(r#"id="install-windows""#));
        assert!(html.contains("navigator.userAgentData?.platform ?? navigator.userAgent"));
    }

    #[test]
    fn index_page_claims_the_clone_storage_advantage_exactly() {
        let html = render();
        assert!(html.contains("copy-on-write clone"));
        assert!(html.contains("plain copy"));
        assert!(html.contains("sccache"));
    }

    #[test]
    fn index_page_talks_to_the_lookup_r2_host() {
        let html = render();
        assert!(html.contains("https://stow-index.waterui.dev"));
        assert!(html.contains("/v1/lookup/"));
        assert!(!html.contains("/api/v1/index/"));
    }

    #[test]
    fn stats_page_constrains_figures_and_digest_leaderboards() {
        let html = StatsPage {
            repository_url: REPOSITORY_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
            js: STATS_JS,
        }
        .render()
        .expect("stats page renders");
        assert!(html.contains("container-type: inline-size;"));
        assert!(html.contains("grid-template-columns: minmax(0, 1fr);"));
        assert!(html.contains("text-overflow: ellipsis;"));
        assert!(html.contains("name.title = row.name;"));
    }
}
