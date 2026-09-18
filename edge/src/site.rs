//! The landing page served at `GET /`: what stow is, the measured numbers,
//! how it works, and the crate request form that is its primary action.
//!
//! All HTML lives in `templates/index.html` (askama); the stylesheet and
//! client script are `include_str!` payloads embedded into the `<style>` and
//! `<script>` blocks the template declares, so the worker bundle stays
//! self-contained — no static-asset routes, no extra requests beyond the
//! Turnstile API script.

use askama::Template;
use stow_types::api::CI_TARGET_TRIPLES;

/// Page stylesheet, embedded into the template's `<style>` block.
const SITE_CSS: &str = include_str!("../templates/site.css");

/// Client-side form handler, embedded into the template's `<script>` block.
const SITE_JS: &str = include_str!("../templates/site.js");

/// The project repository every documentation link points into.
const REPOSITORY_URL: &str = "https://github.com/water-rs/stow";

/// The audit the numbers section cites, pinned to `main`.
const AUDIT_URL: &str = "https://github.com/water-rs/stow/blob/main/docs/acceleration-audit.md";

/// Page configuration probed once at worker startup.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Public Turnstile site key rendered into the widget's `data-sitekey`.
    pub turnstile_site_key: String,
}

/// Askama context for `templates/index.html`.
#[derive(Debug, Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    turnstile_site_key: String,
    targets: &'static [&'static str],
    repository_url: &'static str,
    audit_url: &'static str,
    version: &'static str,
    css: &'static str,
    js: &'static str,
}

impl IndexPage {
    /// Build the render context from the startup-probed configuration.
    fn new(config: &SiteConfig) -> Self {
        Self {
            turnstile_site_key: config.turnstile_site_key.clone(),
            targets: CI_TARGET_TRIPLES,
            repository_url: REPOSITORY_URL,
            audit_url: AUDIT_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
            js: SITE_JS,
        }
    }
}

/// `GET /` — render the landing page.
#[cfg(target_arch = "wasm32")]
pub async fn index(
    skyzen::utils::State(site): skyzen::utils::State<SiteConfig>,
) -> Result<skyzen::utils::Html<String>, crate::api::GetArtifactError> {
    IndexPage::new(&site)
        .render()
        .map(skyzen::utils::Html)
        .map_err(|error| crate::api::GetArtifactError::InternalWithMessage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use stow_types::api::CI_TARGET_TRIPLES;

    use super::{AUDIT_URL, IndexPage, SiteConfig};

    fn render() -> String {
        IndexPage::new(&SiteConfig {
            turnstile_site_key: "1x00000000000000000000AA".to_owned(),
        })
        .render()
        .expect("index page renders")
    }

    #[test]
    fn index_page_renders_site_key_and_targets() {
        let html = render();
        assert!(html.contains(r#"data-sitekey="1x00000000000000000000AA""#));
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
    fn index_page_embeds_the_stylesheet_and_script_inline() {
        let html = render();
        assert!(html.contains("<style>:root {"));
        assert!(html.contains("<script>\"use strict\";"));
        assert!(html.contains("/api/v1/requests"));
    }
}
