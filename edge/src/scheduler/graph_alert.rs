//! The alert a wake raises when the graph it loads is larger than the
//! scheduler's memory line (stow#1501). It goes out through the edge's
//! one alert channel, the `send_email` binding; the `incident` issue is
//! the watchdog's, opened when the admin status it reads stops
//! answering.

use askama::Template;

use crate::freeze::AlertDraft;

/// The incident key of the alert.
pub const GRAPH_MEMORY_INCIDENT_KEY: &str = "scheduler-graph-memory";

#[derive(Template)]
#[template(path = "graph_memory_alert.txt")]
struct GraphMemoryAlertTemplate {
    needed: u64,
    budget: u64,
}

#[derive(Template)]
#[template(path = "graph_memory_alert.html")]
struct GraphMemoryAlertHtmlTemplate {
    needed: u64,
    budget: u64,
}

/// Render the alert for a graph that needs `needed` bytes against a
/// line of `budget`.
///
/// # Errors
/// `askama::Error` when a template fails to render.
pub fn render(needed: u64, budget: u64) -> Result<AlertDraft, askama::Error> {
    Ok(AlertDraft {
        key: GRAPH_MEMORY_INCIDENT_KEY,
        subject: "[stow] scheduler graph exceeds its memory line".to_owned(),
        body: GraphMemoryAlertTemplate { needed, budget }.render()?,
        html: GraphMemoryAlertHtmlTemplate { needed, budget }.render()?,
    })
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn the_alert_names_both_figures() {
        let draft = render(121_000_000, 110_000_000).expect("render");
        assert!(draft.body.contains("121000000") && draft.body.contains("110000000"));
        assert!(draft.html.contains("121000000") && draft.html.contains("110000000"));
    }
}
