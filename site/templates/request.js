"use strict";

/* Request-status page: reads the id off `/requests/{id}` (the
 * `_redirects` rewrite serves this file for every id), renders the
 * `GET /api/v1/requests/{id}` record, and re-fetches it on the refresh
 * cadence the meta-refresh version used until the record settles. */
(() => {
  const POLL_MS = 20000;
  // `CrateRequestState` → (label, settled): the two states a task never
  // moves out of, matching the page's server-side view of "settled".
  const STATE = {
    cached: ["cached", true],
    queued: ["queued", false],
    already_queued: ["already queued", false],
    building: ["building", false],
    closure_queued: ["deps queued (no library)", true],
  };
  const TASK_ID_SHORT = 12;

  const title = document.getElementById("request-title");
  const badge = document.getElementById("request-badge");
  const summary = document.getElementById("request-summary");
  const details = document.getElementById("request-details");
  const detailsList = document.getElementById("request-details-list");
  const rustcCell = document.getElementById("request-rustc");
  const targetsSection = document.getElementById("request-targets");
  const targetsCount = document.getElementById("request-targets-count");
  const targetsBody = document.getElementById("request-targets-body");
  const idLine = document.getElementById("request-id-line");

  // `/requests/<id>` — the rewrite also serves this file at
  // `/request.html`, where no id exists.
  const id = decodeURIComponent(
    location.pathname.startsWith("/requests/")
      ? location.pathname.slice("/requests/".length).replace(/\/+$/, "")
      : "",
  );

  const row = (label, value) => {
    const li = document.createElement("li");
    const key = document.createElement("span");
    key.textContent = label;
    const leader = document.createElement("span");
    leader.className = "leader";
    const val = document.createElement("span");
    val.append(value);
    li.append(key, leader, val);
    detailsList.appendChild(li);
  };

  const showUnknown = (message) => {
    document.title = "unknown request — stow";
    title.textContent = "Unknown request";
    badge.textContent = "not found";
    badge.dataset.state = "failed";
    summary.textContent = message;
    idLine.textContent = id;
  };

  const featuresLabel = (raw) => {
    let features = [];
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (Array.isArray(parsed)) {
        features = parsed;
      }
    } catch {
      // A malformed canonical list renders as the bare build — the API
      // never sends one, so this branch is unreachable in practice.
    }
    return features.length > 0 ? features.join(", ") : "--no-default-features";
  };

  const render = (status) => {
    const phase = String(status.status);
    const targets = Array.isArray(status.targets) ? status.targets : [];
    const allSettled =
      targets.length > 0 && targets.every((t) => (STATE[t.state] ?? ["", false])[1]);
    const settled = phase === "failed" || (phase === "enqueued" && allSettled);
    const summaries = {
      accepted:
        "Accepted — a CI job is dispatching to resolve its dependency closure; this page refreshes itself.",
      resolving:
        "Resolving the dependency closure on CI now; this page refreshes itself.",
      enqueued:
        "Resolved — the tasks are in the human lane, ahead of the miss queue. Each target below lands on its own.",
      failed:
        "The resolve failed before any task was queued. Requesting the same crate again re-attempts it.",
    };

    document.title = `${status.crate_name} ${status.version} · ${phase} — stow`;
    title.textContent = `${status.crate_name} ${status.version}`;
    badge.textContent = phase;
    badge.dataset.state = phase;
    summary.textContent = summaries[phase] ?? phase;

    rustcCell.textContent = status.rustc_version;
    detailsList.replaceChildren();
    row("crate", `${status.crate_name} ${status.version}`);
    row("rustc", status.rustc_version);
    row("features", featuresLabel(status.features_json));
    row("state", phase);
    if (status.github_run_url) {
      const link = document.createElement("a");
      link.href = status.github_run_url;
      link.textContent = "view on GitHub";
      row("resolve run", link);
    }
    if (status.error) {
      row("error", status.error);
    }
    details.hidden = false;

    targetsBody.replaceChildren();
    if (targets.length > 0) {
      targetsCount.textContent = `${targets.length} platforms`;
      for (const target of targets) {
        const tr = document.createElement("tr");
        const append = (text, className) => {
          const td = document.createElement("td");
          if (className) {
            td.className = className;
          }
          td.textContent = text;
          tr.appendChild(td);
        };
        append(target.target);
        append((STATE[target.state] ?? [String(target.state)])[0]);
        append(
          typeof target.human_lane_position === "number"
            ? `#${target.human_lane_position}`
            : "—",
          "num",
        );
        const taskCell = document.createElement("td");
        taskCell.className = "task-col";
        if (target.task_id) {
          const link = document.createElement("a");
          link.href = `/api/v1/requests/${encodeURIComponent(status.request_id)}`;
          link.title = target.task_id;
          link.textContent = target.task_id.slice(0, TASK_ID_SHORT);
          taskCell.appendChild(link);
        } else {
          taskCell.textContent = "—";
        }
        tr.appendChild(taskCell);
        targetsBody.appendChild(tr);
      }
      targetsSection.hidden = false;
    }

    idLine.replaceChildren(
      document.createTextNode(`${status.request_id} · `),
      Object.assign(document.createElement("a"), {
        href: `/api/v1/requests/${encodeURIComponent(status.request_id)}`,
        textContent: "JSON",
      }),
    );
    return settled;
  };

  const poll = async () => {
    let settled = true;
    try {
      const response = await fetch(`/api/v1/requests/${encodeURIComponent(id)}`, {
        headers: { accept: "application/json" },
      });
      if (response.status === 404) {
        showUnknown(
          "The scheduler has no request record with this id. A mistyped link never existed; one from before a record was reaped has expired.",
        );
        return;
      }
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      settled = render(await response.json());
    } catch (error) {
      // A transient read failure keeps the poll alive — the record's
      // own state, not this fetch, decides when to stop.
      badge.textContent = "error";
      badge.dataset.state = "failed";
      summary.textContent = `the request record failed to load: ${error instanceof Error ? error.message : String(error)} — retrying`;
      settled = false;
    }
    if (!settled) {
      setTimeout(() => void poll(), POLL_MS);
    }
  };

  if (id === "") {
    showUnknown("No request id in the URL — the status links come from the request form.");
  } else {
    void poll();
  }
})();
