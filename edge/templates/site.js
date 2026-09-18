"use strict";

(() => {
  const form = document.getElementById("request-form");
  const crateNameInput = document.getElementById("crate-name");
  const versionInput = document.getElementById("crate-version");
  const featuresInput = document.getElementById("crate-features");
  const widgetContainer = document.getElementById("turnstile-widget");
  const submitButton = document.getElementById("submit-button");
  const status = document.getElementById("form-status");
  const result = document.getElementById("result");
  const resultTitle = document.getElementById("result-title");
  const resultBody = document.getElementById("result-body");

  let widgetId = null;

  const setStatus = (message, kind) => {
    status.textContent = message;
    if (kind) {
      status.dataset.kind = kind;
    } else {
      delete status.dataset.kind;
    }
  };

  // `CrateRequestState` on the wire (snake_case).
  const STATE_LABELS = {
    cached: "cached",
    queued: "queued",
    already_queued: "already queued",
    building: "building",
  };

  const cell = (row, text, className) => {
    const td = document.createElement("td");
    if (className) {
      td.className = className;
    }
    td.textContent = text;
    row.appendChild(td);
    return td;
  };

  const showOutcome = (outcome) => {
    resultTitle.textContent = `${outcome.crate_name} ${outcome.version} · rustc ${outcome.rustc_version}`;
    resultBody.replaceChildren();
    for (const entry of outcome.targets) {
      const row = document.createElement("tr");
      cell(row, entry.target);
      cell(row, STATE_LABELS[entry.state] ?? String(entry.state));
      cell(
        row,
        typeof entry.human_lane_position === "number" ? `#${entry.human_lane_position}` : "—",
        "num",
      );
      const taskCell = cell(row, "");
      if (entry.task_id) {
        const link = document.createElement("a");
        link.href = `/api/v1/requests/${encodeURIComponent(entry.task_id)}`;
        link.textContent = "status";
        taskCell.appendChild(link);
      } else {
        taskCell.textContent = "—";
      }
      resultBody.appendChild(row);
    }
    result.hidden = false;
    result.scrollIntoView({ block: "nearest" });
  };

  const requestFailure = (response, body) => {
    if (body && typeof body.error === "string") {
      const codes = Array.isArray(body["error-codes"]) ? body["error-codes"] : [];
      return codes.length > 0 ? `${body.error}: ${codes.join(", ")}` : body.error;
    }
    return `request failed (HTTP ${response.status})`;
  };

  const submitRequest = async (token) => {
    setStatus("submitting…", "info");
    // `FeaturesJson` travels as a JSON-encoded string of the feature list,
    // sorted and deduplicated: the edge rejects any other order.
    const features = [
      ...new Set(
        featuresInput.value
          .split(",")
          .map((feature) => feature.trim())
          .filter((feature) => feature !== ""),
      ),
    ].sort();
    const payload = {
      crate_name: crateNameInput.value.trim(),
      features_json: JSON.stringify(features),
      turnstile_token: token,
    };
    const version = versionInput.value.trim();
    if (version !== "") {
      payload.version = version;
    }
    try {
      const response = await fetch("/api/v1/requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(requestFailure(response, body));
      }
      showOutcome(body);
      setStatus("", "");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error), "error");
    } finally {
      submitButton.disabled = false;
    }
  };

  // Named in the api.js `onload` query parameter; Turnstile calls it once the
  // script is ready. Deferred script order guarantees this assignment runs
  // first.
  window.stowTurnstileReady = () => {
    widgetId = window.turnstile.render(widgetContainer, {
      sitekey: widgetContainer.dataset.sitekey,
      appearance: "interaction-only",
      execution: "execute",
      callback: submitRequest,
      "error-callback": () => {
        submitButton.disabled = false;
        setStatus("human verification failed — try again", "error");
      },
      "expired-callback": () => {
        window.turnstile.reset(widgetId);
      },
    });
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (crateNameInput.value.trim() === "") {
      setStatus("a crate name is required", "error");
      crateNameInput.focus();
      return;
    }
    if (widgetId === null) {
      setStatus("human verification is still loading — try again in a moment", "error");
      return;
    }
    submitButton.disabled = true;
    setStatus("verifying…", "info");
    window.turnstile.reset(widgetId);
    window.turnstile.execute(widgetId);
  });
})();
