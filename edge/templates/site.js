"use strict";

(() => {
  // The install box shows one OS's command at a time; the rendered default
  // is POSIX so the page works without JavaScript, and the buttons are the
  // manual override when detection is wrong or the install is for
  // elsewhere.
  const posixCommand = document.getElementById("install-posix-command");
  const windowsCommand = document.getElementById("install-windows-command");
  const posixButton = document.getElementById("install-posix");
  const windowsButton = document.getElementById("install-windows");

  const showInstallFor = (windows) => {
    posixCommand.hidden = windows;
    windowsCommand.hidden = !windows;
    posixButton.classList.toggle("is-active", !windows);
    windowsButton.classList.toggle("is-active", windows);
    posixButton.setAttribute("aria-pressed", String(!windows));
    windowsButton.setAttribute("aria-pressed", String(windows));
  };
  posixButton.addEventListener("click", () => showInstallFor(false));
  windowsButton.addEventListener("click", () => showInstallFor(true));

  // \bwin keeps "darwin" (where `win` is mid-word) out of the Windows side.
  const platform = navigator.userAgentData?.platform ?? navigator.userAgent;
  showInstallFor(/\bwin/i.test(platform));

  const form = document.getElementById("request-form");
  const crateNameInput = document.getElementById("crate-name");
  const crateOptions = document.getElementById("crate-options");
  const crateNote = document.getElementById("crate-note");
  const versionSelect = document.getElementById("crate-version");
  const featureField = document.getElementById("feature-field");
  const featureList = document.getElementById("feature-list");
  const featureNote = document.getElementById("feature-note");
  const widgetContainer = document.getElementById("turnstile-widget");
  const submitButton = document.getElementById("submit-button");
  const status = document.getElementById("form-status");
  const result = document.getElementById("result");
  const resultTitle = document.getElementById("result-title");
  const resultBody = document.getElementById("result-body");

  let widgetId = null;

  // The crate name the version and feature controls currently describe, or
  // null while no published crate is selected. Submission is gated on it,
  // so the form can never post a crate crates.io does not have.
  let resolvedCrate = null;
  // The release an empty version field resolves to, mirrored from the last
  // version listing so `selectedVersion` never has to infer it from the
  // option order.
  let latestStableVersion = null;

  // Monotonic ticket per control: a slower earlier response must not
  // overwrite a faster later one when the user keeps typing.
  let searchTicket = 0;
  let versionTicket = 0;
  let featureTicket = 0;

  let searchTimer = null;
  let activeOption = -1;

  // Set when the list is dismissed (Escape, blur, or a selection) so an
  // in-flight search cannot pop it back open over the controls below;
  // cleared by the next keystroke, which is a fresh request for it.
  let optionsDismissed = false;

  // Mirrors `CrateName`'s deserialize rule, so a name the edge would reject
  // is caught before any request goes out.
  const CRATE_NAME = /^[A-Za-z0-9_-]{1,128}$/;
  const SEARCH_DEBOUNCE_MS = 220;
  const MIN_SEARCH_LEN = 2;

  const setNote = (element, message, kind) => {
    element.textContent = message;
    if (kind) {
      element.dataset.kind = kind;
    } else {
      delete element.dataset.kind;
    }
  };

  const setStatus = (message, kind) => setNote(status, message, kind);

  const getJson = async (url) => {
    const response = await fetch(url, { headers: { accept: "application/json" } });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(
        body && typeof body.error === "string" ? body.error : `HTTP ${response.status}`,
      );
    }
    return body;
  };

  /* ---- crate search combobox ---- */

  const closeOptions = () => {
    optionsDismissed = true;
    crateOptions.replaceChildren();
    crateOptions.hidden = true;
    crateNameInput.setAttribute("aria-expanded", "false");
    crateNameInput.removeAttribute("aria-activedescendant");
    activeOption = -1;
  };

  const highlightOption = (index) => {
    const items = [...crateOptions.children];
    if (items.length === 0) {
      return;
    }
    activeOption = (index + items.length) % items.length;
    items.forEach((item, position) => {
      const selected = position === activeOption;
      item.setAttribute("aria-selected", selected ? "true" : "false");
      if (selected) {
        crateNameInput.setAttribute("aria-activedescendant", item.id);
        item.scrollIntoView({ block: "nearest" });
      }
    });
  };

  const renderOptions = (crates) => {
    if (optionsDismissed) {
      return;
    }
    crateOptions.replaceChildren();
    for (const [index, hit] of crates.entries()) {
      const item = document.createElement("li");
      item.id = `crate-option-${index}`;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", "false");
      item.dataset.crate = hit.crate_name;

      const name = document.createElement("span");
      name.className = "option-name";
      name.textContent = `${hit.crate_name} ${hit.max_version}`;
      item.appendChild(name);

      const meta = document.createElement("span");
      meta.className = "option-meta";
      meta.textContent = hit.description ?? "";
      item.appendChild(meta);

      // `mousedown`, not `click`: the input's blur would close the list
      // before a click could land on it.
      item.addEventListener("mousedown", (event) => {
        event.preventDefault();
        chooseCrate(hit.crate_name);
      });
      crateOptions.appendChild(item);
    }
    crateOptions.hidden = crates.length === 0;
    crateNameInput.setAttribute("aria-expanded", crates.length > 0 ? "true" : "false");
    activeOption = -1;
  };

  const searchCrates = async (query) => {
    const ticket = ++searchTicket;
    try {
      const body = await getJson(`/api/v1/crates/search?q=${encodeURIComponent(query)}`);
      if (ticket === searchTicket) {
        renderOptions(body.crates);
      }
    } catch {
      // A failed completion lookup is not a form error: the name the user
      // typed is still validated by the version lookup below.
      if (ticket === searchTicket) {
        closeOptions();
      }
    }
  };

  const chooseCrate = (crateName) => {
    crateNameInput.value = crateName;
    closeOptions();
    void loadVersions(crateName);
  };

  /* ---- versions ---- */

  const resetVersions = () => {
    versionSelect.replaceChildren(new Option("latest stable", ""));
    versionSelect.disabled = true;
  };

  const resetFeatures = (note) => {
    featureList.replaceChildren();
    featureField.disabled = true;
    setNote(featureNote, note, null);
  };

  const invalidateCrate = (message, kind) => {
    resolvedCrate = null;
    crateNameInput.setAttribute("aria-invalid", kind === "error" ? "true" : "false");
    setNote(crateNote, message, kind);
    resetVersions();
    resetFeatures("pick a crate to list its features");
  };

  const loadVersions = async (crateName) => {
    const ticket = ++versionTicket;
    setNote(crateNote, "checking crates.io…", null);
    crateNameInput.setAttribute("aria-invalid", "false");
    try {
      const body = await getJson(`/api/v1/crates/${encodeURIComponent(crateName)}/versions`);
      if (ticket !== versionTicket) {
        return;
      }
      if (body.versions.length === 0) {
        invalidateCrate(`${crateName} has no published release`, "error");
        return;
      }
      resolvedCrate = crateName;
      crateNameInput.setAttribute("aria-invalid", "false");
      setNote(crateNote, `${body.versions.length} published versions`, null);
      // Submitting with no version resolves to the newest non-prerelease
      // release, so that is the one the default option names and the one
      // whose features are listed. A crate whose only releases are
      // prereleases gets no default option at all: the empty value would
      // resolve to nothing and the request would 404.
      const latestStable = body.versions.find((version) => !version.includes("-"));
      latestStableVersion = latestStable ?? null;
      const options = body.versions.map((version) => new Option(version, version));
      if (latestStable !== undefined) {
        options.unshift(new Option(`latest stable (${latestStable})`, ""));
      }
      versionSelect.replaceChildren(...options);
      versionSelect.disabled = false;
      void loadFeatures(crateName, latestStable ?? body.versions[0]);
    } catch (error) {
      if (ticket === versionTicket) {
        invalidateCrate(error instanceof Error ? error.message : String(error), "error");
      }
    }
  };

  /* ---- features ---- */

  // A feature the `default` set already enables is shown ticked but frozen:
  // it is on whenever `default` is, and listing it explicitly would name a
  // different build than the one the user means. Unticking `default` gives
  // each box back the state the user last chose for it — leaving them
  // ticked would post the entire default closure under
  // `--no-default-features`, which is neither what the note promises nor
  // what the user asked for.
  const applyDefaultImplications = () => {
    const defaultBox = featureList.querySelector('input[value="default"]');
    const defaultOn = defaultBox !== null && defaultBox.checked;
    for (const input of featureList.querySelectorAll("input[data-implied-by-default]")) {
      if (defaultOn) {
        if (!input.disabled) {
          input.dataset.userChecked = input.checked ? "true" : "false";
        }
        input.checked = true;
      } else {
        input.checked = input.dataset.userChecked === "true";
      }
      input.disabled = defaultOn;
    }
  };

  const renderFeatures = (features) => {
    featureList.replaceChildren();
    for (const feature of features) {
      const label = document.createElement("label");
      label.className = "feature";

      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = feature.name;
      // `default` is the only feature checked on arrival: it is what cargo
      // builds with when nothing is passed.
      input.checked = feature.name === "default";
      if (feature.default && feature.name !== "default") {
        input.dataset.impliedByDefault = "true";
      }
      if (feature.name === "default") {
        input.addEventListener("change", applyDefaultImplications);
      }
      label.appendChild(input);

      const text = document.createElement("span");
      text.textContent = feature.name;
      if (feature.implies.length > 0) {
        text.title = `enables ${feature.implies.join(", ")}`;
      }
      label.appendChild(text);
      featureList.appendChild(label);
    }
    applyDefaultImplications();
    featureField.disabled = false;
    let note = "this version declares no features";
    if (features.some((feature) => feature.name === "default")) {
      note = "unticking default builds --no-default-features";
    } else if (features.length > 0) {
      note = "this version declares no default feature set";
    }
    setNote(featureNote, note, null);
  };

  const loadFeatures = async (crateName, version) => {
    const ticket = ++featureTicket;
    resetFeatures("loading features…");
    try {
      const body = await getJson(
        `/api/v1/crates/${encodeURIComponent(crateName)}/versions/${encodeURIComponent(version)}/features`,
      );
      if (ticket === featureTicket) {
        renderFeatures(body.features);
      }
    } catch (error) {
      if (ticket === featureTicket) {
        resetFeatures(error instanceof Error ? error.message : String(error));
      }
    }
  };

  const selectedVersion = () =>
    versionSelect.value === "" ? latestStableVersion : versionSelect.value;

  /* ---- submission ---- */

  // `CrateRequestState` on the wire (snake_case).
  const STATE_LABELS = {
    cached: "cached",
    queued: "queued",
    already_queued: "already queued",
    building: "building",
    closure_queued: "deps queued (no library)",
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
        link.href = `/requests/${encodeURIComponent(entry.task_id)}`;
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
    // The field can have moved on since the crate was resolved; posting
    // `resolvedCrate` regardless would mint a task for a crate the user
    // deleted.
    if (resolvedCrate === null || resolvedCrate !== crateNameInput.value.trim()) {
      setStatus("pick a crate from the list first", "error");
      submitButton.disabled = false;
      return;
    }
    setStatus("submitting…", "info");
    // `FeaturesJson` travels as a JSON-encoded string of the feature list,
    // sorted and deduplicated: the edge rejects any other order. Only the
    // features the user ticked go out; the edge expands what they imply.
    const features = [
      ...new Set(
        [...featureList.querySelectorAll("input:checked:not(:disabled)")].map(
          (input) => input.value,
        ),
      ),
    ].sort();
    const payload = {
      crate_name: resolvedCrate,
      features_json: JSON.stringify(features),
      turnstile_token: token,
    };
    if (versionSelect.value !== "") {
      payload.version = versionSelect.value;
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

  /* ---- wiring ---- */

  crateNameInput.addEventListener("input", () => {
    const query = crateNameInput.value.trim();
    optionsDismissed = false;
    resolvedCrate = null;
    // Every request in flight belongs to the name that was in the field a
    // moment ago. Retiring all three tickets here — not when the debounced
    // search finally fires — stops a late version listing from re-arming
    // `resolvedCrate` for a crate the user has already edited away.
    searchTicket += 1;
    versionTicket += 1;
    featureTicket += 1;
    window.clearTimeout(searchTimer);
    if (query === "") {
      closeOptions();
      invalidateCrate("", null);
      return;
    }
    if (!CRATE_NAME.test(query)) {
      closeOptions();
      invalidateCrate("a crate name is letters, digits, `-` and `_`", "error");
      return;
    }
    searchTimer = window.setTimeout(() => {
      if (query.length >= MIN_SEARCH_LEN) {
        void searchCrates(query);
      }
      // The name may be exact without being picked from the list, so it is
      // resolved against crates.io either way.
      void loadVersions(query);
    }, SEARCH_DEBOUNCE_MS);
  });

  crateNameInput.addEventListener("keydown", (event) => {
    // Escape is handled even with the list closed: a search may still be in
    // flight, and dismissing has to stop it from arriving.
    if (event.key === "Escape") {
      closeOptions();
      return;
    }
    if (crateOptions.hidden) {
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      highlightOption(activeOption + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      highlightOption(activeOption - 1);
    } else if (event.key === "Enter" && activeOption >= 0) {
      event.preventDefault();
      chooseCrate(crateOptions.children[activeOption].dataset.crate);
    }
  });

  crateNameInput.addEventListener("blur", closeOptions);

  versionSelect.addEventListener("change", () => {
    const version = selectedVersion();
    if (resolvedCrate !== null && version) {
      void loadFeatures(resolvedCrate, version);
    }
  });

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
    if (resolvedCrate === null) {
      setStatus("pick a crate that is published on crates.io", "error");
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

/* ---- cache lookup: "is this crate cached?" answered from the index slice ---- */
(() => {
  const targetSelect = document.getElementById("lookup-target");
  const crateInput = document.getElementById("lookup-crate");
  const note = document.getElementById("lookup-note");
  const sliceLabel = document.getElementById("lookup-slice");
  const result = document.getElementById("lookup-result");
  const resultBody = document.getElementById("lookup-result-body");

  // Mirrors `CrateName`'s deserialize rule.
  const CRATE_NAME = /^[A-Za-z0-9_-]{1,128}$/;
  // Mirrors `ARTIFACT_INDEX_FORMAT_VERSION` in types/src/index.rs.
  const INDEX_FORMAT_VERSION = 1;
  const LOOKUP_DEBOUNCE_MS = 180;

  // Monotonic ticket: a slower earlier load must not overwrite a faster
  // later answer when the user keeps typing or switches target.
  let lookupTicket = 0;
  let lookupTimer = null;

  // One slice fetch per target, armed lazily on the first query — the
  // landing page never pays for data nobody asked about. A rejected
  // fetch retires the request so the next keystroke retries; a slice
  // that fails to load shows an error, never an empty result.
  let sliceRequest = null;

  const setNote = (element, message, kind) => {
    element.textContent = message;
    if (kind) {
      element.dataset.kind = kind;
    } else {
      delete element.dataset.kind;
    }
  };

  const getJson = async (url) => {
    const response = await fetch(url, { headers: { accept: "application/json" } });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(
        body && typeof body.error === "string" ? body.error : `HTTP ${response.status}`,
      );
    }
    return body;
  };

  // First the short-lived digest pointer (the tag moves at every index
  // publish), then the immutable digest-addressed blob — which the
  // browser cache can hold forever, so the second visit loads nothing.
  // fetch() decodes the negotiated Content-Encoding itself (zstd or
  // gzip), so `response.json()` always reads the index document.
  const fetchSlice = async (target) => {
    const pointer = await getJson(
      `/api/v1/index/${encodeURIComponent(target)}/stable`,
    );
    const url =
      `/api/v1/index/${encodeURIComponent(target)}` +
      `/${encodeURIComponent(pointer.rustc_version)}` +
      `/${encodeURIComponent(pointer.digest)}`;
    const response = await fetch(url, { headers: { accept: "application/json" } });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(
        body && typeof body.error === "string" ? body.error : `HTTP ${response.status}`,
      );
    }
    const index = await response.json();
    // The same two gates `stow_types::index::decode` enforces — a slice
    // in a format this page does not understand is a load error, never
    // a "not cached".
    const header = index && index.header;
    if (!header || header.format_version !== INDEX_FORMAT_VERSION) {
      throw new Error(
        `the index slice uses format_version ${header ? header.format_version : "none"} — this page understands ${INDEX_FORMAT_VERSION}`,
      );
    }
    if (header.row_count !== (index.rows ? index.rows.length : undefined)) {
      throw new Error("the index slice's row count does not match its rows");
    }
    return index;
  };

  const ensureSlice = () => {
    const target = targetSelect.value;
    if (sliceRequest === null || sliceRequest.target !== target) {
      const request = { target, promise: null };
      request.promise = fetchSlice(target).then((index) => {
        // Only the live request writes the label — a slow slice for a
        // target the user has already left must not overwrite the new
        // target's label.
        if (sliceRequest === request) {
          sliceLabel.textContent = `rustc ${index.header.rustc_version} · ${index.rows.length} rows`;
        }
        // Group rows by crate once; every later keystroke is a Map hit.
        const byCrate = new Map();
        for (const row of index.rows) {
          let rows = byCrate.get(row.crate_name);
          if (rows === undefined) {
            rows = [];
            byCrate.set(row.crate_name, rows);
          }
          rows.push(row);
        }
        return byCrate;
      });
      request.promise.catch(() => {
        if (sliceRequest === request) {
          sliceRequest = null;
          sliceLabel.textContent = "slice failed to load";
        }
      });
      sliceRequest = request;
    }
    return sliceRequest.promise;
  };

  // `features_json` is the canonical JSON-encoded feature list.
  const parseFeatures = (raw) => {
    if (Array.isArray(raw)) {
      return raw;
    }
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  };

  const formatSize = (bytes) =>
    bytes >= 1024 * 1024
      ? `${(bytes / 1024 / 1024).toFixed(1)} MiB`
      : `${Math.round(bytes / 1024)} KiB`;

  const cell = (row, text, className) => {
    const td = document.createElement("td");
    if (className) {
      td.className = className;
    }
    td.textContent = text;
    row.appendChild(td);
  };

  const answer = async (crateName, ticket) => {
    result.hidden = true;
    resultBody.replaceChildren();
    setNote(note, "loading index slice…", null);

    let byCrate;
    try {
      byCrate = await ensureSlice();
    } catch (error) {
      if (ticket !== lookupTicket) {
        return;
      }
      setNote(
        note,
        `the index slice failed to load: ${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
      return;
    }
    if (ticket !== lookupTicket) {
      return;
    }

    // version -> the distinct feature sets it is cached with.
    const byVersion = new Map();
    for (const row of byCrate.get(crateName) ?? []) {
      const features = parseFeatures(row.features_json);
      const label = features.length > 0 ? features.join(", ") : "--no-default-features";
      let sets = byVersion.get(row.version);
      if (sets === undefined) {
        sets = new Map();
        byVersion.set(row.version, sets);
      }
      sets.set(label, row.bundle_size);
    }

    if (byVersion.size === 0) {
      setNote(note, `not cached on ${targetSelect.value} — request it below`, null);
      return;
    }

    const versions = [...byVersion.keys()].sort((a, b) =>
      b.localeCompare(a, undefined, { numeric: true }),
    );
    for (const version of versions) {
      for (const [features, size] of byVersion.get(version)) {
        const row = document.createElement("tr");
        cell(row, version);
        cell(row, features);
        cell(row, formatSize(size), "num");
        resultBody.appendChild(row);
      }
    }
    result.hidden = false;
    setNote(
      note,
      `cached on ${targetSelect.value} — ${versions.length} version${versions.length === 1 ? "" : "s"}`,
      null,
    );
  };

  crateInput.addEventListener("input", () => {
    const query = crateInput.value.trim();
    lookupTicket += 1;
    window.clearTimeout(lookupTimer);
    result.hidden = true;
    resultBody.replaceChildren();
    if (query === "") {
      setNote(note, "", null);
      return;
    }
    if (!CRATE_NAME.test(query)) {
      setNote(note, "a crate name is letters, digits, `-` and `_`", "error");
      return;
    }
    lookupTimer = window.setTimeout(() => {
      void answer(query, lookupTicket);
    }, LOOKUP_DEBOUNCE_MS);
  });

  // A different target is a different slice: drop the loaded one, clear
  // the answer, and let the next keystroke fetch the new target lazily.
  targetSelect.addEventListener("change", () => {
    lookupTicket += 1;
    sliceRequest = null;
    sliceLabel.textContent = "slice loads on first query";
    result.hidden = true;
    resultBody.replaceChildren();
    setNote(note, "", null);
    if (crateInput.value.trim() !== "") {
      void answer(crateInput.value.trim(), lookupTicket);
    }
  });
})();
