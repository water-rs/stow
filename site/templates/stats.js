"use strict";

/* Stats page: renders `GET /api/v1/stats` into the figures and
 * leaderboards — the same JSON the API serves programs, formatted the
 * way the page's captions read. */
(() => {
  const note = document.getElementById("stats-note");

  // `12_345_678` → `"12,345,678"`.
  const grouped = (value) =>
    String(Math.round(value)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

  // CPU hours: one decimal under 10, a grouped integer above.
  const cpuHours = (hours) => (hours >= 10 ? grouped(hours) : hours.toFixed(1));

  const figure = (id, text) => {
    document.getElementById(id).textContent = text;
  };

  const leaderboard = (id, rows, empty) => {
    const list = document.getElementById(id);
    list.replaceChildren();
    if (!rows || rows.length === 0) {
      const li = document.createElement("li");
      const span = document.createElement("span");
      span.textContent = empty;
      li.appendChild(span);
      list.appendChild(li);
      return;
    }
    for (const row of rows) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = row.name;
      const leader = document.createElement("span");
      leader.className = "leader";
      const hits = document.createElement("span");
      hits.textContent = grouped(row.hits);
      li.append(name, leader, hits);
      list.appendChild(li);
    }
  };

  const render = (stats) => {
    figure("figure-builds", grouped(stats.builds_24h));
    figure("figure-hits", grouped(stats.hits_24h));
    figure("figure-misses", grouped(stats.misses_24h));
    figure("figure-hit-rate", `${Math.round(stats.hit_rate_24h * 100)}%`);
    figure("figure-cpu-hours", `${cpuHours(stats.cpu_hours_saved_30d)} h`);
    if (stats.daily_active_installs_7d !== null) {
      figure("figure-installs-value", grouped(stats.daily_active_installs_7d));
      document.getElementById("figure-installs").hidden = false;
    }
    leaderboard("lb-top-digests", stats.top_digests_30d, "no hits yet");
    leaderboard("lb-rustc-versions", stats.rustc_versions_30d, "no hits yet");
    leaderboard("lb-cli-versions", stats.cli_versions_30d, "no hits yet");
    leaderboard("lb-operating-systems", stats.operating_systems_30d, "no reports yet");
    leaderboard("lb-countries", stats.countries_30d, "no reports yet");
    leaderboard("lb-environments", stats.environments_30d, "no reports yet");
    note.textContent = "";
  };

  const load = async () => {
    try {
      const response = await fetch("/api/v1/stats", {
        headers: { accept: "application/json" },
      });
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(
          body && typeof body.error === "string" ? body.error : `HTTP ${response.status}`,
        );
      }
      render(body);
    } catch (error) {
      note.textContent = `the published aggregates failed to load: ${error instanceof Error ? error.message : String(error)}`;
    }
  };

  void load();
})();
