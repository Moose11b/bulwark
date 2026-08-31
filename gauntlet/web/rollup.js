/* Gauntlet parallel roll-up — compare every run of a scenario. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);

  async function api(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(res.statusText);
    return res.json();
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "dark"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }

  async function loadScenarios() {
    const scns = await api("/api/scenarios");
    $("scenarioSel").innerHTML = scns.length
      ? scns.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("")
      : '<option value="">no scenarios</option>';
    if (scns.length) loadRollup();
  }

  function fmt(v, suffix = "") { return v === null || v === undefined ? "—" : v + suffix; }

  async function loadRollup() {
    const id = Number($("scenarioSel").value);
    if (!id) return;
    let r;
    try { r = await api(`/api/scenarios/${id}/rollup`); } catch (e) { return; }
    const t = r.totals;

    const stat = (label, value) =>
      `<div class="stat"><div class="stat-v">${value}</div><div class="stat-l">${label}</div></div>`;

    const stats = `<div class="stats">
      ${stat("Runs", t.sessions)}
      ${stat("Actions adjudicated", t.adjudications)}
      ${stat("Detection rate", t.detection_rate !== null ? Math.round(t.detection_rate * 100) + "%" : "—")}
      ${stat("Mean MTTD", fmt(t.mean_mttd, " min"))}
    </div>`;

    const rows = r.sessions.map((s) => `
      <tr>
        <td><b>${esc(s.name)}</b></td>
        <td><span class="pill ${s.status}">${s.status}</span></td>
        <td>${s.injects}</td>
        <td>${s.detected}/${s.adjudications}</td>
        <td>${fmt(s.mttd, " min")}</td>
        <td>${s.objectives_met}</td>
        <td>${s.coverage_gaps.length ? esc(s.coverage_gaps.join(", ")) : "—"}</td>
      </tr>`).join("");

    const sessionsTable = `<div class="panel"><p class="eyebrow">Runs of this scenario</p>
      <div class="scroll"><table class="grid">
        <thead><tr><th>Run</th><th>Status</th><th>Injects</th><th>Detected</th><th>MTTD</th><th>Obj. met</th><th>Coverage gaps</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="muted">No runs yet — start sessions of this scenario in the console.</td></tr>'}</tbody>
      </table></div></div>`;

    const cov = r.technique_coverage.map((c) => {
      const pct = c.sessions_total ? Math.round((c.sessions_detected / c.sessions_total) * 100) : 0;
      return `<div class="cov-row">
        <span class="cov-tech">${esc(c.technique)}</span>
        <span class="cov-meta">${c.injects} inject${c.injects === 1 ? "" : "s"}</span>
        <span class="cov-bar"><span class="cov-fill" style="width:${pct}%"></span></span>
        <span class="cov-num">${c.sessions_detected}/${c.sessions_total}</span>
      </div>`;
    }).join("");

    const coverage = `<div class="panel"><p class="eyebrow">ATT&amp;CK coverage across runs
      <span class="hint">— how often each technique was detected</span></p>
      ${cov || '<p class="muted">No techniques mapped.</p>'}</div>`;

    $("app").innerHTML = `<div class="panel"><p class="eyebrow">${esc(r.scenario_name)}</p>${stats}</div>` +
      sessionsTable + coverage;
  }

  function init() {
    initTheme();
    $("scenarioSel").addEventListener("change", loadRollup);
    $("btnRefresh").addEventListener("click", loadRollup);
    loadScenarios();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
