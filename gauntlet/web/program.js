/* Gauntlet program coverage — ATT&CK coverage and improvement tracking across the program. */
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

  const stat = (label, value) =>
    `<div class="stat"><div class="stat-v">${value}</div><div class="stat-l">${label}</div></div>`;

  async function load() {
    let cov, imp;
    try { cov = await api("/api/program/coverage"); imp = await api("/api/program/improvements"); }
    catch (e) { $("app").innerHTML = `<div class="panel"><p class="muted">Could not load analytics.</p></div>`; return; }

    const testedTechs = cov.techniques.filter((t) => t.tested).length;

    const stats = `<div class="panel"><p class="eyebrow">Program at a glance</p><div class="stats">
      ${stat("Scenarios", cov.scenarios)}
      ${stat("Runs", cov.sessions)}
      ${stat("Techniques tested", `${testedTechs}/${cov.techniques.length}`)}
      ${stat("Open improvements", imp.open)}
    </div></div>`;

    // Coverage by tactic
    const tacticRows = cov.tactics.map((t) => {
      const pct = t.techniques ? Math.round((t.tested / t.techniques) * 100) : 0;
      return `<div class="cov-row tactic">
        <span class="cov-tech">${esc(t.tactic)}</span>
        <span class="cov-meta">${t.tested}/${t.techniques} tested</span>
        <span class="cov-bar"><span class="cov-fill" style="width:${pct}%"></span></span>
        <span class="cov-num">${pct}%</span>
      </div>`;
    }).join("");
    const byTactic = `<div class="panel"><p class="eyebrow">Coverage by ATT&amp;CK tactic</p>${tacticRows || '<p class="muted">No techniques mapped yet.</p>'}</div>`;

    // Technique table
    const rows = cov.techniques.map((t) => `
      <tr>
        <td><span class="cov-tech">${esc(t.technique)}</span></td>
        <td>${esc(t.tactic)}</td>
        <td>${t.scenarios}</td>
        <td>${t.exercised}</td>
        <td>${t.detected}</td>
        <td>${t.tested ? '<span class="chip good">tested</span>' : '<span class="chip warn">never tested</span>'}</td>
      </tr>`).join("");
    const table = `<div class="panel"><p class="eyebrow">Techniques across the program</p>
      <div class="scroll"><table class="grid">
        <thead><tr><th>Technique</th><th>Tactic</th><th>Scenarios</th><th>Exercised</th><th>Detected</th><th>Status</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">No techniques yet.</td></tr>'}</tbody>
      </table></div></div>`;

    // Improvement items
    const items = imp.items.map((it) => `
      <li class="imp ${it.status}">
        <span class="imp-status ${it.status}">${it.status}</span>
        <span class="imp-body"><b>${esc(it.objective_code)} · ${esc(it.objective)}</b>
          <span class="muted"> — ${esc(it.scenario)} / ${esc(it.session)}</span><br>
          ${esc(it.note)}</span>
      </li>`).join("");
    const improvements = `<div class="panel"><p class="eyebrow">Improvement items
      <span class="hint">— objectives observed as missed or partial</span></p>
      <ul class="imp-list">${items || '<li class="muted">No improvement items yet.</li>'}</ul></div>`;

    $("app").innerHTML = stats + byTactic + table + improvements;
  }

  function init() {
    initTheme();
    $("btnRefresh").addEventListener("click", load);
    load();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
