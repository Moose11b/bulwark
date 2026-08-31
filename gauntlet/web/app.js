/* Gauntlet facilitator console — vanilla SPA over the Gauntlet API. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  let currentSid = null;
  let selectedRating = "note";
  let objectives = [];

  // ---- api helper -------------------------------------------------------- //
  async function api(path, method = "GET", body) {
    const res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch (e) { /* noop */ }
      throw new Error(detail);
    }
    return res.status === 204 ? null : res.json();
  }

  function toast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(t._timer);
    t._timer = setTimeout(() => (t.hidden = true), 2600);
  }

  // ---- theme ------------------------------------------------------------- //
  function initTheme() {
    let t = "dark";
    try { t = localStorage.getItem("gauntlet-theme") || "dark"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("gauntlet-theme", next); } catch (e) { /* noop */ }
    });
  }

  // ---- empty / setup ----------------------------------------------------- //
  async function loadHome() {
    $("console").hidden = true;
    $("emptyState").hidden = false;
    $("sessionMeta").hidden = true;
    ["btnPause", "btnResume", "btnVerify"].forEach((id) => ($(id).hidden = true));

    const [scenarios, sessions] = await Promise.all([
      api("/api/scenarios"),
      api("/api/sessions"),
    ]);

    const sel = $("scenarioSel");
    sel.innerHTML = "";
    scenarios.forEach((s) => {
      const o = document.createElement("option");
      o.value = s.id;
      o.textContent = `${s.name} · ${s.exercise_type}`;
      sel.appendChild(o);
    });

    if (scenarios.length) {
      $("emptySub").textContent = "Pick a scenario and brief the room, or resume a run below.";
      $("setupForm").hidden = false;
    } else {
      $("emptySub").textContent = "No scenarios found. Seed the database or author one via the API.";
    }

    const list = $("sessList");
    list.innerHTML = "";
    sessions.slice(0, 8).forEach((s) => {
      const li = document.createElement("li");
      li.innerHTML = `<span><b>${escapeHtml(s.name)}</b> · <span class="pill ${s.status}">${s.status}</span></span>`;
      const btn = document.createElement("button");
      btn.className = "btn ghost";
      btn.textContent = s.status === "complete" ? "Review" : "Resume";
      btn.onclick = () => openSession(s.id);
      li.appendChild(btn);
      list.appendChild(li);
    });
  }

  async function startNew() {
    const scenarioId = Number($("scenarioSel").value);
    const name = $("sessInput").value.trim() || "Untitled exercise";
    try {
      const sess = await api("/api/sessions", "POST", { scenario_id: scenarioId, name });
      await api(`/api/sessions/${sess.id}/start`, "POST");
      openSession(sess.id);
    } catch (e) { toast("Could not start: " + e.message); }
  }

  async function openSession(sid) {
    currentSid = sid;
    $("emptyState").hidden = true;
    $("console").hidden = false;
    $("sessionMeta").hidden = false;
    await loadState();
  }

  // ---- render running state ---------------------------------------------- //
  async function loadState() {
    const state = await api(`/api/sessions/${currentSid}`);
    render(state);
  }

  function render(state) {
    const { session, scenario, current_inject, available_branches, timeline, observations, terminal } = state;

    // top bar
    $("statusPill").textContent = session.status;
    $("statusPill").className = "pill " + session.status;
    $("sessName").textContent = session.name;
    $("clock").textContent = current_inject ? current_inject.clock || "T+00:00" : "—";
    $("btnPause").hidden = session.status !== "running";
    $("btnResume").hidden = session.status !== "paused";
    $("btnVerify").hidden = false;

    // left rail
    $("scnName").textContent = scenario.name;
    $("scnActor").textContent = scenario.threat_actor;

    // scene
    if (current_inject) {
      $("scenePanel").hidden = false;
      $("injChannel").textContent = current_inject.channel;
      $("injCode").textContent = current_inject.code;
      $("injClock").textContent = current_inject.clock;
      $("injTitle").textContent = current_inject.title;
      $("injNarrative").textContent = current_inject.narrative;
      $("injActions").innerHTML = (current_inject.expected_actions || [])
        .map((a) => `<li>${escapeHtml(a)}</li>`).join("");
      const maps = (current_inject.attack_techniques || []).map((t) => `<span class="tag">${t}</span>`).join("");
      const obj = current_inject.objective_code ? `<span class="tag obj">${current_inject.objective_code}</span>` : "";
      $("injMaps").innerHTML = maps + obj || '<span class="hint">—</span>';
    }

    // branches
    const branchWrap = $("branches");
    branchWrap.innerHTML = "";
    (available_branches || []).forEach((b) => {
      const el = document.createElement("button");
      el.className = "branch";
      el.innerHTML =
        `<span class="when ${b.when}">${(b.when || "").replace("_", " ")}</span>` +
        `<span class="lab">${escapeHtml(b.label || b.goto)}</span>` +
        `<span class="goto">${b.goto} →</span>`;
      el.onclick = () => advance(b.when, b.trigger || null, null);
      branchWrap.appendChild(el);
    });
    $("branchPanel").hidden = terminal || session.status === "complete";
    $("terminalNote").hidden = !terminal || session.status === "complete";

    // objectives (rail) + observation selector
    objectives = scenario_objectives_cache[scenario.id] || [];
    if (!objectives.length) fetchObjectives(scenario.id);
    else renderObjectives(observations);

    // environment summary (rail)
    fetchEnvOnce(scenario.id);

    // timeline
    const tl = $("timeline");
    tl.innerHTML = "";
    (timeline || []).slice().reverse().forEach((e) => {
      const li = document.createElement("li");
      li.className = "k-" + e.kind;
      li.innerHTML = `<span class="tclock">${e.game_clock || "--:--"}</span>${describeEvent(e)}`;
      tl.appendChild(li);
    });
  }

  const scenario_objectives_cache = {};
  const env_cache = {};

  async function fetchObjectives(scenarioId) {
    const scn = await api(`/api/scenarios/${scenarioId}`);
    scenario_objectives_cache[scenarioId] = scn.objectives;
    objectives = scn.objectives;
    $("scnRoe").textContent = scn.rules_of_engagement;
    renderObjectives();
  }

  function renderObjectives(observations = []) {
    const ratingByObj = {};
    observations.forEach((o) => {
      const rank = { missed: 3, partial: 2, met: 1, note: 0 };
      if ((rank[o.rating] || 0) >= (rank[ratingByObj[o.objective_code]] || 0)) {
        ratingByObj[o.objective_code] = o.rating;
      }
    });
    $("objList").innerHTML = objectives.map((o) => {
      const r = ratingByObj[o.code];
      const badge = r && r !== "note" ? ` <span class="tag">${r}</span>` : "";
      return `<li><b>${o.code}</b>${escapeHtml(o.title)}${badge}</li>`;
    }).join("");

    const sel = $("obsObj");
    sel.innerHTML = '<option value="">— general —</option>' +
      objectives.map((o) => `<option value="${o.code}">${o.code} · ${escapeHtml(o.title)}</option>`).join("");
  }

  async function fetchEnvOnce(scenarioId) {
    if (env_cache[scenarioId]) return renderEnv(env_cache[scenarioId]);
    const scn = await api(`/api/scenarios/${scenarioId}`);
    const env = await api(`/api/environments/${scn.environment_id}`);
    env_cache[scenarioId] = env;
    renderEnv(env);
  }

  function renderEnv(env) {
    const rows = [
      ["Name", env.name],
      ["Sector", env.sector],
      ["Box", env.box_type],
      ["Assets", (env.assets || []).length],
      ["Controls", (env.controls || []).length + (env.detections || []).length],
      ["Deception", (env.deception_assets || []).length],
    ];
    $("envSummary").innerHTML =
      rows.map(([k, v]) => `<div class="row"><span>${k}</span><span>${escapeHtml(String(v))}</span></div>`).join("") +
      `<div class="cj">Crown jewels: ${(env.crown_jewels || []).join(", ")}</div>`;
  }

  // ---- proctor actions --------------------------------------------------- //
  async function advance(when, trigger, goto) {
    try {
      await api(`/api/sessions/${currentSid}/advance`, "POST", { when, trigger, goto });
      await loadState();
    } catch (e) { toast(e.message); }
  }

  async function adjudicate() {
    const techniques = $("adjTech").value.split(",").map((t) => t.trim()).filter(Boolean);
    const target_asset = $("adjAsset").value.trim();
    try {
      const out = await api(`/api/sessions/${currentSid}/adjudicate`, "POST", { techniques, target_asset });
      renderRuling(out.ruling);
      await loadState();
    } catch (e) { toast(e.message); }
  }

  function renderRuling(r) {
    const box = $("rulingOut");
    box.hidden = false;
    box.className = "ruling " + (r.detected ? "detected" : "missed");
    const controls = (r.controls_hit || []).map((c) =>
      `<div class="c"><span>${escapeHtml(c.name)}${c.deception ? " ⚑" : ""}</span><span>p·eff ${c.efficacy}</span></div>`).join("");
    box.innerHTML =
      `<div class="verdict"><span class="${r.detected ? "v-detected" : "v-missed"}">${r.detected ? "DETECTED" : "MISSED"}</span>` +
      `<span>${r.time_to_detect_min != null ? r.time_to_detect_min + " min" : "—"}</span></div>` +
      `<div class="rationale">${escapeHtml(r.rationale)}</div>` +
      (controls ? `<div class="controls">${controls}</div>` : "");
  }

  async function observe() {
    const note = $("obsNote").value.trim();
    if (!note) return toast("Add a note first.");
    try {
      await api(`/api/sessions/${currentSid}/observe`, "POST", {
        objective_code: $("obsObj").value,
        rating: selectedRating,
        note,
      });
      $("obsNote").value = "";
      toast("Observation logged.");
      await loadState();
    } catch (e) { toast(e.message); }
  }

  async function setStatus(action) {
    try { await api(`/api/sessions/${currentSid}/${action}`, "POST"); await loadState(); }
    catch (e) { toast(e.message); }
  }

  async function verify() {
    const v = await api(`/api/sessions/${currentSid}/verify`);
    $("chainState").innerHTML = v.chain_valid
      ? `<span class="chainok">✓ chain intact · ${v.events} events</span>`
      : `<span class="chainbad">✗ chain broken</span>`;
    toast(v.chain_valid ? "Timeline verified — hash-chain intact." : "Timeline verification FAILED.");
  }

  async function generateReport(audience) {
    try {
      const rep = await api(`/api/sessions/${currentSid}/reports`, "POST", { audience });
      $("modalBody").innerHTML = renderMarkdown(rep.content);
      $("modal").hidden = false;
    } catch (e) { toast(e.message); }
  }

  // ---- helpers ----------------------------------------------------------- //
  function describeEvent(e) {
    const p = e.payload || {};
    switch (e.kind) {
      case "inject_fired": return `<b>${e.ref}</b> ${escapeHtml(p.title || "")}`;
      case "decision": return `Decision → ${escapeHtml(p.label || p.goto || "")}`;
      case "adjudication": return `Adjudication [<b>${p.detected ? "detected" : "missed"}</b>] ${escapeHtml(truncate(p.rationale, 90))}`;
      case "observation": return `Observation [${p.rating}] ${escapeHtml(truncate(p.note, 80))}`;
      case "note": return `Note — ${escapeHtml(truncate(p.text, 90))}`;
      case "status": return `Status → ${p.status}`;
      default: return e.kind;
    }
  }

  function truncate(s, n) { s = s || ""; return s.length > n ? s.slice(0, n) + "…" : s; }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // Minimal, safe markdown renderer for the report viewer.
  function renderMarkdown(md) {
    const lines = md.split("\n");
    let html = "", inTable = false, inList = false;
    const inline = (t) => escapeHtml(t)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+?)`/g, "<code>$1</code>")
      .replace(/_(.+?)_/g, "<em>$1</em>");
    const closeList = () => { if (inList) { html += "</ul>"; inList = false; } };
    const closeTable = () => { if (inTable) { html += "</tbody></table>"; inTable = false; } };

    for (const raw of lines) {
      const line = raw.trimEnd();
      if (/^\|.*\|$/.test(line)) {
        const cells = line.split("|").slice(1, -1).map((c) => c.trim());
        if (/^[-:\s|]+$/.test(line.replace(/\|/g, ""))) continue; // separator row
        if (!inTable) { closeList(); html += "<table><tbody>"; inTable = true; }
        const tag = "td";
        html += "<tr>" + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join("") + "</tr>";
        continue;
      }
      closeTable();
      if (/^#{1,3}\s/.test(line)) {
        closeList();
        const level = line.match(/^#+/)[0].length;
        html += `<h${level}>${inline(line.replace(/^#+\s/, ""))}</h${level}>`;
      } else if (/^>\s?/.test(line)) {
        closeList(); html += `<blockquote>${inline(line.replace(/^>\s?/, ""))}</blockquote>`;
      } else if (/^[-*]\s/.test(line)) {
        if (!inList) { html += "<ul>"; inList = true; }
        html += `<li>${inline(line.replace(/^[-*]\s/, ""))}</li>`;
      } else if (line === "") {
        closeList();
      } else {
        closeList(); html += `<p>${inline(line)}</p>`;
      }
    }
    closeList(); closeTable();
    return html;
  }

  // ---- wire up ----------------------------------------------------------- //
  function init() {
    initTheme();
    $("btnNew").addEventListener("click", loadHome);
    $("btnStart").addEventListener("click", startNew);
    $("btnAdjudicate").addEventListener("click", adjudicate);
    $("btnObserve").addEventListener("click", observe);
    $("btnOverride").addEventListener("click", () => {
      const goto = $("overrideGoto").value.trim();
      if (goto) advance("proctor_choice", null, goto);
    });
    $("btnPause").addEventListener("click", () => setStatus("pause"));
    $("btnResume").addEventListener("click", () => setStatus("resume"));
    $("btnComplete").addEventListener("click", () => setStatus("complete"));
    $("btnVerify").addEventListener("click", verify);
    $("modalX").addEventListener("click", () => ($("modal").hidden = true));
    $("modal").addEventListener("click", (e) => { if (e.target === $("modal")) $("modal").hidden = true; });

    $("obsRatings").querySelectorAll(".rating").forEach((b) => {
      b.addEventListener("click", () => {
        $("obsRatings").querySelectorAll(".rating").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        selectedRating = b.dataset.r;
      });
    });
    document.querySelectorAll(".report-btns .btn").forEach((b) =>
      b.addEventListener("click", () => generateReport(b.dataset.aud)));

    loadHome();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
