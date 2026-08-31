/* Gauntlet evaluator companion — observe a cell's fog-of-war view, log observations. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  let sessions = [];
  let scenarioCache = {};

  async function api(path, method = "GET", body) {
    const res = await fetch(path, {
      method, headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let d = res.statusText;
      try { d = (await res.json()).detail || d; } catch (e) { /* noop */ }
      throw new Error(d);
    }
    return res.status === 204 ? null : res.json();
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function toast(m) { const t = $("toast"); t.textContent = m; t.hidden = false; clearTimeout(t._t); t._t = setTimeout(() => (t.hidden = true), 2400); }

  function initTheme() {
    let t = "dark"; try { t = localStorage.getItem("gauntlet-theme") || "dark"; } catch (e) { /* noop */ }
    document.documentElement.setAttribute("data-theme", t);
    $("btnTheme").addEventListener("click", () => {
      const n = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", n);
      try { localStorage.setItem("gauntlet-theme", n); } catch (e) { /* noop */ }
    });
  }

  async function loadSessions() {
    sessions = await api("/api/sessions");
    $("sessionSel").innerHTML = sessions.length
      ? sessions.map((s) => `<option value="${s.id}">${esc(s.name)} · ${s.status}</option>`).join("")
      : '<option value="">no sessions yet</option>';
    if (sessions.length) await onSessionChange();
  }

  async function scenarioFor(session) {
    if (!scenarioCache[session.scenario_id]) {
      scenarioCache[session.scenario_id] = await api(`/api/scenarios/${session.scenario_id}`);
    }
    return scenarioCache[session.scenario_id];
  }

  async function onSessionChange() {
    const sid = Number($("sessionSel").value);
    const session = sessions.find((s) => s.id === sid);
    if (!session) return;
    const scn = await scenarioFor(session);
    const cells = scn.cells && scn.cells.length ? scn.cells
      : [{ key: "white_cell", name: "White Cell" }, { key: "blue_cell", name: "Blue Cell" }];
    $("cellSel").innerHTML = cells
      .map((c) => `<option value="${c.key}">${esc(c.name)}</option>`).join("");
    // Default to observing the participant cell if present.
    const blue = cells.find((c) => c.kind === "participant");
    if (blue) $("cellSel").value = blue.key;
    await loadView();
  }

  async function loadView() {
    const sid = Number($("sessionSel").value);
    const cell = $("cellSel").value;
    if (!sid || !cell) return;
    const view = await api(`/api/sessions/${sid}/cell/${cell}`);

    const fog = $("fogPill");
    fog.hidden = false;
    fog.textContent = view.can_see_all ? "sees all (control)" : "fog of war";
    fog.className = "pill " + (view.can_see_all ? "complete" : "paused");
    $("fogHint").textContent = view.can_see_all
      ? "This is a control cell — full visibility."
      : "Redacted to what this cell was shown.";

    renderScene(view.current_inject);
    renderTimeline(view.timeline);
    renderObjectives(view.objectives, sid);
  }

  function renderScene(inj) {
    const box = $("cellScene");
    if (!inj) { box.innerHTML = '<p class="muted">No inject is currently addressed to this cell.</p>'; return; }
    box.innerHTML =
      `<div class="scene-head"><span class="chan">${esc(inj.channel)}</span>` +
      `<span class="code">${esc(inj.code)}</span><span class="gc">${esc(inj.clock)}</span></div>` +
      `<h2 style="font-size:1.1rem;margin:.2rem 0 .4rem">${esc(inj.title)}</h2>` +
      `<p class="muted" style="font-size:.88rem">${esc(inj.narrative)}</p>`;
  }

  function renderTimeline(events) {
    $("cellTimeline").innerHTML = events.slice().reverse().map((e) => {
      const p = e.payload || {};
      let text = e.kind;
      if (e.kind === "inject_fired") text = `<b>${esc(e.ref)}</b> ${esc(p.title || "")}`;
      else if (e.kind === "status") text = `Status → ${esc(p.status || "")}`;
      return `<li class="k-${e.kind}"><span class="tclock">${esc(e.game_clock || "--:--")}</span>${text}</li>`;
    }).join("") || '<li class="muted">Nothing visible to this cell yet.</li>';
  }

  function renderObjectives(objectives, sid) {
    const wrap = $("evalObjectives");
    wrap.innerHTML = `<div class="panel"><p class="eyebrow">Objectives &amp; evaluation guide</p>
      <p class="hint">Rate each objective as you observe the cell; notes are logged to the exercise timeline.</p></div>` +
      objectives.map((o) => {
        const eeg = (o.eeg || []).map((q) => `<li>${esc(q)}</li>`).join("");
        return `<div class="panel eval-obj" data-obj="${esc(o.code)}">
          <div class="eval-obj-head"><span class="obj-code">${esc(o.code)}</span><b>${esc(o.title)}</b></div>
          ${o.success_criteria ? `<p class="hint" style="margin:.2rem 0 .5rem">Success: ${esc(o.success_criteria)}</p>` : ""}
          ${eeg ? `<ul class="eeg">${eeg}</ul>` : ""}
          <div class="ratings">
            <button class="rating" data-r="met">Met</button>
            <button class="rating" data-r="partial">Partial</button>
            <button class="rating" data-r="missed">Missed</button>
          </div>
          <div class="eval-note"><input type="text" placeholder="Observation…"><button class="btn small">Log</button></div>
        </div>`;
      }).join("");

    wrap.querySelectorAll(".eval-obj").forEach((card) => {
      let rating = "met";
      card.querySelectorAll(".rating").forEach((b) => b.addEventListener("click", () => {
        card.querySelectorAll(".rating").forEach((x) => x.classList.remove("active"));
        b.classList.add("active"); rating = b.dataset.r;
      }));
      const input = card.querySelector(".eval-note input");
      card.querySelector(".eval-note .btn").addEventListener("click", async () => {
        const note = input.value.trim();
        if (!note) return toast("Add a note.");
        try {
          await api(`/api/sessions/${sid}/observe`, "POST",
            { objective_code: card.dataset.obj, rating, note });
          input.value = ""; toast(`Logged for ${card.dataset.obj}.`);
        } catch (e) { toast(e.message); }
      });
    });
  }

  function init() {
    initTheme();
    $("sessionSel").addEventListener("change", onSessionChange);
    $("cellSel").addEventListener("change", loadView);
    $("btnRefresh").addEventListener("click", loadView);
    loadSessions();
  }
  document.addEventListener("DOMContentLoaded", init);
})();
