let SIEGE = {};  // populated from /api/bootstrap at boot

/* ── Static metadata ──────────────────────────────────────────── */
const OBJ_ICONS = {
  initial_foothold:'M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z',
  domain_admin:'M12 2l7 4v6c0 4-3 7.5-7 10-4-2.5-7-6-7-10V6z',
  data_exfiltration:'M4 7h16M4 12h10M4 17h7M20 14l-4 4 4 4M22 18h-8',
  ransomware_simulation:'M5 11h14v10H5zM8 11V8a4 4 0 018 0v3M12 15v3',
  cloud_takeover:'M6 16a4 4 0 010-8 6 6 0 0111-2 4 4 0 011 8H6zM12 12v4M10 14h4',
  email_compromise:'M3 6h18v12H3zM3 6l9 7 9-7',
};
const OBJ_DESC = {
  initial_foothold:'First code execution on a host inside scope.',
  domain_admin:'Domain-wide privileged control of Active Directory.',
  data_exfiltration:'Demonstrate exfiltration of sensitive data.',
  ransomware_simulation:'Show impact reach with reversible, signed-off actions.',
  cloud_takeover:'Tenant / cloud administrator control.',
  email_compromise:'Access to target mailboxes and messaging.',
};
const BOX_DESC = {
  black:'No prior knowledge. Start from the public edge.',
  grey:'Partial knowledge — usually a low-privilege foothold.',
  white:'Full knowledge, source, and standing access.',
};
const TACTIC_LABEL = {
  'reconnaissance':'Reconnaissance','resource-development':'Resource Dev','initial-access':'Initial Access',
  'execution':'Execution','persistence':'Persistence','privilege-escalation':'Privilege Escalation',
  'defense-evasion':'Defense Evasion','credential-access':'Credential Access','discovery':'Discovery',
  'lateral-movement':'Lateral Movement','collection':'Collection','command-and-control':'C2',
  'exfiltration':'Exfiltration','impact':'Impact',
};
const TACTIC_COLOR = {
  'reconnaissance':'#6B7F8C','initial-access':'#9C3B2E','execution':'#A9822C','persistence':'#7A6A9C',
  'privilege-escalation':'#B06A2E','defense-evasion':'#7C6A55','credential-access':'#4E7C6B',
  'discovery':'#3C5A6B','lateral-movement':'#8A6D3B','collection':'#5E6B2C',
  'command-and-control':'#6B5B41','exfiltration':'#97362A','impact':'#5A3A3A',
};
const OUTCOMES = ['attempted','succeeded','fell_back','failed','blocked','skipped'];
const OUTCOME_LABEL = {attempted:'Attempted',succeeded:'Succeeded',fell_back:'Fell back',
  failed:'Failed',blocked:'Blocked',skipped:'Skipped',not_started:'Not started'};


/* ── State ────────────────────────────────────────────────────── */
const state = {
  view:'home', authorized:false,
  objective:'domain_admin', box:'grey',
  platforms:new Set(['windows','active_directory']), restrictions:new Set(),
  plan:[], logs:{}, open:new Set(), seededFrom:null, palFilter:'', engagementId:null, status:'active',
};
let _uid = 1; const uid = () => 's' + (_uid++);
const PB = {}; (SIEGE.playbook||[]).forEach(p => PB[p.technique_id] = p);

/* Per-step documentation records. logs[uid] = {outcome, operator, notes, evidence[], targets[], startedAt, completedAt} */
const RESOLVED = new Set(['succeeded','fell_back','failed','blocked','skipped']);
const BAD = new Set(['failed','blocked']);
function ensureLog(u){ if(!state.logs[u]) state.logs[u]={outcome:undefined,operator:'',notes:'',evidence:[],targets:[],startedAt:null,completedAt:null}; return state.logs[u]; }
function outcomeOf(u){ return state.logs[u] ? state.logs[u].outcome : undefined; }
function nowStamp(){ return new Date().toISOString().slice(0,16).replace('T',' '); }

const $ = s => document.querySelector(s);
const el = (t,c,h)=>{const e=document.createElement(t); if(c)e.className=c; if(h!=null)e.innerHTML=h; return e;};
const svg = p => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="${p}"/></svg>`;
const titleCase = s => (s||'').replace(/[_-]/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
// Escape for HTML text AND attribute contexts (quotes included).
const esc = s => String(s==null?'':s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const currentResult = () => SIEGE.results[`${state.objective}|${state.box}`];

/* ── Auth / API layer ─────────────────────────────────────────── */
let AUTH_TOKEN = null;
try { AUTH_TOKEN = sessionStorage.getItem('siege_token'); } catch (e) {}
let CURRENT_USER = null;

function setToken(t){
  AUTH_TOKEN = t;
  try { t ? sessionStorage.setItem('siege_token', t) : sessionStorage.removeItem('siege_token'); } catch (e) {}
}

// Every API call goes through here: attaches the bearer token, sets JSON
// content-type, and bounces to the login screen on 401.
async function api(path, opts){
  opts = opts || {};
  const headers = Object.assign({}, opts.headers || {});
  if (AUTH_TOKEN) headers['Authorization'] = 'Bearer ' + AUTH_TOKEN;
  // Don't force JSON on FormData — the browser must set the multipart boundary.
  const isForm = (typeof FormData !== 'undefined') && (opts.body instanceof FormData);
  if (opts.body && !isForm && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401){ setToken(null); CURRENT_USER = null; showLogin(); throw new Error('unauthorized'); }
  return res;
}

/* ── Theme (light / dark) ─────────────────────────────────────── */
function currentTheme(){ try { return localStorage.getItem('siege_theme') || 'light'; } catch(e){ return 'light'; } }
function applyTheme(t){
  if (t === 'dark') document.documentElement.setAttribute('data-theme','dark');
  else document.documentElement.removeAttribute('data-theme');
  const btn = document.querySelector('#themeToggle');
  if (btn) btn.textContent = (t === 'dark') ? '☀' : '☾';
}
function toggleTheme(){
  const t = (currentTheme() === 'dark') ? 'light' : 'dark';
  try { localStorage.setItem('siege_theme', t); } catch(e){}
  applyTheme(t);
}
applyTheme(currentTheme());  // apply immediately, including on the login screen

/* ── Intake ───────────────────────────────────────────────────── */
function buildIntake(){
  const ot=$('#objTiles'); ot.innerHTML='';
  SIEGE.reference.objectives.forEach(o=>{
    const t=el('button','tile'); t.setAttribute('aria-pressed',o.value===state.objective); t.dataset.v=o.value;
    t.innerHTML=`<span class="tick">${svg('M20 6L9 17l-5-5')}</span>
      <div class="ti"><span class="ic"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="${OBJ_ICONS[o.value]||''}"/></svg></span><h3>${o.label}</h3></div>
      <p>${OBJ_DESC[o.value]||''}</p>`;
    t.onclick=()=>{state.objective=o.value; [...ot.children].forEach(c=>c.setAttribute('aria-pressed',c.dataset.v===o.value)); syncChips();};
    ot.appendChild(t);
  });
  const bt=$('#boxTiles'); bt.innerHTML='';
  SIEGE.reference.box_types.forEach(b=>{
    const t=el('button','tile'); t.setAttribute('aria-pressed',b.value===state.box); t.dataset.v=b.value;
    t.innerHTML=`<span class="tick">${svg('M20 6L9 17l-5-5')}</span><span class="box-k">${b.value}-box</span><h3>${b.label}</h3><p>${BOX_DESC[b.value]||''}</p>`;
    t.onclick=()=>{state.box=b.value; [...bt.children].forEach(c=>c.setAttribute('aria-pressed',c.dataset.v===b.value)); syncChips();};
    bt.appendChild(t);
  });
  const pc=$('#platChips'); pc.innerHTML='';
  SIEGE.reference.platforms.forEach(p=>{
    const c=el('button','mchip'); c.setAttribute('aria-pressed',state.platforms.has(p.value));
    c.innerHTML=`<span class="dot"></span>${p.label}`;
    c.onclick=()=>{state.platforms.has(p.value)?state.platforms.delete(p.value):state.platforms.add(p.value); c.setAttribute('aria-pressed',state.platforms.has(p.value)); syncChips();};
    pc.appendChild(c);
  });
  const rc=$('#restChips'); rc.innerHTML='';
  SIEGE.reference.restrictions.forEach(r=>{
    const c=el('button','mchip'); c.setAttribute('aria-pressed',state.restrictions.has(r.value));
    c.innerHTML=`<span class="dot"></span>${r.label}`;
    c.onclick=()=>{state.restrictions.has(r.value)?state.restrictions.delete(r.value):state.restrictions.add(r.value); c.setAttribute('aria-pressed',state.restrictions.has(r.value)); syncChips();};
    rc.appendChild(c);
  });
  $('#railTech').textContent=SIEGE.playbook_stats.total; $('#heroTech').textContent=SIEGE.playbook_stats.total;
  const pm=SIEGE.playbook_meta;
  if(pm){ const a=$('#heroAttack'), l=$('#heroPlaybook');
    if(a) a.textContent='v'+esc(pm.attack_version);
    if(l) l.textContent='ATT&CK · playbook v'+esc(pm.playbook_version); }
}
function syncChips(){
  $('#tbTitle').textContent=$('#fName').value||'New engagement';
  $('#tbSub').textContent=`${titleCase(state.objective)} · ${titleCase(state.box)}-box`;
  const chips=$('#tbChips'); chips.innerHTML='';
  chips.appendChild(el('span','chip accent',`<span class="k">Objective</span>${titleCase(state.objective)}`));
  chips.appendChild(el('span','chip',`<span class="k">Box</span>${titleCase(state.box)}`));
  if(state.platforms.size) chips.appendChild(el('span','chip',`<span class="k">Scope</span>${state.platforms.size} platform${state.platforms.size>1?'s':''}`));
}

/* ── Recommended plans ────────────────────────────────────────── */
function segMeter(val,max,cls){let h=`<div class="seg ${cls||''}">`;for(let i=1;i<=max;i++)h+=`<i class="${i<=Math.round(val)?'on':''}"></i>`;return h+'</div>';}
function buildPlans(){
  const res=currentResult(); $('#stepPlans').disabled=false; $('#stepBuild').disabled=false;
  const objLabel=titleCase(state.objective);
  $('#plansLead').textContent=res.options.length
    ? `${res.options.length} legal approaches reach ${objLabel.toLowerCase()} from a ${state.box}-box start, ranked by fit to your ROE. Open one in the builder to customize it, or build your own from the library.`
    : `No legal path reaches ${objLabel.toLowerCase()} under these constraints.`;
  $('#plansNote').textContent=res.excluded_count?`${res.excluded_count} techniques excluded by your ROE.`:'';
  $('#tbSub').textContent=`${objLabel} · ${titleCase(state.box)}-box · ${res.options.length} plan${res.options.length!==1?'s':''}`;
  const grid=$('#planGrid'); grid.innerHTML='';
  const budget=parseFloat($('#fBudget').value)||null;
  res.options.forEach((o,i)=>{
    const hrs=o.est_total_minutes/60, over=budget&&hrs>budget;
    const card=el('div','plan');
    const tacts=o.covered_tactics.map(t=>`<span class="tact">${TACTIC_LABEL[t]||t}</span>`).join('');
    const bpct=budget?Math.min(100,hrs/budget*100):Math.min(100,hrs/48*100);
    card.innerHTML=`
      <div class="plan-top"><div class="medal" style="--p:${o.fit_score}"><span class="v tnum">${Math.round(o.fit_score)}</span></div>
        <div><div class="rank">Rank ${i+1} · fit ${o.fit_score}</div><h3>${o.title}</h3></div></div>
      <div class="tacts">${tacts}</div>
      <p class="why">${o.rationale[0]||''}</p>
      <div class="meters">
        <div class="meter"><span class="ml">Time</span><div class="bar ${over?'over':''}"><span style="width:${bpct}%"></span></div><span class="mv">${hrs.toFixed(1)}h${budget?` / ${budget}`:''}</span></div>
        <div class="meter"><span class="ml">Stealth</span>${segMeter(6-o.aggregate_noise,5,'')}<span class="mv">noise ${o.aggregate_noise.toFixed(1)}</span></div>
        <div class="meter"><span class="ml">Difficulty</span>${segMeter(o.max_difficulty,5,o.max_difficulty>=4?'crit':(o.max_difficulty>=3?'warn':''))}<span class="mv">${o.max_difficulty}/5</span></div>
      </div>
      <div class="plan-foot"><span class="steps">${o.steps.length} steps · ${o.covered_tactics.length} tactics</span>
        <span class="go">Open in builder ${svg('M5 12h14M13 6l6 6-6 6')}</span></div>`;
    card.onclick=()=>openBuilderFromOption(o);
    grid.appendChild(card);
  });
}

/* ── Builder ──────────────────────────────────────────────────── */
function openBuilderFromOption(o){
  state.engagementId=null; state.plan=o.steps.map(s=>({uid:uid(),tid:s.technique_id}));
  state.logs={}; state.open=new Set(state.plan.length?[state.plan[0].uid]:[]); state.seededFrom=o.title;
  enterBuild(`Seeded from “${o.title}” — rearrange, add, or trim as you see fit.`);
}
function openBuilderScratch(){
  state.engagementId=null; state.plan=[]; state.logs={}; state.open=new Set(); state.seededFrom=null;
  enterBuild('Empty board — drag pieces from the library to build your line of march.');
}
function enterBuild(note){
  $('#stepPlans').disabled=false; $('#stepBuild').disabled=false;
  $('#buildNote').textContent=note||''; state.palFilter='';
  const s=$('#palSearch'); if(s) s.value='';
  renderPalette(); renderBoard(); updateSummary(); go('build');
}
function pieceIn(tid){return state.plan.some(x=>x.tid===tid);}

function renderPalette(){
  const list=$('#palList'); list.innerHTML=''; const f=state.palFilter.toLowerCase();
  (SIEGE.tactic_order||[]).forEach(tac=>{
    const pieces=SIEGE.playbook.filter(p=>p.tactic===tac).filter(p=>{
      if(!f) return true;
      return (p.technique_id+' '+p.name+' '+TACTIC_LABEL[p.tactic]+' '+(p.recommended_tools||[]).join(' ')).toLowerCase().includes(f);
    });
    if(!pieces.length) return;
    const g=el('div','pal-group'); g.innerHTML=`<h4><span class="tc" style="background:${TACTIC_COLOR[tac]}"></span>${TACTIC_LABEL[tac]||tac} · ${pieces.length}</h4>`;
    pieces.forEach(p=>{
      const pc=el('div','pal-piece'+(pieceIn(p.technique_id)?' placed':'')); pc.draggable=true; pc.dataset.tid=p.technique_id;
      pc.innerHTML=`<span class="grip">${svg('M9 5h.01M9 12h.01M9 19h.01M15 5h.01M15 12h.01M15 19h.01')}</span>
        <div class="pp-main"><div class="pp-id">${p.technique_id}</div><div class="pp-name">${p.name}</div>
        <div class="pp-meta">${(p.recommended_tools||[]).slice(0,2).join(', ')||'—'} · ${Math.round(p.est_minutes)}m</div></div>
        <button class="add" title="Add to plan" aria-label="Add ${p.name}">${svg('M12 5v14M5 12h14')}</button>`;
      pc.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/plain','palette:'+p.technique_id); e.dataTransfer.effectAllowed='copy';});
      pc.querySelector('.add').onclick=e=>{e.stopPropagation(); addPiece(p.technique_id);};
      pc.onclick=()=>addPiece(p.technique_id);
      g.appendChild(pc);
    });
    list.appendChild(g);
  });
  if(!list.children.length) list.innerHTML='<div class="pal-group"><p style="color:var(--ink-faint);font-size:13px;padding:10px 6px">No techniques match your search.</p></div>';
}

function renderBoard(){
  const board=$('#board'); board.innerHTML='';
  if(!state.plan.length){
    board.innerHTML=`<div class="dropzone-empty">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3v18M3 12h18" stroke-dasharray="2 2"/><rect x="7" y="7" width="10" height="10" rx="2"/></svg>
      <div class="t">Lay out your line of march</div>
      <div class="s">Drag pieces from the library, or click a piece to place it here.</div></div>`;
    return;
  }
  state.plan.forEach((slot,i)=>board.appendChild(slotEl(slot,i)));
}
function slotEl(slot,i){
  const p=PB[slot.tid]; const open=state.open.has(slot.uid);
  const node=el('div','slot'+(open?' open':'')); node.dataset.uid=slot.uid;
  const col=TACTIC_COLOR[p.tactic]||'#8A6D3B';
  const tools=(p.recommended_tools||[]).map(t=>`<span class="toolchip">${t}</span>`).join('')||'—';
  const acts=(p.steps||[]).map((a,ix)=>`<li><span class="an tnum">${ix+1}</span><div><div class="at">${a.action}</div><div class="ax">→ ${a.expected_result}</div></div></li>`).join('');
  const fbs=(p.fallback_technique_ids||[]).map(f=>`<span class="fb">${f}</span>`).join('')||'—';
  const gains=(p.provides||[]).map(g=>`<span class="pill good">${svg('M20 6L9 17l-5-5')}${g}</span>`).join('')||'—';
  node.innerHTML=`
    <span class="stripe" style="background:${col}"></span>
    <div class="slot-head">
      <span class="snum tnum">${i+1}</span>
      <div class="slot-main">
        <div class="st-top"><span class="tid">${p.technique_id}</span>
          <span class="pieceflag" style="background:${col}">${TACTIC_LABEL[p.tactic]||p.tactic}</span></div>
        <h3>${p.name}</h3><div class="ss">${p.summary}</div>
      </div>
      <div class="slot-ctl">
        <button class="drag-handle" draggable="true" title="Drag to reorder" aria-label="Drag to reorder">${svg('M9 5h.01M9 12h.01M9 19h.01M15 5h.01M15 12h.01M15 19h.01')}</button>
        <button class="mv-up" title="Move up" aria-label="Move up">${svg('M18 15l-6-6-6 6')}</button>
        <button class="mv-dn" title="Move down" aria-label="Move down">${svg('M6 9l6 6 6-6')}</button>
        <button class="rm" title="Remove" aria-label="Remove">${svg('M6 6l12 12M18 6L6 18')}</button>
        <button class="exp" title="Details" aria-label="Toggle details"><span class="chev">${svg('M6 9l6 6 6-6')}</span></button>
      </div>
    </div>
    <div class="slot-body">
      <div class="nb-grid">
        <div>
          <div class="nb-block"><div class="bh">Objective</div><div class="rv" style="font-size:13.5px;color:var(--ink-soft)">${p.objective||'—'}</div></div>
          <div class="nb-block" style="margin-top:16px"><div class="bh">Actions</div><ul class="actions-list">${acts}</ul></div>
        </div>
        <div class="kv">
          <div class="nb-block"><div class="bh">Suggested tools</div><div class="toolchips">${tools}</div></div>
          <div class="row"><div class="rk">Prerequisite</div><div class="rv">${p.prerequisite_note||'—'}</div></div>
          <div class="row"><div class="rk">Success indicator</div><div class="rv">${p.success_indicator||'—'}</div></div>
          <div class="row"><div class="rk">If it fails, fall back to</div><div class="fallbacks">${fbs}</div></div>
          <div class="row"><div class="rk">Blue-team detection</div><div class="rv">${p.detection||'—'}</div></div>
          <div class="row"><div class="rk">Gains</div><div class="toolchips">${gains}</div></div>
        </div>
      </div>
    </div>`;
  node.querySelector('.exp').onclick=()=>{open?state.open.delete(slot.uid):state.open.add(slot.uid); node.classList.toggle('open');};
  node.querySelector('.rm').onclick=()=>removeSlot(slot.uid);
  node.querySelector('.mv-up').onclick=()=>moveSlot(slot.uid,-1);
  node.querySelector('.mv-dn').onclick=()=>moveSlot(slot.uid,1);
  const h=node.querySelector('.drag-handle');
  h.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/plain','track:'+slot.uid); e.dataTransfer.effectAllowed='move'; node.classList.add('dragging');});
  h.addEventListener('dragend',()=>node.classList.remove('dragging'));
  return node;
}
function addPiece(tid){ state.plan.push({uid:uid(),tid}); afterPlanChange(); }
function insertPiece(tid,idx){ state.plan.splice(idx,0,{uid:uid(),tid}); afterPlanChange(); }
function removeSlot(u){ state.plan=state.plan.filter(s=>s.uid!==u); delete state.logs[u]; state.open.delete(u); afterPlanChange(); }
function moveSlot(u,dir){ const i=state.plan.findIndex(s=>s.uid===u); const j=i+dir; if(j<0||j>=state.plan.length) return;
  [state.plan[i],state.plan[j]]=[state.plan[j],state.plan[i]]; afterPlanChange(); }
function moveTo(u,idx){ const i=state.plan.findIndex(s=>s.uid===u); if(i<0) return; const [it]=state.plan.splice(i,1);
  if(idx>i) idx--; state.plan.splice(Math.max(0,Math.min(idx,state.plan.length)),0,it); afterPlanChange(); }
function afterPlanChange(){ renderBoard(); renderPalette(); updateSummary(); }
function updateSummary(){
  const n=state.plan.length;
  const mins=state.plan.reduce((a,s)=>a+(PB[s.tid]?PB[s.tid].est_minutes:0),0);
  const tacts=new Set(state.plan.map(s=>PB[s.tid]&&PB[s.tid].tactic)); tacts.delete(undefined);
  $('#sbSteps').textContent=n; $('#sbTime').textContent=(mins/60).toFixed(1)+'h'; $('#sbTactics').textContent=tacts.size;
  const cb=$('#confirmBtn'); if(cb) cb.disabled = n===0;
}

/* ── Execution screen (run & document) ────────────────────────── */
function confirmPlan(){
  if(!state.plan.length) return;
  state.confirmed=true; $('#stepExecute').disabled=false;
  let i=state.plan.findIndex(s=>!RESOLVED.has(outcomeOf(s.uid)));
  state.execIndex = i<0 ? 0 : i;
  renderExecute(); go('execute');
}
function renderExecute(){
  $('#execTitle').textContent = ($('#fName').value||'Execute the plan');
  renderExecRail(); renderExecPanel(); updateExecProgress();
}
function updateExecProgress(){
  const n=state.plan.length, done=state.plan.filter(s=>RESOLVED.has(outcomeOf(s.uid))).length;
  const pct=n?Math.round(100*done/n):0;
  $('#execPct').textContent=pct+'%'; $('#execProgBar').style.width=pct+'%';
  $('#execStepLbl').textContent=`Step ${Math.min(state.execIndex+1,n)} of ${n}`;
  $('#execSub').textContent=`${done} of ${n} steps resolved`;
}
function renderExecRail(){
  const rail=$('#execRail'); rail.innerHTML='';
  state.plan.forEach((s,i)=>{
    const p=PB[s.tid], oc=outcomeOf(s.uid), res=RESOLVED.has(oc);
    const r=el('div','ex-step'+(i===state.execIndex?' cur':'')+(res?' resolved':'')+(BAD.has(oc)?' bad':''));
    r.innerHTML=`<span class="stripe2" style="background:${TACTIC_COLOR[p.tactic]||'#8A6D3B'}"></span>
      <span class="exd tnum">${res?(BAD.has(oc)?'✕':'✓'):(i+1)}</span>
      <span class="exi"><span class="en">${p.name}</span>
      <span class="em"><span>${p.technique_id}</span><span>· ${oc?OUTCOME_LABEL[oc]:'pending'}</span></span></span>`;
    r.onclick=()=>{ state.execIndex=i; renderExecute(); };
    rail.appendChild(r);
  });
}
function renderExecPanel(){
  const panel=$('#execPanel'), n=state.plan.length;
  if(!n){ panel.innerHTML='<div class="ex-body"><p style="color:var(--ink-faint)">No steps in the plan. Go back to the builder and add pieces.</p></div>'; return; }
  const slot=state.plan[state.execIndex], p=PB[slot.tid], l=ensureLog(slot.uid), col=TACTIC_COLOR[p.tactic]||'#8A6D3B';
  const tools=(p.recommended_tools||[]).map(t=>`<span class="toolchip">${t}</span>`).join('')||'—';
  const acts=(p.steps||[]).map((a,ix)=>`<li><span class="an tnum">${ix+1}</span><div><div class="at">${a.action}</div><div class="ax">→ ${a.expected_result}</div></div></li>`).join('');
  const fbs=(p.fallback_technique_ids||[]).map(f=>`<span class="fb">${f}</span>`).join('')||'—';
  const ev=l.evidence.map((x,ix)=>`<span class="tagchip">${esc(x)}<button data-ev="${ix}" aria-label="Remove">${svg('M6 6l12 12M18 6L6 18')}</button></span>`).join('');
  const tg=l.targets.map((x,ix)=>`<span class="tagchip">${esc(x)}<button data-tg="${ix}" aria-label="Remove">${svg('M6 6l12 12M18 6L6 18')}</button></span>`).join('');
  panel.innerHTML=`
    <div class="xp-head"><span class="xnum tnum" style="border-color:${col};color:${col}">${state.execIndex+1}</span>
      <div><div class="xh-top"><span class="tid">${p.technique_id}</span><span class="pieceflag" style="background:${col}">${TACTIC_LABEL[p.tactic]||p.tactic}</span></div>
      <h2>${p.name}</h2></div></div>
    <div class="ex-body">
      <div class="brief">
        <div>
          <div class="nb-block"><div class="bh">Objective</div><div class="rv" style="font-size:13.5px;color:var(--ink-soft)">${p.objective||'—'}</div></div>
          <div class="nb-block" style="margin-top:15px"><div class="bh">Actions</div><ul class="actions-list">${acts}</ul></div>
          <div class="nb-block" style="margin-top:15px"><div class="bh">Success indicator</div><div class="rv" style="font-size:13px;color:var(--ink-soft)">${p.success_indicator||'—'}</div></div>
        </div>
        <div class="kv">
          <div class="nb-block"><div class="bh">Suggested tools</div><div class="toolchips">${tools}</div></div>
          <div class="row"><div class="rk">If it fails, fall back to</div><div class="fallbacks">${fbs}</div></div>
          <div class="row"><div class="rk">Blue-team detection</div><div class="rv">${p.detection||'—'}</div></div>
        </div>
      </div>
      <div class="doc-form">
        <div class="df-h">${svg('M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z')} Document this step</div>
        <div class="dfield"><label>Outcome</label>
          <div class="oc-choice">${OUTCOMES.map(o=>`<button class="oc-btn" data-oc="${o}" aria-pressed="${l.outcome===o}">${OUTCOME_LABEL[o]}</button>`).join('')}</div></div>
        <div class="stamp-row dfield">
          <div class="stamp"><div class="sl">Started</div><div class="sv"><span id="tsStart">${l.startedAt||'—'}</span><button id="btnStart" type="button">stamp now</button></div></div>
          <div class="stamp"><div class="sl">Completed</div><div class="sv"><span id="tsDone">${l.completedAt||'—'}</span><button id="btnDone" type="button">stamp now</button></div></div>
        </div>
        <div class="dfield"><label>Operator</label><input id="dOperator" value="${esc(l.operator)}" placeholder="Who ran this step" autocomplete="off"></div>
        <div class="dfield"><label>Notes — what happened</label><textarea id="dNotes" rows="3" placeholder="Observations, what worked, deviations…">${esc(l.notes)}</textarea></div>
        <div class="dfield"><label>Evidence references</label><div class="tagline" id="evLine">${ev}</div>
          <div class="tag-add"><input id="evIn" placeholder="filename, ticket id, screenshot ref…" autocomplete="off"><button id="evAdd" type="button">Add</button></div></div>
        <div class="dfield"><label>Targets touched</label><div class="tagline" id="tgLine">${tg}</div>
          <div class="tag-add"><input id="tgIn" placeholder="host / IP you noted" autocomplete="off"><button id="tgAdd" type="button">Add</button></div></div>
      </div>
      <div class="followups" id="followups" hidden></div>
      <div class="exec-nav">
        <button class="btn btn-ghost" id="prevStep" ${state.execIndex===0?'disabled':''}>${svg('M19 12H5M11 6l-6 6 6 6')} Previous</button>
        <span class="spacer"></span>
        <button class="btn btn-primary" id="nextStep">${state.execIndex>=n-1?'Finish &amp; report':'Save &amp; next step'} ${svg('M5 12h14M13 6l6 6-6 6')}</button>
      </div>
    </div>`;
  panel.querySelectorAll('.oc-btn').forEach(b=>b.onclick=()=>{
    l.outcome=(l.outcome===b.dataset.oc)?undefined:b.dataset.oc;
    panel.querySelectorAll('.oc-btn').forEach(x=>x.setAttribute('aria-pressed',x.dataset.oc===l.outcome));
    renderExecRail(); updateExecProgress(); renderFollowups();
  });
  $('#btnStart').onclick=()=>{ l.startedAt=nowStamp(); $('#tsStart').textContent=l.startedAt; };
  $('#btnDone').onclick=()=>{ l.completedAt=nowStamp(); $('#tsDone').textContent=l.completedAt; };
  $('#dOperator').oninput=e=>l.operator=e.target.value;
  $('#dNotes').oninput=e=>l.notes=e.target.value;
  $('#evAdd').onclick=()=>{ const v=$('#evIn').value.trim(); if(v){ l.evidence.push(v); renderExecPanel(); } };
  $('#tgAdd').onclick=()=>{ const v=$('#tgIn').value.trim(); if(v){ l.targets.push(v); renderExecPanel(); } };
  $('#evIn').onkeydown=e=>{ if(e.key==='Enter'){ e.preventDefault(); $('#evAdd').click(); } };
  $('#tgIn').onkeydown=e=>{ if(e.key==='Enter'){ e.preventDefault(); $('#tgAdd').click(); } };
  panel.querySelectorAll('[data-ev]').forEach(b=>b.onclick=()=>{ l.evidence.splice(+b.dataset.ev,1); renderExecPanel(); });
  panel.querySelectorAll('[data-tg]').forEach(b=>b.onclick=()=>{ l.targets.splice(+b.dataset.tg,1); renderExecPanel(); });
  $('#prevStep').onclick=()=>{ if(state.execIndex>0){ state.execIndex--; renderExecute(); } };
  $('#nextStep').onclick=()=>{ if(state.execIndex<n-1){ state.execIndex++; renderExecute(); } else { openReport(); } };
  renderFollowups();
}

/* ── Follow-ups when a step fails ──────────────────────────────── */
// Technique IDs of steps that have worked so far — used to decide which
// follow-ups are ready now and still reach the objective.
function succeededTids(){
  const out=[];
  state.plan.forEach(s=>{ const oc=outcomeOf(s.uid); if(oc==='succeeded'||oc==='fell_back') out.push(s.tid); });
  return out;
}

async function renderFollowups(){
  const box=$('#followups'); if(!box) return;
  const slot=state.plan[state.execIndex]; if(!slot){ box.hidden=true; return; }
  const oc=outcomeOf(slot.uid);
  if(oc!=='failed'&&oc!=='blocked'){ box.hidden=true; box.innerHTML=''; return; }
  box.hidden=false;
  box.innerHTML='<div class="fu-head">Recommended follow-ups</div><div class="fu-note">Fetching alternate routes…</div>';
  let data;
  try{
    const res=await api('/api/followups',{method:'POST',body:JSON.stringify({
      failed_technique_id:slot.tid, objective:state.objective, box_type:state.box,
      scope_platforms:[...state.platforms], restrictions:[...state.restrictions],
      succeeded_technique_ids:succeededTids(),
    })});
    data=await res.json();
  }catch(e){ box.innerHTML='<div class="fu-head">Recommended follow-ups</div><div class="fu-note">Could not load suggestions.</div>'; return; }
  const sugg=(data&&data.suggestions)||[];
  if(!sugg.length){ box.innerHTML='<div class="fu-head">Recommended follow-ups</div><div class="fu-note">No in-scope alternative reaches the objective from here. Consider revisiting scope or an earlier step.</div>'; return; }
  const cards=sugg.map(s=>{
    const badges=[
      s.is_fallback?'<span class="fu-badge fb">Curated fallback</span>':'',
      s.ready_now?'<span class="fu-badge ready">Ready now</span>':'<span class="fu-badge wait">Needs a prior step</span>',
      s.keeps_path_open?'<span class="fu-badge path">Keeps path to objective</span>':'',
    ].filter(Boolean).join('');
    const provides=(s.provides||[]).map(x=>`<span class="fu-cap">${esc(x)}</span>`).join('');
    return `<div class="fu-card">
      <div class="fu-top"><span class="fu-tid">${esc(s.technique_id)}</span>
        <span class="fu-tac">${esc(TACTIC_LABEL[s.tactic]||s.tactic)}</span>
        <button class="fu-add" data-tid="${esc(s.technique_id)}" type="button">+ Add to plan</button></div>
      <div class="fu-name">${esc(s.name)}</div>
      <div class="fu-why">${esc(s.reason)}</div>
      <div class="fu-badges">${badges}</div>
      ${provides?`<div class="fu-provides">Grants: ${provides}</div>`:''}
    </div>`;
  }).join('');
  box.innerHTML=`<div class="fu-head">Recommended follow-ups <span class="fu-sub">this step ${esc(OUTCOME_LABEL[oc]||oc).toLowerCase()} — here are other ways forward</span></div><div class="fu-grid">${cards}</div>`;
  box.querySelectorAll('.fu-add').forEach(b=>b.onclick=()=>{
    // Insert the chosen technique as the next step, right after the failed one.
    state.plan.splice(state.execIndex+1,0,{uid:uid(),tid:b.dataset.tid});
    state.execIndex++; renderExecute();
  });
}

/* board-level drag & drop (wired once) */
function initBoardDnD(){
  const board=$('#board');
  const clearMarks=()=>board.querySelectorAll('.slot').forEach(s=>s.classList.remove('drop-before','drop-after'));
  const idxAt=y=>{const slots=[...board.querySelectorAll('.slot')];
    for(let i=0;i<slots.length;i++){const r=slots[i].getBoundingClientRect(); if(y<r.top+r.height/2) return i;} return slots.length;};
  board.addEventListener('dragover',e=>{e.preventDefault(); board.classList.add('dragover');
    const slots=[...board.querySelectorAll('.slot')]; const idx=idxAt(e.clientY); clearMarks();
    if(slots.length){ if(idx<slots.length) slots[idx].classList.add('drop-before'); else slots[slots.length-1].classList.add('drop-after'); }});
  board.addEventListener('dragleave',e=>{ if(!board.contains(e.relatedTarget)){board.classList.remove('dragover'); clearMarks();} });
  board.addEventListener('drop',e=>{e.preventDefault(); board.classList.remove('dragover');
    const data=e.dataTransfer.getData('text/plain')||''; const idx=idxAt(e.clientY); clearMarks();
    if(data.startsWith('palette:')) insertPiece(data.slice(8),idx);
    else if(data.startsWith('track:')) moveTo(data.slice(6),idx);});
}

/* ── History / launch ─────────────────────────────────────────── */
async function renderHistory(){
  const gate=$('#histGate'); gate.classList.toggle('locked',!state.authorized);
  $('#histToggle').setAttribute('aria-pressed',state.authorized);
  const list=$('#histList'); list.innerHTML='';
  if(!state.authorized) return;
  let items=[];
  try{ items=((await (await api('/api/engagements')).json()).engagements)||[]; }
  catch(e){ list.innerHTML='<p style="color:var(--ink-faint);font-size:13.5px;padding:10px">Could not reach the server.</p>'; return; }
  if(!items.length){ list.innerHTML='<p style="color:var(--ink-faint);font-size:13.5px;padding:10px">No saved engagements yet. Plan one, then Save it from the Execute screen.</p>'; return; }
  items.forEach(h=>{
    const pr=h.progress||{pct:0,worked:0,steps:0}; const date=(h.updated_at||'').slice(0,10);
    const c=el('div','eng-card');
    c.innerHTML=`<div class="ec-top"><div><h3>${esc(h.name)||'Untitled'}</h3><div class="ec-meta">${esc(h.client)||'—'} · ${esc(date)}</div></div>
      <span class="status ${esc(h.status)||'planning'}">${esc(h.status)||'planning'}</span></div>
      <div class="tacts"><span class="tact">${esc(titleCase(h.objective))}</span><span class="tact">${esc(h.box_type)||'?'}-box</span></div>
      <div class="progress"><span style="width:${pr.pct}%"></span></div>
      <div class="ec-foot"><span>${pr.worked}/${pr.steps} steps documented</span><span>${pr.pct}%</span></div>`;
    c.onclick=async()=>{ try{ const full=await (await api('/api/engagements/'+h.id)).json(); loadEngagement(full); }catch(e){} };
    list.appendChild(c);
  });
}
function loadEngagement(h){
  state.engagementId=h.id||null;
  state.objective=h.objective||state.objective; state.box=h.box_type||state.box; state.confirmed=true;
  state.plan=(h.plan||[]).map(s=>({uid:s.uid||uid(),tid:s.tid})); state.logs={}; state.open=new Set(); state.seededFrom=h.name;
  (h.plan||[]).forEach((s,i)=>{ const l=(h.logs||{})[s.uid]; if(l) state.logs[state.plan[i].uid]=Object.assign({outcome:undefined,operator:'',notes:'',evidence:[],targets:[],startedAt:null,completedAt:null},l); });
  state.platforms=new Set(h.scope_platforms||[]); state.restrictions=new Set(h.restrictions||[]);
  buildIntake();
  $('#objTiles').querySelectorAll('.tile').forEach(c=>c.setAttribute('aria-pressed',c.dataset.v===state.objective));
  $('#boxTiles').querySelectorAll('.tile').forEach(c=>c.setAttribute('aria-pressed',c.dataset.v===state.box));
  $('#fName').value=h.name||''; if(h.client!=null)$('#fClient').value=h.client; if(h.authorization_ref!=null)$('#fAuth').value=h.authorization_ref;
  if(h.time_budget_hours!=null)$('#fBudget').value=h.time_budget_hours;
  if(h.in_scope_targets)$('#fTargets').value=(h.in_scope_targets||[]).join(', ');
  syncChips();
  $('#stepPlans').disabled=false; $('#stepBuild').disabled=false; $('#stepExecute').disabled=false;
  let i=state.plan.findIndex(s=>!RESOLVED.has(outcomeOf(s.uid))); state.execIndex=i<0?0:i;
  renderPalette(); renderBoard(); updateSummary(); renderExecute(); go('execute');
}

/* ── Report ───────────────────────────────────────────────────── */
/* ── Coverage heatmap (tactic columns × techniques, by outcome) ── */
const TACTIC_ORDER=['reconnaissance','resource-development','initial-access','execution',
  'persistence','privilege-escalation','defense-evasion','credential-access','discovery',
  'lateral-movement','collection','command-and-control','exfiltration','impact'];
function ocClass(oc){
  if(oc==='succeeded'||oc==='fell_back') return 'hc-worked';
  if(oc==='failed'||oc==='blocked') return 'hc-failed';
  if(oc==='attempted') return 'hc-attempted';
  if(oc==='skipped') return 'hc-skipped';
  return 'hc-planned';
}
function heatmapHTML(cells){
  // cells: [{technique_id, tactic, name, outcome}]
  if(!cells.length) return '<div class="roadmap-empty">No techniques to map yet.</div>';
  const byTactic={};
  cells.forEach(c=>{ (byTactic[c.tactic]=byTactic[c.tactic]||[]).push(c); });
  const order=TACTIC_ORDER.filter(t=>byTactic[t]);
  Object.keys(byTactic).forEach(t=>{ if(!order.includes(t)) order.push(t); });
  const cols=order.map(t=>{
    const col=TACTIC_COLOR[t]||'#8A6D3B';
    const chips=byTactic[t].map(c=>`<div class="heat-cell ${ocClass(c.outcome)}" title="${esc(c.name||c.technique_id)} — ${esc((c.outcome||'planned').replace(/_/g,' '))}">
        <span class="hc-tid">${esc(c.technique_id)}</span></div>`).join('');
    return `<div class="heat-col"><div class="heat-th" style="border-bottom-color:${col}">${esc(TACTIC_LABEL[t]||t)} <span>${byTactic[t].length}</span></div>${chips}</div>`;
  }).join('');
  return `<div class="heat-wrap"><div class="heat">${cols}</div></div>`;
}
function reportHeatmap(){
  const cells=state.plan.map(s=>{ const p=PB[s.tid]||{}; return {
    technique_id:p.technique_id||s.tid, tactic:p.tactic, name:p.name, outcome:outcomeOf(s.uid)}; });
  return heatmapHTML(cells);
}

/* ── Attack-path roadmap (dots + arrows through the successful path) ── */
const OC_STYLE={
  succeeded:{fill:true, badge:'✓', worked:true},
  fell_back:{fill:true, badge:'↺', worked:true},
  failed:{fill:false, badge:'✕', danger:true},
  blocked:{fill:false, badge:'✕', danger:true},
  skipped:{fill:false, badge:'–', faint:true},
  not_started:{fill:false, badge:'', faint:true},
};
function roadmapSVG(){
  const steps=state.plan; if(!steps.length) return '<div class="roadmap-empty">No steps to map yet.</div>';
  const cs=getComputedStyle(document.documentElement);
  const C=k=>cs.getPropertyValue(k).trim();
  const SURFACE=C('--surface'), INK=C('--ink'), FAINT=C('--ink-faint'),
        ACCENT=C('--accent'), CRIT=C('--crit'), LINE=C('--line-strong');
  const gap=122, mx=26, r=19, cy=46, H=118;
  const W=mx*2 + (steps.length-1)*gap + r*2;
  let arrows='', nodes='';
  steps.forEach((s,i)=>{
    const p=PB[s.tid]||{}; const oc=outcomeOf(s.uid)||'not_started';
    const st=OC_STYLE[oc]||OC_STYLE.not_started;
    const cx=mx+r+i*gap; const col=TACTIC_COLOR[p.tactic]||'#8A6D3B';
    const ring=st.danger?CRIT:(st.faint?LINE:col);
    const fill=st.fill?col:SURFACE;
    const tcol=st.fill?'#F6EFE6':INK;
    if(i<steps.length-1){
      const x1=cx+r, x2=mx+r+(i+1)*gap-r;
      arrows+=`<line x1="${x1}" y1="${cy}" x2="${x2-4}" y2="${cy}" stroke="${st.worked?ACCENT:FAINT}" `
        +`stroke-width="${st.worked?2.2:1.3}" ${st.worked?'':'stroke-dasharray="3 4"'} `
        +`marker-end="url(#${st.worked?'rmA':'rmF'})" opacity="${st.worked?1:.75}"/>`;
    }
    nodes+=`<g><circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" stroke="${ring}" stroke-width="2.4" `
      +`${st.faint?'stroke-dasharray="3 3"':''}/>`
      +`<text x="${cx}" y="${cy+4}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="12" font-weight="600" fill="${tcol}">${i+1}</text>`
      +(st.badge?`<text x="${cx+r-3}" y="${cy-r+7}" text-anchor="middle" font-size="11" fill="${st.danger?CRIT:ACCENT}">${st.badge}</text>`:'')
      +`<text x="${cx}" y="${cy+r+15}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="9.5" fill="${FAINT}">${esc(p.technique_id||s.tid)}</text>`
      +`</g>`;
  });
  const defs=`<defs>`
    +`<marker id="rmA" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="none" stroke="${ACCENT}" stroke-width="1.5"/></marker>`
    +`<marker id="rmF" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="none" stroke="${FAINT}" stroke-width="1.3"/></marker></defs>`;
  return `<div class="roadmap-wrap"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="roadmap" role="img" aria-label="Attack path roadmap">${defs}${arrows}${nodes}</svg></div>`;
}

function openReport(){
  const worked=state.plan.filter(s=>{const o=outcomeOf(s.uid); return o&&o!=='skipped';}).length;
  const pct=state.plan.length?Math.round(100*worked/state.plan.length):0;
  const rows=state.plan.map((s,i)=>{const p=PB[s.tid]; const l=state.logs[s.uid]||{}; const oc=l.outcome||'not_started';
    const extra=[l.operator?('op: '+esc(l.operator)):'', (l.evidence&&l.evidence.length)?(l.evidence.length+' evidence ref'+(l.evidence.length>1?'s':'')):''].filter(Boolean).join(' · ');
    return `<div class="logrow"><span class="ocdot ${oc}"></span><div style="flex:1"><div class="lt">${i+1}. ${p.name}</div>
      <div class="lx">${p.technique_id} · ${TACTIC_LABEL[p.tactic]||p.tactic}${extra?' · '+extra:''}</div>
      ${l.notes?`<div style="font-size:12.5px;color:var(--ink-soft);margin-top:3px">${esc(l.notes)}</div>`:''}</div>
      <span class="pill">${OUTCOME_LABEL[oc]}</span></div>`;}).join('');
  const plats=[...state.platforms].map(titleCase).join(', ')||'—';
  const rests=[...state.restrictions].map(titleCase).join(', ')||'None';
  const tacts=new Set(state.plan.map(s=>PB[s.tid]&&PB[s.tid].tactic)); tacts.delete(undefined);
  $('#reportBody').innerHTML=`
    <h3>Attack path</h3>
    <div class="roadmap-legend">
      <span><i class="lg-dot worked"></i>Worked (solid = path to objective)</span>
      <span><i class="lg-dot failed"></i>Failed / blocked</span>
      <span><i class="lg-dot skipped"></i>Skipped / not started</span>
    </div>
    ${roadmapSVG()}
    <h3>Coverage heatmap</h3>
    <div class="roadmap-legend">
      <span><i class="lg-dot worked"></i>Worked</span>
      <span><i class="lg-dot failed"></i>Failed / blocked</span>
      <span><i class="lg-dot skipped"></i>Skipped / planned</span>
      <span style="color:var(--ink-faint)">columns = ATT&CK tactics</span>
    </div>
    ${reportHeatmap()}
    <h3>Overview</h3>
    <div class="rgrid">
      <div class="ri"><div class="rk">Engagement</div><div class="rv">${esc($('#fName').value)||'—'}</div></div>
      <div class="ri"><div class="rk">Client</div><div class="rv">${esc($('#fClient').value)||'—'}</div></div>
      <div class="ri"><div class="rk">Authorization</div><div class="rv">${esc($('#fAuth').value)||'—'}</div></div>
      <div class="ri"><div class="rk">Objective</div><div class="rv">${titleCase(state.objective)}</div></div>
      <div class="ri"><div class="rk">Box type</div><div class="rv">${titleCase(state.box)}</div></div>
      <div class="ri"><div class="rk">Plan source</div><div class="rv">${state.seededFrom?esc(state.seededFrom):'Custom build'}</div></div>
    </div>
    <h3>Rules of engagement</h3>
    <div class="rgrid">
      <div class="ri"><div class="rk">In-scope platforms</div><div class="rv">${plats}</div></div>
      <div class="ri"><div class="rk">In-scope targets</div><div class="rv">${esc($('#fTargets').value)||'—'}</div></div>
      <div class="ri"><div class="rk">Restrictions</div><div class="rv">${rests}</div></div>
      <div class="ri"><div class="rk">Tactics covered</div><div class="rv">${tacts.size}</div></div>
    </div>
    <h3>Execution coverage</h3>
    <div class="covbig"><span class="n tnum">${pct}%</span><span style="color:var(--ink-soft)">of the ${state.plan.length}-step plan documented (${worked} worked)</span></div>
    <div style="margin-top:14px">${rows||'<div class="rv" style="color:var(--ink-faint)">Add pieces to the board and document them to populate the log.</div>'}</div>
    <p style="margin-top:22px;font-size:12px;color:var(--ink-faint)">Compiled by Siege Tower — a planning &amp; documentation artifact. Mirrors the JSON / Markdown report the Bulwark API produces from the same data.</p>`;
  const dlNote=$('#repDlNote');
  if(dlNote) dlNote.textContent = state.engagementId
    ? 'Downloads reflect the last saved version.'
    : 'Save the engagement to enable downloads.';
  const sp=$('#sharePanel'); if(sp) sp.hidden=true;
  $('#scrim').classList.add('open');
}

/* ── Persistence ──────────────────────────────────────────────── */
function collectEngagement(){
  return {
    name:$('#fName').value, client:$('#fClient').value, authorization_ref:$('#fAuth').value,
    objective:state.objective, box_type:state.box,
    scope_platforms:[...state.platforms], restrictions:[...state.restrictions],
    in_scope_targets:($('#fTargets').value||'').split(',').map(x=>x.trim()).filter(Boolean),
    time_budget_hours:parseFloat($('#fBudget').value)||null,
    plan:state.plan.map(s=>({uid:s.uid,tid:s.tid})), logs:state.logs, status:state.status||'active',
  };
}
async function saveEngagement(){
  const note=$('#execNote'); const body=collectEngagement();
  try{
    const url='/api/engagements'+(state.engagementId?('/'+state.engagementId):'');
    const res=await api(url,{method:state.engagementId?'PUT':'POST',body:JSON.stringify(body)});
    const data=await res.json(); if(data&&data.id) state.engagementId=data.id;
    if(note){ note.textContent='Saved.'; setTimeout(()=>{ if(note.textContent==='Saved.') note.textContent=''; },2500); }
  }catch(e){ if(note) note.textContent='Save failed — is the server running?'; }
}

/* ── Navigation ───────────────────────────────────────────────── */
function go(view){
  state.view=view;
  ['home','intake','plans','build','execute'].forEach(s=>$('#stage-'+s).classList.toggle('hidden',s!==view));
  document.querySelectorAll('.step').forEach(b=>b.setAttribute('aria-current', b.dataset.goto===view));
  const order={home:0,intake:1,plans:2,build:3,execute:4}[view]||0;
  document.querySelectorAll('#hprog i').forEach((seg,ix)=>seg.classList.toggle('on', ix<order));
  window.scrollTo({top:0,behavior:'smooth'});
}
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>{
  const g=b.dataset.goto;
  if(g==='plans'){ if($('#stepPlans').disabled) return; buildPlans(); }
  if(g==='build'){ if($('#stepBuild').disabled) return; renderPalette(); renderBoard(); updateSummary(); }
  if(g==='execute'){ if($('#stepExecute').disabled) return; renderExecute(); }
  go(g);
}));
$('#homeBtn').addEventListener('click',()=>go('home'));
$('#homeBtn').addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault(); go('home');}});
$('#newEngBtn').onclick=()=>{ state.engagementId=null; state.plan=[]; state.logs={}; state.confirmed=false; buildIntake(); syncChips(); go('intake'); };
$('#scratchHomeBtn').onclick=()=>{ buildIntake(); syncChips(); openBuilderScratch(); };
$('#scratchBtn').onclick=openBuilderScratch;
$('#genBtn').onclick=()=>{ buildPlans(); go('plans'); };
$('#confirmBtn').onclick=confirmPlan;
$('#fName').addEventListener('input',syncChips);
$('#palSearch').addEventListener('input',e=>{state.palFilter=e.target.value; renderPalette();});
$('#histToggle').onclick=()=>{ state.authorized=!state.authorized; renderHistory(); };
$('#reportBtn').onclick=openReport;
$('#saveBtn').onclick=saveEngagement;
$('#repClose').onclick=()=>$('#scrim').classList.remove('open');
document.querySelectorAll('#repDownloads .dl-btn[data-fmt]').forEach(b=>b.onclick=()=>downloadReport(b.dataset.fmt));

/* ── Shareable client links ───────────────────────────────────── */
const $share=()=>document.querySelector('#sharePanel');
$('#shareBtn').onclick=()=>{ const p=$share(); if(!p) return; if(p.hidden){ p.hidden=false; renderSharePanel(); } else p.hidden=true; };

async function renderSharePanel(){
  const p=$share();
  if(!state.engagementId){ p.innerHTML='<h4>Share with client</h4><div class="rep-dl-note">Save the engagement first to create a share link.</div>'; return; }
  p.innerHTML='<h4>Share with client</h4><div class="rep-dl-note">Loading…</div>';
  let shares=[];
  try{ shares=((await (await api('/api/engagements/'+state.engagementId+'/shares')).json()).shares)||[]; }catch(e){}
  const origin=location.origin;
  const rows=shares.map(s=>{
    const exp=(s.expires_at||'').slice(0,10);
    const status=s.revoked?'revoked':(s.active?('expires '+exp):('expired '+exp));
    return `<div class="share-row ${s.revoked||!s.active?'revoked':''}">
      <input readonly value="${esc(origin)}/share.html#…" title="Token shown once at creation; copy it then">
      <span class="exp">${esc(status)}</span>
      ${(!s.revoked&&s.active)?`<button class="share-mini" data-revoke="${esc(s.id)}">Revoke</button>`:''}
    </div>`;
  }).join('');
  p.innerHTML=`<h4>Share with client</h4>
    <div class="rep-dl-note" style="margin-bottom:8px">Creates a read-only link to this report (findings, roadmap, coverage) — no account needed. The full link is shown once, at creation.</div>
    <div class="share-create">
      <label class="rep-dl-lbl">Expires in</label>
      <select id="shareTtl"><option value="7">7 days</option><option value="14" selected>14 days</option><option value="30">30 days</option><option value="90">90 days</option></select>
      <button class="share-mini" id="shareCreate">Create link</button>
      <span class="rep-dl-note" id="shareNote"></span>
    </div>
    ${rows||'<div class="rep-dl-note">No active links.</div>'}`;
  $('#shareCreate').onclick=createShareLink;
  p.querySelectorAll('[data-revoke]').forEach(b=>b.onclick=()=>revokeShare(b.dataset.revoke));
}

async function createShareLink(){
  const note=$('#shareNote'); const ttl=parseInt($('#shareTtl').value,10)||14;
  if(note) note.textContent='Creating…';
  try{
    const r=await api('/api/engagements/'+state.engagementId+'/shares',{method:'POST',body:JSON.stringify({ttl_days:ttl})});
    if(!r.ok){ if(note) note.textContent='Failed.'; return; }
    const d=await r.json();
    const full=location.origin+d.url;
    // Show the full link once, in a copyable field prepended to the panel.
    const box=document.createElement('div'); box.className='share-row';
    box.innerHTML=`<input readonly id="newShareUrl" value="${esc(full)}"><button class="share-mini" id="copyShare">Copy</button><span class="exp">new · copy now</span>`;
    const create=$('#sharePanel .share-create'); create.insertAdjacentElement('afterend',box);
    const inp=document.querySelector('#newShareUrl'); inp.focus(); inp.select();
    document.querySelector('#copyShare').onclick=()=>{ inp.select(); try{ navigator.clipboard.writeText(full); }catch(e){ document.execCommand&&document.execCommand('copy'); } document.querySelector('#copyShare').textContent='Copied'; };
    if(note) note.textContent='Link created — copy it now (shown once).';
  }catch(e){ if(note) note.textContent='Failed.'; }
}

async function revokeShare(id){
  try{ await api('/api/shares/'+id,{method:'DELETE'}); }catch(e){}
  renderSharePanel();
}

// Download the server-compiled report (includes findings + evidence) for the
// saved engagement. Uses the auth wrapper, so the bearer token is sent.
async function downloadReport(fmt){
  const note=$('#repDlNote');
  if(!state.engagementId){ if(note) note.textContent='Save the engagement first to download.'; return; }
  if(note) note.textContent='Preparing…';
  try{
    const path=(fmt==='navigator')
      ? '/api/engagements/'+state.engagementId+'/navigator'
      : '/api/engagements/'+state.engagementId+'/report?format='+fmt;
    const res=await api(path);
    if(!res.ok){ if(note) note.textContent='Download failed.'; return; }
    const blob=await res.blob();
    const ext=(fmt==='markdown')?'md':(fmt==='navigator')?'navigator.json':fmt;
    const base=($('#fName').value||'engagement').replace(/[^\w.-]+/g,'_');
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=base+'.'+ext;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
    if(note) note.textContent='';
  }catch(e){ if(note) note.textContent='Download failed.'; }
}
$('#scrim').onclick=e=>{ if(e.target===$('#scrim')) $('#scrim').classList.remove('open'); };
document.addEventListener('keydown',e=>{ if(e.key==='Escape') $('#scrim').classList.remove('open'); });

/* ── Findings manager ─────────────────────────────────────────── */
const SEV_OPTS=['','critical','high','medium','low','informational'];
const STATUS_OPTS=['open','in_remediation','retest','fixed','risk_accepted','false_positive'];
const findState={items:[],selected:null};
let _cvssTimer=null;

function openFindings(){
  if(!state.engagementId){
    const n=$('#execNote'); if(n) n.textContent='Saving engagement…';
    saveEngagement().then(()=>{ if(state.engagementId){ _openFindingsModal(); } else if(n){ n.textContent='Save first to add findings.'; } });
    return;
  }
  _openFindingsModal();
}
function _openFindingsModal(){ $('#findScrim').classList.add('open'); loadFindingsList().then(()=>renderFindingEditor(null)); }
function closeFindings(){ $('#findScrim').classList.remove('open'); }

async function loadFindingsList(){
  try{ const r=await api('/api/findings?engagement_id='+encodeURIComponent(state.engagementId));
    findState.items=(await r.json()).findings||[]; }catch(e){ findState.items=[]; }
  renderFindingsList();
}
function renderFindingsList(){
  const box=$('#findItems'); box.innerHTML='';
  if(!findState.items.length){ box.innerHTML='<p style="color:var(--ink-faint);font-size:13px;padding:10px">No findings yet. Create one, or seed from the library.</p>'; return; }
  findState.items.forEach(f=>{
    const d=el('div','find-item'+(findState.selected===f.id?' sel':''));
    const sev=f.severity||'none';
    d.innerHTML=`<h4>${esc(f.title)||'Untitled'}</h4><div class="fi-meta">
      <span class="sev-chip sev-${esc(sev)}">${esc(sev)}</span>
      <span class="st-chip">${esc((f.status||'open').replace(/_/g,' '))}</span>
      ${f.cvss_score!=null?`<span class="st-chip">CVSS ${esc(f.cvss_score)}</span>`:''}</div>`;
    d.onclick=()=>{ findState.selected=f.id; renderFindingsList(); selectFinding(f.id); };
    box.appendChild(d);
  });
}
async function selectFinding(id){
  try{ const f=await (await api('/api/findings/'+id)).json(); renderFindingEditor(f); }catch(e){}
}

function _opt(v,sel){ return `<option value="${esc(v)}"${v===sel?' selected':''}>${esc(v?v.replace(/_/g,' '):'— none —')}</option>`; }
function _csv(a){ return (a||[]).join(', '); }
function _splitCsv(s){ return (s||'').split(',').map(x=>x.trim()).filter(Boolean); }

function renderFindingEditor(f){
  const ed=$('#findEditor'); const isNew=!f;
  f=f||{status:'open',severity:'',affected_assets:[],references:[],technique_ids:[],tags:[],evidence_ids:[]};
  ed.innerHTML=`
    <div class="fe-row"><div class="fe-field" style="flex:2"><label>Title</label>
      <input id="fe_title" value="${esc(f.title)}" placeholder="e.g. Unauthenticated RCE in portal"></div></div>
    <div class="fe-row">
      <div class="fe-field"><label>CVSS vector</label>
        <input id="fe_cvss" value="${esc(f.cvss_vector)}" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">
        <div class="fe-cvss-out" id="fe_cvss_out"></div></div>
      <div class="fe-field"><label>Severity</label>
        <select id="fe_severity">${SEV_OPTS.map(s=>_opt(s,f.severity||'')).join('')}</select></div>
      <div class="fe-field"><label>Status</label>
        <select id="fe_status">${STATUS_OPTS.map(s=>_opt(s,f.status||'open')).join('')}</select></div>
    </div>
    <div class="fe-field"><label>Affected assets (comma-separated)</label>
      <input id="fe_assets" value="${esc(_csv(f.affected_assets))}" placeholder="host, url, IP"></div>
    <div class="fe-field"><label>Description</label><textarea id="fe_desc">${esc(f.description)}</textarea></div>
    <div class="fe-field"><label>Impact</label><textarea id="fe_impact">${esc(f.impact)}</textarea></div>
    <div class="fe-field"><label>Reproduction</label><textarea id="fe_repro">${esc(f.reproduction)}</textarea></div>
    <div class="fe-field"><label>Remediation</label><textarea id="fe_remed">${esc(f.remediation)}</textarea></div>
    <div class="fe-row">
      <div class="fe-field"><label>ATT&CK technique IDs (comma)</label>
        <input id="fe_tids" value="${esc(_csv(f.technique_ids))}" placeholder="T1190, T1059"></div>
      <div class="fe-field"><label>CWE</label><input id="fe_cwe" value="${esc(f.cwe)}" placeholder="CWE-89"></div>
    </div>
    <div class="fe-row">
      <div class="fe-field"><label>References (comma)</label><input id="fe_refs" value="${esc(_csv(f.references))}"></div>
      <div class="fe-field"><label>Tags (comma)</label><input id="fe_tags" value="${esc(_csv(f.tags))}"></div>
    </div>
    <div class="fe-field"><label>Evidence</label>
      <div class="ev-list" id="fe_evlist"></div>
      <div id="fe_evupload"></div></div>
    <div class="fe-actions">
      <button type="button" class="btn btn-primary" id="fe_save">${isNew?'Create finding':'Save changes'}</button>
      ${isNew?'':'<button type="button" class="btn btn-ghost" id="fe_retest">Retest…</button>'}
      ${isNew?'':'<button type="button" class="btn btn-ghost" id="fe_tolib">Save to library</button>'}
      ${isNew?'':'<button type="button" class="btn btn-ghost" id="fe_del">Delete</button>'}
      <span class="fe-note" id="fe_note"></span>
    </div>`;
  // CVSS live scoring.
  const cvssIn=$('#fe_cvss');
  const scoreNow=()=>{ const v=cvssIn.value.trim(); const out=$('#fe_cvss_out');
    if(!v){ out.textContent=''; return; }
    api('/api/cvss?vector='+encodeURIComponent(v)).then(r=>r.json()).then(d=>{
      if(d.score!=null){ out.textContent='Score '+d.score+' · '+d.severity; out.style.color='#7C2A20';
        if(!$('#fe_severity').value) $('#fe_severity').value=d.severity;
      } else { out.textContent=d.version==='4.0'?'v4.0 — enter severity manually':'—'; out.style.color='var(--ink-faint)'; }
    }).catch(()=>{});
  };
  cvssIn.oninput=()=>{ clearTimeout(_cvssTimer); _cvssTimer=setTimeout(scoreNow,400); };
  if(f.cvss_vector) scoreNow();
  $('#fe_save').onclick=()=>saveFinding(f.id);
  if(!isNew){
    $('#fe_del').onclick=()=>deleteFinding(f.id);
    $('#fe_tolib').onclick=()=>saveToLibrary(f.id);
    $('#fe_retest').onclick=()=>doRetest(f.id);
    renderEvidence(f.id);
  } else {
    $('#fe_evupload').innerHTML='<p class="fe-note">Save the finding first to attach evidence.</p>';
  }
}

function collectFindingForm(){
  return {
    title:$('#fe_title').value.trim(), cvss_vector:$('#fe_cvss').value.trim()||null,
    severity:$('#fe_severity').value||null, status:$('#fe_status').value,
    affected_assets:_splitCsv($('#fe_assets').value),
    description:$('#fe_desc').value, impact:$('#fe_impact').value,
    reproduction:$('#fe_repro').value, remediation:$('#fe_remed').value,
    technique_ids:_splitCsv($('#fe_tids').value), cwe:$('#fe_cwe').value.trim()||null,
    references:_splitCsv($('#fe_refs').value), tags:_splitCsv($('#fe_tags').value),
  };
}
async function saveFinding(id){
  const note=$('#fe_note'); const body=collectFindingForm();
  if(!body.title){ if(note) note.textContent='Title is required.'; return; }
  try{
    let res, saved;
    if(id){ res=await api('/api/findings/'+id,{method:'PUT',body:JSON.stringify(body)}); }
    else { body.engagement_id=state.engagementId; res=await api('/api/findings',{method:'POST',body:JSON.stringify(body)}); }
    if(!res.ok){ if(note) note.textContent='Save failed.'; return; }
    saved=await res.json();
    findState.selected=saved.id;
    await loadFindingsList(); renderFindingEditor(saved);
    const n2=$('#fe_note'); if(n2) n2.textContent='Saved.';
  }catch(e){ if(note) note.textContent='Save failed.'; }
}
async function deleteFinding(id){
  try{ await api('/api/findings/'+id,{method:'DELETE'}); }catch(e){}
  findState.selected=null; await loadFindingsList(); renderFindingEditor(null);
}
async function saveToLibrary(id){
  const note=$('#fe_note');
  try{ const r=await api('/api/findings/'+id+'/save-to-library',{method:'POST'});
    if(note) note.textContent=r.ok?'Saved to library.':'Failed.'; }catch(e){ if(note) note.textContent='Failed.'; }
}
async function doRetest(id){
  const status=prompt('New status (open, in_remediation, retest, fixed, risk_accepted, false_positive):','fixed');
  if(!status) return;
  const note=prompt('Retest note (optional):','')||null;
  try{ const r=await api('/api/findings/'+id+'/retest',{method:'POST',body:JSON.stringify({status,note})});
    if(r.ok){ const f=await r.json(); await loadFindingsList(); renderFindingEditor(f); }
    else { const n=$('#fe_note'); if(n) n.textContent='Retest failed (check status value).'; }
  }catch(e){}
}

async function renderEvidence(fid){
  const up=$('#fe_evupload'), list=$('#fe_evlist'); if(!up) return;
  up.innerHTML='<input type="file" id="fe_evfile"><button type="button" class="btn btn-ghost" id="fe_evadd" style="margin-left:8px;font-size:13px;padding:7px 11px">Upload evidence</button>';
  $('#fe_evadd').onclick=async()=>{
    const inp=$('#fe_evfile'); if(!inp.files||!inp.files[0]) return;
    const fd=new FormData(); fd.append('file',inp.files[0]); fd.append('finding_id',fid); fd.append('engagement_id',state.engagementId);
    const note=$('#fe_note'); if(note) note.textContent='Uploading…';
    try{ const r=await api('/api/evidence',{method:'POST',body:fd});
      if(note) note.textContent=r.ok?'Evidence uploaded.':'Upload failed.'; renderEvidence(fid);
    }catch(e){ if(note) note.textContent='Upload failed.'; }
  };
  try{ const evs=(await (await api('/api/evidence?finding_id='+fid)).json()).evidence||[];
    list.innerHTML=evs.map(e=>`<div class="ev-row"><span class="ev-name">${esc(e.filename)}</span>
      <span style="color:var(--ink-faint);font-size:11px">${(e.size/1024).toFixed(1)} KB · ${esc(String(e.sha256).slice(0,10))}…</span>
      <button data-ev="${esc(e.id)}" data-fn="${esc(e.filename)}">Download</button></div>`).join('')
      ||'<span class="fe-note">No evidence attached.</span>';
    list.querySelectorAll('[data-ev]').forEach(b=>b.onclick=()=>downloadEvidence(b.dataset.ev,b.dataset.fn));
  }catch(e){}
}
async function downloadEvidence(id,filename){
  try{ const r=await api('/api/evidence/'+id+'/download'); if(!r.ok) return;
    const blob=await r.blob(); const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=filename||'evidence'; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1500);
  }catch(e){}
}
async function findingsFromLibrary(){
  let items=[];
  try{ items=(await (await api('/api/library')).json()).library||[]; }catch(e){}
  const ed=$('#findEditor');
  if(!items.length){ ed.innerHTML='<div class="fe-empty">The library is empty. Create a finding and use “Save to library” to add a reusable template.</div>'; return; }
  ed.innerHTML='<h3 style="font-family:Fraunces,Georgia,serif;color:#7C2A20;margin:0 0 10px">Instantiate from library</h3>'+
    items.map(it=>`<div class="find-item" data-lib="${esc(it.id)}"><h4>${esc(it.title)}</h4>
      <div class="fi-meta"><span class="sev-chip sev-${esc(it.severity||'none')}">${esc(it.severity||'none')}</span>
      ${it.cvss_score!=null?`<span class="st-chip">CVSS ${esc(it.cvss_score)}</span>`:''}</div></div>`).join('');
  ed.querySelectorAll('[data-lib]').forEach(d=>d.onclick=async()=>{
    try{ const r=await api('/api/library/'+d.dataset.lib+'/instantiate?engagement_id='+encodeURIComponent(state.engagementId),{method:'POST'});
      if(r.ok){ const f=await r.json(); findState.selected=f.id; await loadFindingsList(); renderFindingEditor(f); }
    }catch(e){}
  });
}

async function importScan(fileInput){
  const note=$('#findImportNote');
  if(!fileInput.files||!fileInput.files[0]) return;
  if(!state.engagementId){ if(note) note.textContent='Save the engagement first.'; return; }
  const fd=new FormData(); fd.append('file',fileInput.files[0]); fd.append('engagement_id',state.engagementId);
  if(note) note.textContent='Importing…';
  try{
    const r=await api('/api/imports',{method:'POST',body:fd});
    const d=await r.json().catch(()=>({}));
    if(!r.ok){ if(note) note.textContent=(d.detail||'Import failed.'); return; }
    if(note) note.textContent=`Imported ${d.imported} finding(s) from ${d.source}.`;
    await loadFindingsList();
  }catch(e){ if(note) note.textContent='Import failed.'; }
  finally{ fileInput.value=''; }
}

$('#findingsBtn').onclick=openFindings;
$('#findClose').onclick=closeFindings;
$('#findImportBtn').onclick=()=>$('#findImportFile').click();
$('#findImportFile').onchange=e=>importScan(e.target);
$('#findNew').onclick=()=>{ findState.selected=null; renderFindingsList(); renderFindingEditor(null); };
$('#findFromLib').onclick=findingsFromLibrary;
$('#findScrim').onclick=e=>{ if(e.target===$('#findScrim')) closeFindings(); };
$('#brandBtn').onclick=openBranding;
$('#brandClose').onclick=closeBranding;
$('#brandScrim').onclick=e=>{ if(e.target===$('#brandScrim')) closeBranding(); };

/* ── Login ────────────────────────────────────────────────────── */
function showLogin(msg){
  const ov=$('#loginOverlay'); if(!ov) return;
  ov.hidden=false;
  const e=$('#loginError'); if(e) e.textContent=msg||'';
  const u=$('#loginUser'); if(u) u.focus();
}
function hideLogin(){ const ov=$('#loginOverlay'); if(ov) ov.hidden=true; }

async function doLogin(){
  const username=$('#loginUser').value.trim(), password=$('#loginPass').value;
  if(!username||!password){ $('#loginError').textContent='Enter a username and password.'; return; }
  const btn=$('#loginBtn'); if(btn) btn.disabled=true;
  try{
    const res=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username,password})});
    if(!res.ok){
      const d=await res.json().catch(()=>({}));
      $('#loginError').textContent=(res.status===429)?(d.detail||'Too many attempts.'):'Invalid credentials.';
      return;
    }
    const data=await res.json();
    setToken(data.token); CURRENT_USER=data.user;
    $('#loginPass').value='';
    await startApp();
  }catch(e){ $('#loginError').textContent='Could not reach the server.'; }
  finally{ if(btn) btn.disabled=false; }
}

async function logout(){
  try{ await api('/api/auth/logout',{method:'POST'}); }catch(e){}
  setToken(null); CURRENT_USER=null;
  showLogin(); go('home');
}

function refreshUserChip(){
  const chip=$('#userChip'); if(!chip) return;
  if(CURRENT_USER){ chip.hidden=false; $('#userName').textContent=CURRENT_USER.username+' · '+CURRENT_USER.role;
    const bb=$('#brandBtn'); if(bb) bb.hidden = (CURRENT_USER.role!=='admin');
  } else chip.hidden=true;
}

/* ── Branding settings (admin) ────────────────────────────────── */
async function openBranding(){
  $('#brandScrim').classList.add('open');
  const body=$('#brandBody'); body.innerHTML='<div class="brand-note">Loading…</div>';
  let b={};
  try{ b=await (await api('/api/branding')).json(); }catch(e){}
  const accent=(b.accent&&/^#[0-9A-Fa-f]{6}$/.test(b.accent))?b.accent:'#B0472C';
  body.innerHTML=`
    <div class="brand-note" style="margin-bottom:14px">Applied to your reports (PDF / DOCX), the report modal, and shared client links.</div>
    <div class="fe-field"><label>Accent colour</label>
      <div class="brand-color"><input type="color" id="brAccent" value="${esc(accent)}">
        <input type="text" id="brAccentHex" value="${esc(accent)}" style="max-width:130px" spellcheck="false"></div></div>
    <div class="fe-field"><label>Company name (shown as “Prepared by”)</label>
      <input type="text" id="brCompany" value="${esc(b.company_name)}" placeholder="Your consultancy name"></div>
    <div class="fe-field"><label>Confidentiality label</label>
      <input type="text" id="brConf" value="${esc(b.confidentiality)}" placeholder="CONFIDENTIAL"></div>
    <div class="fe-field"><label>Report footer</label>
      <input type="text" id="brFooter" value="${esc(b.footer)}" placeholder="© Your Company · Confidential"></div>
    <div class="fe-field"><label>Logo</label>
      <div class="brand-logo">
        <img id="brLogoImg" alt="logo" ${b.has_logo?'':'hidden'} src="${b.has_logo?('/api/branding/logo?t='+Date.now()):''}">
        <div>
          <input type="file" id="brLogoFile" accept="image/*" hidden>
          <div class="brand-actions">
            <button type="button" class="share-mini" id="brLogoBtn">Upload logo</button>
            ${b.has_logo?'<button type="button" class="share-mini" id="brLogoDel">Remove</button>':''}
          </div>
          <div class="brand-note" style="margin-top:5px">PNG/JPG/SVG, up to 256 KB.</div>
        </div>
      </div></div>
    <div class="brand-actions"><button type="button" class="btn btn-primary" id="brSave">Save</button>
      <span class="brand-note" id="brNote"></span></div>`;
  // Sync color <-> hex
  const col=$('#brAccent'), hex=$('#brAccentHex');
  col.oninput=()=>{ hex.value=col.value; };
  hex.oninput=()=>{ if(/^#[0-9A-Fa-f]{6}$/.test(hex.value)) col.value=hex.value; };
  $('#brSave').onclick=saveBranding;
  $('#brLogoBtn').onclick=()=>$('#brLogoFile').click();
  $('#brLogoFile').onchange=e=>uploadLogo(e.target);
  const del=$('#brLogoDel'); if(del) del.onclick=deleteLogo;
}
function closeBranding(){ $('#brandScrim').classList.remove('open'); }

async function saveBranding(){
  const note=$('#brNote'); const hex=$('#brAccentHex').value.trim();
  if(hex && !/^#[0-9A-Fa-f]{6}$/.test(hex)){ if(note) note.textContent='Accent must be a #RRGGBB colour.'; return; }
  const body={ accent:hex||null, company_name:$('#brCompany').value.trim()||null,
    confidentiality:$('#brConf').value.trim()||null, footer:$('#brFooter').value.trim()||null };
  if(note) note.textContent='Saving…';
  try{ const r=await api('/api/branding',{method:'PUT',body:JSON.stringify(body)});
    if(note) note.textContent=r.ok?'Saved.':'Save failed.'; }catch(e){ if(note) note.textContent='Save failed.'; }
}
async function uploadLogo(inp){
  const note=$('#brNote'); if(!inp.files||!inp.files[0]) return;
  const fd=new FormData(); fd.append('file',inp.files[0]);
  if(note) note.textContent='Uploading logo…';
  try{ const r=await api('/api/branding/logo',{method:'POST',body:fd});
    if(!r.ok){ const d=await r.json().catch(()=>({})); if(note) note.textContent=(d.detail||'Upload failed.'); return; }
    if(note) note.textContent='Logo updated.'; openBranding();
  }catch(e){ if(note) note.textContent='Upload failed.'; }
  finally{ inp.value=''; }
}
async function deleteLogo(){
  try{ await api('/api/branding/logo',{method:'DELETE'}); }catch(e){}
  openBranding();
}

/* ── Boot ─────────────────────────────────────────────────────── */
async function startApp(){
  try{ SIEGE = await (await api('/api/bootstrap')).json(); }
  catch(e){
    if(String(e && e.message)==='unauthorized') return;  // login overlay already shown
    document.body.innerHTML='<div style="padding:48px;font-family:Georgia,serif;max-width:640px;margin:0 auto"><h1>Siege Tower</h1><p>Could not load planning data. Ensure the server is running and reload this page.</p></div>';
    return;
  }
  // (Re)populate the technique map now that SIEGE actually holds the playbook.
  for(const k in PB) delete PB[k];
  (SIEGE.playbook||[]).forEach(p => PB[p.technique_id] = p);
  hideLogin();
  buildIntake(); syncChips(); initBoardDnD(); renderHistory(); refreshUserChip(); go('home');
}

async function boot(){
  const loginForm=$('#loginForm');
  if(loginForm) loginForm.addEventListener('submit', e=>{ e.preventDefault(); doLogin(); });
  const lo=$('#logoutBtn'); if(lo) lo.onclick=logout;
  const tt=$('#themeToggle'); if(tt) tt.onclick=toggleTheme;
  applyTheme(currentTheme());
  if(AUTH_TOKEN){
    try{
      const r=await fetch('/api/auth/me',{headers:{'Authorization':'Bearer '+AUTH_TOKEN}});
      if(r.ok){ CURRENT_USER=await r.json(); await startApp(); return; }
    }catch(e){}
    setToken(null);
  }
  showLogin();
}
boot();
