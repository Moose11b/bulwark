/* Public read-only shared report viewer. Token comes from the URL fragment
   (kept out of server logs); the report is fetched from /api/share/<token>. */
const $ = s => document.querySelector(s);
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const lbl = v => v ? String(v).replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : '—';
const joinList = a => (a && a.length) ? a.map(esc).join(', ') : '—';

const TACTIC_COLOR = {
  'reconnaissance': '#6B7F8C', 'resource-development': '#6B5B41', 'initial-access': '#9C3B2E',
  'execution': '#A9822C', 'persistence': '#7A6A9C', 'privilege-escalation': '#B06A2E',
  'defense-evasion': '#7C6A55', 'credential-access': '#4E7C6B', 'discovery': '#3C5A6B',
  'lateral-movement': '#8A6D3B', 'collection': '#5E6B2C', 'command-and-control': '#6B5B41',
  'exfiltration': '#97362A', 'impact': '#5A3A3A',
};
const OC = {
  succeeded: { fill: 1, badge: '✓', worked: 1 }, fell_back: { fill: 1, badge: '↺', worked: 1 },
  failed: { badge: '✕', danger: 1 }, blocked: { badge: '✕', danger: 1 },
  skipped: { badge: '–', faint: 1 }, not_started: { faint: 1 },
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

function roadmap(steps) {
  if (!steps || !steps.length) return '';
  const gap = 122, mx = 26, r = 19, cy = 46, H = 118;
  const W = mx * 2 + (steps.length - 1) * gap + r * 2;
  const ACCENT = '#B0472C', CRIT = '#9C2B1B', FAINT = '#79806F', LINE = '#B4A788', SURF = '#F7F3EB', INK = '#20261E';
  let arrows = '', nodes = '';
  steps.forEach((s, i) => {
    const oc = s.outcome || 'not_started'; const st = OC[oc] || OC.not_started;
    const cx = mx + r + i * gap; const col = TACTIC_COLOR[s.tactic] || '#8A6D3B';
    const ring = st.danger ? CRIT : (st.faint ? LINE : col);
    const fill = st.fill ? col : SURF; const tcol = st.fill ? '#F6EFE6' : INK;
    if (i < steps.length - 1) {
      const x1 = cx + r, x2 = mx + r + (i + 1) * gap - r;
      arrows += `<line x1="${x1}" y1="${cy}" x2="${x2 - 4}" y2="${cy}" stroke="${st.worked ? ACCENT : FAINT}" stroke-width="${st.worked ? 2.2 : 1.3}" ${st.worked ? '' : 'stroke-dasharray="3 4"'} marker-end="url(#${st.worked ? 'a' : 'f'})" opacity="${st.worked ? 1 : .75}"/>`;
    }
    nodes += `<g><circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" stroke="${ring}" stroke-width="2.4" ${st.faint ? 'stroke-dasharray="3 3"' : ''}/>`
      + `<text x="${cx}" y="${cy + 4}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="12" font-weight="600" fill="${tcol}">${i + 1}</text>`
      + (st.badge ? `<text x="${cx + r - 3}" y="${cy - r + 7}" text-anchor="middle" font-size="11" fill="${st.danger ? CRIT : ACCENT}">${st.badge}</text>` : '')
      + `<text x="${cx}" y="${cy + r + 15}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="9.5" fill="${FAINT}">${esc(s.technique_id || '')}</text></g>`;
  });
  const defs = `<defs><marker id="a" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="none" stroke="${ACCENT}" stroke-width="1.5"/></marker>`
    + `<marker id="f" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="none" stroke="${FAINT}" stroke-width="1.3"/></marker></defs>`;
  return `<div class="roadmap-wrap"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Attack path">${defs}${arrows}${nodes}</svg></div>`;
}

function findingHTML(f) {
  const sev = f.severity || 'none';
  const flds = [
    ['Affected assets', joinList(f.affected_assets)],
    ['Description', f.description], ['Impact', f.impact],
    ['Reproduction', f.reproduction], ['Remediation', f.remediation],
  ].filter(([, v]) => v && v !== '—');
  const refs = (f.references && f.references.length)
    ? `<div class="fld"><div class="l">References</div><div class="chips">${f.references.map(r => `<span class="chip">${esc(r)}</span>`).join('')}</div></div>` : '';
  const tids = (f.technique_ids && f.technique_ids.length)
    ? `<div class="fld"><div class="l">ATT&CK</div><div class="chips">${f.technique_ids.map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div></div>` : '';
  const ev = (f.evidence && f.evidence.length)
    ? `<div class="fld"><div class="l">Evidence</div><div class="chips">${f.evidence.map(e => `<span class="chip">${esc(e.filename || '?')} · ${esc(String(e.sha256 || '').slice(0, 10))}…</span>`).join('')}</div></div>` : '';
  return `<div class="finding"><h3><span class="sev ${esc(sev)}">${esc(sev)}</span>${esc(f.title) || 'Untitled'}`
    + (f.cvss_score != null ? `<span class="cvss">CVSS ${esc(f.cvss_score)}</span>` : '')
    + `<span class="cvss">· ${esc(lbl(f.status))}</span></h3>`
    + flds.map(([k, v]) => `<div class="fld"><div class="l">${k}</div><div class="t">${esc(v)}</div></div>`).join('')
    + tids + refs + ev + `</div>`;
}

function render(rep, token) {
  const e = rep.engagement || {}, roe = rep.roe || {}, cov = rep.coverage || {};
  const brand = rep.branding || {};
  // Apply org branding: accent colour and (below) logo / company / footer.
  if (brand.accent && /^#[0-9A-Fa-f]{6}$/.test(brand.accent)) {
    document.documentElement.style.setProperty('--accent', brand.accent);
    document.documentElement.style.setProperty('--accent-deep', brand.accent);
  }
  const preparedBy = brand.company_name || rep.org_name || '—';
  const conf = brand.confidentiality || 'CONFIDENTIAL';
  const logo = brand.logo_data_uri
    ? `<img src="${esc(brand.logo_data_uri)}" alt="" style="max-height:64px;max-width:220px;display:block;margin-bottom:14px">` : '';
  let findings = (rep.findings || []).slice().sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5) || String(a.title).localeCompare(String(b.title)));
  const dl = `/api/share/${encodeURIComponent(token)}/download`;
  $('#content').innerHTML = `
    <div class="doc">
      ${logo}
      <p class="eyebrow">Penetration Test Report</p>
      <h1>${esc(e.name) || 'Engagement Report'}</h1>
      <div class="sub">Client: ${esc(e.client) || '—'} · Prepared by: ${esc(preparedBy)} · Objective: ${esc(lbl(e.objective))}</div>
      <p class="banner">${esc(conf)} — authorized assessment record. Planning and documentation only.</p>
      <div class="dl"><a href="${dl}?format=pdf">Download PDF</a><a href="${dl}?format=docx">Download DOCX</a><a href="${dl}?format=markdown">Markdown</a></div>

      <h2>Attack path</h2>
      <div class="legend"><span><i class="lg w"></i>Worked (solid = path to objective)</span><span><i class="lg f"></i>Failed / blocked</span><span><i class="lg s"></i>Skipped</span></div>
      ${roadmap(rep.steps) || '<div class="sub">No steps documented.</div>'}

      <h2>Executive summary</h2>
      <div class="cov">${cov.coverage_pct != null ? cov.coverage_pct : 0}%</div>
      <div class="sub">${cov.steps_worked || 0} of ${cov.total_steps || 0} planned steps worked · ${findings.length} finding(s)</div>
      <div class="grid" style="margin-top:12px">
        <div class="kv"><div class="k">Box type</div><div class="v">${esc(lbl(e.box_type))}</div></div>
        <div class="kv"><div class="k">Authorization</div><div class="v">${esc(e.authorization_ref) || '—'}</div></div>
        <div class="kv"><div class="k">In-scope platforms</div><div class="v">${joinList(roe.scope_platforms)}</div></div>
        <div class="kv"><div class="k">In-scope targets</div><div class="v">${joinList(roe.in_scope_targets)}</div></div>
        <div class="kv"><div class="k">Restrictions</div><div class="v">${joinList(roe.restrictions)}</div></div>
      </div>

      <h2>Findings</h2>
      ${findings.length ? findings.map(findingHTML).join('') : '<div class="sub">No findings recorded.</div>'}

      ${brand.footer ? `<div class="foot">${esc(brand.footer)}</div>` : ''}
      <div class="foot">Shared via Siege Tower — this is a read-only view.</div>
    </div>`;
  $('#message').hidden = true;
  $('#content').hidden = false;
  document.title = (e.name || 'Shared Report') + ' — Siege Tower';
}

function fail(msg) {
  $('#content').hidden = true;
  $('#message').hidden = false;
  $('#message').innerHTML = `<h1>Report unavailable</h1><p>${esc(msg)}</p>`;
}

async function boot() {
  const token = (location.hash || '').slice(1);
  if (!token) { fail('No link token provided.'); return; }
  try {
    const r = await fetch('/api/share/' + encodeURIComponent(token));
    if (!r.ok) { fail('This link is invalid or has expired.'); return; }
    render(await r.json(), token);
  } catch (e) { fail('Could not load the report. Please try again later.'); }
}
window.addEventListener('hashchange', boot);
boot();
