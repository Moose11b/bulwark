# Siege Tower — Product & Security Review

*Prepared 2026-09-07. Scope: the standalone `siege-tower/` app (engine + FastAPI
server + web UI) and the `backend/app/routers/siege.py` integration into the
Bulwark platform. Goal: make Siege Tower a sellable product for independent
pentesters and companies that test themselves or others.*

This document has three parts:

1. **Market** — where Siege Tower sits against competitors, and where the gaps are.
2. **Product** — what to improve to be competitive.
3. **Security** — a prioritised list of changes needed before this is safe to sell.

---

## Part 1 — Market: competitors, positioning, and the gap

Siege Tower sits at the intersection of three markets usually sold separately:
(1) pentest **engagement management & reporting**, (2) **ATT&CK-based attack
planning / adversary emulation**, and (3) **offensive orchestration / C2**. The
core finding: almost no incumbent spans planning + documentation + a scanner
pairing in one product *without also executing exploits*. That un-served
overlap is exactly where Siege Tower can win.

### 1.1 Reporting / engagement-management platforms (Siege Tower's closest rivals)

These own the "document the engagement and produce the report" job.

- **PlexTrac** — market-leading commercial, AI-assisted "report as you test"
  platform. Quote-based SaaS, widely seen as premium (deals commonly in the
  tens of thousands/year). *Strengths:* best-in-class reporting UX, reusable
  findings library (WriteupsDB), analytics, retest tracking, multi-scanner
  consolidation. *Weaknesses:* **price is the #1 complaint** — prohibitive for
  solos/small teams; integrations lag the core; overkill for one-person shops.
- **AttackForge** — full-lifecycle management/reporting; enterprise workflow +
  self-service. From ~$50/user/mo up to packaged $150–$800/mo; free Community
  tier. *Strengths:* standardized test cases, auto-maps vulns into attack
  paths, strong REST API, good value. *Weaknesses:* rapid-release churn, UI
  less polished than PlexTrac, steeper initial setup.
- **Dradis** — long-standing self-hosted collaboration + reporting. **CE free
  (GPL)**; Pro $100–$149/user/mo. *Strengths:* mature scanner importers, Issue
  Library + Rules Engine, data ownership. *Weaknesses:* dated UI, template
  learning curve, per-user cost scales.
- **PenTest.WS** — lightweight, solo-focused workspace (hosts/services/findings,
  command templates). Cheap individual tiers (free Hobby + low Pro).
  *Strengths:* fast and cheap for solo operators. *Weaknesses:* not built for
  consultancy scale, light on portals/theming/integrations.
- **Pentest Collaboration Framework (PCF)** — free/OSS team project management +
  automation. *Strengths:* genuinely free Faraday/Dradis analog, Nmap/Nessus/
  Nikto imports. *Weaknesses:* fragmented forks, thinner reporting, small
  ecosystem.
- **Reconmap** — OSS collaboration-first sec-ops platform; SaaS option.
  *Strengths:* command automation + output parsing + AI summaries, DOCX/PDF/
  XLSX/MD/HTML reports, **Model Context Protocol (LLM) support**. *Weaknesses:*
  smaller community, self-host burden, thinner client-portal/compliance.
- **Ghostwriter (SpecterOps)** — FOSS project-management + reporting engine.
  *Strengths:* reusable findings library, RBAC/SSO/MFA, DOCX/XLSX/PPTX via
  Jinja2, GraphQL API, Mythic/Cobalt Strike activity logging. *Weaknesses:*
  red-team-op-centric, Jinja2/DOCX template learning curve, self-host ops.
- **Cervantes (OWASP)** — free/OSS collaboration-first platform. *Strengths:*
  real-time multi-user by design, dashboards, one-click reports, AI features,
  JIRA. *Weaknesses:* younger project, smaller ecosystem, enterprise hardening
  still maturing.
- **Hexway (Hive/Pentest)** — on-prem workspace with a live client portal
  ("Apiary"). Community free + Pentest tier ~$78/user/mo. *Strengths:*
  collaborative workspace, live client portal, broad tool integrations.
  *Weaknesses:* on-prem overhead, smaller North American footprint.
- **Rootshell (Prism)** — vendor-agnostic vuln-management + offensive platform /
  PTaaS. Quote-based, annual contracts. *Strengths:* single pane across
  vendors, prioritization, ticketing. *Weaknesses:* enterprise sales motion,
  more a client-side remediation hub than a tester's authoring tool.
- **Astra (PTaaS)** — scanner + human pentest, per-target, client dashboard.
  **Publicly priced**: scanner from $1,999/yr/target, manual pentest
  $5,999/yr/target. *Strengths:* transparent pricing, scan+human+remediation,
  compliance framing. *Weaknesses:* a service for *buyers* of pentests, not a
  tester's tool; per-target cost scales.
- **Cobalt.io (PtaaS)** — category-defining freelance-tester marketplace.
  Credit-based; engagements start ~$8,500; first-year packages ~$65k–$90k.
  *Strengths:* fast start, retest workflow, integrations. *Weaknesses:*
  **confusing non-rolling credit model**, variable freelance depth, expensive.
- **Sprocket** — expert-led *continuous* pentesting + portal. Quote-based
  subscription. *Strengths:* continuous coverage, real-time portal.
  *Weaknesses:* managed service (you buy their testers), not for independents.
- **Adjacent tooling worth benchmarking:** **Faraday** (OSS + Pro; aggregates
  80+ tools live), **SysReptor** (OSS + low-cost Pro; beautiful HTML/CSS→PDF
  reports — a strong low-cost benchmark for Siege Tower's documentation
  module), and a wave of AI-first tools (**PentestPad, Pentest-Tools.com** at
  $95–$190/user/mo bundling their own scanners + reporting — the exact
  scanner-plus-reporting bundle Siege Tower + Bulwark is aiming at).

### 1.2 Attack-planning / adversary-emulation / ATT&CK tooling

Siege Tower's planning module competes here on playbook value while deliberately
*not* executing.

- **MITRE Caldera** — free/OSS automated adversary emulation (a real C2).
  *Strengths:* deep ATT&CK grounding, plugins, auto attack-chaining.
  *Weaknesses:* **it executes** (operationally heavy/risky), planners can
  generate unrealistic chains, web UI not hardened, lab-only per MITRE.
- **Atomic Red Team (Red Canary)** — free/OSS library of small ATT&CK-mapped
  tests. *Strengths:* huge, well-maintained, ATT&CK-indexed — a great *content
  source* for planning. *Weaknesses:* a test library, not a platform (no
  engagement mgmt/reporting/planning UI).
- **VECTR (Security Risk Advisors)** — purple-team planning + results tracking +
  benchmarking. Community free; Enterprise quote-based. *Strengths:*
  **conceptually closest to Siege Tower's philosophy** — plans and documents,
  doesn't execute; ATT&CK-aligned, trend/benchmark reporting. *Weaknesses:*
  oriented to internal purple teams/detection engineering, not consultant
  pentest deliverables; opaque enterprise pricing.
- **Prelude Operator** — free desktop adversary emulation. *Strengths:*
  accessible, good ATT&CK TTP coverage. *Weaknesses:* **executes**; commercial
  focus has shifted, raising continuity questions.
- **SCYTHE** — commercial adversarial emulation / BAS. Custom-quoted.
  *Strengths:* fast campaign building, realistic emulation, purple-team
  workflows. *Weaknesses:* **executes**, enterprise price, overkill for solos.
- **MITRE ATT&CK Navigator** — free/OSS matrix annotation/visualization.
  *Strengths:* universal lingua franca for coverage, shareable JSON layers.
  *Weaknesses:* just a visualizer — no engagement mgmt, execution, or
  reporting. **Siege Tower should ingest/emit Navigator layers.**
- **"Vaunt" — UNVERIFIED.** The research could not confirm a security/ATT&CK
  product by this name; it resolves to an unrelated aviation app and a
  developer-relations tool. Treat as not-a-known-competitor until the exact
  product/URL is confirmed. Flagged rather than fabricated.

### 1.3 Offensive orchestration / C2 (context only — Siege Tower does not compete)

Execution engines buyers mentally place nearby; Siege Tower should *interoperate
with and log alongside* them, not replace them.

- **Metasploit** — Framework free/OSS; Pro commercial (quote-based, low five
  figures/user/yr). Gold-standard exploit library; Pro reporting is generic.
- **Cobalt Strike (Fortra)** — premium red-team C2, ~$3,500/user/yr, purchase
  vetting. Gold-standard C2; execution-only; integrates with Ghostwriter for
  logging.
- **Sliver (Bishop Fox)** — free/OSS modern C2, the leading Cobalt Strike
  alternative. Execution-only, CLI-centric, no reporting layer.

### 1.4 How incumbents handle the cross-cutting capabilities

| Capability | Who does it well | Gap Siege Tower can exploit |
| --- | --- | --- |
| Real-time collaboration | Cervantes, Faraday, SysReptor Pro, Hexway, Reconmap | Older tools bolt it on; concurrent editing is now table-stakes |
| Client / multi-tenant separation | PlexTrac, AttackForge, Rootshell, Astra, Cobalt, Hexway portal | Most OSS tools assume single-org — weak client separation |
| Findings / writeup library | PlexTrac (WriteupsDB), Ghostwriter, Dradis Pro, AttackForge | Biggest report time-saver; Siege Tower has none yet |
| Retest / remediation tracking | PlexTrac, Rootshell, Cobalt, Astra, AttackForge, Sprocket | Auditor requirement; strongest in client-facing commercial tools |
| Compliance mapping | Astra, Pentest-Tools.com, PlexTrac | Uneven in OSS; Bulwark already maps 4 frameworks — reuse it |
| Evidence / screenshot capture | PlexTrac ("report as you test"), Hexway, Faraday | Capturing *during* testing is the recurring pain point |
| ATT&CK planning ↔ reporting link | VECTR, Navigator, Caldera (planning only) | **Nobody links planning to the report — the core opening** |

### 1.5 The gaps pentesters actually complain about

1. **Reporting is the universally hated bottleneck** — teams spend 20–60% of
   engagement time on reports (8–14 hours unaided, ~5–6 with a platform). Root
   cause: documentation happens *after* the hacking, so context decays.
2. **Repetitive rewriting** of the same findings across clients; CVSS scoring
   alone can eat ~3 hours per report.
3. **Ugly tool output** that doesn't paste cleanly into a report.
4. **Price cliffs for small players** — a painful gap between free-but-clunky
   OSS and expensive-but-polished enterprise SaaS.
5. **Planning and reporting are disconnected** — plan in Navigator/VECTR/a
   spreadsheet, execute in Metasploit/Burp/Sliver, report in PlexTrac/Dradis:
   three disjoint worlds with manual re-entry. Nobody owns the full
   plan → evidence → report thread for a manual pentester.
6. **Execution tools scare buyers** — Caldera/Prelude/SCYTHE/Cobalt Strike/
   Sliver all execute; many orgs and compliance regimes want the planning,
   methodology, and documentation *without a live C2 in their environment*.
7. **Confusing commercial models** — non-rolling credits and pervasive
   quote-only pricing frustrate buyers who want predictable, self-serve plans.

### 1.6 Pricing landscape

- **Free / OSS (self-host effort):** Ghostwriter, Cervantes, Reconmap, PCF,
  SysReptor CE, Faraday CE, Dradis CE, Caldera, Atomic Red Team, ATT&CK
  Navigator, VECTR Community, Prelude Operator, Sliver, Metasploit Framework.
- **Prosumer / small-team (~$30–$200/user/mo):** PenTest.WS, Hexway
  (~$78), Dradis Pro ($100–$149), AttackForge (~$50 up to packaged
  $150–$800/mo), Pentest-Tools.com ($95–$190), SysReptor Pro.
- **Enterprise / quote-based (low-five to six figures/yr):** PlexTrac, Rootshell
  Prism, SCYTHE, VECTR Enterprise, Metasploit Pro, Cobalt Strike (~$3,500/user).
- **PtaaS / per-engagement:** Astra ($1,999–$5,999/yr/target, transparent),
  Cobalt (~$8,500 start, $65k–$90k first-year), Sprocket (continuous). Broader
  market: a web/API pentest runs $4,000–$50,000 per engagement.

**Pricing takeaway:** there is a clear **"prosumer" white space** — a polished
planning + documentation product in the **~$30–$99/user/month** band with a
genuinely useful free tier, undercutting PlexTrac while out-polishing the free
OSS pack, and bundling Bulwark the way Pentest-Tools.com and Astra bundle their
scanners.

*(A few exact figures above — PenTest.WS tiers, Metasploit Pro per-seat — are
approximate because vendor pages were quote-walled or blocked during research;
treat those as directional.)*

### 1.7 Table stakes any serious entrant must have

Reusable findings/writeup library with **CVSS 3.1 and 4.0** auto-scoring;
document-as-you-test evidence capture (screenshots, request/response, command
output); scanner import + de-dup + normalization (Burp, Nessus, Nmap, Nuclei,
ZAP, OpenVAS, **and Bulwark**); one-click branded **DOCX/PDF** export;
multi-project/client separation with RBAC + SSO/MFA; retest/remediation
tracking; compliance mapping (SOC 2, ISO 27001, PCI DSS, HIPAA, NIST);
real-time collaboration + an API; ATT&CK alignment with Navigator layer
import/export; and, for the company segment, a client portal.

### 1.8 Where Siege Tower differentiates

1. **Own the full thread: Plan → Execute-assist → Evidence → Report, in one
   product.** No incumbent unifies ATT&CK planning with consulting-grade
   reporting. Pitch: *"the plan you build is the report you ship"* — planned
   techniques become the reporting scaffold, and captured evidence attaches
   back to the planned ATT&CK step.
2. **"Execution assistant, not executor" — as a feature, not a limitation.**
   No C2 in the client's environment means easier legal sign-off, no dual-use/
   abuse risk, and it directly attacks the #1 pain (post-hoc reconstruction) by
   capturing the exploitation chain *as the human does it*.
3. **Deep Bulwark (DAST) pairing competitors can't match** — scan findings flow
   straight into the plan and the report, auto-mapped to ATT&CK and the four
   compliance frameworks Bulwark already supports. A tight scan → plan → report
   loop with retest-driven rescans is a defensible story.
4. **ATT&CK-native playbooks as reusable IP** — ship the technique library as
   methodology + report structure; import/emit Navigator layers.
5. **AI that removes drudgery, grounded in the planned technique and captured
   evidence** (findings drafting, exec summaries, CVSS suggestions, output
   cleanup) — higher fidelity than generic AI because it's context-anchored.
6. **Predictable, transparent, self-serve pricing** with a real free tier — a
   direct wedge against PlexTrac's price complaints and Cobalt's credit model.
7. **Interoperate with the C2 world rather than compete** — log alongside and
   ingest output from Cobalt Strike / Sliver / Metasploit (the Ghostwriter
   model), so Siege Tower is the documentation/planning brain regardless of the
   exploitation tools the tester uses.

### 1.9 Positioning: independents vs. companies

- **Independents / consultants (land here first):** lead with time-to-report
  and price — "cut report time in half, polished output that out-classes free
  OSS, at a fraction of PlexTrac." Solo workflow: plan in ATT&CK, capture
  evidence live, one-click branded DOCX/PDF, reusable findings so client #2
  reuses client #1's writeups. Bundle Bulwark. Ship a free/individual tier to
  win mindshare against Ghostwriter/SysReptor/PenTest.WS.
- **Companies (internal teams, MSSPs, consultancies — expand into):** lead with
  multi-tenant client separation, SSO/MFA/RBAC, client portal, compliance
  mapping, and retest tracking — enterprise table stakes without the enterprise
  price pain. Emphasize standardized methodology + ATT&CK coverage reporting
  (VECTR-style) to prove testing depth to clients/auditors, and the
  "no C2 in the environment" safety story for regulated buyers. Offer
  self-hosted deployment for data-ownership-conscious buyers. Frame vs.
  PlexTrac: *"the planning + reporting depth of PlexTrac, with a built-in
  scanner and ATT&CK planning, at a price that doesn't require a board
  meeting."*

---

## Part 2 — Product review: what Siege Tower is, and what to improve

### What it is today

Siege Tower is a **red-team engagement planner and documentation tool**. It
does not scan or exploit. Its value chain is: structure a Rules of Engagement
(ROE) → generate 3–5 ranked, ATT&CK-mapped attack plans → let the operator drag
technique "pieces" into an ordered line of march → walk the plan step by step
recording outcomes → compile a field report.

Architecture is sound and deliberate:

- **Engine** (`siege_tower/`): a dependency-free, standard-library-only Python
  package. Deterministic capability-graph planner (same ROE always yields the
  same plans; no randomness). ~49 ATT&CK-mapped technique entries across
  `playbook.py` (18) and `plays_ext.py` (31). No network, no subprocess — it
  *structurally cannot* touch a target.
- **Standalone server** (`server/`): a thin FastAPI wrapper with SQLite
  persistence and a no-build-step web UI.
- **Integrated router** (`backend/app/routers/siege.py`): the same engine wired
  into the Bulwark platform with real auth, org scoping, and Pydantic models.

The "plans and documents, never executes" positioning is genuinely a
differentiator (see Part 1) and is enforced by a test guard
(`test_siege_no_execution.py`) plus the dependency-free engine design. Keep it.

### Product gaps to close (ranked by impact on sellability)

**Tier 1 — table stakes; you cannot sell without these**

1. **Real reporting output.** Today the app emits JSON and Markdown only
   (`render.py`, `server/report.py`). Every commercial competitor ships
   branded, client-ready **PDF and DOCX** with a cover page, logo, executive
   summary, and per-finding detail. The Bulwark platform already has PDF
   reporting — reuse that pipeline. Add customisable templates and org branding.
2. **A findings / vulnerability model, distinct from execution steps.** Right
   now an engagement is a plan + a step log. Pentest deliverables are organised
   around *findings*: title, severity (CVSS), affected assets, evidence,
   reproduction, remediation, references. Add a first-class `Finding` entity
   with a reusable **findings library** (write once, reuse across reports) —
   this is the single most-requested feature in the competitor set (PlexTrac,
   Dradis, AttackForge all lead with it).
3. **Real evidence handling.** Evidence is currently a free-text reference
   ("filename, ticket id, screenshot ref"). There is no file upload, storage,
   or integrity. Add authenticated **evidence upload** (screenshots, PCAPs,
   logs) with SHA-256 hashing and timestamps for chain-of-custody, linked to
   steps/findings.
4. **User accounts and teams in the standalone app.** The standalone server has
   *no* concept of a user — the integrated router does (org + user + role).
   Independents need at least single-user auth; consultancies need teams. This
   overlaps with the security work in Part 3 and should be built once.
5. **Retest / remediation tracking.** Findings need a lifecycle (open →
   retest → fixed / risk-accepted) and the ability to diff engagements over
   time. This is what turns a one-off report into a recurring subscription.

**Tier 2 — strong differentiators**

6. **ATT&CK Navigator layer export.** Export the plan/coverage as a Navigator
   JSON layer. Cheap to build (you already hold technique IDs), and it is a
   language every blue team and competitor speaks. Pairs naturally with a
   **coverage heatmap** view.
7. **Client-facing read-only portal / shareable report links** with expiry.
   Consultancies deliver to clients; a secure share link beats emailing PDFs.
8. **ROE and report templating with org branding**, plus reusable engagement
   templates (e.g. "internal AD assessment", "external web app").
9. **Importers.** Ingest findings/hosts from Nessus, Burp, Nmap, and — the
   obvious one — **Bulwark scan results** directly into an engagement. The
   adapter already exists conceptually; make it a real import path.
10. **Playbook currency.** The technique library is static data that must be
    hand-edited. Add a documented update cadence, versioning of the playbook,
    and ideally a sync against MITRE ATT&CK releases so "keeps pace with
    tradecraft" is true in practice, not just structurally possible.

**Tier 3 — polish and scale**

11. **Collaboration**: multiple operators on one engagement, activity feed,
    comments. (Requires the auth/tenancy work first.)
12. **Metrics dashboards**: time-to-objective, technique success rates,
    coverage over time — sellable to internal red teams proving value.
13. **API tokens** for automation/CI use of the planning engine.
14. **Responsive/mobile** review of the web UI (it is desktop-first).
15. **Deployment story**: a hardened Docker image, `docker compose` with TLS
    termination, and a one-line install, matching the Bulwark platform's story.

### Positioning recommendation

- **Independents / one-person shops:** free or low-cost open-core. The
  dependency-free engine + CLI + local SQLite is a genuinely nice "just works,
  no cloud" story. Monetise with PDF/DOCX reporting, branding, and the findings
  library as a paid tier.
- **Companies (internal red teams and consultancies):** the paid product is
  teams, multi-tenant client separation, evidence storage, retest tracking,
  client portal, SSO/RBAC, and audit logging. Sell the Siege Tower + Bulwark
  bundle: *plan and document in Siege Tower, scan and enrich with Bulwark,
  one report out.* That integrated story is the differentiator neither a pure
  reporting tool (PlexTrac) nor a pure scanner has.

---

## Part 3 — Security review

Two very different security postures live in this codebase, and the difference
is the headline finding.

- **The integrated router (`backend/app/routers/siege.py`) is in good shape.**
  Every endpoint requires `get_current_user` + `get_current_org`, every query is
  scoped by `org_id`, request bodies are validated Pydantic models with length
  limits, and enums are validated. Multi-tenant separation is enforced at the
  query layer. This is the model to follow.
- **The standalone app (`siege-tower/server/`) is not safe to expose.** It has
  no authentication, no tenancy, no transport security, no encryption at rest,
  no input validation, and a stored-XSS bug in the UI. As shipped it is a
  local, single-trusted-user tool only — and the README's default `SIEGE_HOST`
  can bind it to all interfaces with none of those protections.

The engine itself is clean: no `eval`/`exec`/`subprocess`/`socket`/network
calls, and the no-execution test guard keeps it that way. The safety-by-design
claim holds. The problems are all in the standalone web/server tier and the
data it stores (client names, in-scope target IPs, authorization references,
operator names, engagement notes — all sensitive).

### Resolution status (standalone app)

All standalone findings below were closed in this branch. Summary:

| ID | Finding | Status |
| --- | --- | --- |
| C1 | No authentication | **Fixed** — bearer-token auth on every `/api` route except health/login (`server/auth.py`, `server/security.py`) |
| C2 | No tenant/client separation | **Fixed** — org model; all engagement queries scoped by `org_id` in `server/db.py` |
| C3 | Stored XSS in UI | **Fixed** — quote-safe `esc()` applied to the history list and all user fields (`web/app.js`) |
| H1 | Plaintext HTTP | **Fixed** — TLS config + non-loopback bind guard + HSTS (`server/__main__.py`, headers middleware) |
| H2 | No encryption at rest | **Fixed** — Fernet encryption of the engagement blob, key via `SIEGE_ENCRYPTION_KEY` |
| H3 | Unvalidated bodies / mass assignment | **Fixed** — typed, length-bounded Pydantic models; 1 MiB body cap |
| H4 | Unauth network exposure via `SIEGE_HOST` | **Fixed** — refuses non-loopback bind without TLS unless opted in |
| H5 | Missing CSP / security headers | **Fixed** — strict CSP (external JS) + hardening headers middleware |
| M1 | No audit log | **Fixed** — append-only `audit_log`, admin-readable at `/api/audit` |
| M2 | CSRF once cookies added | **Avoided** — header-based bearer tokens, no cookie/CSRF surface |
| M3 | No rate limiting | **Fixed** — per-IP API limit + strict login limit |
| M4 | Hard delete / UI-only retention | **Fixed** — soft delete + admin-only audited purge |
| M5 | Error text leakage | **Fixed** — generic 500s; detail logged server-side |
| L1 | `datetime.utcnow()` deprecation | **Fixed** in the standalone server (timezone-aware) |
| L2 | No authorization-reference gate | Deferred — product guardrail, tracked for phase 2 |
| L3 | CORS lockdown if a split frontend is added | Documented in `SECURITY.md` |

The details below are retained as the original review. See `SECURITY.md` for the
implemented model and `tests/test_security.py` for the executable guarantees.

### Required changes, by severity

Severity reflects a networked/product deployment. For a purely local
single-user tool, C-tier items are lower priority — but the moment this is sold
or hosted, they are release blockers.

#### CRITICAL — release blockers

**C1. No authentication on the standalone API.**
Every endpoint (`/api/engagements` read/write/delete, `/api/.../report`) is
open. Anyone who can reach the port can read, alter, or destroy all engagement
data and pull full reports. *Fix:* require authentication on all `/api/*` and
static routes. Reuse the integrated pattern — a login/session or bearer token,
verified server-side. Do not ship a networked build without it.

**C2. No multi-tenant / client separation in the standalone app.**
One flat `engagements` table; every caller sees every engagement
(`list_engagements()` returns all rows). A consultancy testing Client A and
Client B cannot keep their data apart. *Fix:* introduce owner/org scoping on
every query, exactly as `_get_owned_engagement()` does in the integrated router
(`WHERE org_id = ...`). This is both a security and a contractual/legal
requirement for testing third parties.

**C3. Stored XSS in the web UI.**
The history/launch list renders engagement fields with `innerHTML` and **no
escaping**: `web/index.html` ~line 1192 injects `h.name`, `h.client`,
`h.objective`, `h.box_type`, and `h.status` raw. An operator (or an
attacker-influenced client name) can store `<img src=x onerror=…>` and it
executes in any viewer's browser — a real cross-operator attack in a shared
instance. Additionally, the `esc()` helper (line 865) escapes only `& < >`, not
quotes, so it is insufficient in attribute contexts such as
`value="${esc(l.operator)}"` (line ~1141), which can be broken out of with a
`"`. *Fix:* escape all user-controlled values on output; use a quote-safe
escaper for attribute contexts (or set values via `textContent` /
`setAttribute` rather than string-built `innerHTML`). Audit every `innerHTML`
template for unescaped interpolation.

#### HIGH

**H1. No transport security (plaintext HTTP).**
`server/__main__.py` runs uvicorn over plain HTTP. Client names, target IPs,
authorization refs, and operator identities travel and are entered in
cleartext. *Fix:* terminate TLS (reverse proxy or uvicorn TLS), redirect HTTP→
HTTPS, and set HSTS for any hosted deployment.

**H2. No encryption at rest.**
`siege.db` is an unencrypted SQLite JSON blob of sensitive engagement data. Disk
or backup theft exposes everything. *Fix:* support encrypted storage
(SQLCipher, filesystem/volume encryption, or move to the platform's Postgres
with encryption) and document backup encryption. At minimum, restrict file
permissions (0600) and document the exposure.

**H3. Unvalidated request bodies and mass assignment.**
Standalone `create_engagement`/`update_engagement` take `data: dict = Body(...)`
with no schema. `update_engagement` merges `{**existing, **data}`, letting a
client overwrite any field except `id`. There are no size limits, so a large
JSON body is stored verbatim (storage-exhaustion DoS). *Fix:* adopt Pydantic
models with field types, `max_length`, and an allow-list of writable fields —
mirror `EngagementCreate`/`EngagementUpdate` from the integrated router. Add a
request body size limit at the server/proxy.

**H4. `SIEGE_HOST` can expose an unauthenticated app to the network.**
The default bind is `127.0.0.1` (good), but setting `SIEGE_HOST=0.0.0.0`
exposes the unauthenticated API to the LAN/internet with no other change. *Fix:*
refuse to bind to a non-loopback interface unless authentication is configured;
warn loudly on startup otherwise.

**H5. Missing security response headers / no Content-Security-Policy.**
No CSP, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`,
`Referrer-Policy`, or HSTS. The UI also pulls fonts from Google's CDN, so a CSP
must be defined deliberately. A CSP is defence-in-depth against C3. *Fix:* add a
strict CSP (self + the specific font origins, no inline script if feasible) and
the standard hardening headers via middleware.

#### MEDIUM

**M1. No audit logging / chain-of-custody trail.**
Nothing records who created, viewed, edited, or deleted an engagement or pulled
a report. For authorized-testing records that may be evidentiary, this is a
gap. *Fix:* append-only audit log of actor, action, target, timestamp.

**M2. No CSRF protection once cookie auth is added.**
Currently no auth so no CSRF surface, but state-changing endpoints (POST/PUT/
DELETE) will need CSRF defence the moment cookie-based sessions land. *Fix:* use
bearer tokens, or SameSite cookies + CSRF tokens; decide before adding C1.

**M3. No rate limiting / abuse controls.**
No throttling on any endpoint. *Fix:* per-client rate limits at the app or proxy.

**M4. Hard delete with no retention / legal-hold; "authorized data retention"
is UI-only.** `DELETE` is permanent, and the README's "client authorized data
retention" switch is a client-side toggle not enforced server-side. Engagement
records can be irrecoverably destroyed, and the retention control is
cosmetic. *Fix:* soft-delete + retention policy; enforce the retention/authorization
gate server-side, not in the browser.

**M5. Error responses echo exception text.**
E.g. `HTTPException(detail=f"Invalid ROE: {exc}")` leaks internal detail. *Fix:*
return generic client-facing messages; log detail server-side only.

#### LOW

**L1. `datetime.utcnow()` is deprecated (Py3.12)** in `server/db.py`,
`server/report.py`, and the integrated router. *Fix:* use
`datetime.now(timezone.utc)`.

**L2. No authorization-reference gate.** The tool is for authorized testing but
never requires an `authorization_ref` before planning or documenting. *Fix:*
optionally require a recorded authorization reference to create an engagement —
a guardrail that reinforces the responsible-use posture and is a selling point.

**L3. CORS must stay locked when a separate frontend is added.** Today there is
no CORS config (fine — same-origin). If a split frontend is introduced, do not
use `allow_origins=["*"]` with credentials. *Fix:* explicit origin allow-list.

### Recommended sequence

1. Fix **C3** now (self-contained, no architecture change).
2. Build auth + tenancy (**C1, C2**) once, shared by standalone and platform —
   this also unblocks the Tier-1 product work (users/teams, collaboration).
3. Ship transport + at-rest protection and input validation (**H1–H5**).
4. Layer in audit logging, retention, CSRF, rate limiting (**M-tier**).
5. Clean up the **L-tier** items opportunistically.

The fastest safe path to a product is to **make the standalone server reuse the
integrated router's security model** rather than maintaining two postures. The
engine stays shared and untouched; only the thin web/server tier needs the
hardening.
