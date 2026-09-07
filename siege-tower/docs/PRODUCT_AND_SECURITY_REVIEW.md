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
