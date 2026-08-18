# ⛨ Bulwark

**Fortify · Detect · Defend**

Dynamic application security testing (DAST) built to run as a CI/CD pipeline gate. Point it at a running app, get findings mapped to OWASP / MITRE ATT&CK / compliance frameworks, and fail the build when something dangerous ships — with native GitHub Security tab integration via SARIF.

[![CI](https://github.com/moose11b/bulwark/actions/workflows/ci.yml/badge.svg)](https://github.com/moose11b/bulwark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/moose11b/bulwark?sort=semver)](https://github.com/moose11b/bulwark/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blue)]()

---

## 30-second start

Add a security gate to any GitHub workflow:

```yaml
- name: Bulwark DAST gate
  uses: moose11b/bulwark@v1
  with:
    target: http://localhost:3000
    fail-on: high
```

Findings show up in your repo's **Security → Code scanning** tab. The build fails if anything `high` or above is found. No account, no database, no security team required.

Or run it anywhere with Docker:

```bash
docker run --rm --network host ghcr.io/moose11b/bulwark-cli:latest \
  scan http://localhost:3000 --fail-on high --sarif results.sarif
```

---

## Why it exists

Pipeline security tooling skews two ways: heavyweight SAST/SCA scanners, or DAST products that a security team owns and developers never touch. Bulwark is the missing middle — **dynamic scanning of a running app that a developer drops into a pipeline in three lines.** It's the kind of tool the enterprise platforms (Tenable, Qualys, Rapid7) are repeatedly dinged for *not* being: simple, fast, and free to start.

- **Pipeline-native** — one command, sensible exit codes, SARIF output
- **API-aware** — point it at an OpenAPI/Swagger spec (`--api-spec`) and it checks whether endpoints declared as secured actually enforce it (BOLA, broken auth, error handling)
- **Diff-aware** — gate on **new** findings only (`--baseline` + `--fail-on-new`), with reviewable, expiring suppressions in `.bulwark.yml`
- **Zero infrastructure** — no database, agents, or account for the core scan
- **Findings with context** — OWASP Top 10, MITRE ATT&CK, Cyber Kill Chain, and four compliance frameworks (PCI-DSS v4.0, ISO 27001:2022, NIST CSF 2.0, CIS Controls v8)
- **Real CVE intelligence** — CVSS (NVD), exploit probability (EPSS), active-exploitation flags (CISA KEV)
- **SSRF-safe by design** — refuses to scan internal, loopback, and cloud-metadata addresses

-> **Full CLI & Action docs: [README-cli.md](README-cli.md)**

---

## What's in this repo

Bulwark has two faces that share one scan engine:

### 1. The CLI / GitHub Action  *(free, open source - start here)*
A lean, standalone scanner for pipelines and local use. No external dependencies — the scan engine runs, classifies findings, and emits SARIF/JSON with nothing but the container. This is what the Action and `ghcr.io/moose11b/bulwark-cli` ship.

### 2. The Bulwark Platform  *(self-hostable full stack)*
The same engine wrapped in a multi-tenant web application: a FastAPI backend, Next.js dashboard, PostgreSQL, and Celery workers. It adds scan history, live progress, scheduled scans, trend dashboards, threat-intel feed syncing (MITRE ATT&CK + AlienVault OTX), PDF reporting, and team/RBAC features. Run it with `docker compose up`.

The CLI can optionally report results to a platform instance (`--report-to <token>`), but never requires one.

---

## Architecture

```
+-------------------------------------------------------+
|              Shared scan engine                       |
|  Nmap . TLS . headers . DNS . Nikto . Nuclei .        |
|  exposure . Shodan                                    |
|  -> OWASP / ATT&CK / kill-chain / compliance mapping  |
|  -> NVD + EPSS + CISA KEV enrichment                  |
+---------------+-------------------+---------------------+
                |                   |
     standalone_engine.py    scan_orchestrator.py
        (no DB / no I/O)      (Postgres + Redis + Celery)
                |                   |
        +-------+------+     +------+-----------+
        |  CLI / Action |     |  Bulwark Platform |
        |  SARIF . JSON |     |  Dashboard . API  |
        +---------------+     +-------------------+
```

The split is deliberate: the engine is decoupled from storage so it runs in a 3-line CI step *or* behind a full web platform, with identical findings either way.

---

## Tech stack

**Engine & CLI:** Python 3.12, async scanners, SARIF 2.1.0 output
**Platform backend:** FastAPI, SQLAlchemy (async), PostgreSQL, Celery + Redis, Clerk auth
**Platform frontend:** Next.js 15, React 19, TailwindCSS
**Scanners:** Nmap, Nikto, Nuclei, plus native TLS/header/DNS/exposure modules
**Packaging:** Docker, GitHub Actions (multi-arch builds to GHCR)

---

## Scan profiles

| Profile | Scanners | Use |
|---------|----------|-----|
| `headers` | security headers, HSTS, CSP, cookies | fast PR gate (~10s) |
| `web` | headers + TLS + Nikto + Nuclei | default, balanced |
| `network` | port scan + TLS posture | infrastructure checks |
| `api` | headers + TLS + OpenAPI-driven endpoint checks | REST/JSON APIs |
| `full` | everything + DNS + exposure + API | scheduled deep scans |

---

## Running the full platform

```bash
cp .env.example .env     # add your Clerk keys (see .env.example)
docker compose up --build
# dashboard -> http://localhost:3001
# API docs  -> http://localhost:8000/docs
```

---

## Authentication

Bulwark authenticates API requests with signed JWTs, verified against a
**configured** issuer — a token's own issuer claim never decides which keys to
trust.

- **Clerk** (default): set `CLERK_PUBLISHABLE_KEY`; the trusted issuer is
  derived from it, or set `CLERK_ISSUER` to override.
- **Self-hosted OIDC**: set `OIDC_ISSUER` (and `OIDC_CLIENT_ID`) to use your
  own provider — Keycloak, Authentik, Authelia, or any OIDC-compliant IdP.
  With `OIDC_AUTO_PROVISION=true`, a user is created on first valid login; the
  first user into the default organisation becomes its admin.

## Upgrading

Schema changes are managed by Alembic and applied automatically on startup.

Upgrading from v1.0.x needs no manual step: those installs predate Alembic, so
the first start detects the existing tables, stamps them at the baseline
revision, and applies anything newer. Migrations run behind a Postgres advisory
lock, so bringing up the API and workers together is safe.

To apply migrations manually instead:

```bash
docker compose exec backend alembic upgrade head
```

Take a database backup before upgrading, as with any schema change.

## Responsible use

Only scan systems you own or are explicitly authorised to test. Unauthorised scanning may be illegal. Bulwark blocks internal/loopback/metadata addresses by default, but you are responsible for having permission to scan any target.

**On compliance:** control mappings show which framework controls a finding is *relevant to*. They aid remediation prioritisation and are **not** a compliance assessment, audit, or attestation.

---

## License

MIT — see [LICENSE](LICENSE). Bundled open-source scanners (Nmap, Nikto, Nuclei) retain their own licenses.
