# Siege Tower

**A rules + [MITRE ATT&CK](https://attack.mitre.org/) engagement planner for authorized red teams — a standalone app that plans and documents, and never runs anything.**

Siege Tower turns a structured Rules of Engagement (ROE) into a small set of
ranked, ATT&CK-mapped attack plans, lets a team **drag technique "pieces" into
their own line of march** like a commander laying counters on a campaign map,
then **walks the engagement step by step and documents every move** — compiling
the field report as it goes.

> **What this is — and isn't.** Siege Tower is a **planner and documenter** for
> authorized assessments. It **suggests** which techniques and tools fit an
> objective and **records** what the team did. It does **not** execute anything,
> launch any tool, or connect to any target, and it has **no ability to read or
> move data** from a client's systems. Use it strictly within a signed scope
> and Rules of Engagement.

The planning **engine is a dependency-free Python package** with no network or
subprocess access, so the planning logic *cannot act on a target* — that safety
posture is structural, not just a promise.

---

## Quickstart

```bash
git clone https://github.com/MooseArsenal/SiegeTower.git
cd SiegeTower
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[server]"

# Generate an at-rest encryption key and choose an admin password.
export SIEGE_ENCRYPTION_KEY="$(python -m server.security keygen)"
export SIEGE_ADMIN_PASSWORD="choose-a-strong-password"

# Run the app, then open http://127.0.0.1:8000 and sign in as `admin`.
python -m server        # or: siege-tower-server   (SIEGE_RELOAD=1 for autoreload)
```

The app requires authentication. On first run it creates one organization and
an `admin` user (password from `SIEGE_ADMIN_PASSWORD`, or generated and printed
once to the log). Engagements are isolated per organization, and the stored data
is encrypted at rest when `SIEGE_ENCRYPTION_KEY` is set. See
[SECURITY.md](SECURITY.md) for the full security model and configuration.

Prefer the terminal? The engine ships a CLI with no dependencies at all:

```bash
pip install -e .
python -m siege_tower.cli --objective domain_admin --box grey
```

Engagements you save are stored in a local SQLite file (`siege.db`, git-ignored) —
it never leaves your machine and holds only what you type.

## What you get

- **Launch page** — start a new engagement, or review past ones (with progress),
  gated behind a "client authorized data retention" switch.
- **Scope** — enter the ROE as tiles: objective, box type, in-scope platforms,
  restrictions, time budget, adversary to emulate.
- **Plan** — 3–5 ranked, ATT&CK-mapped approaches, scored on fit to your ROE
  (time, stealth, reliability), each explaining *why* it was offered.
- **Build** — drag pieces from the technique library into your own ordered plan;
  reorder, trim, or extend it to any length.
- **Execute** — walk the plan step by step and document each move: outcome,
  operator, timestamps, notes, evidence references, and targets touched, with a
  live progress bar. When a step is marked **failed or blocked**, Siege Tower
  surfaces ranked **follow-up techniques** — curated fallbacks plus functional
  alternatives that reach the same capability and keep a path to the objective
  open — each addable to the plan in one click.
- **Field report** — compiled from the ROE, the plan, and the log, as JSON or
  Markdown.

## Project structure

```
siege_tower/        # the planning engine — zero dependencies, importable anywhere
  playbook.py       #   the ATT&CK-mapped technique library (data, not code)
  plays_ext.py      #   breadth: more initial access, cloud, email, impact …
  tools.py          #   suggested tooling per technique
  engine.py         #   the deterministic capability-graph planner
  cli.py            #   standalone command-line interface
server/             # a thin FastAPI app wrapping the engine (SQLite persistence)
web/                # the planner UI (fetches from the server; no build step)
integrations/bulwark/   # how to embed the engine in a larger platform
tests/              # engine + API tests
```

## API

All endpoints are planning/documentation only — none execute anything or contact a target.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/api/bootstrap` | reference vocab, technique library, ranked plans |
| `POST` | `/api/plan` | rank plans for one ROE payload |
| `POST` | `/api/followups` | suggest alternatives after a step fails (ATT&CK-mapped) |
| `GET`  | `/api/engagements/{id}/navigator` | export a MITRE ATT&CK Navigator layer (JSON) |
| `POST/GET/DELETE` | `/api/engagements/{id}/shares`, `/api/shares/{id}` | create / list / revoke read-only client links |
| `GET`  | `/api/share/{token}` (public) | client-facing read-only report + `/download` |
| `GET`  | `/api/engagements` | list saved engagements (with progress) |
| `POST` | `/api/engagements` | save a new engagement |
| `GET/PUT/DELETE` | `/api/engagements/{id}` | read / update / remove one |
| `GET`  | `/api/engagements/{id}/report?format=json\|markdown\|docx\|pdf` | compile the report (branded DOCX/PDF include findings) |
| `GET/POST/PUT/DELETE` | `/api/findings`, `/api/library` | findings & reusable findings library |
| `POST/GET` | `/api/evidence` (+`/{id}/download`) | upload / fetch evidence (hashed, encrypted) |
| `GET`  | `/api/cvss?vector=...` | CVSS v3.1 score + severity |
| `GET/PUT` `POST/DELETE` | `/api/branding` (+`/logo`) | org report branding: colours, company, footer, logo (admin) |

## Keeping the playbook current

The technique library is **data** (`siege_tower/playbook.py` + `plays_ext.py`),
not hardcoded UI. Add or edit `Play` entries and the API, the drag-and-drop
palette, and the recommended plans all pick them up — so the tool keeps pace as
tradecraft advances. Bring your own `Play` list to replace it entirely.

The playbook is **versioned** (`siege_tower/version.py`) and validated against
MITRE ATT&CK. Check for drift (revoked / deprecated / renumbered techniques)
with the built-in currency tool:

```bash
python -m siege_tower.attack_sync --fetch        # against the latest ATT&CK
```

A weekly GitHub Action runs this automatically. The app shows the ATT&CK and
playbook versions on the launch screen. See [docs/PLAYBOOK.md](docs/PLAYBOOK.md)
for the update policy and cadence.

## Integrating with a larger platform

A host app can import the engine directly instead of running this server — see
[`integrations/bulwark/`](integrations/bulwark/README.md).

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
