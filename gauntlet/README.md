# Gauntlet

**A dungeon master for security exercises.** Gauntlet turns what a security team
already knows about its own environment — defenses, detections, policies, traps,
and training — into a living tabletop exercise that a proctor steers as it
unfolds, then reports on for every audience that needs to learn from it.

> **Working title.** "Gauntlet" is a placeholder — a trial of readiness, and a
> piece of armor. Rename with a single find-and-replace.

This is the **tabletop-first** reference implementation. It is a standalone
product with no dependency on any other system. See
[`docs/design.html`](docs/design.html) (open in a browser) or
[`docs/DESIGN.md`](docs/DESIGN.md) for the full design brief.

---

## What it does

- **Intake** — model the environment under test: assets, controls, detections,
  playbooks, policies, personnel, deception assets, and crown jewels, with
  per-audience visibility (white / grey / black box).
- **Scenario + MSEL** — a scenario carries objectives and a Master Scenario
  Events List: an ordered, **branching** set of injects. Branches fire on a
  player action, a game-clock timeout, or the proctor's choice.
- **Conduct** — the facilitator console presents the current inject, offers the
  branches, and drives the exercise forward.
- **Adjudication** — rule a player action against the environment's control
  coverage. Transparent, deterministic, explainable, and always overridable by
  the proctor.
- **Tamper-evident timeline** — every step is written to an append-only,
  hash-chained log that can be verified.
- **Reports** — one timeline, four audience lenses: executive, technical (SOC/IR),
  GRC/audit evidence, and training gaps.

A worked example — a finance-sector ransomware tabletop (*Operation Frostbite*)
— is seeded on first run so the whole loop works immediately.

---

## Run it

```bash
cd gauntlet/backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

Then open:

- **Facilitator console** — <http://localhost:8000/>
- **API docs (OpenAPI)** — <http://localhost:8000/docs>

Zero infrastructure: it uses a local SQLite file by default. Point
`GAUNTLET_DB_URL` at Postgres to scale out.

## Test

```bash
cd gauntlet/backend && . .venv/bin/activate
python -m pytest -q
```

---

## Layout

```
gauntlet/
├── backend/
│   ├── app/
│   │   ├── main.py            FastAPI app + console host
│   │   ├── models.py          ORM domain model
│   │   ├── schemas.py         API contract (Pydantic)
│   │   ├── timeline.py        append-only, hash-chained log
│   │   ├── seed.py            worked ransomware tabletop
│   │   ├── engine/
│   │   │   ├── msel.py         branching MSEL logic
│   │   │   ├── adjudication.py rule an action vs. the environment
│   │   │   └── reporting.py    audience-tailored reports
│   │   └── api/               environments · scenarios · sessions · reports
│   └── tests/                 engine unit tests + API end-to-end
├── web/                       facilitator console (served SPA)
└── docs/                      design brief (HTML + Markdown)
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GAUNTLET_DB_URL` | `sqlite:///…/gauntlet.db` | Database URL (SQLite or Postgres) |
| `GAUNTLET_SEED` | `1` | Load the worked example on an empty database |

---

## Roadmap

| Phase | Scope |
|---|---|
| **M1 — Tabletop core** *(this build)* | Intake, scenario + MSEL, console, adjudication, timeline, reports |
| M2 — Authoring & library | Template library, threat-actor-driven generation, inject bank, multi-channel delivery |
| M3 — Multi-cell & parallel | Fog-of-war per cell, evaluator companion, parallel/functional modes |
| M4 — Sandbox & real-time | Cyber-range hooks, live technical injects, program-level coverage analytics |

## Responsible use

Gauntlet is for designing and running **defensive** exercises against an
environment you own or are explicitly authorized to test. Adversary techniques
are modelled only to build the exercise — not as operational guidance against
systems you do not control. Real-time modes that could touch production stay
gated behind explicit rules of engagement.
