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

| Phase | Scope | Status |
|---|---|---|
| **M1 — Tabletop core** | Intake, scenario + MSEL, console, adjudication, timeline, reports | Shipped |
| **M2 — Authoring & library** | Template library, threat-actor-driven generation, inject bank, multi-channel delivery | Shipped |
| **M3 — Multi-cell & parallel** | Fog-of-war per cell, evaluator companion, parallel/functional roll-up | Shipped |
| **M4 — Sandbox & real-time** | Authorization-gated live/technical injects (pluggable range adapter), program-level coverage analytics | Shipped |

### Sandbox, real-time & program analytics (M4)

Operational modes execute technical injects through a **pluggable range
adapter** — the shipped default is a **simulation** adapter that contacts
nothing and derives synthetic telemetry from the environment model. A live
inject is **refused unless the session carries a valid, unexpired authorization
grant whose scope covers the target** — the guardrail that keeps operational
modes in bounds.

```bash
# Create a sandbox session, authorize a scope, then run a live inject
SID=$(curl -s -X POST localhost:8000/api/sessions -H 'content-type: application/json' \
  -d '{"scenario_id":1,"name":"range run","mode":"sandbox"}' | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -X POST localhost:8000/api/sessions/$SID/authorize -H 'content-type: application/json' \
  -d '{"scope":["FIN-APP-02"],"authorized_by":"CISO","ttl_minutes":60}'
curl -X POST localhost:8000/api/sessions/$SID/live-inject -H 'content-type: application/json' \
  -d '{"technique":"T1003.001","target":"FIN-APP-02"}'   # refused for out-of-scope targets

# Program-level analytics across every scenario and run
curl localhost:8000/api/program/coverage
curl localhost:8000/api/program/improvements
```

The **program coverage** page (`/program.html`) shows ATT&CK coverage by tactic,
a per-technique table (exercised / detected / never-tested), and improvement
items that mark themselves *improved* when a later run meets a previously missed
objective.

### Multi-cell & parallel (M3)

```bash
# What one cell is allowed to see (fog of war) during a running session
curl localhost:8000/api/sessions/1/cell/blue_cell

# A per-cell redacted environment (white/grey/black box)
curl "localhost:8000/api/environments/1/view/blue_cell?scenario_id=1"

# Compare every run of a scenario (parallel / program view)
curl localhost:8000/api/scenarios/1/rollup
```

The console links two more surfaces: the **evaluator companion**
(`/evaluator.html`) — objectives with their evaluation guides, quick
observation logging, and the fog-of-war view of what a chosen cell can see —
and the **parallel roll-up** (`/rollup.html`) — per-run metrics and an ATT&CK
coverage heatmap across every run of a scenario.

### Authoring (M2)

Generate a grounded, branching scenario instead of starting from a blank MSEL:

```bash
# List the catalog
curl localhost:8000/api/catalog/actors
curl localhost:8000/api/catalog/templates

# Generate a scenario bound to an environment, then it's immediately runnable
curl -X POST localhost:8000/api/scenarios/generate \
  -H 'content-type: application/json' \
  -d '{"environment_id":1,"template_key":"ransomware_finance","name":"Q3 drill"}'
```

The generator walks a threat actor's kill-chain, picks real target assets from
the environment for each phase, and wires valid branches to good/bad
resolutions. Refine the draft with `PATCH /api/scenarios/{id}` and
`PATCH /api/injects/{id}`, and preview any inject in its channel with
`GET /api/injects/{id}/delivery`. The facilitator console exposes generation
(empty-state) and delivery preview (on the scene).

## Responsible use

Gauntlet is for designing and running **defensive** exercises against an
environment you own or are explicitly authorized to test. Adversary techniques
are modelled only to build the exercise — not as operational guidance against
systems you do not control. Real-time modes that could touch production stay
gated behind explicit rules of engagement.
