# Siege Tower

**A rules + ATT&CK attack-plan builder for authorized red teams.**

Siege Tower turns a structured Rules of Engagement (ROE) into a small set of
ranked, [MITRE ATT&CK](https://attack.mitre.org/)-mapped attack plans. Each plan
is broad at the top — an ordered kill chain — and drills down into concrete
commands, expected results, a success indicator, and a fallback technique for
every step. The reasoning behind each plan is written out, so the output is an
auditable engagement artifact, not a black box.

It is a **standalone program** (library + CLI) with a **zero-dependency core**
(standard library only), designed to also drop into the
[Bulwark](../README.md) platform as a library.

> **Authorized use only.** Siege Tower plans offensive security engagements. Use
> it strictly within a signed scope and Rules of Engagement. The commands in the
> playbook are illustrative starting points for sanctioned testing.

---

## Why it exists

Red teams lose time assembling each engagement by hand: re-deriving the kill
chain, pulling technique detail from scattered references, and writing the plan
and the report separately. Siege Tower accelerates the **build → execute →
document** loop so a team can run more engagements without cutting corners.

## How the engine works

The engine is a **deterministic capability-graph planner** — explicitly *not* a
model. That matters for a red-team artifact: the same ROE always produces the
same plans, and every step can be traced to the rule that put it there.

The seed playbook (`playbook.py` + `plays_ext.py`) spans ~49 ATT&CK-mapped
plays across the kill chain — reconnaissance, initial access, execution,
persistence, privilege escalation, credential access, discovery, lateral
movement, collection, exfiltration, and impact — including full cloud (Entra
ID / M365) and hybrid on-prem-to-cloud chains. It is data, not code: bring your
own `Play` list to extend or replace it (see below).

1. **Start state.** The box type (black / grey / white) sets a baseline of
   starting *capabilities*; the access the client granted (`provided_access`:
   named creds, a VPN handle, source code) is added on top.
2. **Constraint filter.** Every play is checked against the ROE — in-scope
   platforms, forbidden techniques/tactics, phishing / exploitation / DoS /
   brute-force restrictions, and whether evidence removal or destructive actions
   are permitted. Each excluded play is recorded *with its reason* for the audit
   trail.
3. **Search.** Plays form a graph: each one *requires* a set of capabilities and
   *provides* another. The engine searches for chains that carry the team from
   the start state to the goal capability implied by the objective, then reduces
   each chain to a minimal spine where every step is load-bearing.
4. **Rank.** Each distinct plan is scored on time-fit, stealth, reliability,
   difficulty, and adversary-emulation match, and the best 3–5 are returned with
   a plain-language rationale and warnings.

### Objectives → goal capability

| Objective                | Goal reached                         |
| ------------------------ | ------------------------------------ |
| `initial_foothold`       | Code execution on a host             |
| `domain_admin`           | Domain-wide privileged control       |
| `data_exfiltration`      | Sensitive data exfiltrated           |
| `ransomware_simulation`  | Impact demonstrated (simulated)      |
| `cloud_takeover`         | Cloud / tenant admin                 |
| `email_compromise`       | Mailbox / messaging access           |

## Install

```bash
cd siege-tower
pip install -e ".[dev]"     # editable install with pytest
# or just run it in place — the core needs no dependencies
```

## CLI usage

```bash
# Black-box, aim for Domain Admin, no phishing, 40-hour window, Markdown brief
python -m siege_tower.cli --objective domain_admin --box black \
    --scope windows,active_directory --restrict no_phishing --hours 40

# Grey-box from a saved ROE file, emulate APT29, JSON out
python -m siege_tower.cli --roe examples/engagement.json --emulate APT29 --format json
```

Flags override values from `--roe`, so a saved engagement can be tweaked
per-run. See `python -m siege_tower.cli --help` for the full list.

## Library usage

```python
from siege_tower import EngagementInput, Objective, BoxType, Platform, build_plans
from siege_tower import plan_result_to_markdown

roe = EngagementInput(
    objective=Objective.DOMAIN_ADMIN,
    box_type=BoxType.BLACK,
    scope_platforms=[Platform.WINDOWS, Platform.ACTIVE_DIRECTORY],
    time_budget_hours=40,
    emulate_adversary="APT29",
)

result = build_plans(roe)
for opt in result.options:
    print(opt.plan_id, opt.fit_score, opt.title)

print(plan_result_to_markdown(result))   # full engagement brief
```

`build_plans` returns a `PlanResult` dataclass; `plan_result_to_dict` gives a
JSON-serialisable form for an API or storage.

## ROE file schema

All keys are optional except `objective`.

```json
{
  "objective": "domain_admin",
  "box_type": "grey",
  "scope_platforms": ["windows", "active_directory"],
  "provided_access": ["domain_user", "internal_network"],
  "restrictions": ["no_phishing", "stealth_required"],
  "forbidden_technique_ids": ["T1486"],
  "forbidden_tactics": ["impact"],
  "time_budget_hours": 40,
  "allow_evidence_removal": false,
  "emulate_adversary": "APT29",
  "max_plans": 5,
  "objective_note": "Prove reach to the finance DB."
}
```

## Bringing your own playbook

The seed playbook (`siege_tower/playbook.py`) is **data, not code**. Pass your
own list of `Play` objects to override it:

```python
from siege_tower import build_plans, Play
my_plays = [ ... ]
result = build_plans(roe, playbook=my_plays)
```

This is the integration seam: a host can build `Play` objects from its own
tradecraft library or from live ATT&CK data and feed them straight in.

## Integrating into Bulwark

The core engine imports nothing from Bulwark, so integration is a thin adapter,
not a rewrite:

- **Data.** Bulwark already syncs live ATT&CK techniques
  (`MitreTechnique`). An adapter can enrich or generate `Play` objects from that
  table and pass them as a custom playbook, keeping technique names and links
  current.
- **API.** Wrap `build_plans` in a FastAPI router under `/api/siege`, persist
  `EngagementInput` and `PlanResult` per organisation, and reuse Bulwark's auth
  and audit-log conventions.
- **Reporting.** `plan_result_to_markdown` feeds Bulwark's existing report
  generator so an engagement plan sits alongside scan findings.

These are deliberately kept out of this package so it stays standalone.

## Tests

```bash
python -m pytest
```

The suite is pure logic (no network, DB, or tools) and pins the guarantees that
make the output trustworthy: the ROE constrains the plans, box type changes the
start state, every plan is legal and minimal, destructive actions are gated on
permission, and the same ROE is reproducible.

## Roadmap

- macOS and OT/ICS playbook depth to match the Windows/AD and cloud chains.
- Adapter package for Bulwark (router, persistence, ATT&CK-sourced plays).
- Execution tracking: mark steps attempted / succeeded / fell back, and compile
  results into the final report.
