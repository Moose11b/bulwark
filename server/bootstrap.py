"""
Bootstrap payload for the Siege Tower web UI.

Runs the standalone engine once to produce everything the browser needs:
the reference vocabulary, the full technique library (draggable pieces), the
kill-chain tactic order, and pre-computed ranked plans for every
objective/box-type combination. The UI fetches this at load instead of
embedding a snapshot, so it always reflects the installed playbook.

Pure and read-only — it computes plans, it never runs or contacts anything.
"""
from __future__ import annotations

import dataclasses
from collections import Counter

from siege_tower import BoxType, EngagementInput, Objective, build_plans
from siege_tower.capabilities import CAPABILITY_LABELS
from siege_tower.playbook import DEFAULT_PLAYBOOK
from siege_tower.schema import Platform, Restriction, Tactic
from siege_tower.tools import tools_for

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _opts(enum_cls):
    return [{"value": e.value, "label": e.value.replace("_", " ").replace("-", " ").title()}
            for e in enum_cls]


def _piece(p):
    return {
        "technique_id": p.technique_id, "name": p.name, "tactic": p.tactic.value,
        "summary": p.summary, "objective": p.objective,
        "prerequisite_note": p.prerequisite_note,
        "provides": [CAPABILITY_LABELS.get(c, c) for c in sorted(p.provides)],
        "est_minutes": p.est_minutes, "noise": p.noise, "difficulty": p.difficulty,
        "reliability": p.reliability,
        "steps": [{"action": s.action, "expected_result": s.expected_result} for s in p.steps],
        "success_indicator": p.success_indicator,
        "fallback_technique_ids": list(p.fallback_technique_ids),
        "detection": p.detection, "references": list(p.references),
        "recommended_tools": tools_for(p.technique_id, p.tactic.value),
        "platforms": sorted(pl.value for pl in p.platforms),
    }


def _result(r):
    return {
        "objective": r.objective, "goal_capability": r.goal_capability,
        "start_capabilities": r.start_capabilities,
        "excluded_count": len(r.excluded_by_constraints), "notes": r.notes,
        "options": [dataclasses.asdict(o) for o in r.options],
    }


def build_bootstrap() -> dict:
    results = {}
    for obj in Objective:
        for box in BoxType:
            roe = EngagementInput(
                objective=obj, box_type=box, time_budget_hours=40,
                allow_evidence_removal=(obj == Objective.RANSOMWARE_SIMULATION),
            )
            results[f"{obj.value}|{box.value}"] = _result(build_plans(roe))

    playbook = [_piece(p) for p in DEFAULT_PLAYBOOK]
    return {
        "reference": {
            "objectives": _opts(Objective), "box_types": _opts(BoxType),
            "platforms": _opts(Platform), "restrictions": _opts(Restriction),
        },
        "playbook": playbook,
        "tactic_order": [t for t in _TACTIC_ORDER if any(p["tactic"] == t for p in playbook)],
        "playbook_stats": {
            "total": len(DEFAULT_PLAYBOOK),
            "by_tactic": dict(Counter(p.tactic.value for p in DEFAULT_PLAYBOOK)),
        },
        "results": results,
    }
