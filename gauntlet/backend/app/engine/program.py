"""Program-level analytics (M4): coverage and improvement tracking across the
whole exercise program — every scenario and every run, not just one scenario.

The question this answers: across everything we've drilled, which ATT&CK
tactics and techniques do we keep exercising and detecting, and which have we
never tested? And what improvement items are still open?
"""
from __future__ import annotations

# Minimal technique -> ATT&CK tactic map covering the techniques this product's
# catalog and seed use. Extend as the inject bank grows.
TECHNIQUE_TACTIC = {
    "T1566.001": "Initial Access", "T1566.002": "Initial Access", "T1190": "Initial Access",
    "T1078": "Initial Access", "T1204.002": "Execution", "T1059.001": "Execution",
    "T1071.001": "Command and Control", "T1003.001": "Credential Access",
    "T1021": "Lateral Movement", "T1021.002": "Lateral Movement",
    "T1098": "Privilege Escalation", "T1074": "Collection", "T1005": "Collection",
    "T1048": "Exfiltration", "T1041": "Exfiltration", "T1486": "Impact",
    "T1490": "Impact", "T1656": "Impact", "T1657": "Impact",
}


def _tactic_for(technique: str) -> str:
    return TECHNIQUE_TACTIC.get(technique, "Uncategorized")


def build_program_coverage(scenarios, sessions) -> dict:
    """Technique and tactic coverage across the whole program."""
    # Which scenarios reference each technique.
    technique_scenarios: dict[str, set] = {}
    for scn in scenarios:
        for inj in scn.injects:
            for t in inj.attack_techniques or []:
                technique_scenarios.setdefault(t, set()).add(scn.id)

    # Which techniques were ever exercised / detected across all sessions.
    exercised: dict[str, int] = {}
    detected: dict[str, int] = {}
    for s in sessions:
        for e in s.events:
            if e.kind == "adjudication":
                for t in e.payload.get("techniques") or []:
                    exercised[t] = exercised.get(t, 0) + 1
                    if e.payload.get("detected"):
                        detected[t] = detected.get(t, 0) + 1

    techniques = []
    for t in sorted(technique_scenarios):
        techniques.append({
            "technique": t,
            "tactic": _tactic_for(t),
            "scenarios": len(technique_scenarios[t]),
            "exercised": exercised.get(t, 0),
            "detected": detected.get(t, 0),
            "tested": t in exercised,
        })

    # Group into tactics.
    tactics: dict[str, dict] = {}
    for row in techniques:
        tac = tactics.setdefault(row["tactic"], {"tactic": row["tactic"], "techniques": 0, "tested": 0, "detected": 0})
        tac["techniques"] += 1
        if row["tested"]:
            tac["tested"] += 1
        if row["detected"]:
            tac["detected"] += 1

    return {
        "scenarios": len(list(scenarios)),
        "sessions": len(list(sessions)),
        "techniques": techniques,
        "tactics": sorted(tactics.values(), key=lambda x: x["tactic"]),
        "never_tested": [r["technique"] for r in techniques if not r["tested"]],
    }


def build_improvements(scenarios, sessions) -> dict:
    """Open improvement items: objectives observed as missed or partial, with a
    per-objective trend across successive runs of the same scenario."""
    scenario_name = {scn.id: scn.name for scn in scenarios}
    objective_title = {
        (scn.id, o.code): o.title for scn in scenarios for o in scn.objectives
    }

    # Per (scenario, objective): the session ids at which it was met, so a later
    # 'met' can mark an earlier gap as improved.
    met_at: dict[tuple, list[int]] = {}
    for s in sessions:
        for o in s.observations:
            if o.rating == "met":
                met_at.setdefault((s.scenario_id, o.objective_code), []).append(s.id)

    items = []
    for s in sorted(sessions, key=lambda x: x.id):
        for o in s.observations:
            if o.rating not in ("missed", "partial"):
                continue
            key = (s.scenario_id, o.objective_code)
            improved = any(later > s.id for later in met_at.get(key, []))
            items.append({
                "scenario_id": s.scenario_id,
                "scenario": scenario_name.get(s.scenario_id, "?"),
                "session_id": s.id,
                "session": s.name,
                "objective_code": o.objective_code,
                "objective": objective_title.get(key, o.objective_code),
                "rating": o.rating,
                "note": o.note,
                "status": "improved" if improved else "open",
            })

    open_count = sum(1 for it in items if it["status"] == "open")
    return {"items": items, "open": open_count, "total": len(items)}
