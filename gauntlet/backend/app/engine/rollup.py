"""Parallel roll-up: compare every run of one scenario.

When several teams run the same scenario (parallel or functional exercises), or
one team runs it over successive quarters, the value is in the comparison — who
detected what, how fast, and which ATT&CK techniques the program keeps missing.
"""
from __future__ import annotations

from .reporting import _metrics


def _objectives_met(observations) -> int:
    met = set()
    for o in observations:
        if o.rating == "met":
            met.add(o.objective_code or "general")
    return len(met)


def build_rollup(scenario, sessions) -> dict:
    """Aggregate metrics and ATT&CK coverage across a scenario's sessions."""
    scenario_techniques = sorted(
        {t for inj in scenario.injects for t in (inj.attack_techniques or [])}
    )

    session_rows = []
    detected_by_technique: dict[str, int] = {t: 0 for t in scenario_techniques}

    for s in sessions:
        events = list(s.events)
        m = _metrics(events)
        session_rows.append({
            "id": s.id,
            "name": s.name,
            "status": s.status,
            "injects": m["injects"],
            "adjudications": m["adjudications"],
            "detected": m["detected"],
            "missed": m["missed"],
            "mttd": m["mttd"],
            "coverage_gaps": m["coverage_gaps"],
            "objectives_met": _objectives_met(list(s.observations)),
        })
        # Which techniques did this session detect at least once?
        for e in events:
            if e.kind == "adjudication" and e.payload.get("detected"):
                for t in e.payload.get("techniques") or []:
                    if t in detected_by_technique:
                        detected_by_technique[t] += 1

    total_sessions = len(session_rows)
    technique_coverage = [
        {
            "technique": t,
            "injects": sum(1 for inj in scenario.injects if t in (inj.attack_techniques or [])),
            "sessions_detected": detected_by_technique[t],
            "sessions_total": total_sessions,
        }
        for t in scenario_techniques
    ]

    detected_totals = sum(r["detected"] for r in session_rows)
    adjud_totals = sum(r["adjudications"] for r in session_rows)
    mttds = [r["mttd"] for r in session_rows if r["mttd"] is not None]

    return {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "sessions": session_rows,
        "technique_coverage": technique_coverage,
        "totals": {
            "sessions": total_sessions,
            "adjudications": adjud_totals,
            "detected": detected_totals,
            "detection_rate": round(detected_totals / adjud_totals, 2) if adjud_totals else None,
            "mean_mttd": round(sum(mttds) / len(mttds), 1) if mttds else None,
        },
    }
