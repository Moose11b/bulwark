"""
MITRE ATT&CK Navigator layer export.

Turns an engagement's plan (and its documented outcomes) plus its findings into
a Navigator layer JSON that a blue/purple team can open at
https://mitre-attack.github.io/attack-navigator/ — techniques coloured by what
actually happened (worked / attempted / failed / planned). Pure data mapping.
"""
from __future__ import annotations

_OUTCOME = {
    "succeeded": ("#3E7A5A", 100, "Worked"),
    "fell_back": ("#3E7A5A", 90, "Worked (fell back)"),
    "attempted": ("#B08814", 60, "Attempted"),
    "failed": ("#9C2B1B", 30, "Failed"),
    "blocked": ("#9C2B1B", 30, "Blocked"),
    "skipped": ("#828A7B", 10, "Skipped"),
    "planned": ("#3E6B72", 40, "Planned"),
    "not_started": ("#3E6B72", 40, "Planned"),
}


def build_layer(engagement: dict, plays_by_id: dict, findings: list | None = None) -> dict:
    plan = engagement.get("plan", []) or []
    logs = engagement.get("logs", {}) or {}
    name = (engagement.get("name") or "Siege Tower engagement")[:255]

    techniques: dict[str, dict] = {}

    for slot in plan:
        tid = slot.get("tid")
        if not tid:
            continue
        play = plays_by_id.get(tid)
        log = logs.get(slot.get("uid"), {}) or {}
        oc = log.get("outcome") or "planned"
        color, score, _label = _OUTCOME.get(oc, _OUTCOME["planned"])
        comment = (play.name if play else tid) + f" — {oc.replace('_', ' ')}"
        meta = [{"name": "outcome", "value": oc}]
        if log.get("operator"):
            meta.append({"name": "operator", "value": log["operator"]})
        entry = {
            "techniqueID": tid, "score": score, "color": color,
            "comment": comment, "enabled": True, "metadata": meta,
            "showSubtechniques": "." in tid,
        }
        if play is not None:
            entry["tactic"] = play.tactic.value
        techniques[tid] = entry

    # Techniques cited by findings that aren't already in the plan.
    for f in (findings or []):
        for tid in (f.get("technique_ids") or []):
            if tid in techniques:
                techniques[tid].setdefault("metadata", []).append(
                    {"name": "finding", "value": f.get("title") or ""})
                continue
            play = plays_by_id.get(tid)
            entry = {
                "techniqueID": tid, "score": 70, "color": "#B0472C",
                "comment": "Finding: " + (f.get("title") or ""), "enabled": True,
                "metadata": [{"name": "finding", "value": f.get("title") or ""}],
                "showSubtechniques": "." in tid,
            }
            if play is not None:
                entry["tactic"] = play.tactic.value
            techniques[tid] = entry

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Exported from Siege Tower — planning and documentation only.",
        "techniques": list(techniques.values()),
        "gradient": {"colors": ["#EFE1D6", "#B0472C"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Worked", "color": "#3E7A5A"},
            {"label": "Attempted", "color": "#B08814"},
            {"label": "Failed / blocked", "color": "#9C2B1B"},
            {"label": "Planned", "color": "#3E6B72"},
            {"label": "Finding", "color": "#B0472C"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2C3540",
        "selectTechniquesAcrossTactics": True,
        "sorting": 0,
        "hideDisabled": False,
    }
