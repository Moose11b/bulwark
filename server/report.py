"""
Engagement report compiler for the standalone app.

Compiles the report from a stored engagement (its ROE, the built plan, and the
per-step documentation) into a structured dict and Markdown. Pure and
side-effect free — it reformats what the team entered; it runs nothing and
reads no client systems.
"""
from __future__ import annotations

from datetime import datetime

_RESOLVED = {"succeeded", "fell_back", "failed", "blocked", "skipped"}
_TACTIC_LABEL = {
    "reconnaissance": "Reconnaissance", "initial-access": "Initial Access",
    "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "credential-access": "Credential Access",
    "discovery": "Discovery", "lateral-movement": "Lateral Movement",
    "collection": "Collection", "command-and-control": "C2",
    "exfiltration": "Exfiltration", "impact": "Impact",
}
_OUTCOME_LABEL = {
    "attempted": "Attempted", "succeeded": "Succeeded", "fell_back": "Fell back",
    "failed": "Failed", "blocked": "Blocked", "skipped": "Skipped", "not_started": "Not started",
}


def build_report(eng: dict, pb: dict) -> dict:
    plan = eng.get("plan", [])
    logs = eng.get("logs", {})
    steps = []
    worked = 0
    exercised, succeeded, operators = set(), set(), set()
    by_outcome: dict[str, int] = {}
    for i, slot in enumerate(plan):
        tid = slot.get("tid")
        p = pb.get(tid, {"name": tid, "tactic": ""})
        log = logs.get(slot.get("uid"), {}) or {}
        oc = log.get("outcome") or "not_started"
        by_outcome[oc] = by_outcome.get(oc, 0) + 1
        if oc in _RESOLVED and oc != "skipped":
            worked += 1
        if tid:
            exercised.add(tid)
            if oc in ("succeeded", "fell_back"):
                succeeded.add(tid)
        if log.get("operator"):
            operators.add(log["operator"])
        steps.append({
            "index": i, "technique_id": tid, "name": p.get("name"),
            "tactic": p.get("tactic"), "outcome": oc,
            "operator": log.get("operator", ""), "notes": log.get("notes", ""),
            "evidence": log.get("evidence", []), "targets": log.get("targets", []),
            "started_at": log.get("startedAt"), "completed_at": log.get("completedAt"),
        })
    total = len(plan)
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "engagement": {k: eng.get(k) for k in (
            "id", "name", "client", "authorization_ref", "objective", "box_type", "status")},
        "roe": {k: eng.get(k) for k in (
            "scope_platforms", "in_scope_targets", "out_of_scope", "restrictions",
            "time_budget_hours")},
        "coverage": {
            "total_steps": total, "steps_worked": worked,
            "coverage_pct": round(100.0 * worked / total, 1) if total else 0.0,
        },
        "summary": {
            "by_outcome": by_outcome,
            "techniques_exercised": sorted(exercised),
            "techniques_succeeded": sorted(succeeded),
            "operators": sorted(operators),
        },
        "steps": steps,
    }


def render_markdown(rep: dict) -> str:
    e, roe, cov = rep["engagement"], rep["roe"], rep["coverage"]
    out = [f"# Engagement Report — {e.get('name') or 'Untitled'}", "",
           f"*Generated {(rep.get('generated_at') or '')[:16].replace('T', ' ')} · Siege Tower*", "",
           "> Authorized red-team assessment record. Planning and documentation only.", "",
           "## Overview", ""]
    out += [f"- **Client:** {e.get('client') or '—'}",
            f"- **Authorization:** {e.get('authorization_ref') or '—'}",
            f"- **Objective:** {_lbl(e.get('objective'))}",
            f"- **Box type:** {_lbl(e.get('box_type'))}",
            f"- **Status:** {_lbl(e.get('status'))}", "",
            "## Rules of engagement", "",
            f"- **In-scope platforms:** {_join(roe.get('scope_platforms'))}",
            f"- **In-scope targets:** {_join(roe.get('in_scope_targets'))}",
            f"- **Restrictions:** {_join(roe.get('restrictions')) or 'None'}",
            f"- **Time budget:** {roe.get('time_budget_hours') or '—'} h", "",
            "## Execution coverage", "",
            f"- **Coverage:** {cov['coverage_pct']}% ({cov['steps_worked']} of {cov['total_steps']} steps worked)"]
    bo = rep["summary"]["by_outcome"]
    if bo:
        out.append(f"- **By outcome:** " + ", ".join(f"{_lbl(k)}: {v}" for k, v in sorted(bo.items())))
    out += ["", "## Execution log", ""]
    if not rep["steps"]:
        out.append("_No steps documented._")
    for s in rep["steps"]:
        when = (s.get("started_at") or "")[:16].replace("T", " ")
        out.append(f"### {s['index']+1}. {s['name']} — {_lbl(s['outcome'])}")
        meta = [f"{s['technique_id']}", _TACTIC_LABEL.get(s['tactic'], s['tactic'])]
        if s.get("operator"):
            meta.append(f"operator {s['operator']}")
        if when:
            meta.append(when)
        out.append("*" + " · ".join(meta) + "*")
        if s.get("notes"):
            out += ["", s["notes"]]
        if s.get("evidence"):
            out.append(f"*Evidence:* {_join(s['evidence'])}")
        out.append("")
    return "\n".join(out)


def _lbl(v):
    return str(v).replace("_", " ").replace("-", " ").title() if v else "—"


def _join(v):
    return ", ".join(str(x) for x in (v or [])) or "—"
