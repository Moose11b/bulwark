"""
Siege Tower report compiler.

Assembles an engagement report from three plain inputs — the engagement (its
ROE), the generated plans, and the execution log the team wrote — into a
structured dict and a Markdown document.

Pure and side-effect free: it takes already-serialized dicts, touches no
database, runs nothing, and reaches no network. It only reformats what the team
has already entered, which is what "compile the results" means for a planner.
"""
from __future__ import annotations

from datetime import datetime

# Best-to-worst ordering so a step's overall outcome is the strongest thing
# recorded against it.
_OUTCOME_RANK = {
    "succeeded": 6,
    "fell_back": 5,
    "attempted": 4,
    "failed": 3,
    "blocked": 2,
    "skipped": 1,
    "not_started": 0,
}
# Outcomes that count as "the step was worked" for coverage.
_WORKED = {"succeeded", "fell_back", "attempted", "failed", "blocked"}


def build_report(engagement: dict, plans: list[dict], logs: list[dict]) -> dict:
    """Compile the structured engagement report."""
    selected = next((p for p in plans if p.get("is_selected")), None)
    alternatives = [
        {"plan_key": p["plan_key"], "title": p.get("title", "")}
        for p in plans if not p.get("is_selected")
    ]

    coverage = _coverage(selected, logs) if selected else None
    summary = _summary(logs, coverage)
    timeline = sorted(
        logs,
        key=lambda e: (e.get("started_at") or e.get("created_at") or ""),
    )

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "engagement": {
            "id": engagement.get("id"),
            "name": engagement.get("name"),
            "client_name": engagement.get("client_name"),
            "authorization_ref": engagement.get("authorization_ref"),
            "objective": engagement.get("objective"),
            "box_type": engagement.get("box_type"),
            "status": engagement.get("status"),
        },
        "roe": {
            "scope_platforms": engagement.get("scope_platforms", []),
            "in_scope_targets": engagement.get("in_scope_targets", []),
            "out_of_scope": engagement.get("out_of_scope", []),
            "provided_access": engagement.get("provided_access", []),
            "restrictions": engagement.get("restrictions", []),
            "forbidden_technique_ids": engagement.get("forbidden_technique_ids", []),
            "forbidden_tactics": engagement.get("forbidden_tactics", []),
            "time_budget_hours": engagement.get("time_budget_hours"),
            "allow_evidence_removal": engagement.get("allow_evidence_removal"),
            "emulate_adversary": engagement.get("emulate_adversary"),
            "roe_notes": engagement.get("roe_notes"),
        },
        "selected_plan": selected,
        "alternative_plans": alternatives,
        "coverage": coverage,
        "summary": summary,
        "timeline": timeline,
        "plan_meta": engagement.get("last_plan_meta", {}),
    }


def _coverage(plan: dict, logs: list[dict]) -> dict:
    """Per-step best outcome for the selected plan, plus a coverage percentage."""
    plan_key = plan.get("plan_key")
    steps = plan.get("steps", [])
    per_step = []
    worked_count = 0
    for i, step in enumerate(steps):
        matches = [
            e for e in logs
            if e.get("plan_key") == plan_key
            and (e.get("step_index") == i or e.get("technique_id") == step.get("technique_id"))
        ]
        best = _best_outcome(matches)
        if best in _WORKED:
            worked_count += 1
        per_step.append({
            "step_index": i,
            "technique_id": step.get("technique_id"),
            "name": step.get("name"),
            "best_outcome": best,
            "entry_count": len(matches),
        })
    total = len(steps)
    return {
        "plan_key": plan_key,
        "total_steps": total,
        "steps_worked": worked_count,
        "coverage_pct": round(100.0 * worked_count / total, 1) if total else 0.0,
        "per_step": per_step,
    }


def _best_outcome(entries: list[dict]) -> str:
    best = "not_started"
    for e in entries:
        oc = e.get("outcome", "not_started")
        if _OUTCOME_RANK.get(oc, 0) > _OUTCOME_RANK.get(best, 0):
            best = oc
    return best


def _summary(logs: list[dict], coverage: dict | None) -> dict:
    by_outcome: dict[str, int] = {}
    exercised: set[str] = set()
    succeeded: set[str] = set()
    operators: set[str] = set()
    for e in logs:
        oc = e.get("outcome", "not_started")
        by_outcome[oc] = by_outcome.get(oc, 0) + 1
        tid = e.get("technique_id")
        if tid:
            exercised.add(tid)
            if oc in ("succeeded", "fell_back"):
                succeeded.add(tid)
        if e.get("operator"):
            operators.add(e["operator"])
    return {
        "total_entries": len(logs),
        "by_outcome": by_outcome,
        "techniques_exercised": sorted(exercised),
        "techniques_succeeded": sorted(succeeded),
        "operators": sorted(operators),
        "coverage_pct": coverage["coverage_pct"] if coverage else None,
    }


# ── Markdown rendering ───────────────────────────────────────────

def _fmt_dt(value) -> str:
    return value.replace("T", " ")[:16] if isinstance(value, str) else "—"


def render_markdown(report: dict) -> str:
    e = report["engagement"]
    roe = report["roe"]
    out: list[str] = []

    out.append(f"# Engagement Report — {e.get('name') or 'Untitled'}")
    out.append("")
    out.append(f"*Generated {_fmt_dt(report.get('generated_at'))} · Siege Tower*")
    out.append("")
    out.append("> Authorized red-team assessment record. Planning and "
               "documentation only — Siege Tower runs nothing and stores no "
               "data taken from client systems.")
    out.append("")

    # Overview
    out.append("## Overview")
    out.append("")
    out.append(f"- **Client:** {e.get('client_name') or '—'}")
    out.append(f"- **Authorization:** {e.get('authorization_ref') or '—'}")
    out.append(f"- **Objective:** {_label(e.get('objective'))}")
    out.append(f"- **Box type:** {_label(e.get('box_type'))}")
    out.append(f"- **Status:** {_label(e.get('status'))}")
    out.append("")

    # Rules of Engagement
    out.append("## Rules of Engagement")
    out.append("")
    out.append(f"- **In-scope platforms:** {_join(roe.get('scope_platforms'))}")
    out.append(f"- **In-scope targets:** {_join(roe.get('in_scope_targets'))}")
    out.append(f"- **Out of scope:** {_join(roe.get('out_of_scope'))}")
    out.append(f"- **Provided access:** {_join(roe.get('provided_access'))}")
    out.append(f"- **Restrictions:** {_join(roe.get('restrictions'))}")
    forb = list(roe.get("forbidden_technique_ids") or []) + list(roe.get("forbidden_tactics") or [])
    out.append(f"- **Forbidden techniques/tactics:** {_join(forb)}")
    budget = roe.get("time_budget_hours")
    out.append(f"- **Time budget:** {f'{budget} h' if budget else '—'}")
    out.append(f"- **Evidence removal allowed:** {'yes' if roe.get('allow_evidence_removal') else 'no'}")
    if roe.get("emulate_adversary"):
        out.append(f"- **Adversary emulated:** {roe['emulate_adversary']}")
    if roe.get("roe_notes"):
        out.append(f"- **Notes:** {roe['roe_notes']}")
    out.append("")

    # Summary
    s = report["summary"]
    out.append("## Execution summary")
    out.append("")
    if s.get("coverage_pct") is not None:
        out.append(f"- **Selected-plan coverage:** {s['coverage_pct']}%")
    out.append(f"- **Log entries:** {s['total_entries']}")
    if s["by_outcome"]:
        parts = ", ".join(f"{_label(k)}: {v}" for k, v in sorted(s["by_outcome"].items()))
        out.append(f"- **By outcome:** {parts}")
    out.append(f"- **Techniques exercised:** {_join(s['techniques_exercised'])}")
    out.append(f"- **Techniques succeeded:** {_join(s['techniques_succeeded'])}")
    if s["operators"]:
        out.append(f"- **Operators:** {_join(s['operators'])}")
    out.append("")

    # Selected plan + coverage
    plan = report.get("selected_plan")
    cov = report.get("coverage")
    if plan:
        out.append(f"## Selected plan — {plan.get('title', plan.get('plan_key'))}")
        out.append("")
        if plan.get("rationale"):
            for r in plan["rationale"]:
                out.append(f"- {r}")
            out.append("")
        cov_by_index = {c["step_index"]: c for c in (cov["per_step"] if cov else [])}
        out.append("| # | Technique | Step | Outcome | Entries |")
        out.append("| --- | --- | --- | --- | --- |")
        for i, step in enumerate(plan.get("steps", [])):
            c = cov_by_index.get(i, {})
            out.append(
                f"| {i+1} | {step.get('technique_id')} — {step.get('name')} "
                f"| {step.get('summary', '')} | {_label(c.get('best_outcome', 'not_started'))} "
                f"| {c.get('entry_count', 0)} |"
            )
        out.append("")
    else:
        out.append("## Selected plan")
        out.append("")
        out.append("_No plan selected yet._")
        out.append("")

    if report.get("alternative_plans"):
        alts = ", ".join(f"{a['plan_key']} ({a['title']})" for a in report["alternative_plans"])
        out.append(f"*Alternative plans considered:* {alts}")
        out.append("")

    # Timeline / execution log
    out.append("## Execution log")
    out.append("")
    if not report["timeline"]:
        out.append("_No actions documented yet._")
        out.append("")
    for entry in report["timeline"]:
        when = _fmt_dt(entry.get("started_at") or entry.get("created_at"))
        head = f"### {when} · {entry.get('title', 'Action')} — {_label(entry.get('outcome'))}"
        out.append(head)
        meta = []
        if entry.get("technique_id"):
            meta.append(f"technique {entry['technique_id']}")
        if entry.get("operator"):
            meta.append(f"operator {entry['operator']}")
        if entry.get("targets"):
            meta.append(f"targets {_join(entry['targets'])}")
        if meta:
            out.append(f"*{' · '.join(meta)}*")
        if entry.get("notes"):
            out.append("")
            out.append(entry["notes"])
        if entry.get("evidence_refs"):
            out.append("")
            out.append(f"*Evidence:* {_join(entry['evidence_refs'])}")
        out.append("")

    return "\n".join(out)


def _label(value) -> str:
    if not value:
        return "—"
    return str(value).replace("_", " ").replace("-", " ").title()


def _join(values) -> str:
    values = [str(v) for v in (values or [])]
    return ", ".join(values) if values else "—"
