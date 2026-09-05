"""
Siege Tower — output rendering.

Turns a PlanResult into (a) a JSON-serialisable dict for APIs and storage, and
(b) a Markdown engagement brief for humans. The Markdown is the documentation
pillar: broad plan up top, every step drillable into its commands, expected
results, success indicator, fallback technique, and detection notes.
"""
from __future__ import annotations

from dataclasses import asdict

from .schema import PlanResult


def plan_result_to_dict(result: PlanResult) -> dict:
    """Full, JSON-serialisable representation (safe for an API response)."""
    return asdict(result)


def _fmt_minutes(minutes: int) -> str:
    hours = minutes / 60.0
    if hours < 1:
        return f"{minutes} min"
    return f"~{hours:.1f} h"


def plan_result_to_markdown(result: PlanResult, roe_summary: str | None = None) -> str:
    """Render a PlanResult as a Markdown engagement brief."""
    out: list[str] = []
    out.append("# Siege Tower — Engagement Attack Plan")
    out.append("")
    out.append(f"**Objective:** {result.objective}  ")
    out.append(f"**Goal capability:** {result.goal_capability}  ")
    out.append(f"**Starting capabilities:** {', '.join(result.start_capabilities) or 'none'}  ")
    out.append(f"**Plays considered (in-scope):** {result.considered_play_count}")
    if roe_summary:
        out.append("")
        out.append(f"> {roe_summary}")
    out.append("")

    if result.notes:
        out.append("## Notes")
        for n in result.notes:
            out.append(f"- {n}")
        out.append("")

    if not result.options:
        out.append("_No plans were generated. See notes above._")
        out.append("")
    for opt in result.options:
        out.append(f"## {opt.plan_id.upper()} · {opt.title}")
        out.append("")
        out.append(f"**Fit score:** {opt.fit_score}/100  ")
        out.append(f"**Estimated total effort:** {_fmt_minutes(opt.est_total_minutes)}  ")
        budget = {True: "yes", False: "NO", None: "n/a"}[opt.within_time_budget]
        out.append(f"**Within time budget:** {budget}  ")
        out.append(f"**Mean noise:** {opt.aggregate_noise}/5 · **Max difficulty:** {opt.max_difficulty}/5  ")
        out.append(f"**Kill-chain coverage:** {' → '.join(opt.covered_tactics)}")
        out.append("")

        if opt.rationale:
            out.append("**Why this plan:**")
            for r in opt.rationale:
                out.append(f"- {r}")
            out.append("")
        if opt.warnings:
            out.append("**Warnings:**")
            for w in opt.warnings:
                out.append(f"- ⚠️ {w}")
            out.append("")

        out.append("### Steps (broad)")
        for i, step in enumerate(opt.steps, start=1):
            out.append(
                f"{i}. **{step.technique_id} — {step.name}** "
                f"(_{step.tactic}_, {_fmt_minutes(step.est_minutes)}) — {step.summary}"
            )
        out.append("")

        out.append("### Steps (detailed)")
        for i, step in enumerate(opt.steps, start=1):
            out.append(f"#### {i}. {step.technique_id} — {step.name}")
            if step.objective:
                out.append(f"*Objective:* {step.objective}")
            if step.prerequisite_note:
                out.append(f"*Prerequisite:* {step.prerequisite_note}")
            if step.provides:
                out.append(f"*Gains:* {', '.join(step.provides)}")
            out.append(
                f"*Noise {step.noise}/5 · Difficulty {step.difficulty}/5 · "
                f"Reliability {step.reliability}/5*"
            )
            if step.steps:
                out.append("")
                out.append("| Command | What it does | Expected result |")
                out.append("| --- | --- | --- |")
                for s in step.steps:
                    cmd = s["command"].replace("|", "\\|")
                    desc = s["description"].replace("|", "\\|")
                    exp = s["expected_result"].replace("|", "\\|")
                    out.append(f"| `{cmd}` | {desc} | {exp} |")
            if step.success_indicator:
                out.append("")
                out.append(f"*Success indicator:* {step.success_indicator}")
            if step.fallback_technique_ids:
                out.append(f"*If it fails, fall back to:* {', '.join(step.fallback_technique_ids)}")
            if step.detection:
                out.append(f"*Blue-team detection:* {step.detection}")
            if step.references:
                out.append(f"*References:* {', '.join(step.references)}")
            out.append("")

    if result.excluded_by_constraints:
        out.append("## Excluded by the Rules of Engagement")
        out.append("")
        out.append("_These plays were dropped before planning; recorded for the audit trail._")
        out.append("")
        for ex in result.excluded_by_constraints:
            out.append(f"- {ex}")
        out.append("")

    return "\n".join(out)
