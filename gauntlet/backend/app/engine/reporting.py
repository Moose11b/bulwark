"""Render one exercise timeline through different audience lenses.

Nobody re-keys findings: the executive summary, the technical hotwash, the GRC
evidence package, and the training-gap view are all projections of the same
append-only timeline plus the evaluators' observations.
"""
from __future__ import annotations

from datetime import datetime
from typing import Sequence

AUDIENCES = {
    "executive": "Executive Summary",
    "technical": "Technical Hotwash",
    "grc": "Compliance Evidence Package",
    "training": "Capability & Training Gaps",
}

_RATING_LABEL = {"met": "Met", "partial": "Partially met", "missed": "Not met", "note": "Note"}


def _metrics(events: Sequence) -> dict:
    injects = [e for e in events if e.kind == "inject_fired"]
    adjuds = [e for e in events if e.kind == "adjudication"]
    detected = [e for e in adjuds if e.payload.get("detected")]
    missed = [e for e in adjuds if not e.payload.get("detected")]
    ttds = [
        e.payload.get("time_to_detect_min")
        for e in detected
        if e.payload.get("time_to_detect_min") is not None
    ]
    techniques = sorted(
        {t for e in adjuds for t in (e.payload.get("techniques") or [])}
    )
    gaps = sorted(
        {t for e in missed for t in (e.payload.get("techniques") or [])}
    )
    return {
        "injects": len(injects),
        "decisions": len([e for e in events if e.kind == "decision"]),
        "adjudications": len(adjuds),
        "detected": len(detected),
        "missed": len(missed),
        "mttd": round(sum(ttds) / len(ttds), 1) if ttds else None,
        "techniques_exercised": techniques,
        "coverage_gaps": gaps,
    }


def _objective_lines(objectives: Sequence, observations: Sequence) -> list[str]:
    by_obj: dict[str, list] = {}
    for o in observations:
        by_obj.setdefault(o.objective_code, []).append(o)
    lines = []
    for obj in objectives:
        obs = by_obj.get(obj.code, [])
        ratings = [o.rating for o in obs if o.rating in _RATING_LABEL]
        if "missed" in ratings:
            verdict = "Not met"
        elif "partial" in ratings:
            verdict = "Partially met"
        elif "met" in ratings:
            verdict = "Met"
        else:
            verdict = "Not assessed"
        lines.append(f"- **{obj.code} — {obj.title}:** {verdict}")
    return lines


def _timeline_lines(events: Sequence) -> list[str]:
    out = []
    for e in events:
        clock = e.game_clock or "--:--"
        if e.kind == "inject_fired":
            out.append(f"- `{clock}` **Inject {e.ref}** — {e.payload.get('title', '')}")
        elif e.kind == "decision":
            out.append(f"- `{clock}` Decision → {e.payload.get('label', e.payload.get('goto', ''))}")
        elif e.kind == "adjudication":
            verdict = "DETECTED" if e.payload.get("detected") else "MISSED"
            out.append(f"- `{clock}` Adjudication [{verdict}] — {e.payload.get('rationale', '')}")
        elif e.kind == "note":
            out.append(f"- `{clock}` Note — {e.payload.get('text', '')}")
        elif e.kind == "status":
            out.append(f"- `{clock}` Status → {e.payload.get('status', '')}")
    return out


def build_report(session, scenario, environment, events, observations, audience: str):
    """Return ``(title, markdown)`` for the requested audience."""
    audience = audience if audience in AUDIENCES else "executive"
    m = _metrics(events)
    when = datetime.utcnow().strftime("%Y-%m-%d")
    head = f"# {scenario.name} — {AUDIENCES[audience]}\n"
    meta = (
        f"_Exercise session: **{session.name}** · Type: {scenario.exercise_type} · "
        f"Generated {when}_\n\n"
        f"> This is an exercise record. Control mappings indicate relevance for "
        f"remediation and are not a compliance attestation.\n"
    )

    if audience == "executive":
        gaps = ", ".join(m["coverage_gaps"]) or "none of note"
        body = (
            f"## Bottom line\n\n"
            f"The team ran **{m['injects']} injects** against a {scenario.threat_actor or 'threat'} "
            f"scenario. Of {m['adjudications']} adversary actions adjudicated, "
            f"**{m['detected']} were detected** and **{m['missed']} went unnoticed**"
            + (f", with a mean time-to-detect of **{m['mttd']} minutes**" if m["mttd"] is not None else "")
            + ".\n\n"
            f"## Objectives\n\n" + "\n".join(_objective_lines(scenario.objectives, observations)) + "\n\n"
            f"## Where we were exposed\n\n"
            f"Techniques that went undetected: **{gaps}**. These are the priority "
            f"gaps for the improvement plan below.\n\n"
            f"## Improvement commitments\n\n"
            f"{_improvement_block(observations)}\n"
        )
    elif audience == "technical":
        body = (
            f"## Metrics\n\n"
            f"| Metric | Value |\n|---|---|\n"
            f"| Injects fired | {m['injects']} |\n"
            f"| Proctor decisions | {m['decisions']} |\n"
            f"| Actions adjudicated | {m['adjudications']} |\n"
            f"| Detected / missed | {m['detected']} / {m['missed']} |\n"
            f"| Mean time-to-detect | {m['mttd'] if m['mttd'] is not None else 'n/a'} min |\n"
            f"| ATT&CK techniques exercised | {', '.join(m['techniques_exercised']) or 'n/a'} |\n"
            f"| Coverage gaps | {', '.join(m['coverage_gaps']) or 'none'} |\n\n"
            f"## Full timeline\n\n" + "\n".join(_timeline_lines(events)) + "\n\n"
            f"## Evaluator observations\n\n" + _observation_block(observations) + "\n"
        )
    elif audience == "grc":
        body = (
            f"## Exercise evidence\n\n"
            f"- **Scenario:** {scenario.name}\n"
            f"- **Threat modelled:** {scenario.threat_actor or 'n/a'}\n"
            f"- **Scope:** {scenario.scope or 'n/a'}\n"
            f"- **Rules of engagement:** {scenario.rules_of_engagement or 'n/a'}\n"
            f"- **Environment under test:** {environment.name} ({environment.sector})\n"
            f"- **Injects delivered:** {m['injects']}\n"
            f"- **Adversary actions adjudicated:** {m['adjudications']}\n\n"
            f"## Objectives assessed\n\n"
            + "\n".join(_objective_lines(scenario.objectives, observations)) + "\n\n"
            f"## Attestation trail\n\n"
            f"The full exercise is recorded on a hash-chained, append-only timeline "
            f"({len(events)} events). This record demonstrates that an incident-response "
            f"exercise was designed, conducted, and evaluated — evidence relevant to "
            f"controls that mandate periodic testing (e.g. PCI-DSS 12.10.2, ISO 27001 "
            f"A.5.24–A.5.30, SOC 2 CC7.x).\n"
        )
    else:  # training
        body = (
            f"## Capability gaps observed\n\n"
            + (_gap_block(observations) or "_No gaps flagged by evaluators._\n")
            + "\n## Undetected techniques → drill next\n\n"
            + ("\n".join(f"- {t}" for t in m["coverage_gaps"]) or "_None._")
            + "\n"
        )

    return f"{scenario.name} — {AUDIENCES[audience]}", head + meta + "\n" + body


def _observation_block(observations: Sequence) -> str:
    if not observations:
        return "_No observations recorded._"
    return "\n".join(
        f"- **[{_RATING_LABEL.get(o.rating, o.rating)}]** ({o.objective_code or 'general'}) {o.note}"
        for o in observations
    )


def _improvement_block(observations: Sequence) -> str:
    items = [o for o in observations if o.rating in ("missed", "partial")]
    if not items:
        return "_No improvement items flagged._"
    return "\n".join(f"- {o.note} _(owner: TBD · due: TBD)_" for o in items)


def _gap_block(observations: Sequence) -> str:
    items = [o for o in observations if o.rating in ("missed", "partial")]
    return "\n".join(f"- ({o.objective_code or 'general'}) {o.note}" for o in items)
