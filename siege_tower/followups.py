"""
Follow-up suggestions for a failed step.

When a technique fails or is blocked mid-engagement, the team needs another way
forward. This module answers, deterministically and without running anything:
"that step didn't work — what else reaches the same goal from here?"

It draws on three things the engine already models:
  * the play's own curated ``fallback_technique_ids`` (the hand-picked
    "if it fails, try this"),
  * the capability graph — other in-scope plays that *provide* a capability the
    failed step would have granted (a functional alternative), and
  * reachability — whether, after taking a candidate, the objective is still
    reachable at all (so the team isn't sent down a dead end).

Everything is filtered by the same Rules-of-Engagement constraints as the main
planner, so a suggestion never violates the scope. Pure computation: no network,
no subprocess, no target contact.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capabilities import CAPABILITY_LABELS, GOAL_CAPABILITY
from .engine import _reachable, filter_playbook, start_capabilities
from .playbook import DEFAULT_PLAYBOOK
from .schema import EngagementInput, Play


@dataclass(frozen=True)
class FollowupSuggestion:
    technique_id: str
    name: str
    tactic: str
    summary: str
    reason: str
    is_fallback: bool          # a curated fallback of the failed technique
    ready_now: bool            # its prerequisites are already satisfied
    keeps_path_open: bool      # the objective is still reachable if taken
    provides: list[str]        # capability labels this grants
    noise: int
    difficulty: int
    reliability: int
    est_minutes: int


def _fit(p: Play) -> float:
    """Higher is better: reward reliability, penalise noise and difficulty."""
    return p.reliability * 4.0 - p.noise * 2.0 - p.difficulty * 2.0


def suggest_followups(
    failed_technique_id: str,
    inp: EngagementInput,
    achieved: set[str] | list[str] | None = None,
    playbook: list[Play] | None = None,
    limit: int = 6,
) -> list[FollowupSuggestion]:
    """Rank alternative techniques to try after ``failed_technique_id`` fails.

    ``achieved`` is the set of capability tokens the team already holds from
    steps that have succeeded so far (in addition to the box-type baseline and
    provided access). It drives the ``ready_now`` and ``keeps_path_open`` flags.
    """
    playbook = playbook if playbook is not None else DEFAULT_PLAYBOOK
    by_id = {p.technique_id: p for p in playbook}
    failed = by_id.get(failed_technique_id)

    allowed, _ = filter_playbook(playbook, inp)
    goal = GOAL_CAPABILITY.get(inp.objective.value)

    have = start_capabilities(inp)
    if achieved:
        have = set(have) | set(achieved)

    # The capabilities the failed step would have delivered — the gap to fill.
    gap = set(failed.provides) if failed else set()

    # tid -> (play, reason, is_fallback)
    candidates: dict[str, tuple[Play, str, bool]] = {}

    # 1) Curated fallbacks for the failed technique (exact or sub-technique family).
    if failed:
        for fid in failed.fallback_technique_ids:
            for p in allowed:
                if p.technique_id == fid or p.technique_id.startswith(fid + "."):
                    candidates.setdefault(
                        p.technique_id,
                        (p, f"Curated fallback for {failed.technique_id}", True),
                    )

    # 2) Functional alternatives: any in-scope play that provides a capability
    #    the failed step would have granted.
    if gap:
        for p in allowed:
            if failed and p.technique_id == failed.technique_id:
                continue
            shared = gap & set(p.provides)
            if shared:
                labels = ", ".join(sorted(CAPABILITY_LABELS.get(c, c) for c in shared))
                candidates.setdefault(
                    p.technique_id, (p, f"Alternative route to: {labels}", False)
                )

    # 3) If we can't tell what the failed step provided (unknown technique, or a
    #    play with no capability effects), fall back to "what can we do now that
    #    still leads to the objective" — ready, goal-advancing plays.
    if not candidates:
        for p in allowed:
            if failed and p.technique_id == failed.technique_id:
                continue
            if p.requires <= have and p.provides - have:
                candidates.setdefault(
                    p.technique_id, (p, "Available next move toward the objective", False)
                )

    out: list[FollowupSuggestion] = []
    for tid, (p, reason, is_fb) in candidates.items():
        ready = p.requires <= have
        new_state = have | set(p.provides)
        keeps = bool(goal) and (goal in new_state or _reachable(allowed, new_state, goal))
        out.append(FollowupSuggestion(
            technique_id=p.technique_id,
            name=p.name,
            tactic=p.tactic.value,
            summary=p.summary,
            reason=reason,
            is_fallback=is_fb,
            ready_now=ready,
            keeps_path_open=keeps,
            provides=[CAPABILITY_LABELS.get(c, c) for c in sorted(p.provides)],
            noise=p.noise,
            difficulty=p.difficulty,
            reliability=p.reliability,
            est_minutes=p.est_minutes,
        ))

    # Curated fallbacks first, then goal-preserving and ready options, then fit;
    # technique id last for a stable, deterministic order.
    out.sort(key=lambda s: (
        0 if s.is_fallback else 1,
        0 if s.keeps_path_open else 1,
        0 if s.ready_now else 1,
        -(s.reliability * 4.0 - s.noise * 2.0 - s.difficulty * 2.0),
        s.technique_id,
    ))
    return out[:limit]
