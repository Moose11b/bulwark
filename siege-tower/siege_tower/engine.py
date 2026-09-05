"""
Siege Tower — the rules + ATT&CK planning engine.

Given a structured Rules of Engagement (EngagementInput), the engine:

  1. Derives the *starting capabilities* from the box type and the access the
     client granted.
  2. Filters the playbook against the ROE (scope, forbidden techniques/tactics,
     phishing/exploitation/DoS restrictions, evidence-removal rules), recording
     exactly why each excluded play was dropped.
  3. Searches the surviving plays as a capability graph — each play consumes a
     set of capabilities and produces another — for chains that carry the team
     from the start state to the goal capability implied by the objective.
  4. Scores every distinct chain on time-fit, stealth, reliability, difficulty
     and adversary match, and returns the best 3-5 as ranked plans with a
     plain-language, auditable rationale.

The whole thing is deterministic and explainable by design: no model, no
randomness. The same ROE always yields the same ranked plans, and every plan
can point at the rule that put each step there — which is what a red-team
artifact needs.
"""
from __future__ import annotations

import itertools

from .capabilities import BOX_TYPE_BASELINE, CAPABILITY_LABELS, GOAL_CAPABILITY
from .playbook import DEFAULT_PLAYBOOK, playbook_by_id
from .schema import (
    EngagementInput, PlanOption, PlanResult, PlanStepView, Play, Restriction,
)

# Depth ceiling for the chain search — well beyond any realistic hand-run
# kill chain, but bounds the search on a pathological playbook.
_MAX_DEPTH = 9
# Hard cap on distinct chains kept before ranking, so a large playbook can't
# blow up the search.
_MAX_CHAINS = 400
# Ceiling on DFS node expansions. A reachable-but-branchy playbook can have an
# enormous search tree; this bounds worst-case time even when few solutions are
# found. Deterministic technique-ID ordering means we still explore the same
# nodes first every run.
_MAX_EXPANSIONS = 150_000

# Which Play boolean flag each friendly restriction gates.
_RESTRICTION_FLAG = {
    Restriction.NO_PHISHING: "is_phishing",
    Restriction.NO_SOCIAL_ENGINEERING: "is_social_engineering",
    Restriction.NO_EXPLOITATION: "is_exploitation",
    Restriction.NO_DENIAL_OF_SERVICE: "is_denial_of_service",
    Restriction.NO_CREDENTIAL_BRUTEFORCE: "is_credential_bruteforce",
    Restriction.NO_PERSISTENCE: "is_persistence",
}


# ── Starting state ───────────────────────────────────────────────

def start_capabilities(inp: EngagementInput) -> set[str]:
    """Capabilities the team holds before the first action.

    Box type sets a baseline; anything in `provided_access` (named creds, a
    VPN handle, a workstation, source) is unioned on top.
    """
    caps = set(BOX_TYPE_BASELINE.get(inp.box_type.value, set()))
    caps.update(inp.provided_access)
    return caps


# ── Constraint filtering ─────────────────────────────────────────

def _exclusion_reason(play: Play, inp: EngagementInput) -> str | None:
    """Return why this play is disallowed by the ROE, or None if it is legal."""
    # Hard-forbidden technique IDs (exact or sub-technique family, e.g. a ban on
    # "T1558" also removes "T1558.003").
    for fid in inp.forbidden_technique_ids:
        if play.technique_id == fid or play.technique_id.startswith(fid + "."):
            return f"forbidden technique {fid}"

    if play.tactic in inp.forbidden_tactics:
        return f"forbidden tactic {play.tactic.value}"

    # Platform scope: a scoped-out play (no in-scope platform) is dropped.
    if inp.scope_platforms and play.platforms:
        if play.platforms.isdisjoint(inp.scope_platforms):
            plats = "/".join(sorted(p.value for p in play.platforms))
            return f"out of scope (platforms: {plats})"

    # Friendly ROE restriction switches.
    for restriction in inp.restrictions:
        flag = _RESTRICTION_FLAG.get(restriction)
        if flag and getattr(play, flag, False):
            return restriction.value

    # Evidence handling: destructive or cleanup-requiring plays need permission.
    if (play.destructive or play.requires_evidence_removal) and not inp.allow_evidence_removal:
        return "evidence removal / destructive action not permitted"

    return None


def filter_playbook(
    playbook: list[Play], inp: EngagementInput
) -> tuple[list[Play], list[str]]:
    """Split a playbook into (allowed, excluded-reasons) under the ROE."""
    allowed: list[Play] = []
    excluded: list[str] = []
    for play in playbook:
        reason = _exclusion_reason(play, inp)
        if reason:
            excluded.append(f"{play.technique_id} ({play.name}): {reason}")
        else:
            allowed.append(play)
    return allowed, excluded


# ── Chain search ─────────────────────────────────────────────────

def _reachable(plays: list[Play], start: set[str], goal: str) -> bool:
    """True if `goal` is reachable from `start` at all, ignoring order/one-use.

    A cheap fixpoint over the union of every applicable play's effects. If the
    goal is not in this closure, no ordered chain can reach it either — so the
    expensive DFS can be skipped entirely. This is what keeps an impossible
    objective (e.g. a destructive goal with destructive plays all forbidden)
    from triggering a full combinatorial search that never finds a solution.
    """
    closure = set(start)
    changed = True
    while changed:
        changed = False
        for play in plays:
            if play.requires.issubset(closure) and not play.provides.issubset(closure):
                closure |= play.provides
                changed = True
        if goal in closure:
            return True
    return goal in closure


def _search_chains(
    plays: list[Play], start: set[str], goal: str
) -> list[list[Play]]:
    """Enumerate distinct play chains from `start` to a state containing `goal`.

    Forward depth-first search over capability states. A play is applicable
    only when the operator already holds all of its `requires`, and only if it
    expands the state (adds a capability not already held) — that prunes no-op
    recon loops and guarantees termination. The search is bounded by a solution
    cap, a depth cap, and a node-expansion budget so a large playbook can never
    blow up the running time.
    """
    if not _reachable(plays, start, goal):
        return []

    # Deterministic order so identical inputs yield identical plans.
    ordered = sorted(plays, key=lambda p: p.technique_id)
    chains: list[list[Play]] = []
    seen_sequences: set[tuple[str, ...]] = set()
    budget = [_MAX_EXPANSIONS]

    def dfs(state: set[str], path: list[Play]):
        if len(chains) >= _MAX_CHAINS or budget[0] <= 0:
            return
        if goal in state:
            key = tuple(p.technique_id for p in path)
            if key not in seen_sequences:
                seen_sequences.add(key)
                chains.append(list(path))
            return
        if len(path) >= _MAX_DEPTH:
            return
        used = {p.technique_id for p in path}
        for play in ordered:
            if budget[0] <= 0:
                return
            if play.technique_id in used:
                continue
            if not play.requires.issubset(state):
                continue
            if play.provides.issubset(state):  # would not expand the state
                continue
            budget[0] -= 1
            dfs(state | play.provides, path + [play])

    dfs(set(start), [])
    return chains


def _chain_valid(chain: list[Play], start: set[str], goal: str) -> bool:
    """True if replaying `chain` in order from `start` reaches `goal` legally."""
    state = set(start)
    for play in chain:
        if not play.requires.issubset(state):
            return False
        state |= play.provides
    return goal in state


def _minimize_chain(path: list[Play], start: set[str], goal: str) -> list[Play]:
    """Reduce an ordered path to a minimal coherent chain that reaches `goal`.

    A forward search can pad a chain with plays that expand the capability state
    but do not contribute to the objective (staging data on the way to Domain
    Admin, or a second foothold added only for an adversary-match bonus). A play
    is redundant when the chain still reaches the goal without it; dropping such
    plays one at a time until none remain leaves a spine where every step is
    load-bearing, so the reasons for each step hold up.
    """
    chain = list(path)
    changed = True
    while changed:
        changed = False
        for i in range(len(chain)):
            trial = chain[:i] + chain[i + 1:]
            if _chain_valid(trial, start, goal):
                chain = trial
                changed = True
                break
    return chain


# ── Scoring ──────────────────────────────────────────────────────

def _score_chain(chain: list[Play], inp: EngagementInput) -> tuple[float, list[str], list[str]]:
    """Return (fit_score 0..100, rationale lines, warnings) for a chain."""
    total_minutes = sum(p.est_minutes for p in chain)
    mean_noise = sum(p.noise for p in chain) / len(chain)
    mean_reliability = sum(p.reliability for p in chain) / len(chain)
    max_difficulty = max(p.difficulty for p in chain)
    stealth = Restriction.STEALTH_REQUIRED in inp.restrictions

    score = 100.0
    rationale: list[str] = []
    warnings: list[str] = []

    # Fewer steps is generally better tradecraft (less exposure).
    score -= (len(chain) - 1) * 3.0

    # Time fit.
    hours = total_minutes / 60.0
    if inp.time_budget_hours is not None:
        budget_min = inp.time_budget_hours * 60.0
        if total_minutes <= budget_min:
            rationale.append(
                f"Fits the {inp.time_budget_hours:g}h window "
                f"(~{hours:.1f}h estimated)."
            )
        else:
            over = (total_minutes - budget_min) / 60.0
            penalty = min(40.0, over * 8.0)
            score -= penalty
            warnings.append(
                f"Exceeds the {inp.time_budget_hours:g}h window by ~{over:.1f}h."
            )
    else:
        rationale.append(f"Estimated effort ~{hours:.1f}h across {len(chain)} steps.")

    # Stealth / noise.
    noise_weight = 9.0 if stealth else 4.0
    score -= (mean_noise - 1) * noise_weight
    if stealth:
        if mean_noise <= 2.5:
            rationale.append(f"Low mean noise ({mean_noise:.1f}/5) suits the stealth requirement.")
        else:
            warnings.append(f"Mean noise {mean_noise:.1f}/5 is high for a stealth engagement.")
        for p in chain:
            if p.noise >= 5:
                warnings.append(f"{p.technique_id} is high-noise ({p.name}).")

    # Reliability rewards, difficulty penalty.
    score += (mean_reliability - 3) * 4.0
    score -= (max_difficulty - 3) * 2.0
    if mean_reliability >= 4:
        rationale.append(f"High expected reliability ({mean_reliability:.1f}/5).")

    # Adversary emulation match.
    if inp.emulate_adversary:
        actor = inp.emulate_adversary.strip().lower()
        matches = [p for p in chain if any(a.lower() == actor for a in p.attributed_actors)]
        if matches:
            score += min(12.0, 4.0 * len(matches))
            ids = ", ".join(p.technique_id for p in matches)
            rationale.append(
                f"Mirrors {inp.emulate_adversary}: {len(matches)} attributed "
                f"technique(s) ({ids})."
            )

    # Name the escalation approach so the reason is concrete.
    pivotal = _pivotal_play(chain, inp)
    if pivotal:
        rationale.append(f"Escalation approach: {pivotal.name} ({pivotal.technique_id}).")

    score = max(0.0, min(100.0, score))
    return round(score, 1), rationale, warnings


def _pivotal_play(chain: list[Play], inp: EngagementInput) -> Play | None:
    """The play that actually reaches the goal capability (for titling/rationale)."""
    goal = GOAL_CAPABILITY.get(inp.objective.value)
    for play in reversed(chain):
        if goal and goal in play.provides:
            return play
    return chain[-1] if chain else None


def _entry_play(chain: list[Play]) -> Play | None:
    """First play that gains a foothold/credential (skips pure recon)."""
    return chain[0] if chain else None


def _short(name: str) -> str:
    """A compact label for titles."""
    return name.split("(")[0].strip()


# ── Public API ───────────────────────────────────────────────────

def build_plans(
    inp: EngagementInput, playbook: list[Play] | None = None
) -> PlanResult:
    """Produce a ranked set of attack plans for an engagement.

    Pass a custom `playbook` (e.g. built from Bulwark's synced ATT&CK data or a
    team's own tradecraft) to override the seed knowledge base.
    """
    pb = playbook if playbook is not None else DEFAULT_PLAYBOOK
    by_id = playbook_by_id(pb)

    goal = GOAL_CAPABILITY.get(inp.objective.value)
    start = start_capabilities(inp)
    allowed, excluded = filter_playbook(pb, inp)

    notes: list[str] = []
    options: list[PlanOption] = []

    if goal is None:
        notes.append(f"Unknown objective '{inp.objective}'; no goal capability mapped.")
    elif goal in start:
        notes.append(
            "The objective's goal capability is already granted by the box "
            "type / provided access; no offensive path is required to reach it."
        )
    else:
        raw_chains = _search_chains(allowed, start, goal)
        # Collapse each path to its minimal coherent spine, then de-duplicate:
        # many padded paths reduce to the same real plan.
        chains = []
        seen: set[tuple[str, ...]] = set()
        for raw in raw_chains:
            minimal = _minimize_chain(raw, start, goal)
            if not minimal:
                continue
            key = tuple(p.technique_id for p in minimal)
            if key not in seen:
                seen.add(key)
                chains.append(minimal)
        if not chains:
            notes.append(
                "No legal path from the starting capabilities to the objective "
                "under these constraints. Loosen a restriction, widen scope, or "
                "grant more starting access."
            )
        scored = []
        for chain in chains:
            score, rationale, warnings = _score_chain(chain, inp)
            scored.append((score, chain, rationale, warnings))
        # Rank by score desc, then shorter chain, then technique order (stable).
        scored.sort(key=lambda t: (-t[0], len(t[1]), tuple(p.technique_id for p in t[1])))

        want = max(3, min(5, inp.max_plans))
        for idx, (score, chain, rationale, warnings) in enumerate(scored[:want], start=1):
            options.append(_build_option(idx, score, chain, rationale, warnings, inp, by_id))
        if 0 < len(chains) < 3:
            notes.append(
                f"Only {len(chains)} legal plan(s) exist under these constraints; "
                "relax the ROE to surface more options."
            )

    return PlanResult(
        objective=inp.objective.value,
        goal_capability=goal or "unknown",
        start_capabilities=sorted(start),
        options=options,
        considered_play_count=len(allowed),
        excluded_by_constraints=excluded,
        notes=notes,
    )


def _build_option(
    idx: int,
    score: float,
    chain: list[Play],
    rationale: list[str],
    warnings: list[str],
    inp: EngagementInput,
    by_id: dict[str, Play],
) -> PlanOption:
    entry = _entry_play(chain)
    pivotal = _pivotal_play(chain, inp)
    if entry and pivotal and entry.technique_id != pivotal.technique_id:
        title = f"{_short(entry.name)} → {_short(pivotal.name)}"
    elif pivotal:
        title = _short(pivotal.name)
    else:
        title = f"Plan {idx}"

    steps: list[PlanStepView] = []
    for play in chain:
        # Enrich fallbacks with names when we know them.
        fbs = list(play.fallback_technique_ids)
        steps.append(PlanStepView(
            technique_id=play.technique_id,
            name=play.name,
            tactic=play.tactic.value,
            summary=play.summary,
            objective=play.objective,
            prerequisite_note=play.prerequisite_note,
            provides=[CAPABILITY_LABELS.get(c, c) for c in sorted(play.provides)],
            est_minutes=play.est_minutes,
            noise=play.noise,
            difficulty=play.difficulty,
            reliability=play.reliability,
            steps=[
                {
                    "command": s.command,
                    "description": s.description,
                    "expected_result": s.expected_result,
                }
                for s in play.steps
            ],
            success_indicator=play.success_indicator,
            fallback_technique_ids=fbs,
            detection=play.detection,
            references=list(play.references),
        ))

    total_minutes = sum(p.est_minutes for p in chain)
    within_budget: bool | None = None
    if inp.time_budget_hours is not None:
        within_budget = total_minutes <= inp.time_budget_hours * 60.0

    covered = []
    for p in chain:
        if p.tactic.value not in covered:
            covered.append(p.tactic.value)

    return PlanOption(
        plan_id=f"plan-{idx}",
        title=title,
        fit_score=score,
        rationale=rationale,
        steps=steps,
        est_total_minutes=total_minutes,
        within_time_budget=within_budget,
        aggregate_noise=round(sum(p.noise for p in chain) / len(chain), 2),
        max_difficulty=max(p.difficulty for p in chain),
        covered_tactics=covered,
        warnings=warnings,
    )
