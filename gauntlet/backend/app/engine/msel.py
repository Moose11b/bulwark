"""The branching Master Scenario Events List engine.

An inject's ``branches`` are the choose-your-own-adventure spine. Each branch is
a rule of the shape::

    {"when": "action_taken", "trigger": "isolate_host", "goto": "INJ-05a",
     "label": "Blue cell isolates the host"}
    {"when": "timeout",      "after": "PT10M",          "goto": "INJ-05b"}
    {"when": "proctor_choice",                          "goto": "INJ-05c"}

``resolve_branch`` decides which branch a proctor decision selects. The proctor
is always the final authority: an explicit ``goto`` in the decision wins over
any rule, which is how "write a new turn on the spot" is expressed.
"""
from __future__ import annotations

from typing import Iterable, Optional

# What a decision can be. Kept as plain strings so the API and UI share them.
WHEN_ACTION = "action_taken"
WHEN_TIMEOUT = "timeout"
WHEN_PROCTOR = "proctor_choice"


def index_by_code(injects: Iterable) -> dict:
    return {inj.code: inj for inj in injects}


def get_start_inject(injects: Iterable):
    """The first scene: the inject flagged ``is_start``, else the lowest sequence."""
    injects = list(injects)
    for inj in injects:
        if getattr(inj, "is_start", False):
            return inj
    return min(injects, key=lambda i: i.sequence, default=None)


def available_branches(inject) -> list[dict]:
    """Branches a proctor can choose from, in a stable, display-friendly order."""
    return list(inject.branches or [])


def resolve_branch(
    inject,
    when: str,
    trigger: Optional[str] = None,
    explicit_goto: Optional[str] = None,
) -> Optional[dict]:
    """Return the branch dict a decision selects, or ``None`` if nothing matches.

    * ``explicit_goto`` — proctor overrides with an exact next inject. Always wins.
    * ``when == action_taken`` — match a branch whose ``trigger`` equals ``trigger``.
    * ``when == timeout`` — the first ``timeout`` branch.
    * ``when == proctor_choice`` — the first ``proctor_choice`` branch, or, when a
      ``trigger`` names a branch label, that one.
    """
    branches = available_branches(inject)

    if explicit_goto:
        for b in branches:
            if b.get("goto") == explicit_goto:
                return b
        # A destination the proctor typed that isn't a pre-authored branch:
        # synthesise one so the session can still route there.
        return {"when": WHEN_PROCTOR, "goto": explicit_goto, "label": "Proctor override"}

    if when == WHEN_ACTION:
        for b in branches:
            if b.get("when") == WHEN_ACTION and b.get("trigger") == trigger:
                return b
        return None

    if when == WHEN_TIMEOUT:
        for b in branches:
            if b.get("when") == WHEN_TIMEOUT:
                return b
        return None

    if when == WHEN_PROCTOR:
        if trigger:
            for b in branches:
                if b.get("label") == trigger or b.get("goto") == trigger:
                    return b
        for b in branches:
            if b.get("when") == WHEN_PROCTOR:
                return b
        return None

    return None


def is_terminal(inject) -> bool:
    """A scene with no onward branches ends the arc."""
    return not available_branches(inject)
