"""Fog of war: what each cell is allowed to see.

Two redactions:

* **Timeline** — a participant or observer cell sees the injects delivered to it
  (and status changes), but not the White Cell's internal machinery: the
  adjudication reasoning, the proctor's branch decisions, notes, or other cells'
  observations. A control cell sees everything.
* **Environment** — the environment's ``visibility`` map lists which sections
  each cell may read. This is how white / grey / black box is realised per
  audience over one shared environment.
"""
from __future__ import annotations

ENV_SECTIONS = [
    "assets", "controls", "detections", "playbooks", "policies",
    "personnel", "deception_assets", "crown_jewels",
]

# Timeline event kinds a non-control cell may see (in addition to injects
# addressed to it).
_PARTICIPANT_KINDS = {"status"}


def is_control_cell(scenario, cell_key: str) -> bool:
    """A control / White Cell sees everything."""
    if cell_key in ("white_cell", "control"):
        return True
    for c in scenario.cells or []:
        if c.get("key") == cell_key and c.get("kind") == "control":
            return True
    return False


def inject_visible_to(inject_visible_to: list, cell_key: str) -> bool:
    # An empty ``visible_to`` means "everyone"; otherwise the cell must be listed.
    return (not inject_visible_to) or (cell_key in inject_visible_to)


def filter_timeline(events, scenario, cell_key: str) -> list:
    """Return the timeline events a cell is permitted to see."""
    if is_control_cell(scenario, cell_key):
        return list(events)
    out = []
    for e in events:
        if e.kind == "inject_fired" and inject_visible_to(e.payload.get("visible_to") or [], cell_key):
            out.append(e)
        elif e.kind in _PARTICIPANT_KINDS:
            out.append(e)
    return out


def current_inject_for_cell(inject, scenario, cell_key: str):
    """The current inject, or ``None`` if this cell isn't meant to see it yet."""
    if inject is None:
        return None
    if is_control_cell(scenario, cell_key):
        return inject
    return inject if inject_visible_to(inject.visible_to or [], cell_key) else None


def filter_environment(env, scenario, cell_key: str) -> dict:
    """Return a per-cell redacted view of the environment."""
    control = is_control_cell(scenario, cell_key)
    allowed = set(ENV_SECTIONS) if control else set((env.visibility or {}).get(cell_key, []))

    view = {
        "id": env.id,
        "name": env.name,
        "sector": env.sector,
        "box_type": env.box_type,
        "cell_key": cell_key,
        "redacted": [s for s in ENV_SECTIONS if s not in allowed],
    }
    for section in ENV_SECTIONS:
        view[section] = list(getattr(env, section) or []) if section in allowed else []
    return view
