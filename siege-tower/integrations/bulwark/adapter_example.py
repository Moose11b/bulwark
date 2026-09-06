"""
Siege Tower adapter.

The bridge between Bulwark and the standalone Siege Tower engine. Siege Tower
lives in its own dependency-free package (`siege_tower`, the repo's
`siege-tower/` project); this module imports it and maps between Bulwark's
`Engagement` model and the engine's `EngagementInput` / `PlanResult`.

SAFETY INVARIANTS (enforced here and in the router):
  * This module never executes any command, launches any tool, or connects to
    any target. It only computes plans from the ROE the team typed in.
  * It never reads or moves data from a client's systems. The only inputs are
    the engagement's stored ROE fields; the only outputs are plan text.
Keeping the engine standalone is deliberate: the planning logic has no access
to Bulwark's scanners, credentials, or network, so it *cannot* act even by
mistake.

The import is defensive: if the engine package is not installed/mounted,
`ENGINE_AVAILABLE` is False and the router returns a clear 503 rather than the
whole API failing to boot.
"""
from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

import structlog

logger = structlog.get_logger()


def _ensure_importable() -> None:
    """Make `siege_tower` importable without hard-coupling the two projects.

    Tries a normal import first (installed as a package, or already on
    PYTHONPATH — e.g. the docker-compose volume mount). Falls back to a few
    conventional locations so a local, non-Docker checkout also works: an
    explicit SIEGE_TOWER_PATH, /opt/siege-tower, and the sibling `siege-tower/`
    directory next to the backend in the repo.
    """
    candidates: list[Path] = []
    env_path = os.getenv("SIEGE_TOWER_PATH")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/opt/siege-tower"))
    # backend/app/services/siege_adapter.py -> repo root is parents[3]
    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root / "siege-tower")

    for cand in candidates:
        if (cand / "siege_tower" / "__init__.py").is_file():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            return


try:
    _ensure_importable()
    import siege_tower as _st
    from siege_tower import (
        BoxType, EngagementInput, Objective, Platform, Restriction, build_plans,
    )
    from siege_tower.schema import Tactic as _Tactic
    from siege_tower.playbook import DEFAULT_PLAYBOOK as _PLAYBOOK
    from siege_tower.tools import tools_for as _tools_for

    ENGINE_AVAILABLE = True
    ENGINE_VERSION = getattr(_st, "__version__", "unknown")
except Exception as exc:  # pragma: no cover - only when the package is absent
    ENGINE_AVAILABLE = False
    ENGINE_VERSION = None
    logger.warning("siege.engine_unavailable", error=str(exc))


class EngineUnavailable(RuntimeError):
    """Raised when a plan is requested but the engine package isn't present."""


class InvalidEngagement(ValueError):
    """The stored engagement can't be mapped to a valid engine input."""


def _require_engine() -> None:
    if not ENGINE_AVAILABLE:
        raise EngineUnavailable(
            "The Siege Tower planning engine is not installed. Mount the "
            "siege-tower package or set SIEGE_TOWER_PATH."
        )


# ── Mapping: Bulwark Engagement -> engine EngagementInput ─────────

def engagement_to_input(engagement) -> "EngagementInput":
    """Translate an Engagement ORM row into the engine's EngagementInput.

    Invalid enum values are rejected with a clear message rather than silently
    dropped, except for the *lists* of scope/restrictions, where unknown entries
    are skipped so a forward-compatible UI can't hard-fail an older engine.
    """
    _require_engine()

    try:
        objective = Objective(engagement.objective)
    except ValueError:
        raise InvalidEngagement(f"Unknown objective: {engagement.objective!r}")
    try:
        box_type = BoxType(engagement.box_type or "black")
    except ValueError:
        raise InvalidEngagement(f"Unknown box type: {engagement.box_type!r}")

    scope = _coerce_enum_list(engagement.scope_platforms, Platform)
    restrictions = _coerce_enum_list(engagement.restrictions, Restriction)
    forbidden_tactics = _coerce_enum_list(engagement.forbidden_tactics, _Tactic)

    return EngagementInput(
        objective=objective,
        box_type=box_type,
        scope_platforms=scope,
        provided_access=list(engagement.provided_access or []),
        restrictions=restrictions,
        forbidden_technique_ids=list(engagement.forbidden_technique_ids or []),
        forbidden_tactics=forbidden_tactics,
        time_budget_hours=engagement.time_budget_hours,
        allow_evidence_removal=bool(engagement.allow_evidence_removal),
        emulate_adversary=engagement.emulate_adversary,
        objective_note=engagement.objective_note,
    )


def _coerce_enum_list(values, enum_cls) -> list:
    out = []
    for v in values or []:
        try:
            out.append(enum_cls(v))
        except ValueError:
            logger.info("siege.skip_unknown_enum", enum=enum_cls.__name__, value=v)
    return out


# ── Plan generation + serialization ──────────────────────────────

def generate_plan_result(engagement):
    """Run the engine for an engagement and return the raw PlanResult."""
    _require_engine()
    inp = engagement_to_input(engagement)
    return build_plans(inp)


def option_to_row_fields(option) -> dict:
    """Serialize a PlanOption into the columns of an EngagementPlan row."""
    return {
        "plan_key": option.plan_id,
        "title": option.title,
        "fit_score": option.fit_score,
        "rationale": list(option.rationale),
        "steps": [dataclasses.asdict(s) for s in option.steps],
        "est_total_minutes": option.est_total_minutes,
        "within_time_budget": option.within_time_budget,
        "aggregate_noise": option.aggregate_noise,
        "max_difficulty": option.max_difficulty,
        "covered_tactics": list(option.covered_tactics),
        "warnings": list(option.warnings),
    }


def result_meta(result) -> dict:
    """Serialize the result-level metadata (goal, start state, exclusions)."""
    return {
        "objective": result.objective,
        "goal_capability": result.goal_capability,
        "start_capabilities": list(result.start_capabilities),
        "considered_play_count": result.considered_play_count,
        "excluded_by_constraints": list(result.excluded_by_constraints),
        "notes": list(result.notes),
    }


# ── Reference catalogs for the planning UI ───────────────────────

def reference_catalog() -> dict:
    """Enumerate the engine's vocabulary so the UI can build its tiles.

    Returns the selectable objectives, box types, platforms, restrictions, and
    tactics — value + human label — plus engine availability/version.
    """
    if not ENGINE_AVAILABLE:
        return {"engine_available": False, "engine_version": None}

    def opts(enum_cls):
        return [{"value": e.value, "label": _labelize(e.value)} for e in enum_cls]

    return {
        "engine_available": True,
        "engine_version": ENGINE_VERSION,
        "objectives": opts(Objective),
        "box_types": opts(BoxType),
        "platforms": opts(Platform),
        "restrictions": opts(Restriction),
        "tactics": opts(_Tactic),
    }


def playbook_catalog() -> list[dict]:
    """List every play as a tile: technique, tactic, summary, suggested tools.

    This is reference material for the planner UI — no commands, just what each
    technique is for and which programs a team typically uses for it.
    """
    if not ENGINE_AVAILABLE:
        return []
    tiles = []
    for p in _PLAYBOOK:
        tiles.append({
            "technique_id": p.technique_id,
            "name": p.name,
            "tactic": p.tactic.value,
            "summary": p.summary,
            "platforms": sorted(pl.value for pl in p.platforms),
            "recommended_tools": _tools_for(p.technique_id, p.tactic.value),
        })
    tiles.sort(key=lambda t: (t["tactic"], t["technique_id"]))
    return tiles


def _labelize(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()
