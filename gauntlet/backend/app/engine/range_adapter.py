"""Cyber-range hooks (M4): a pluggable adapter for live/technical injects.

An operational or sandbox exercise can execute a technical action and feed the
resulting telemetry back into adjudication. The adapter interface makes the
range pluggable; the shipped default is a **simulation** adapter that contacts
nothing — it derives synthetic telemetry from the environment model, so the
product is safe out of the box.

Safety posture: a real adapter that touches systems must be gated by an
authorization grant and a target allow-list (see ``app/api/live.py``). Adversary
actions are executed only against an environment the user is authorized to test.
"""
from __future__ import annotations

from . import adjudication


class RangeAdapter:
    """Interface a concrete range integration implements."""

    name = "base"

    def execute(self, environment, technique: str, target: str) -> dict:  # pragma: no cover
        raise NotImplementedError


class SimulationRangeAdapter(RangeAdapter):
    """Default, safe adapter. Contacts no external system.

    It runs the technique through the deterministic adjudication engine to decide
    what the environment's controls *would* have observed, and returns that as
    synthetic telemetry alongside the ruling.
    """

    name = "simulation"

    def execute(self, environment, technique: str, target: str) -> dict:
        ruling = adjudication.adjudicate(environment, [technique], target)
        telemetry = [
            {"source": c["name"], "type": c["type"], "deception": c.get("deception", False)}
            for c in ruling["controls_hit"]
        ]
        return {
            "adapter": self.name,
            "executed": True,
            "technique": technique,
            "target": target,
            "telemetry": telemetry,
            "ruling": ruling,
            "note": "Synthetic telemetry — no live system was contacted.",
        }


# The active adapter. A deployment can swap this for a real integration; the
# authorization gate in the API applies regardless of which adapter is set.
_ADAPTER: RangeAdapter = SimulationRangeAdapter()


def get_adapter() -> RangeAdapter:
    return _ADAPTER


def set_adapter(adapter: RangeAdapter) -> None:
    global _ADAPTER
    _ADAPTER = adapter
