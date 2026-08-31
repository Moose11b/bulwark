"""Adjudication: rule a player action against the environment's defenses.

The engine is deliberately transparent and deterministic — no randomness — so a
ruling is reproducible and every outcome can point at the exact control that
caused it. The proctor always sees this reasoning and may override the result;
the model proposes, the human disposes.

Environment ``controls`` and ``detections`` are dicts shaped like::

    {"name": "Defender for Endpoint", "type": "edr",
     "covers": ["T1003.001", "T1055"],   # ATT&CK technique ids, or ["*"]
     "assets": ["FIN-APP-02", "*"],       # asset codes, or ["*"] for all
     "efficacy": 0.8,                     # 0..1 chance this catches it
     "latency_min": 8}                    # minutes to surface when it does

Deception assets (honeypots, canaries) are shaped the same but, when tripped,
reveal the adversary early and hand the blue cell an advantage.
"""
from __future__ import annotations

from typing import Iterable

DETECT_THRESHOLD = 0.5


def _applies(control: dict, techniques: Iterable[str], asset: str) -> bool:
    covers = control.get("covers") or []
    assets = control.get("assets") or ["*"]
    technique_match = "*" in covers or any(t in covers for t in techniques)
    asset_match = "*" in assets or (asset and asset in assets)
    # A control counts if it covers the technique on an in-scope asset. When a
    # control lists no techniques it is treated as asset-scoped monitoring.
    if not covers:
        return asset_match
    return technique_match and asset_match


def _combined_probability(controls: list[dict]) -> float:
    """P(at least one control detects) = 1 - product(1 - efficacy)."""
    miss = 1.0
    for c in controls:
        eff = float(c.get("efficacy", 0.0))
        miss *= (1.0 - max(0.0, min(1.0, eff)))
    return round(1.0 - miss, 3)


def adjudicate(environment, techniques: list[str], target_asset: str) -> dict:
    """Return a ruling for an action described by ATT&CK techniques on an asset."""
    techniques = [t for t in (techniques or []) if t]
    controls = list(environment.controls or []) + list(environment.detections or [])
    deception = list(environment.deception_assets or [])

    applicable = [c for c in controls if _applies(c, techniques, target_asset)]
    tripped = [d for d in deception if _applies(d, techniques, target_asset)]

    probability = _combined_probability(applicable + tripped)
    detected = bool(tripped) or probability >= DETECT_THRESHOLD

    detecting = tripped + applicable
    time_to_detect = (
        min((int(c.get("latency_min", 30)) for c in detecting), default=None)
        if detected
        else None
    )
    if tripped:
        # A canary fires the moment it is touched.
        time_to_detect = min(time_to_detect or 5, 5)

    controls_hit = [
        {
            "name": c.get("name", "unnamed control"),
            "type": c.get("type", "control"),
            "efficacy": c.get("efficacy", 0.0),
            "latency_min": c.get("latency_min"),
            "deception": c in tripped,
        }
        for c in detecting
    ]

    if tripped:
        rationale = (
            f"Deception asset '{tripped[0].get('name')}' was tripped — the adversary "
            "revealed itself early; the blue cell gains an advantage."
        )
    elif detected:
        names = ", ".join(c.get("name", "?") for c in applicable) or "existing controls"
        rationale = (
            f"Detected (p={probability}) by {names}; expected time-to-detect "
            f"{time_to_detect} min against {target_asset or 'the target'}."
        )
    elif applicable:
        rationale = (
            f"Controls exist but combined coverage is weak (p={probability}); the "
            f"action likely goes unnoticed on {target_asset or 'the target'}."
        )
    else:
        techs = ", ".join(techniques) or "this action"
        rationale = (
            f"No control in the environment covers {techs} on "
            f"{target_asset or 'the target'} — a detection gap. The action succeeds unseen."
        )

    return {
        "detected": detected,
        "probability": probability,
        "time_to_detect_min": time_to_detect,
        "deception_tripped": bool(tripped),
        "controls_hit": controls_hit,
        "techniques": techniques,
        "target_asset": target_asset,
        "rationale": rationale,
        "suggested_outcome": "detected" if detected else "missed",
    }
