"""Ground a threat-actor kill-chain into a playable, branching scenario.

The generator walks the actor's ordered inject-bank keys, picks a real target
asset from the environment for each phase, fills the scene text, and wires the
branches so the arc is valid: every non-final scene routes to the next phase on
a player action, a timeout, or the proctor's choice, and the final active scene
branches to a good or bad resolution. The result is a draft the proctor edits.
"""
from __future__ import annotations

from .. import models
from .catalog import INJECT_BANK, SCENARIO_TEMPLATES, THREAT_ACTORS


def _pick_asset(env: models.Environment, zone: str) -> dict:
    """Choose a plausible target asset for a phase, preferring the phase's zone."""
    assets = env.assets or []
    for a in assets:
        if a.get("zone") == zone:
            return a
    # Fall back to a crown jewel, then to anything at all.
    for cj in env.crown_jewels or []:
        for a in assets:
            if a.get("code") == cj:
                return a
    return assets[0] if assets else {"code": "UNKNOWN", "name": "an in-scope host"}


def _clock(step: int) -> str:
    total = step * 20  # 20 game-minutes between scenes
    return f"T+{total // 60:02d}:{total % 60:02d}"


def _fill(text: str, org: str, asset: dict) -> str:
    return (text.replace("{org}", org)
                .replace("{asset_name}", asset.get("name", asset.get("code", "the host")))
                .replace("{asset}", asset.get("code", "?")))


def _objective_for(actor: dict, phase_index: int) -> str:
    objs = actor["objectives"]
    return objs[min(phase_index, len(objs) - 1)]["code"]


def build_scenario(
    env: models.Environment,
    actor_key: str,
    name: str | None = None,
    template_key: str | None = None,
) -> models.Scenario:
    """Return an unsaved ``Scenario`` (with objectives and injects) for ``env``."""
    if actor_key not in THREAT_ACTORS:
        raise ValueError(f"unknown threat actor '{actor_key}'")
    actor = THREAT_ACTORS[actor_key]
    tmpl = SCENARIO_TEMPLATES.get(template_key or "", {})

    phases = actor["kill_chain"]
    codes = [f"INJ-{i + 1:02d}" for i in range(len(phases))]
    good_code = f"INJ-{len(phases) + 1:02d}a"
    bad_code = f"INJ-{len(phases) + 1:02d}b"

    injects: list[models.Inject] = []
    for i, bank_key in enumerate(phases):
        t = INJECT_BANK[bank_key]
        asset = _pick_asset(env, t["target_zone"])
        last_active = i == len(phases) - 1
        phase = t["phase"]

        if not last_active:
            nxt = codes[i + 1]
            branches = [
                {"when": "action_taken", "trigger": f"respond_{phase}", "goto": nxt,
                 "label": f"Blue cell responds to the {phase} activity"},
                {"when": "timeout", "after": "PT10M", "goto": nxt,
                 "label": "No timely response — the adversary presses on"},
                {"when": "proctor_choice", "goto": nxt,
                 "label": "Proctor: advance the scenario"},
            ]
        else:
            branches = [
                {"when": "action_taken", "trigger": "contain_and_recover", "goto": good_code,
                 "label": "Team contains and recovers"},
                {"when": "timeout", "after": "PT20M", "goto": bad_code,
                 "label": "Slow response — major impact"},
                {"when": "proctor_choice", "goto": good_code,
                 "label": "Proctor: team resolves the incident"},
            ]

        injects.append(models.Inject(
            code=codes[i], sequence=i + 1, is_start=(i == 0),
            title=_fill(t["title"], env.name, asset),
            channel=t["channel"], clock=_clock(i),
            narrative=_fill(t["narrative"], env.name, asset),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=list(t["expected_actions"]),
            attack_techniques=list(t["techniques"]),
            target_asset=asset.get("code", ""),
            objective_code=_objective_for(actor, i),
            branches=branches,
        ))

    last_obj = actor["objectives"][-1]["code"]
    injects.append(models.Inject(
        code=good_code, sequence=len(phases) + 1, is_start=False,
        title="Contained and recovered (resolution)", channel="briefing",
        clock=_clock(len(phases)),
        narrative=("The team detected, contained, and recovered in time. The exercise "
                   "resolves with limited impact. Capture final observations and run the hotwash."),
        visible_to=["blue_cell", "white_cell"],
        expected_actions=["Confirm recovery", "Run the hotwash"],
        attack_techniques=[], target_asset="", objective_code=last_obj, branches=[],
    ))
    injects.append(models.Inject(
        code=bad_code, sequence=len(phases) + 2, is_start=False,
        title="Objectives missed — major impact (resolution)", channel="briefing",
        clock=_clock(len(phases) + 1),
        narrative=("Containment came too late and the adversary achieved its objective. "
                   "The exercise resolves with major impact. Capture the decision timeline "
                   "and run the hotwash."),
        visible_to=["blue_cell", "white_cell"],
        expected_actions=["Capture the decision timeline", "Run the hotwash"],
        attack_techniques=[], target_asset="", objective_code=last_obj, branches=[],
    ))

    scenario = models.Scenario(
        environment_id=env.id,
        name=name or f"{actor['name']} — {env.name}",
        threat_actor=actor["label"],
        narrative=tmpl.get("narrative", actor["description"]),
        scope=tmpl.get("scope", "Discussion-based tabletop. No live systems are touched."),
        rules_of_engagement=tmpl.get(
            "roe", "Facilitated exercise only. 'Pause' halts play at any time."),
        exercise_type="tabletop",
        cells=[
            {"key": "white_cell", "name": "White Cell / Control", "kind": "control"},
            {"key": "blue_cell", "name": "Blue Cell (SOC + IR)", "kind": "participant"},
            {"key": "observers", "name": "Observers", "kind": "observer"},
        ],
    )
    scenario.objectives = [models.Objective(**o) for o in actor["objectives"]]
    scenario.injects = injects
    return scenario
