"""Unit tests for the M2 scenario generator and delivery renderer."""
from types import SimpleNamespace

import pytest

from app.authoring import delivery, generator
from app.authoring.catalog import INJECT_BANK, THREAT_ACTORS


def _env():
    return SimpleNamespace(
        id=1, name="Testbank",
        assets=[
            {"code": "WKS-1", "name": "Workstation", "zone": "user"},
            {"code": "GW-1", "name": "Gateway", "zone": "perimeter"},
            {"code": "APP-1", "name": "App host", "zone": "app"},
            {"code": "DC-1", "name": "Domain controller", "zone": "core"},
        ],
        crown_jewels=["DC-1"],
    )


@pytest.mark.parametrize("actor_key", list(THREAT_ACTORS.keys()))
def test_generated_scenario_is_valid_and_playable(actor_key):
    scenario = generator.build_scenario(_env(), actor_key)
    codes = {i.code for i in scenario.injects}

    # Exactly one start inject.
    assert sum(1 for i in scenario.injects if i.is_start) == 1

    # Every branch routes to an inject that exists (no dangling goto).
    for inj in scenario.injects:
        for b in inj.branches:
            assert b["goto"] in codes, f"{inj.code} -> {b['goto']} missing"

    # At least one terminal resolution exists.
    assert any(not i.branches for i in scenario.injects)

    # Objectives match the actor's preset set.
    assert len(scenario.objectives) == len(THREAT_ACTORS[actor_key]["objectives"])


def test_targets_and_techniques_are_grounded():
    env = _env()
    scenario = generator.build_scenario(env, "ransomware_affiliate")
    asset_codes = {a["code"] for a in env.assets}
    bank_techniques = {t for e in INJECT_BANK.values() for t in e["techniques"]}

    for inj in scenario.injects:
        if inj.target_asset:
            assert inj.target_asset in asset_codes
        for tech in inj.attack_techniques:
            assert tech in bank_techniques


def test_template_sets_narrative_and_actor():
    scenario = generator.build_scenario(
        _env(), "ransomware_affiliate", template_key="ransomware_finance"
    )
    assert "ransomware" in scenario.narrative.lower()
    assert scenario.exercise_type == "tabletop"


def test_unknown_actor_raises():
    with pytest.raises(ValueError):
        generator.build_scenario(_env(), "nope")


def test_delivery_renders_email_channel():
    inj = SimpleNamespace(
        channel="email", title="Wire request", narrative="Please pay now.",
        target_asset="WKS-1", clock="T+00:00", attack_techniques=["T1656"],
        expected_actions=["Verify out-of-band"],
    )
    out = delivery.render(inj)
    assert out["channel"] == "email"
    assert "Subject" in out["fields"]
    assert out["expected_actions"] == ["Verify out-of-band"]


def test_delivery_edr_alert_renders_as_alert():
    inj = SimpleNamespace(
        channel="edr_alert", title="LSASS access", narrative="Credential dump.",
        target_asset="APP-1", clock="T+00:40", attack_techniques=["T1003.001"],
        expected_actions=[],
    )
    out = delivery.render(inj)
    assert out["fields"]["Source"] == "EDR"
    assert out["fields"]["Host"] == "APP-1"
    assert "T1003.001" in out["fields"]["Techniques"]


def test_delivery_siem_lists_techniques():
    inj = SimpleNamespace(
        channel="siem_alert", title="Beacon", narrative="C2 traffic.",
        target_asset="APP-1", clock="T+00:20", attack_techniques=["T1071.001"],
        expected_actions=[],
    )
    out = delivery.render(inj)
    assert out["fields"]["Host"] == "APP-1"
    assert "T1071.001" in out["fields"]["Techniques"]
