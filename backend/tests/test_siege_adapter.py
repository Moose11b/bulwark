"""
Siege Tower adapter — mapping and serialization (no database required).

These exercise the bridge between Bulwark's Engagement shape and the standalone
engine: enum mapping, graceful handling of unknown values, and the serialized
plan structure the API returns.
"""
from types import SimpleNamespace

import pytest

from app.services import siege_adapter as adapter

pytestmark = pytest.mark.skipif(
    not adapter.ENGINE_AVAILABLE, reason="siege_tower engine package not present"
)


def _engagement(**over):
    base = dict(
        objective="domain_admin", box_type="grey",
        scope_platforms=["windows", "active_directory"],
        provided_access=["domain_user", "internal_network"],
        restrictions=["no_phishing"], forbidden_technique_ids=[],
        forbidden_tactics=[], time_budget_hours=40.0,
        allow_evidence_removal=False, emulate_adversary=None,
        objective_note=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_maps_and_generates_plans():
    result = adapter.generate_plan_result(_engagement())
    assert result.goal_capability == "domain_admin"
    assert result.options


def test_unknown_enum_values_are_skipped_not_fatal():
    inp = adapter.engagement_to_input(_engagement(
        scope_platforms=["windows", "nonsense"],
        restrictions=["no_phishing", "nonsense"],
    ))
    values = {p.value for p in inp.scope_platforms}
    assert "windows" in values and "nonsense" not in values


def test_invalid_objective_raises():
    with pytest.raises(adapter.InvalidEngagement):
        adapter.engagement_to_input(_engagement(objective="not_a_real_objective"))


def test_invalid_box_type_raises():
    with pytest.raises(adapter.InvalidEngagement):
        adapter.engagement_to_input(_engagement(box_type="translucent"))


def test_option_serialization_shape():
    result = adapter.generate_plan_result(_engagement())
    row = adapter.option_to_row_fields(result.options[0])
    for key in ("plan_key", "title", "fit_score", "steps", "rationale",
                "est_total_minutes", "covered_tactics"):
        assert key in row
    step = row["steps"][0]
    assert "recommended_tools" in step and "technique_id" in step


def test_reference_and_playbook_catalogs():
    ref = adapter.reference_catalog()
    assert ref["engine_available"] is True
    assert any(o["value"] == "domain_admin" for o in ref["objectives"])
    tiles = adapter.playbook_catalog()
    assert len(tiles) >= 40
    assert all("recommended_tools" in t for t in tiles)
