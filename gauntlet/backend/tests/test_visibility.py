"""Unit tests for the fog-of-war visibility engine."""
from types import SimpleNamespace

from app.engine import visibility


def _scenario():
    return SimpleNamespace(cells=[
        {"key": "white_cell", "name": "White Cell", "kind": "control"},
        {"key": "blue_cell", "name": "Blue Cell", "kind": "participant"},
        {"key": "observers", "name": "Observers", "kind": "observer"},
    ])


def _event(kind, visible_to=None):
    return SimpleNamespace(kind=kind, payload={"visible_to": visible_to or []})


def test_control_cell_detection():
    scn = _scenario()
    assert visibility.is_control_cell(scn, "white_cell") is True
    assert visibility.is_control_cell(scn, "blue_cell") is False


def test_inject_visible_to_rules():
    assert visibility.inject_visible_to([], "blue_cell") is True          # empty = all
    assert visibility.inject_visible_to(["blue_cell"], "blue_cell") is True
    assert visibility.inject_visible_to(["white_cell"], "blue_cell") is False


def test_participant_timeline_hides_white_cell_machinery():
    scn = _scenario()
    events = [
        _event("status"),
        _event("inject_fired", ["blue_cell", "white_cell"]),
        _event("inject_fired", ["white_cell"]),   # not for blue
        _event("adjudication"),                    # internal
        _event("decision"),                        # internal
        _event("observation"),                     # internal
    ]
    blue = visibility.filter_timeline(events, scn, "blue_cell")
    kinds = [e.kind for e in blue]
    assert kinds == ["status", "inject_fired"]  # only the addressed inject + status
    # Control sees everything.
    assert len(visibility.filter_timeline(events, scn, "white_cell")) == len(events)


def test_current_inject_gating():
    scn = _scenario()
    inj = SimpleNamespace(visible_to=["white_cell"])
    assert visibility.current_inject_for_cell(inj, scn, "blue_cell") is None
    assert visibility.current_inject_for_cell(inj, scn, "white_cell") is inj


def test_environment_redaction():
    env = SimpleNamespace(
        id=1, name="Env", sector="Fin", box_type="grey",
        assets=[{"code": "A"}], controls=[{"name": "EDR"}], detections=[],
        playbooks=[], policies=[], personnel=[],
        deception_assets=[{"name": "canary"}], crown_jewels=["A"],
        visibility={"blue_cell": ["assets", "controls", "crown_jewels"]},
    )
    scn = _scenario()

    blue = visibility.filter_environment(env, scn, "blue_cell")
    assert blue["assets"] == [{"code": "A"}]
    assert blue["deception_assets"] == []                 # redacted
    assert "deception_assets" in blue["redacted"]

    white = visibility.filter_environment(env, scn, "white_cell")
    assert white["deception_assets"] == [{"name": "canary"}]  # control sees all
    assert white["redacted"] == []
