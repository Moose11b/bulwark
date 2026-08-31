"""Unit tests for the pure engines: MSEL branching and adjudication."""
from types import SimpleNamespace

from app.engine import adjudication, msel


def _inject(code, branches, is_start=False, sequence=1):
    return SimpleNamespace(code=code, branches=branches, is_start=is_start, sequence=sequence)


def test_get_start_inject_prefers_flagged():
    a = _inject("A", [], is_start=False, sequence=2)
    b = _inject("B", [], is_start=True, sequence=5)
    assert msel.get_start_inject([a, b]).code == "B"


def test_get_start_inject_falls_back_to_lowest_sequence():
    a = _inject("A", [], sequence=3)
    b = _inject("B", [], sequence=1)
    assert msel.get_start_inject([a, b]).code == "B"


def test_resolve_action_branch_matches_trigger():
    inj = _inject("A", [
        {"when": "action_taken", "trigger": "isolate", "goto": "B"},
        {"when": "timeout", "after": "PT10M", "goto": "C"},
    ])
    branch = msel.resolve_branch(inj, when="action_taken", trigger="isolate")
    assert branch["goto"] == "B"


def test_resolve_timeout_branch():
    inj = _inject("A", [
        {"when": "action_taken", "trigger": "isolate", "goto": "B"},
        {"when": "timeout", "after": "PT10M", "goto": "C"},
    ])
    assert msel.resolve_branch(inj, when="timeout")["goto"] == "C"


def test_proctor_override_wins_and_synthesises_branch():
    inj = _inject("A", [{"when": "action_taken", "trigger": "isolate", "goto": "B"}])
    branch = msel.resolve_branch(inj, when="proctor_choice", explicit_goto="Z")
    assert branch["goto"] == "Z"
    assert branch["when"] == "proctor_choice"


def test_unmatched_action_returns_none():
    inj = _inject("A", [{"when": "action_taken", "trigger": "isolate", "goto": "B"}])
    assert msel.resolve_branch(inj, when="action_taken", trigger="nope") is None


def test_is_terminal():
    assert msel.is_terminal(_inject("A", [])) is True
    assert msel.is_terminal(_inject("A", [{"when": "proctor_choice", "goto": "B"}])) is False


# --------------------------------------------------------------------------- #
# adjudication
# --------------------------------------------------------------------------- #
def _env(controls=None, detections=None, deception=None):
    return SimpleNamespace(
        controls=controls or [], detections=detections or [], deception_assets=deception or []
    )


def test_covered_technique_is_detected():
    env = _env(controls=[
        {"name": "EDR", "covers": ["T1003.001"], "assets": ["*"], "efficacy": 0.8, "latency_min": 8}
    ])
    ruling = adjudication.adjudicate(env, ["T1003.001"], "FIN-APP-02")
    assert ruling["detected"] is True
    assert ruling["time_to_detect_min"] == 8
    assert ruling["suggested_outcome"] == "detected"


def test_uncovered_technique_is_a_gap():
    env = _env(controls=[
        {"name": "EDR", "covers": ["T1055"], "assets": ["*"], "efficacy": 0.8, "latency_min": 8}
    ])
    ruling = adjudication.adjudicate(env, ["T1486"], "WKS-FINANCE")
    assert ruling["detected"] is False
    assert ruling["probability"] == 0.0
    assert "gap" in ruling["rationale"].lower()


def test_weak_coverage_below_threshold_misses():
    env = _env(detections=[
        {"name": "SIEM", "covers": ["*"], "assets": ["*"], "efficacy": 0.4, "latency_min": 20}
    ])
    ruling = adjudication.adjudicate(env, ["T1021"], "FILE-SRV-01")
    assert ruling["detected"] is False
    assert ruling["probability"] == 0.4


def test_deception_trips_and_reveals_early():
    env = _env(deception=[
        {"name": "Honey-cred", "covers": ["T1021"], "assets": ["FILE-SRV-01"],
         "efficacy": 1.0, "latency_min": 1}
    ])
    ruling = adjudication.adjudicate(env, ["T1021"], "FILE-SRV-01")
    assert ruling["deception_tripped"] is True
    assert ruling["detected"] is True
    assert ruling["time_to_detect_min"] <= 5


def test_combined_probability_stacks_controls():
    env = _env(
        controls=[{"name": "A", "covers": ["T1003.001"], "assets": ["*"], "efficacy": 0.4, "latency_min": 10}],
        detections=[{"name": "B", "covers": ["*"], "assets": ["*"], "efficacy": 0.4, "latency_min": 20}],
    )
    ruling = adjudication.adjudicate(env, ["T1003.001"], "FIN-APP-02")
    # 1 - (0.6 * 0.6) = 0.64
    assert ruling["probability"] == 0.64
    assert ruling["detected"] is True
