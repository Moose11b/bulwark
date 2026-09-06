"""
Siege Tower report compiler (no database required).

Exercises coverage math, the outcome summary, and Markdown rendering from
plain dicts — the same shapes the router passes in.
"""
from app.services import siege_report as R


def _fixture():
    engagement = {
        "id": "e1", "name": "ACME external", "client_name": "ACME Corp",
        "authorization_ref": "SOW-2026-014", "objective": "domain_admin",
        "box_type": "grey", "status": "active",
        "scope_platforms": ["windows"], "in_scope_targets": ["10.0.0.0/24"],
        "out_of_scope": [], "provided_access": ["domain_user"],
        "restrictions": ["no_phishing"], "forbidden_technique_ids": [],
        "forbidden_tactics": [], "time_budget_hours": 40,
        "allow_evidence_removal": False, "emulate_adversary": None,
        "roe_notes": None, "last_plan_meta": {"goal_capability": "domain_admin"},
    }
    plans = [
        {"plan_key": "plan-1", "title": "AD enum → ADCS", "is_selected": True,
         "rationale": ["fits budget"],
         "steps": [{"technique_id": "T1087", "name": "AD enum", "summary": "map"},
                   {"technique_id": "T1649", "name": "ADCS", "summary": "cert"}]},
        {"plan_key": "plan-2", "title": "Kerberoast", "is_selected": False, "steps": []},
    ]
    logs = [
        {"plan_key": "plan-1", "step_index": 0, "technique_id": "T1087",
         "title": "BloodHound", "outcome": "succeeded", "operator": "shamus",
         "targets": ["DC01"], "evidence_refs": ["bh.zip"], "notes": "ESC1 found.",
         "started_at": "2026-09-06T09:00:00", "created_at": "2026-09-06T09:05:00"},
        {"plan_key": "plan-1", "step_index": 1, "technique_id": "T1649",
         "title": "ADCS", "outcome": "fell_back", "operator": "shamus",
         "targets": [], "evidence_refs": [], "notes": "used ESC8.",
         "started_at": "2026-09-06T11:00:00", "created_at": "2026-09-06T11:30:00"},
    ]
    return engagement, plans, logs


def test_coverage_and_summary():
    rep = R.build_report(*_fixture())
    assert rep["coverage"]["coverage_pct"] == 100.0
    assert rep["coverage"]["steps_worked"] == 2
    assert rep["summary"]["by_outcome"] == {"succeeded": 1, "fell_back": 1}
    assert rep["summary"]["techniques_succeeded"] == ["T1087", "T1649"]
    assert rep["alternative_plans"][0]["plan_key"] == "plan-2"


def test_partial_coverage():
    engagement, plans, logs = _fixture()
    rep = R.build_report(engagement, plans, logs[:1])  # only step 0 worked
    assert rep["coverage"]["steps_worked"] == 1
    assert rep["coverage"]["coverage_pct"] == 50.0


def test_markdown_is_clean_and_complete():
    md = R.render_markdown(R.build_report(*_fixture()))
    assert "# Engagement Report — ACME external" in md
    assert "## Rules of Engagement" in md
    assert "## Execution log" in md
    assert "Selected-plan coverage:" in md
    # A report is documentation, never runnable commands.
    assert "msfvenom" not in md and "| Command |" not in md


def test_no_plan_selected_is_handled():
    engagement, plans, logs = _fixture()
    for p in plans:
        p["is_selected"] = False
    rep = R.build_report(engagement, plans, [])
    assert rep["selected_plan"] is None
    assert rep["coverage"] is None
    md = R.render_markdown(rep)
    assert "No plan selected yet" in md
