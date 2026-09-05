"""
Siege Tower engine tests.

Pure logic — no network, DB, or tools. These pin the behaviour that makes the
output trustworthy for a red-team artifact: the ROE actually constrains the
plans, box type changes the starting state, every plan is minimal and legal,
and the same ROE always yields the same ranked result.
"""
from siege_tower import (
    BoxType, EngagementInput, Objective, Platform, Restriction, Tactic,
    build_plans, plan_result_to_markdown,
)
from siege_tower.capabilities import CAP_DOMAIN_ADMIN, CAP_INTERNAL_NETWORK
from siege_tower.engine import _chain_valid, start_capabilities
from siege_tower.playbook import DEFAULT_PLAYBOOK, playbook_by_id

WIN_AD = [Platform.WINDOWS, Platform.ACTIVE_DIRECTORY]


def _roe(**kw) -> EngagementInput:
    kw.setdefault("objective", Objective.DOMAIN_ADMIN)
    kw.setdefault("scope_platforms", list(WIN_AD))
    return EngagementInput(**kw)


# ── Basic contract ───────────────────────────────────────────────

def test_returns_three_to_five_ranked_options():
    result = build_plans(_roe(box_type=BoxType.BLACK))
    assert 3 <= len(result.options) <= 5
    scores = [o.fit_score for o in result.options]
    assert scores == sorted(scores, reverse=True), "options must be ranked by fit"


def test_goal_capability_and_start_reported():
    result = build_plans(_roe(box_type=BoxType.BLACK))
    assert result.goal_capability == CAP_DOMAIN_ADMIN
    assert result.start_capabilities == sorted(start_capabilities(_roe(box_type=BoxType.BLACK)))


# ── Box type shapes the plan ─────────────────────────────────────

def test_box_type_changes_start_state_and_plan_length():
    black = build_plans(_roe(box_type=BoxType.BLACK))
    grey = build_plans(_roe(box_type=BoxType.GREY))

    assert CAP_INTERNAL_NETWORK not in black.start_capabilities
    assert CAP_INTERNAL_NETWORK in grey.start_capabilities
    # A grey-box team starts inside, so its best plan is no longer than black's.
    assert len(grey.options[0].steps) <= len(black.options[0].steps)


def test_provided_access_can_satisfy_objective_directly():
    roe = _roe(box_type=BoxType.BLACK, provided_access=[CAP_DOMAIN_ADMIN])
    result = build_plans(roe)
    assert result.options == []
    assert any("already granted" in n for n in result.notes)


# ── Constraints actually constrain ───────────────────────────────

def test_no_phishing_removes_phishing_from_every_plan_and_records_it():
    result = build_plans(_roe(box_type=BoxType.BLACK, restrictions=[Restriction.NO_PHISHING]))
    used = {s.technique_id
            for o in result.options for s in o.steps}
    assert "T1566" not in used
    assert any(e.startswith("T1566") and "no_phishing" in e
               for e in result.excluded_by_constraints)


def test_forbidden_technique_id_family_is_excluded():
    # Banning the parent T1558 must also drop sub-technique T1558.003.
    result = build_plans(_roe(box_type=BoxType.GREY, forbidden_technique_ids=["T1558"]))
    used = {s.technique_id for o in result.options for s in o.steps}
    assert "T1558.003" not in used


def test_forbidden_tactic_is_excluded():
    result = build_plans(_roe(box_type=BoxType.GREY, forbidden_tactics=[Tactic.CREDENTIAL_ACCESS]))
    for opt in result.options:
        for step in opt.steps:
            assert step.tactic != Tactic.CREDENTIAL_ACCESS.value


def test_out_of_scope_platform_plays_are_dropped():
    # Linux/web-only scope must exclude Windows/AD-only escalation plays.
    result = build_plans(EngagementInput(
        objective=Objective.INITIAL_FOOTHOLD,
        box_type=BoxType.BLACK,
        scope_platforms=[Platform.LINUX, Platform.WEB],
    ))
    used = {s.technique_id for o in result.options for s in o.steps}
    # T1003 (LSASS) is Windows-only; must not appear under a Linux/web scope.
    assert "T1003" not in used


# ── Evidence-handling / destructive gating ───────────────────────

def test_ransomware_blocked_without_evidence_removal_permission():
    roe = EngagementInput(
        objective=Objective.RANSOMWARE_SIMULATION,
        box_type=BoxType.GREY,
        scope_platforms=list(WIN_AD),
        allow_evidence_removal=False,
    )
    result = build_plans(roe)
    assert result.options == []
    assert any("No legal path" in n or "no legal" in n.lower() for n in result.notes)


def test_ransomware_allowed_with_evidence_removal_permission():
    roe = EngagementInput(
        objective=Objective.RANSOMWARE_SIMULATION,
        box_type=BoxType.GREY,
        scope_platforms=list(WIN_AD),
        allow_evidence_removal=True,
    )
    result = build_plans(roe)
    assert result.options, "a simulated-impact plan should exist once permitted"
    used = {s.technique_id for o in result.options for s in o.steps}
    assert "T1486" in used


# ── Plan quality: minimality and legality ────────────────────────

def test_every_plan_is_legal_and_minimal():
    result = build_plans(_roe(box_type=BoxType.BLACK, emulate_adversary="APT29"))
    by_id = playbook_by_id()
    start = start_capabilities(_roe(box_type=BoxType.BLACK))
    goal = result.goal_capability
    for opt in result.options:
        chain = [by_id[s.technique_id] for s in opt.steps]
        assert _chain_valid(chain, start, goal), f"{opt.plan_id} is not a legal chain"
        # Minimal: removing any single step must break the chain.
        for i in range(len(chain)):
            trial = chain[:i] + chain[i + 1:]
            assert not _chain_valid(trial, start, goal), (
                f"{opt.plan_id} still reaches goal without step {chain[i].technique_id}"
            )


def test_plans_are_distinct():
    result = build_plans(_roe(box_type=BoxType.BLACK))
    sequences = [tuple(s.technique_id for s in o.steps) for o in result.options]
    assert len(sequences) == len(set(sequences)), "each plan must be a distinct chain"


# ── Drill-down content is present ────────────────────────────────

def test_steps_carry_drilldown_detail():
    result = build_plans(_roe(box_type=BoxType.GREY))
    top = result.options[0]
    for step in top.steps:
        assert step.objective, "each step needs an engagement objective"
        assert step.steps, "each step needs concrete drill-down commands"
        assert step.success_indicator, "each step needs a success indicator"
        for cmd in step.steps:
            assert cmd["command"] and cmd["expected_result"]


def test_seed_plays_have_fallbacks_where_expected():
    # Initial-access and escalation plays should offer a secondary technique.
    by_id = playbook_by_id()
    assert by_id["T1190"].fallback_technique_ids
    assert by_id["T1558.003"].fallback_technique_ids


# ── Time budget ──────────────────────────────────────────────────

def test_time_budget_flag_and_warning():
    tight = build_plans(_roe(box_type=BoxType.BLACK, time_budget_hours=1))
    # A full DA chain cannot fit in 1 hour; the best plan should say so.
    top = tight.options[0]
    assert top.within_time_budget is False
    assert any("Exceeds" in w for w in top.warnings)

    roomy = build_plans(_roe(box_type=BoxType.GREY, time_budget_hours=100))
    assert roomy.options[0].within_time_budget is True


def test_no_budget_leaves_flag_none():
    result = build_plans(_roe(box_type=BoxType.GREY, time_budget_hours=None))
    assert result.options[0].within_time_budget is None


# ── Adversary emulation ──────────────────────────────────────────

def test_adversary_emulation_biases_ranking():
    plain = build_plans(_roe(box_type=BoxType.BLACK))
    apt = build_plans(_roe(box_type=BoxType.BLACK, emulate_adversary="APT29"))
    # The APT29 run should surface a rationale line crediting the emulation.
    assert any("APT29" in r for o in apt.options for r in o.rationale)
    # Emulation should not reduce the top score below the plain run's top score.
    assert apt.options[0].fit_score >= plain.options[0].fit_score - 0.01


# ── Determinism ──────────────────────────────────────────────────

def test_deterministic_across_runs():
    a = build_plans(_roe(box_type=BoxType.BLACK, emulate_adversary="APT29", time_budget_hours=40))
    b = build_plans(_roe(box_type=BoxType.BLACK, emulate_adversary="APT29", time_budget_hours=40))
    assert [(o.plan_id, o.fit_score, tuple(s.technique_id for s in o.steps)) for o in a.options] \
        == [(o.plan_id, o.fit_score, tuple(s.technique_id for s in o.steps)) for o in b.options]


# ── Rendering ────────────────────────────────────────────────────

def test_markdown_render_has_key_sections():
    result = build_plans(_roe(box_type=BoxType.BLACK, time_budget_hours=40))
    md = plan_result_to_markdown(result, roe_summary="test brief")
    assert "# Siege Tower — Engagement Attack Plan" in md
    assert "### Steps (detailed)" in md
    assert "Excluded by the Rules of Engagement" in md
    assert "| Command |" in md


def test_custom_playbook_is_honoured():
    # An empty playbook can reach nothing; the engine should say so, not crash.
    result = build_plans(_roe(box_type=BoxType.BLACK), playbook=[])
    assert result.options == []
    assert result.considered_play_count == 0
