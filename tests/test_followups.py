"""
Follow-up suggestions: when a step fails, offer other ways to the objective.
"""
from siege_tower import BoxType, EngagementInput, Objective, suggest_followups
from siege_tower.schema import Restriction


def _roe(**kw):
    kw.setdefault("objective", Objective.DOMAIN_ADMIN)
    kw.setdefault("box_type", BoxType.GREY)
    return EngagementInput(**kw)


def test_curated_fallbacks_come_first():
    sugg = suggest_followups("T1649", _roe())
    assert sugg, "expected suggestions for a known technique"
    # The failed technique's curated fallbacks should be surfaced and ranked first.
    fb_ids = {s.technique_id for s in sugg if s.is_fallback}
    assert {"T1558.003", "T1557"} & fb_ids
    assert sugg[0].is_fallback


def test_functional_alternatives_reach_same_capability():
    sugg = suggest_followups("T1649", _roe())
    # Alternatives that also grant Domain administrator control should appear.
    ids = {s.technique_id for s in sugg}
    assert "T1003.006" in ids or "T1021.002" in ids  # DCSync / Pass-the-Hash
    assert all(s.keeps_path_open for s in sugg)  # none is a dead end


def test_suggestions_respect_roe_restrictions():
    # Forbid a fallback technique explicitly; it must not be suggested.
    sugg = suggest_followups("T1649", _roe(forbidden_technique_ids=["T1558"]))
    assert all(not s.technique_id.startswith("T1558") for s in sugg)


def test_achieved_capabilities_flip_ready_now():
    # With local admin + creds already in hand, credentialed DA moves are ready.
    base = {s.technique_id: s for s in suggest_followups("T1649", _roe())}
    with_creds = {s.technique_id: s for s in suggest_followups(
        "T1649", _roe(), achieved={"local_admin", "harvested_creds", "ad_recon"})}
    # At least one suggestion becomes ready-now once prerequisites are held.
    assert any(s.ready_now for s in with_creds.values())
    assert not all(s.ready_now for s in base.values())


def test_unknown_technique_still_offers_moves():
    # A technique id not in the playbook: fall back to available next moves.
    sugg = suggest_followups("T9999", _roe())
    assert isinstance(sugg, list)  # never raises; may propose ready moves
