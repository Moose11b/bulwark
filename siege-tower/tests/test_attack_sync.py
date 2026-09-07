"""
ATT&CK currency check — offline, against a synthetic STIX bundle.
"""
from types import SimpleNamespace

from siege_tower.attack_sync import (
    bundle_attack_version, check_playbook, index_techniques, summarize,
)
from siege_tower.playbook import DEFAULT_PLAYBOOK


def _pattern(tid, name="X", deprecated=False, revoked=False):
    return {
        "type": "attack-pattern", "name": name, "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _bundle(patterns, version="14.1"):
    return {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": version}, *patterns]}


def test_index_and_version():
    b = _bundle([_pattern("T1087", "Account Discovery"),
                 _pattern("T1558.003", "Kerberoasting", deprecated=True)])
    assert bundle_attack_version(b) == "14.1"
    idx = index_techniques(b)
    assert idx["T1087"]["name"] == "Account Discovery"
    assert idx["T1558.003"]["deprecated"] is True


def test_check_statuses():
    idx = index_techniques(_bundle([
        _pattern("T1000", "Live"),
        _pattern("T2000", "Old", deprecated=True),
        _pattern("T3000", "Gone", revoked=True),
    ]))
    plays = [SimpleNamespace(technique_id=t, name=t) for t in
             ("T1000", "T2000", "T3000", "T9999")]
    recs = {r["technique_id"]: r["status"] for r in check_playbook(plays, idx)}
    assert recs == {"T1000": "ok", "T2000": "deprecated",
                    "T3000": "revoked", "T9999": "unknown"}


def test_full_playbook_all_current():
    # A bundle that knows every technique in the shipped playbook → all ok.
    ids = sorted({p.technique_id for p in DEFAULT_PLAYBOOK})
    idx = index_techniques(_bundle([_pattern(t) for t in ids]))
    recs = check_playbook(DEFAULT_PLAYBOOK, idx)
    counts = summarize(recs)
    assert counts.get("ok") == len(DEFAULT_PLAYBOOK)
    assert "unknown" not in counts and "revoked" not in counts


def test_full_playbook_flags_drift():
    ids = sorted({p.technique_id for p in DEFAULT_PLAYBOOK})
    revoked_id = ids[0]
    dropped_id = ids[1]
    patterns = [_pattern(t, revoked=(t == revoked_id)) for t in ids if t != dropped_id]
    idx = index_techniques(_bundle(patterns))
    counts = summarize(check_playbook(DEFAULT_PLAYBOOK, idx))
    assert counts.get("revoked", 0) >= 1
    assert counts.get("unknown", 0) >= 1  # the dropped technique
