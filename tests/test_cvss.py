"""
CVSS v3.1 base scoring — checked against canonical spec example vectors.
"""
import pytest

from siege_tower.cvss import base_score, score_vector, severity_band

# Canonical CVSS v3.1 vectors and their published base scores.
CASES = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "critical"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": (10.0, "critical"),
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": (7.8, "high"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": (6.1, "medium"),
    "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": (2.0, "low"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": (0.0, "none"),
}


@pytest.mark.parametrize("vector,expected", CASES.items())
def test_base_scores(vector, expected):
    score, sev = expected
    assert base_score(vector) == score
    got = score_vector(vector)
    assert got["score"] == score
    assert got["severity"] == sev
    assert got["version"] == "3.1"


def test_severity_bands():
    assert severity_band(0.0) == "none"
    assert severity_band(3.9) == "low"
    assert severity_band(4.0) == "medium"
    assert severity_band(7.0) == "high"
    assert severity_band(9.0) == "critical"


def test_v40_recognized_but_not_scored():
    got = score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert got["version"] == "4.0"
    assert got["score"] is None  # v4.0 auto-scoring not implemented; manual entry


def test_garbage_vector_returns_none():
    assert base_score("not-a-vector") is None
    assert base_score("CVSS:3.1/AV:X/AC:L") is None  # invalid metric value
