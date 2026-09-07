"""
CVSS scoring — dependency-free, part of the standalone engine package.

Implements the CVSS v3.1 (and v3.0) Base Score from a vector string, plus the
qualitative severity band. CVSS v4.0 vectors are recognized and validated but
not auto-scored here (the v4.0 formula is a large lookup table); callers may
carry a manually entered v4.0 score. Everything is a pure function.

Reference: FIRST CVSS v3.1 specification, section 7 (Base metrics / equations).
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def severity_band(score: float) -> str:
    """Qualitative severity for a numeric score (CVSS v3.x bands)."""
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _roundup(x: float) -> float:
    """CVSS v3.1 'roundup': ceil to one decimal with a small epsilon guard."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector string into a {metric: value} dict.

    Accepts an optional ``CVSS:3.1/`` (or 3.0 / 4.0) prefix.
    """
    parts = [p for p in (vector or "").strip().split("/") if p]
    out: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        out[k.strip().upper()] = v.strip().upper()
    return out


def cvss_version(vector: str) -> str | None:
    m = parse_vector(vector)
    return m.get("CVSS")


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.0/3.1 Base Score for a vector, or None if it can't be
    computed (unknown version, or missing/invalid base metrics)."""
    m = parse_vector(vector)
    version = m.get("CVSS", "3.1")
    if not (version.startswith("3.")):
        return None  # v4.0 (or unknown) — not auto-scored here
    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        scope_changed = m["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def score_vector(vector: str) -> dict:
    """Convenience: {version, score, severity} for a vector.

    For v3.x, score is computed; for v4.0/unknown, score is None and severity is
    derived from any provided score by the caller instead.
    """
    version = cvss_version(vector) or ("3.1" if vector else None)
    score = base_score(vector)
    return {
        "version": version,
        "score": score,
        "severity": severity_band(score) if score is not None else None,
    }
