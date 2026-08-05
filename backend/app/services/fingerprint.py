"""
Stable identity for a finding across scans.

Two scans of the same target produce two independent sets of rows. To answer
"what changed since last time" — the question that makes a second scan more
valuable than the first — a finding needs an identity that survives from one
scan to the next.

The fingerprint is deliberately derived from what the finding *is* (source,
CVE, and the thing it names) rather than anything scan-specific. Titles carry
the locus in every scanner here: "Open port 3306: MySQL", "Sensitive path
accessible: /.env", "Missing security header: Content-Security-Policy" — so
the title is doing real identity work, not just display.

Numbers are preserved, because in these titles they are usually identity (a
port, a key length, a CWE). The exception is time-relative phrasing, which
changes on every scan of an unchanged target and would otherwise make a
finding look new each day.
"""
import hashlib
import re

# Phrases that drift between scans while describing the same underlying issue.
# Narrow by design: blanket digit-stripping would collapse "Open port 80" and
# "Open port 8080" into one finding.
_VOLATILE_PHRASES = [
    (re.compile(r"\bin\s+\d+\s+days?\b", re.IGNORECASE), "in N days"),
    (re.compile(r"\b\d+\s+days?\s+ago\b", re.IGNORECASE), "N days ago"),
    (re.compile(r"\bexpires?\s+on\s+\d{4}-\d{2}-\d{2}\b", re.IGNORECASE), "expires on DATE"),
]

_WHITESPACE = re.compile(r"\s+")


def _normalise(text: str) -> str:
    text = (text or "").strip().lower()
    for pattern, replacement in _VOLATILE_PHRASES:
        text = pattern.sub(replacement, text)
    return _WHITESPACE.sub(" ", text).strip()


def finding_fingerprint(finding: dict) -> str:
    """Return a stable hex identity for a finding.

    A CVE, when present, is the strongest identity available and takes
    precedence over the title — the same CVE reported with reworded text is
    still the same finding.
    """
    source = (finding.get("source") or "unknown").strip().lower()
    cve = (finding.get("cve_id") or "").strip().upper()
    title = _normalise(
        finding.get("title") or finding.get("check") or finding.get("description") or ""
    )

    identity = cve or title
    if not identity:
        # Nothing to key on; fall back to the source so such findings at least
        # do not all collapse into a single fingerprint across scanners.
        identity = "unidentified"

    digest = hashlib.sha256(f"{source}|{identity}".encode("utf-8")).hexdigest()
    return digest[:32]
