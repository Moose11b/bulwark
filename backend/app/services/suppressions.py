"""
Finding suppressions from a .bulwark.yml file.

Every gate tool needs a way to accept a risk without deleting the gate: the
first false positive or consciously-accepted finding otherwise becomes the
reason the whole step gets commented out. Suppressions are explicit,
reviewable (they live in the repo), justified (reason is mandatory), and can
be time-boxed (expires) so "temporarily accepted" does not quietly become
"forever".

File format::

    suppressions:
      - fingerprint: 3f2a9c...        # exact, from the JSON output
        reason: "Header set by CDN in prod; staging env lacks it"
      - cve: CVE-2024-12345
        reason: "Not exploitable: feature flag disabled"
        expires: 2026-12-31           # stops suppressing after this date
      - title: "Missing security header: X-Frame-Options*"   # glob, case-insensitive
        reason: "Legacy admin UI, frame-ancestors set instead"

Each entry needs a `reason` and at least one selector (`fingerprint`, `cve`,
or `title`). Suppressed findings stay in the output — marked, never hidden —
but do not count toward the gate. In SARIF they carry a `suppressions` entry,
which GitHub renders as a dismissed alert rather than an open one.
"""
from datetime import date, datetime
from fnmatch import fnmatchcase

SUPPRESSION_FILE_DEFAULT = ".bulwark.yml"


class SuppressionError(ValueError):
    """A malformed suppression file. Fails the run rather than half-applying."""


def load_suppressions(path: str) -> list[dict]:
    """Parse and validate a suppression file. Returns the entry list."""
    import yaml

    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        raise SuppressionError(f"Suppression file not found: {path}")
    except yaml.YAMLError as e:
        raise SuppressionError(f"Suppression file is not valid YAML: {path} ({e})")

    if not isinstance(data, dict) or not isinstance(data.get("suppressions"), list):
        raise SuppressionError(
            f"{path}: expected a top-level 'suppressions:' list"
        )

    entries = []
    for i, entry in enumerate(data["suppressions"], 1):
        if not isinstance(entry, dict):
            raise SuppressionError(f"{path}: suppression #{i} must be a mapping")
        if not str(entry.get("reason") or "").strip():
            raise SuppressionError(
                f"{path}: suppression #{i} has no 'reason' — every accepted "
                f"risk must say why"
            )
        if not any(entry.get(k) for k in ("fingerprint", "cve", "title")):
            raise SuppressionError(
                f"{path}: suppression #{i} needs a 'fingerprint', 'cve', or "
                f"'title' to match on"
            )
        expires = entry.get("expires")
        if expires is not None:
            entry["expires"] = _parse_expiry(expires, path, i)
        entries.append(entry)
    return entries


def _parse_expiry(value, path: str, index: int) -> date:
    # yaml.safe_load already turns unquoted ISO dates into date objects;
    # accept quoted strings too.
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError:
        raise SuppressionError(
            f"{path}: suppression #{index} has an invalid 'expires' date "
            f"({value!r}); use YYYY-MM-DD"
        )


def _matches(entry: dict, finding: dict) -> bool:
    fp = entry.get("fingerprint")
    if fp and str(fp).strip().lower() == str(finding.get("fingerprint") or "").lower():
        return True
    cve = entry.get("cve")
    if cve and str(cve).strip().upper() == str(finding.get("cve_id") or "").upper():
        return True
    title = entry.get("title")
    if title and fnmatchcase(
        str(finding.get("title") or "").lower(), str(title).lower()
    ):
        return True
    return False


def apply_suppressions(result: dict, entries: list[dict], *, today: date | None = None) -> dict:
    """Mark matching findings suppressed and rebuild the summary without them.

    The summary is what the gate reads, so after this call suppressed
    findings cannot fail a build. Expired entries stop matching. Returns the
    same result dict.
    """
    today = today or date.today()
    active = [e for e in entries if e.get("expires") is None or e["expires"] >= today]

    suppressed = 0
    for f in result.get("findings", []):
        match = next((e for e in active if _matches(e, f)), None)
        if match:
            f["suppressed"] = True
            f["suppressed_reason"] = str(match["reason"]).strip()
            suppressed += 1

    _resummarise(result)
    result.setdefault("summary", {})["suppressed"] = suppressed
    return result


def _resummarise(result: dict) -> None:
    """Recompute severity counts over unsuppressed findings only."""
    from app.services.standalone_engine import SEVERITY_ORDER, SEVERITY_RANK

    live = [f for f in result.get("findings", []) if not f.get("suppressed")]
    counts = {s: 0 for s in SEVERITY_ORDER}
    highest = "INFO"
    for f in live:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(highest, 0):
            highest = sev

    summary = result.setdefault("summary", {})
    summary["total"] = len(live)
    summary["by_severity"] = counts
    summary["highest_severity"] = highest
