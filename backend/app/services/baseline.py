"""
Baseline diffing for the standalone engine.

The first scan of any real application produces findings — often dozens. A CI
gate that fails on all of them forever gets removed from the pipeline within a
week. Diffing against a baseline (a previous scan's JSON output, typically
from the default branch) turns the gate into the question teams actually want
answered: "did THIS change make things worse?"

Findings are matched across scans by their stable fingerprint (see
fingerprint.py). Each current finding is annotated new/recurring; baseline
findings with no match in the current scan are reported as resolved.
"""
import json

from app.services.fingerprint import finding_fingerprint


def load_baseline(path: str) -> dict:
    """Load a previous scan-result JSON file.

    Accepts exactly what `bulwark scan --json FILE` writes. Raises ValueError
    with a human-readable message on anything else, so the CLI can exit 2
    rather than silently gating against garbage.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ValueError(f"Baseline file not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Baseline file is not valid JSON: {path} ({e})")

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(
            f"Baseline file does not look like a Bulwark scan result "
            f"(expected a JSON object with a 'findings' list): {path}"
        )
    return data


def _fingerprint_of(finding: dict) -> str:
    # Older result files predate the engine stamping fingerprints; compute
    # on the fly so any historical JSON works as a baseline.
    return finding.get("fingerprint") or finding_fingerprint(finding)


def apply_baseline(result: dict, baseline: dict) -> dict:
    """Annotate result findings against the baseline, in place.

    Adds per-finding `status` ("new"/"recurring"), a `resolved_findings`
    list, `baseline` metadata, and new/recurring/resolved counts to the
    summary. Returns the same result dict for convenience.
    """
    baseline_by_fp: dict[str, dict] = {}
    for f in baseline.get("findings", []):
        baseline_by_fp.setdefault(_fingerprint_of(f), f)

    current_fps = set()
    new = recurring = 0
    for f in result.get("findings", []):
        fp = _fingerprint_of(f)
        f["fingerprint"] = fp
        current_fps.add(fp)
        if fp in baseline_by_fp:
            f["status"] = "recurring"
            recurring += 1
        else:
            f["status"] = "new"
            new += 1

    resolved = [
        {
            "fingerprint": fp,
            "title": bf.get("title"),
            "severity": bf.get("severity"),
            "source": bf.get("source"),
        }
        for fp, bf in baseline_by_fp.items()
        if fp not in current_fps
    ]

    result["baseline"] = {
        "target": baseline.get("target"),
        "completed_at": baseline.get("completed_at"),
        "findings": len(baseline.get("findings", [])),
    }
    result["resolved_findings"] = resolved

    summary = result.setdefault("summary", {})
    summary["new"] = new
    summary["recurring"] = recurring
    summary["resolved"] = len(resolved)
    return result
