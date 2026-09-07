"""
ATT&CK currency check for the Siege Tower playbook.

Validates every technique ID in the playbook against a MITRE ATT&CK Enterprise
STIX bundle and reports drift: techniques that ATT&CK has **revoked**,
**deprecated**, or no longer knows (**unknown** — a bad or renumbered ID). This
is a maintainer / CI tool, deliberately kept *out* of the planning path: the
engine never imports it, and it only touches the network when you explicitly
pass ``--fetch``. See docs/PLAYBOOK.md.

Usage:
    python -m siege_tower.attack_sync --bundle enterprise-attack.json
    python -m siege_tower.attack_sync --fetch            # download latest
    python -m siege_tower.attack_sync --fetch --json     # machine-readable
"""
from __future__ import annotations

import json
import sys

from .playbook import DEFAULT_PLAYBOOK

# Canonical latest Enterprise ATT&CK STIX bundle.
DEFAULT_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
               "master/enterprise-attack/enterprise-attack.json")


def load_bundle(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def fetch_bundle(url: str = DEFAULT_URL, timeout: int = 60) -> dict:
    """Download an ATT&CK STIX bundle. Network access is used ONLY here, and
    only when the caller asks for it (import stays network-free)."""
    import urllib.request  # lazy: keep module import side-effect free
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (documented URL)
        return json.loads(resp.read().decode("utf-8"))


def bundle_attack_version(bundle: dict) -> str | None:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return None


def index_techniques(bundle: dict) -> dict[str, dict]:
    """attack_id (e.g. 'T1087' / 'T1087.001') -> {name, deprecated, revoked}."""
    index: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        attack_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                attack_id = ref["external_id"]
                break
        if not attack_id:
            continue
        index[attack_id] = {
            "name": obj.get("name"),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
        }
    return index


def check_playbook(playbook, index: dict[str, dict]) -> list[dict]:
    """Return one record per playbook technique with its ATT&CK status."""
    out = []
    for play in playbook:
        tid = play.technique_id
        entry = index.get(tid)
        if entry is None:
            status = "unknown"
        elif entry["revoked"]:
            status = "revoked"
        elif entry["deprecated"]:
            status = "deprecated"
        else:
            status = "ok"
        out.append({
            "technique_id": tid,
            "play": play.name,
            "status": status,
            "attack_name": (entry or {}).get("name"),
        })
    return out


def summarize(records: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for r in records:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts


def _main(argv: list[str]) -> int:
    bundle_path = None
    do_fetch = False
    as_json = False
    strict = False
    it = iter(argv)
    for a in it:
        if a == "--bundle":
            bundle_path = next(it, None)
        elif a == "--fetch":
            do_fetch = True
        elif a == "--json":
            as_json = True
        elif a == "--strict":
            strict = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0

    if bundle_path:
        bundle = load_bundle(bundle_path)
    elif do_fetch:
        sys.stderr.write(f"Fetching {DEFAULT_URL} …\n")
        bundle = fetch_bundle()
    else:
        sys.stderr.write("Provide --bundle <path> or --fetch.\n")
        return 2

    index = index_techniques(bundle)
    records = check_playbook(DEFAULT_PLAYBOOK, index)
    counts = summarize(records)
    attack_ver = bundle_attack_version(bundle)
    issues = [r for r in records if r["status"] in ("unknown", "revoked")]
    warnings = [r for r in records if r["status"] == "deprecated"]

    if as_json:
        print(json.dumps({
            "attack_version": attack_ver, "counts": counts,
            "records": records,
        }, indent=2))
    else:
        print(f"ATT&CK bundle version: {attack_ver or 'unknown'}")
        print(f"Playbook techniques:   {len(records)}")
        print("Status: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        for r in issues + warnings:
            print(f"  [{r['status'].upper():10}] {r['technique_id']:12} {r['play']}")
        if not issues and not warnings:
            print("All techniques current. ✔")

    if issues:
        return 1
    if warnings and strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
