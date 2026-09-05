"""
Siege Tower — standalone command-line interface.

Build an attack plan straight from the shell, from flags or from a JSON ROE
file, and print it as Markdown or JSON. This makes the package usable entirely
on its own; Bulwark integration is a separate, optional layer.

Examples
--------
  # Black-box, aim for Domain Admin, no phishing, 40-hour window, Markdown out
  python -m siege_tower.cli --objective domain_admin --box black \\
      --scope windows,active_directory --restrict no_phishing --hours 40

  # Grey-box from a saved ROE file, JSON out
  python -m siege_tower.cli --roe engagement.json --format json

ROE file schema (all keys optional except objective):
  {
    "objective": "domain_admin",
    "box_type": "grey",
    "scope_platforms": ["windows", "active_directory"],
    "provided_access": ["domain_user", "internal_network"],
    "restrictions": ["no_phishing", "stealth_required"],
    "forbidden_technique_ids": ["T1486"],
    "forbidden_tactics": ["impact"],
    "time_budget_hours": 40,
    "allow_evidence_removal": false,
    "emulate_adversary": "APT29",
    "max_plans": 5,
    "objective_note": "Prove reach to the finance DB."
  }
"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import build_plans
from .render import plan_result_to_dict, plan_result_to_markdown
from .schema import (
    BoxType, EngagementInput, Objective, Platform, Restriction, Tactic,
)


def _enum_choices(enum_cls) -> str:
    return ", ".join(e.value for e in enum_cls)


def _coerce_enum(enum_cls, value, field):
    try:
        return enum_cls(value)
    except ValueError:
        raise SystemExit(
            f"error: invalid {field} '{value}'. Valid: {_enum_choices(enum_cls)}"
        )


def _roe_from_dict(data: dict) -> EngagementInput:
    if "objective" not in data:
        raise SystemExit("error: ROE is missing required key 'objective'.")
    return EngagementInput(
        objective=_coerce_enum(Objective, data["objective"], "objective"),
        box_type=_coerce_enum(BoxType, data.get("box_type", "black"), "box_type"),
        scope_platforms=[_coerce_enum(Platform, p, "scope platform")
                         for p in data.get("scope_platforms", [])],
        provided_access=list(data.get("provided_access", [])),
        restrictions=[_coerce_enum(Restriction, r, "restriction")
                      for r in data.get("restrictions", [])],
        forbidden_technique_ids=list(data.get("forbidden_technique_ids", [])),
        forbidden_tactics=[_coerce_enum(Tactic, t, "forbidden tactic")
                           for t in data.get("forbidden_tactics", [])],
        time_budget_hours=data.get("time_budget_hours"),
        allow_evidence_removal=bool(data.get("allow_evidence_removal", False)),
        emulate_adversary=data.get("emulate_adversary"),
        max_plans=int(data.get("max_plans", 5)),
        objective_note=data.get("objective_note"),
    )


def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siege-tower",
        description="Rules + ATT&CK attack-plan builder for authorized red teams.",
    )
    p.add_argument("--roe", help="Path to a JSON ROE file (overridden by flags).")
    p.add_argument("--objective", help=f"One of: {_enum_choices(Objective)}")
    p.add_argument("--box", dest="box_type",
                   help=f"Box type: {_enum_choices(BoxType)} (default black)")
    p.add_argument("--scope", help="Comma-separated in-scope platforms: "
                   f"{_enum_choices(Platform)}")
    p.add_argument("--access", help="Comma-separated provided capability tokens "
                   "(e.g. domain_user,internal_network,source_code).")
    p.add_argument("--restrict", help="Comma-separated ROE restrictions: "
                   f"{_enum_choices(Restriction)}")
    p.add_argument("--forbid-technique", help="Comma-separated ATT&CK IDs to ban "
                   "(e.g. T1486,T1210).")
    p.add_argument("--forbid-tactic", help="Comma-separated ATT&CK tactics to ban.")
    p.add_argument("--hours", type=float, help="Engagement time budget in hours.")
    p.add_argument("--allow-evidence-removal", action="store_true",
                   help="Permit destructive/cleanup plays (default off).")
    p.add_argument("--emulate", help="Threat actor to emulate (e.g. APT29).")
    p.add_argument("--max-plans", type=int, default=5, help="Plans to return (3-5).")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return p


def roe_from_args(args: argparse.Namespace) -> EngagementInput:
    # Start from a file if given, then let explicit flags override.
    if args.roe:
        with open(args.roe, "r", encoding="utf-8") as fh:
            base = json.load(fh)
    else:
        base = {}

    if args.objective:
        base["objective"] = args.objective
    if args.box_type:
        base["box_type"] = args.box_type
    if args.scope is not None:
        base["scope_platforms"] = _split(args.scope)
    if args.access is not None:
        base["provided_access"] = _split(args.access)
    if args.restrict is not None:
        base["restrictions"] = _split(args.restrict)
    if args.forbid_technique is not None:
        base["forbidden_technique_ids"] = _split(args.forbid_technique)
    if args.forbid_tactic is not None:
        base["forbidden_tactics"] = _split(args.forbid_tactic)
    if args.hours is not None:
        base["time_budget_hours"] = args.hours
    if args.allow_evidence_removal:
        base["allow_evidence_removal"] = True
    if args.emulate is not None:
        base["emulate_adversary"] = args.emulate
    if args.max_plans is not None:
        base["max_plans"] = args.max_plans

    return _roe_from_dict(base)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.roe and not args.objective:
        build_parser().print_help()
        print("\nerror: provide --objective or --roe.", file=sys.stderr)
        return 2

    roe = roe_from_args(args)
    result = build_plans(roe)

    if args.format == "json":
        print(json.dumps(plan_result_to_dict(result), indent=2))
    else:
        summary = None
        if roe.objective_note:
            summary = f"ROE objective note: {roe.objective_note}"
        print(plan_result_to_markdown(result, roe_summary=summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
