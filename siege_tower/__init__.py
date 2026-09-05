"""
Siege Tower — a rules + ATT&CK attack-plan builder for authorized red teams.

Standalone library (and CLI) that turns a structured Rules of Engagement into a
small set of ranked, ATT&CK-mapped attack plans, each drillable from a broad
kill-chain into concrete commands and fallbacks, with the reasoning documented.

Designed to run on its own and to integrate into Bulwark as a library: the core
engine imports nothing outside the standard library.

Typical use:

    from siege_tower import EngagementInput, Objective, BoxType, build_plans

    roe = EngagementInput(objective=Objective.DOMAIN_ADMIN, box_type=BoxType.BLACK)
    result = build_plans(roe)
    for option in result.options:
        print(option.title, option.fit_score)
"""
from .capabilities import CAPABILITY_LABELS, GOAL_CAPABILITY
from .engine import build_plans, filter_playbook, start_capabilities
from .playbook import DEFAULT_PLAYBOOK, playbook_by_id
from .render import plan_result_to_dict, plan_result_to_markdown
from .schema import (
    BoxType, EngagementInput, Objective, Platform, Play,
    PlayStep, PlanOption, PlanResult, PlanStepView, Restriction, Tactic,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # inputs
    "EngagementInput", "Objective", "BoxType", "Platform", "Restriction", "Tactic",
    # knowledge base
    "Play", "PlayStep", "DEFAULT_PLAYBOOK", "playbook_by_id",
    # engine
    "build_plans", "filter_playbook", "start_capabilities",
    "GOAL_CAPABILITY", "CAPABILITY_LABELS",
    # outputs
    "PlanResult", "PlanOption", "PlanStepView",
    # rendering
    "plan_result_to_dict", "plan_result_to_markdown",
]
