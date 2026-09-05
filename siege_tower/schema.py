"""
Siege Tower — domain model.

Standalone, dependency-free description of the inputs and outputs of the
attack-plan engine. Nothing here imports Bulwark (or anything outside the
standard library) so the package runs on its own and integrates as a library.

The vocabulary is deliberately close to a real Rules of Engagement (ROE)
document: box type, in-scope platforms, allowed/forbidden techniques, the
access the client has already granted, the time budget, and whether the team
may remove artifacts it creates. The engine turns that into a small set of
ranked, ATT&CK-mapped attack plans.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ── Engagement inputs (the ROE, structured) ──────────────────────

class BoxType(str, Enum):
    """How much the client tells the team before it starts.

    The box type sets a baseline of starting capabilities; `provided_access`
    on the engagement then adds anything granted explicitly (named creds, a
    VPN handle, a workstation, source code).
    """
    BLACK = "black"   # No prior knowledge. Start from the public edge.
    GREY = "grey"     # Partial knowledge — usually a low-priv foothold.
    WHITE = "white"   # Full knowledge, source, and often standing access.


class Objective(str, Enum):
    """The end-state the engagement is contracted to demonstrate.

    Each objective resolves to a goal capability the plan must reach
    (see GOAL_CAPABILITY in engine.py).
    """
    INITIAL_FOOTHOLD = "initial_foothold"
    DOMAIN_ADMIN = "domain_admin"
    DATA_EXFILTRATION = "data_exfiltration"
    RANSOMWARE_SIMULATION = "ransomware_simulation"
    CLOUD_TAKEOVER = "cloud_takeover"
    EMAIL_COMPROMISE = "email_compromise"


class Platform(str, Enum):
    """In-scope system classes, taken from the ROE 'systems in play' list."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    WEB = "web"
    NETWORK = "network"
    ACTIVE_DIRECTORY = "active_directory"
    AZURE_AD = "azure_ad"
    CLOUD = "cloud"


class Tactic(str, Enum):
    """ATT&CK Enterprise tactics — the coarse phase each play belongs to."""
    RECON = "reconnaissance"
    RESOURCE_DEV = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# Friendly ROE constraint switches → the play attributes they gate.
# The engine reads these off EngagementInput so a team can express common
# ROE restrictions ("no phishing", "no DoS") without knowing technique IDs.
class Restriction(str, Enum):
    NO_PHISHING = "no_phishing"
    NO_SOCIAL_ENGINEERING = "no_social_engineering"
    NO_EXPLOITATION = "no_exploitation"        # no memory-corruption / public exploits
    NO_DENIAL_OF_SERVICE = "no_denial_of_service"
    NO_CREDENTIAL_BRUTEFORCE = "no_credential_bruteforce"
    NO_PERSISTENCE = "no_persistence"
    STEALTH_REQUIRED = "stealth_required"       # avoid noisy plays where possible


@dataclass
class EngagementInput:
    """A structured Rules of Engagement, as entered by the red team.

    Only `objective` is strictly required; every other field has a sensible
    default so a team can get a first draft plan from very little, then refine.
    """
    objective: Objective
    box_type: BoxType = BoxType.BLACK

    # Scope — ATT&CK plays are filtered to these platforms. Empty means
    # "no platform restriction" (all in scope).
    scope_platforms: list[Platform] = field(default_factory=list)

    # Access the client has already granted. These are capability tokens
    # (see engine.CAP_*). Documented here so grey/white-box starting state is
    # explicit and auditable.
    provided_access: list[str] = field(default_factory=list)

    # ROE restrictions expressed as friendly switches …
    restrictions: list[Restriction] = field(default_factory=list)
    # … and/or as raw ATT&CK identifiers to hard-exclude.
    forbidden_technique_ids: list[str] = field(default_factory=list)
    forbidden_tactics: list[Tactic] = field(default_factory=list)

    # Engagement window, in hours. Used to flag plans that overrun and to
    # bias ranking toward plans that fit.
    time_budget_hours: float | None = None

    # May the team remove/alter artifacts it creates (destructive actions,
    # anti-forensics, cleanup)? Many ROEs forbid this. When False, plays that
    # require it are excluded.
    allow_evidence_removal: bool = False

    # Optional threat actor to emulate (e.g. "APT29"). Plays attributed to
    # that actor get a ranking bonus so the plan mirrors the adversary.
    emulate_adversary: str | None = None

    # How many ranked plans to return (clamped to 3..5 by the engine).
    max_plans: int = 5

    # Free-text objective note carried into the generated documentation.
    objective_note: str | None = None


# ── Playbook knowledge unit ──────────────────────────────────────

@dataclass(frozen=True)
class PlayStep:
    """One concrete, drill-down action inside a play.

    This is the highly-detailed layer: the command to run, what it does, and
    what a successful run looks like.
    """
    command: str
    description: str
    expected_result: str


@dataclass(frozen=True)
class Play:
    """An ATT&CK-mapped 'play': how to accomplish one step of an engagement.

    A play is a rule in the engine: it is applicable only when the operator
    already holds every capability in `requires`, and applying it grants every
    capability in `provides`. That is what lets the engine chain plays into a
    full attack path and explain each hop.
    """
    technique_id: str          # ATT&CK technique, e.g. "T1190"
    name: str
    tactic: Tactic
    summary: str               # broad, one-line description (top-level view)

    # Capability preconditions / effects (the planner's edges).
    requires: frozenset[str] = frozenset()
    provides: frozenset[str] = frozenset()

    platforms: frozenset[Platform] = frozenset()

    # Rough operational characteristics, 1 (low) .. 5 (high).
    noise: int = 3             # detection footprint
    difficulty: int = 3        # operator skill / effort
    reliability: int = 3       # how often it works in practice
    est_minutes: int = 30      # rough time to execute

    # ROE gating flags.
    destructive: bool = False           # alters/destroys target state
    requires_evidence_removal: bool = False
    is_phishing: bool = False
    is_social_engineering: bool = False
    is_exploitation: bool = False       # memory corruption / public exploit
    is_denial_of_service: bool = False
    is_credential_bruteforce: bool = False
    is_persistence: bool = False

    # Drill-down detail.
    objective: str = ""                 # what this play achieves for the engagement
    prerequisite_note: str = ""         # human-readable precondition
    steps: tuple[PlayStep, ...] = ()
    success_indicator: str = ""
    # Technique IDs to try if this play fails (the 'secondary technique').
    fallback_technique_ids: tuple[str, ...] = ()
    detection: str = ""                 # how a blue team would see it
    attributed_actors: frozenset[str] = frozenset()
    references: tuple[str, ...] = ()


# ── Plan outputs ─────────────────────────────────────────────────

@dataclass
class PlanStepView:
    """A play as it appears inside a generated plan, with its drill-down."""
    technique_id: str
    name: str
    tactic: str
    summary: str
    objective: str
    prerequisite_note: str
    provides: list[str]
    est_minutes: int
    noise: int
    difficulty: int
    reliability: int
    steps: list[dict]                 # {command, description, expected_result}
    success_indicator: str
    fallback_technique_ids: list[str]
    detection: str
    references: list[str]


@dataclass
class PlanOption:
    """One ranked, end-to-end attack plan.

    Broad at the top (an ordered list of steps by kill-chain phase) with each
    step drillable into commands and fallbacks — plus totals and an
    explainable rationale for why this plan was offered.
    """
    plan_id: str
    title: str
    fit_score: float                  # higher is a better fit (0..100)
    rationale: list[str]              # plain-language reasons, auditable
    steps: list[PlanStepView]
    est_total_minutes: int
    within_time_budget: bool | None   # None when no budget was given
    aggregate_noise: float            # mean noise across steps (1..5)
    max_difficulty: int
    covered_tactics: list[str]
    warnings: list[str] = field(default_factory=list)


@dataclass
class PlanResult:
    """The engine's full answer: the ranked options plus how it got there."""
    objective: str
    goal_capability: str
    start_capabilities: list[str]
    options: list[PlanOption]
    considered_play_count: int
    excluded_by_constraints: list[str]  # "T1566: no_phishing", …
    notes: list[str] = field(default_factory=list)
