# Gauntlet — Design Brief

_Security exercise design & proctoring platform. Working-title, revision 0.1._

> A polished, browsable version of this brief is in `design.html` (open in a
> browser). This Markdown copy is the version-controlled canonical text.

## The core idea

Tabletop exercises live or die on the facilitator. A great one keeps the
scenario plausible, adapts injects to what the room actually does, adjudicates
outcomes fairly against the real environment, keeps time, and captures every
decision so the debrief writes itself. Most facilitators do this from a static
document and their own memory.

Gauntlet is a **control surface for that job** — a dungeon master's screen for
security exercises. You feed it the environment. It generates a plausible,
branching scenario grounded in that environment. As the exercise runs, it
presents the next move, offers the branches, and rules on player actions against
the defenses you defined. The proctor can override anything: **the model
proposes, the human disposes.** Every choice is logged to a tamper-evident
timeline that becomes the after-action report.

## Positioning

- **Standalone product** (not coupled to any other tool).
- **Tabletop / discussion-based first.** It carries the highest value per unit of
  effort and contains every concept the other exercise modes reuse.

## Lifecycle (HSEEP / NIST SP 800-84)

Seven phases, one continuous loop. Phase 7 feeds phase 1 of the next exercise.

1. **Intake** — load the environment (assets, controls, detections, playbooks,
   policies, personnel, deception assets, crown jewels). Set the knowledge
   posture (white / grey / black box) per audience.
2. **Design** — define objectives and their Exercise Evaluation Guides. Build the
   scenario and its Master Scenario Events List (the branching injects).
3. **Assemble** — cast roles and cells (White Cell / control, participants,
   evaluators, observers). Set information asymmetry per cell (fog of war).
4. **Conduct** — the facilitator console: present injects, offer branches,
   adjudicate actions, control the game clock, capture observations.
5. **Evaluate** — score against objectives; compute detection latency, decision
   latency, playbook adherence, and ATT&CK coverage from the timeline.
6. **Report** — audience-tailored outputs and the After-Action Report /
   Improvement Plan.
7. **Improve** — track closure of improvement items and roll up program-level
   coverage.

## The spine: MSEL → injects → branches

A **Master Scenario Events List** is the facilitator's script. An **inject** is
one scene: information delivered to the room, an expected participant action, and
a set of **branches** that decide what happens next. Branches fire on the game
clock (`timeout`), a player action (`action_taken` + a `trigger`), or the
proctor's choice (`proctor_choice`). That is the choose-your-own-adventure
structure, expressed as data:

```yaml
inject:
  id: "INJ-04"
  title: "EDR flags LSASS access on FIN-APP-02"
  channel: edr_alert          # email · chat · ticket · siem_alert · phone · news
  visible_to: [blue_cell, white_cell]   # fog of war per cell
  clock: "T+00:35"            # game time, real or compressed
  maps_to: { attack: ["T1003.001"], objective: "OBJ-2" }
  branches:
    - when: action_taken   # players isolate the host
      trigger: "isolate_host"
      goto: "INJ-05a"
    - when: timeout        # no action within 10 game-minutes
      after: "PT10M"
      goto: "INJ-05b"
    - when: proctor_choice # DM overrides with a custom turn
      goto: "INJ-05c"
```

## Adjudication engine

When the room takes an action — or the adversary makes a move — Gauntlet rules on
the outcome **against the defenses you fed it**. A technique against a segment
with tuned EDR and full logging plays out differently than the same technique
against an unmonitored flat network.

- **Rules first, judgment always.** A transparent, deterministic rules engine
  scores detection likelihood (`1 − ∏(1 − efficacy)`) and time-to-detect from the
  mapped control coverage; the proctor confirms, edits, or overrides.
- **Deception is first-class.** Honeypots and canaries (mapped to MITRE Engage)
  can be tripped — revealing the adversary early and handing the blue cell an
  advantage.
- **Explainable.** Every ruling records which control caused which outcome, so the
  report can point at the exact detection gap.

## Domain model

| Entity | Is | Holds |
|---|---|---|
| **Environment** | The system under test | Assets, topology, controls, detections, playbooks, policies, personnel, deception, crown jewels |
| **VisibilityLayer** | Who knows what | Per-audience redaction (white/grey/black box) |
| **Objective** | What we're testing | Goal, success criteria, Exercise Evaluation Guide |
| **Scenario** | The premise | Threat actor, narrative, scope, rules of engagement |
| **Inject** | One scene | Channel, narrative, expected actions, ATT&CK & objective mappings, branches |
| **Role / Cell** | Who's playing | Participants, White Cell, evaluators, observers; visibility scope |
| **Session** | One run | Live state: current inject, game clock, chosen branches, status |
| **TimelineEvent** | The record | Append-only, hash-chained log of injects, decisions, adjudications, notes |
| **Observation** | What an evaluator saw | Note tied to an objective and a timeline moment, with a rating |
| **Report** | The output | Audience, rendered content, AAR / Improvement Plan |

## Reporting — one exercise, a report for every room

| Audience | Output |
|---|---|
| Board / executive | Readiness in one page: objectives met/missed, top risks, commitments |
| SOC / IR | Technical hotwash: full timeline, each adjudication + the control that drove it, detection gaps by ATT&CK technique |
| GRC / audit | Evidence package: participants, objectives, scope, outcome — defensible proof the test happened |
| Training / HR | Capability gaps tied to skills and playbooks, feeding the next training cycle |

**Why it sells:** exercises are increasingly mandatory — PCI-DSS 12.10.2, DORA
threat-led testing, NIS2, ISO 27001 A.5.24–.30, HIPAA, SOC 2, FFIEC, NERC CIP.
An audit-ready evidence package produced automatically is worth the platform on
its own.

## Framework alignment

| Framework | What Gauntlet borrows |
|---|---|
| FEMA HSEEP | Exercise lifecycle and artifacts — ExPlan, SitMan, MSEL, EEG, AAR/IP, hotwash |
| NIST SP 800-84 | Exercise-type taxonomy: discussion-based vs. operational |
| MITRE ATT&CK | Adversary techniques for injects, and program coverage analytics |
| MITRE D3FEND | Structured vocabulary for defensive controls |
| MITRE Engage | Deception & denial mapping for honeypots and canaries |

## Guardrails (day one)

- Authorization and rules of engagement are exercise metadata, surfaced
  everywhere. Real-time modes stay gated behind explicit scope.
- "This is an exercise" framing and a facilitator pause control — the
  psychological-safety, no-fault posture good tabletops require.
- Tamper-evident (append-only, hash-chained) timeline for audit-defensible
  reports.
- Adversary TTPs are generated only to design an exercise against a supplied,
  authorized environment — never as operational guidance against systems the
  user doesn't own.

## Roadmap

- **M1 — Tabletop core** *(shipped)*: intake, scenario + MSEL, console,
  adjudication, timeline, reports.
- **M2 — Authoring & library** *(shipped)*: template library, threat-actor-driven
  generation, inject bank, multi-channel delivery.
- **M3 — Multi-cell & parallel** *(shipped)*: fog-of-war per cell, evaluator
  companion, parallel/functional roll-up.
- **M4 — Sandbox & real-time** *(shipped)*: authorization-gated live/technical
  injects through a pluggable range adapter (safe simulation adapter by
  default), program-level coverage analytics.

## Guardrails realised in M4

Operational modes never touch anything out of bounds: a live inject is refused
unless its session carries a valid, unexpired authorization grant (`scope`,
`authorized_by`, expiry) whose scope covers the target. The shipped range
adapter is a **simulation** that contacts no external system; a real adapter is
pluggable behind the same authorization gate.
