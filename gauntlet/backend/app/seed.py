"""A worked example: a finance-sector ransomware tabletop.

Loaded on an empty database so a fresh checkout can run the full loop
immediately. The environment defines real controls and a deception canary; the
MSEL branches on what the blue cell does, so the same scenario can end in a
clean recovery or a domain-wide compromise depending on the proctor's calls.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


def _environment() -> models.Environment:
    return models.Environment(
        name="Northwind Federal — Core Banking",
        sector="Financial services",
        description=(
            "Retail bank core environment. Grey-box exercise: the blue cell knows the "
            "asset inventory, control stack, and playbooks but not the placement of "
            "deception assets."
        ),
        box_type="grey",
        assets=[
            {"code": "WKS-FINANCE", "name": "Finance workstation", "zone": "user"},
            {"code": "EMAIL-GW", "name": "Email security gateway", "zone": "perimeter"},
            {"code": "VPN-GW", "name": "Remote-access VPN", "zone": "perimeter"},
            {"code": "FIN-APP-02", "name": "Finance application host", "zone": "app"},
            {"code": "FILE-SRV-01", "name": "Departmental file server", "zone": "app"},
            {"code": "DC-01", "name": "Primary domain controller", "zone": "core"},
            {"code": "BACKUP-01", "name": "Immutable backup vault", "zone": "core"},
        ],
        controls=[
            {"name": "Defender for Endpoint (EDR)", "type": "edr",
             "covers": ["T1003.001", "T1055", "T1486", "T1021"], "assets": ["*"],
             "efficacy": 0.8, "latency_min": 8},
            {"name": "Email gateway sandboxing", "type": "email",
             "covers": ["T1566.001", "T1566.002"], "assets": ["EMAIL-GW", "WKS-FINANCE"],
             "efficacy": 0.6, "latency_min": 2},
            {"name": "MFA on remote access", "type": "identity",
             "covers": ["T1078"], "assets": ["VPN-GW", "*"], "efficacy": 0.65, "latency_min": 5},
            {"name": "Immutable backup vault", "type": "resilience",
             "covers": ["T1490", "T1486"], "assets": ["BACKUP-01"], "efficacy": 0.9,
             "latency_min": 3},
        ],
        detections=[
            {"name": "SIEM correlation rules", "type": "siem",
             "covers": ["*"], "assets": ["*"], "efficacy": 0.4, "latency_min": 20},
            {"name": "Domain-controller audit logging", "type": "log",
             "covers": ["T1078", "T1098"], "assets": ["DC-01"], "efficacy": 0.5,
             "latency_min": 15},
        ],
        deception_assets=[
            {"name": "Honey-credentials on file server", "type": "canary",
             "covers": ["T1021", "T1078"], "assets": ["FILE-SRV-01"], "efficacy": 1.0,
             "latency_min": 1},
        ],
        playbooks=[
            {"name": "Ransomware IR playbook", "owner": "IR lead"},
            {"name": "Phishing triage playbook", "owner": "SOC"},
        ],
        policies=[
            {"name": "Acceptable use policy"},
            {"name": "Data classification & handling standard"},
        ],
        personnel=[
            {"role": "SOC analyst (tier 1)", "name": "on-shift"},
            {"role": "Incident response lead", "name": "R. Okafor"},
            {"role": "CISO", "name": "L. Marsh"},
            {"role": "Communications lead", "name": "P. Adeyemi"},
        ],
        crown_jewels=["FIN-APP-02", "DC-01", "BACKUP-01"],
        visibility={
            "white_cell": ["assets", "controls", "detections", "deception_assets",
                           "playbooks", "policies", "personnel", "crown_jewels"],
            "blue_cell": ["assets", "controls", "detections", "playbooks",
                          "policies", "personnel", "crown_jewels"],
            "red_cell": ["assets"],
            "observers": ["assets", "controls"],
        },
    )


def _objectives() -> list[models.Objective]:
    return [
        models.Objective(
            code="OBJ-1", title="Detect the initial intrusion",
            description="Identify the initial-access vector and raise an incident.",
            success_criteria="Phishing / initial access identified and escalated within 30 game-minutes.",
            eeg=["Was the report triaged against the phishing playbook?",
                 "Was an incident opened with the right severity?"],
        ),
        models.Objective(
            code="OBJ-2", title="Triage and scope the compromise",
            description="Work EDR alerts to understand what was touched.",
            success_criteria="Compromised host identified and its crown-jewel dependency recognised.",
            eeg=["Was the EDR alert triaged?", "Was FIN-APP-02 recognised as crown-jewel-adjacent?"],
        ),
        models.Objective(
            code="OBJ-3", title="Contain lateral movement",
            description="Stop the adversary before domain compromise.",
            success_criteria="Host isolated before the domain controller is reached.",
            eeg=["Was containment authorised quickly?", "Did the team consider deception signals?"],
        ),
        models.Objective(
            code="OBJ-4", title="Recover and communicate",
            description="Restore from backups and run stakeholder communications.",
            success_criteria="Recovery initiated from immutable backups; comms plan executed.",
            eeg=["Were immutable backups used?", "Was a comms lead engaged?"],
        ),
    ]


def _injects() -> list[models.Inject]:
    return [
        models.Inject(
            code="INJ-01", sequence=1, is_start=True,
            title="Phishing email reported by a finance clerk",
            channel="email", clock="T+00:00",
            narrative=("A finance clerk forwards a suspicious invoice email to the SOC "
                       "mailbox. It carries a link to a look-alike SSO portal."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Triage against the phishing playbook",
                              "Check whether other users received it"],
            attack_techniques=["T1566.001"], target_asset="WKS-FINANCE",
            objective_code="OBJ-1",
            branches=[
                {"when": "action_taken", "trigger": "investigate_and_block", "goto": "INJ-02a",
                 "label": "SOC investigates and blocks the sender"},
                {"when": "timeout", "after": "PT15M", "goto": "INJ-02b",
                 "label": "No action — a user submits credentials"},
                {"when": "proctor_choice", "goto": "INJ-02b",
                 "label": "Proctor: advance to credential theft"},
            ],
        ),
        models.Inject(
            code="INJ-02a", sequence=2,
            title="Credential-harvesting page confirmed",
            channel="chat", clock="T+00:12",
            narrative=("The SOC detonates the link: it's a credential-harvesting page. "
                       "The sender is blocked and recipients are warned — but one clerk "
                       "already entered credentials before the block."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Force password reset for the affected clerk",
                              "Hunt for logins with the stolen credential"],
            attack_techniques=["T1078"], target_asset="VPN-GW", objective_code="OBJ-1",
            branches=[{"when": "proctor_choice", "goto": "INJ-03",
                       "label": "Continue — attacker uses the credential"}],
        ),
        models.Inject(
            code="INJ-02b", sequence=3,
            title="Stolen credential used over VPN",
            channel="siem_alert", clock="T+00:20",
            narrative=("Hours pass with no triage. The attacker signs in over the VPN "
                       "with the harvested credential and lands on a finance host."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Notice the anomalous VPN login", "Open an incident"],
            attack_techniques=["T1078"], target_asset="VPN-GW", objective_code="OBJ-1",
            branches=[{"when": "proctor_choice", "goto": "INJ-03",
                       "label": "Continue — credential access on the host"}],
        ),
        models.Inject(
            code="INJ-03", sequence=4,
            title="EDR flags LSASS access on FIN-APP-02",
            channel="edr_alert", clock="T+00:35",
            narrative=("Defender for Endpoint raises a medium alert: a non-standard "
                       "process read LSASS memory on the finance application host."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Triage the alert against the IR playbook",
                              "Check whether the host is a crown-jewel dependency"],
            attack_techniques=["T1003.001"], target_asset="FIN-APP-02",
            objective_code="OBJ-2",
            branches=[
                {"when": "action_taken", "trigger": "isolate_host", "goto": "INJ-04a",
                 "label": "Blue cell isolates FIN-APP-02"},
                {"when": "timeout", "after": "PT10M", "goto": "INJ-04b",
                 "label": "No containment — attacker pivots to the DC"},
                {"when": "proctor_choice", "goto": "INJ-04a",
                 "label": "Proctor: team contains the host"},
            ],
        ),
        models.Inject(
            code="INJ-04a", sequence=5,
            title="Contained host — attacker probes the file server",
            channel="edr_alert", clock="T+00:48",
            narrative=("With FIN-APP-02 isolated, the attacker pivots toward the "
                       "departmental file server and reuses the stolen credential."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Watch for lateral movement", "Act on any deception signal"],
            attack_techniques=["T1021"], target_asset="FILE-SRV-01", objective_code="OBJ-3",
            branches=[{"when": "proctor_choice", "goto": "INJ-05",
                       "label": "Continue — ransomware staging begins"}],
        ),
        models.Inject(
            code="INJ-04b", sequence=6,
            title="Domain controller compromised",
            channel="siem_alert", clock="T+00:55",
            narrative=("No containment came. The attacker reaches DC-01, mints a new "
                       "privileged account, and now controls the domain."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Escalate to full IR", "Consider domain-wide credential reset"],
            attack_techniques=["T1078", "T1098"], target_asset="DC-01", objective_code="OBJ-3",
            branches=[{"when": "proctor_choice", "goto": "INJ-05",
                       "label": "Continue — ransomware staging begins"}],
        ),
        models.Inject(
            code="INJ-05", sequence=7,
            title="Ransomware staging on file shares",
            channel="edr_alert", clock="T+01:10",
            narrative=("Encryption activity begins across the file shares, and the "
                       "attacker attempts to delete backup snapshots to block recovery."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Invoke the ransomware IR playbook",
                              "Protect and validate immutable backups",
                              "Engage the comms lead"],
            attack_techniques=["T1486", "T1490"], target_asset="BACKUP-01",
            objective_code="OBJ-4",
            branches=[
                {"when": "action_taken", "trigger": "isolate_and_recover", "goto": "INJ-06a",
                 "label": "Team isolates and recovers from immutable backups"},
                {"when": "timeout", "after": "PT20M", "goto": "INJ-06b",
                 "label": "Slow response — widespread encryption"},
                {"when": "proctor_choice", "goto": "INJ-06a",
                 "label": "Proctor: team executes recovery"},
            ],
        ),
        models.Inject(
            code="INJ-06a", sequence=8,
            title="Recovery from immutable backups (resolution)",
            channel="briefing", clock="T+01:40",
            narrative=("The immutable vault survives the deletion attempt. Systems are "
                       "restored from clean backups and the comms plan runs. The exercise "
                       "resolves with limited impact."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Confirm restoration", "Run the hotwash"],
            attack_techniques=[], target_asset="BACKUP-01", objective_code="OBJ-4",
            branches=[],
        ),
        models.Inject(
            code="INJ-06b", sequence=9,
            title="Widespread encryption and extended outage (resolution)",
            channel="briefing", clock="T+02:10",
            narrative=("Encryption spreads before containment. Some backups were reachable "
                       "and hit, forcing a longer outage and a public-disclosure decision. "
                       "The exercise resolves with major impact."),
            visible_to=["blue_cell", "white_cell"],
            expected_actions=["Capture the decision timeline", "Run the hotwash"],
            attack_techniques=[], target_asset="FILE-SRV-01", objective_code="OBJ-4",
            branches=[],
        ),
    ]


def seed_if_empty(db: Session) -> bool:
    """Load the worked example if no environment exists yet. Returns True if seeded."""
    existing = db.execute(select(models.Environment).limit(1)).scalar_one_or_none()
    if existing:
        return False

    env = _environment()
    db.add(env)
    db.flush()

    scenario = models.Scenario(
        environment_id=env.id,
        name="Operation Frostbite — Ransomware Tabletop",
        threat_actor="Financially motivated ransomware affiliate (BEC → ransomware)",
        narrative=("A phishing-led intrusion escalates toward domain compromise and "
                   "ransomware. The blue cell must detect, contain, and recover."),
        scope="Discussion-based tabletop. No live systems are touched.",
        rules_of_engagement=("Facilitated exercise only. 'Pause' halts play at any time. "
                             "No production access. All actions are simulated."),
        exercise_type="tabletop",
        cells=[
            {"key": "white_cell", "name": "White Cell / Control", "kind": "control"},
            {"key": "blue_cell", "name": "Blue Cell (SOC + IR)", "kind": "participant"},
            {"key": "observers", "name": "Observers", "kind": "observer"},
        ],
    )
    scenario.objectives = _objectives()
    scenario.injects = _injects()
    db.add(scenario)
    db.commit()
    return True
