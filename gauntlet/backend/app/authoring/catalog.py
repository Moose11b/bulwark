"""The reusable catalog: an inject bank, threat-actor profiles, and templates.

* **Inject bank** — parameterised scene templates keyed by kill-chain phase and
  ATT&CK technique, with a delivery channel and a target zone. The generator
  fills the ``{...}`` placeholders with real assets from the environment.
* **Threat actors** — an ordered kill-chain (a list of inject-bank keys) plus a
  preset objective set. Choosing an actor is how you say "generate a plausible
  campaign of this shape".
* **Templates** — a named packaging of an actor with narrative, scope, and
  rules of engagement, so a proctor can start from "Ransomware — finance".
"""
from __future__ import annotations

# --------------------------------------------------------------------------- #
# Inject bank — reusable, parameterised scenes.
#   placeholders: {org} {asset} {asset_name}
#   target_zone steers which environment asset the generator picks.
# --------------------------------------------------------------------------- #
INJECT_BANK: dict[str, dict] = {
    "phish_invoice": {
        "phase": "initial-access", "channel": "email", "target_zone": "user",
        "techniques": ["T1566.001"], "objective_hint": "detect",
        "title": "Phishing email reported — fake invoice",
        "narrative": ("A {org} employee forwards a suspicious invoice email to the SOC "
                      "mailbox. It links to a look-alike SSO portal aimed at {asset_name}."),
        "expected_actions": ["Triage against the phishing playbook",
                             "Check who else received the message"],
    },
    "phish_credential": {
        "phase": "initial-access", "channel": "email", "target_zone": "user",
        "techniques": ["T1566.002"], "objective_hint": "detect",
        "title": "Spear-phish with credential link",
        "narrative": ("A targeted email to a finance approver at {org} carries a link to "
                      "a credential-harvesting page themed as a payment portal."),
        "expected_actions": ["Detonate the link safely", "Warn recipients"],
    },
    "exploit_public": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "perimeter",
        "techniques": ["T1190"], "objective_hint": "detect",
        "title": "Exploit attempt against {asset_name}",
        "narrative": ("The WAF and SIEM show repeated exploitation attempts against the "
                      "internet-facing {asset_name} ({asset})."),
        "expected_actions": ["Confirm whether exploitation succeeded",
                             "Check the asset's patch level"],
    },
    "malware_exec": {
        "phase": "execution", "channel": "edr_alert", "target_zone": "user",
        "techniques": ["T1204.002", "T1059.001"], "objective_hint": "triage",
        "title": "EDR: scripted payload executed on {asset_name}",
        "narrative": ("Defender flags a macro-spawned PowerShell process on {asset_name} "
                      "({asset}) reaching out to an unknown host."),
        "expected_actions": ["Triage the alert", "Contain the endpoint if confirmed"],
    },
    "c2_beacon": {
        "phase": "command-and-control", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1071.001"], "objective_hint": "triage",
        "title": "Beaconing traffic from {asset_name}",
        "narrative": ("Regular, low-and-slow HTTPS beacons leave {asset_name} ({asset}) "
                      "to a newly registered domain."),
        "expected_actions": ["Correlate with proxy logs", "Scope affected hosts"],
    },
    "lsass_dump": {
        "phase": "credential-access", "channel": "edr_alert", "target_zone": "app",
        "techniques": ["T1003.001"], "objective_hint": "contain",
        "title": "EDR flags LSASS access on {asset_name}",
        "narrative": ("A non-standard process read LSASS memory on {asset_name} ({asset}); "
                      "credential theft is likely."),
        "expected_actions": ["Triage against the IR playbook",
                             "Check whether the host is crown-jewel-adjacent"],
    },
    "lateral_smb": {
        "phase": "lateral-movement", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1021.002"], "objective_hint": "contain",
        "title": "Lateral movement toward {asset_name}",
        "narrative": ("Reused credentials authenticate over SMB toward {asset_name} "
                      "({asset}) — the adversary is spreading."),
        "expected_actions": ["Decide on containment", "Watch for any deception signal"],
    },
    "priv_esc_dc": {
        "phase": "privilege-escalation", "channel": "siem_alert", "target_zone": "core",
        "techniques": ["T1078", "T1098"], "objective_hint": "contain",
        "title": "Privileged account minted on {asset_name}",
        "narrative": ("A new privileged account appears on {asset_name} ({asset}); the "
                      "adversary may now control the domain."),
        "expected_actions": ["Escalate to full IR", "Consider domain-wide credential reset"],
    },
    "insider_access": {
        "phase": "initial-access", "channel": "siem_alert", "target_zone": "app",
        "techniques": ["T1078"], "objective_hint": "detect",
        "title": "After-hours access to {asset_name}",
        "narrative": ("A privileged employee accesses {asset_name} ({asset}) far outside "
                      "their normal pattern, browsing data unrelated to their role."),
        "expected_actions": ["Confirm business justification", "Preserve access logs"],
    },
    "data_staging": {
        "phase": "collection", "channel": "ticket", "target_zone": "app",
        "techniques": ["T1074"], "objective_hint": "contain",
        "title": "Large archive staged on {asset_name}",
        "narrative": ("An unusually large compressed archive is assembled on {asset_name} "
                      "({asset}) — data is being staged for exfiltration."),
        "expected_actions": ["Identify the data classification", "Restrict egress"],
    },
    "exfil_dns": {
        "phase": "exfiltration", "channel": "siem_alert", "target_zone": "core",
        "techniques": ["T1048"], "objective_hint": "contain",
        "title": "Exfiltration over an alternate channel from {asset_name}",
        "narrative": ("Sustained anomalous outbound traffic from {asset_name} ({asset}) "
                      "suggests data is leaving over a non-standard channel."),
        "expected_actions": ["Block the channel", "Quantify what left"],
    },
    "bec_wire_request": {
        "phase": "impact", "channel": "email", "target_zone": "user",
        "techniques": ["T1656"], "objective_hint": "prevent-loss",
        "title": "Urgent wire-transfer request from a spoofed executive",
        "narrative": ("Finance at {org} receives an urgent wire-change request appearing "
                      "to come from an executive, pressuring an immediate payment."),
        "expected_actions": ["Verify out-of-band against policy", "Halt the payment"],
    },
    "ransomware_deploy": {
        "phase": "impact", "channel": "edr_alert", "target_zone": "core",
        "techniques": ["T1486", "T1490"], "objective_hint": "recover",
        "title": "Ransomware staging on {asset_name}",
        "narrative": ("Mass file-encryption begins and the adversary tries to delete "
                      "backup snapshots reachable from {asset_name} ({asset})."),
        "expected_actions": ["Invoke the ransomware IR playbook",
                             "Protect and validate immutable backups",
                             "Engage the communications lead"],
    },
}


def _objs(*items) -> list[dict]:
    out = []
    for i, (title, crit) in enumerate(items, start=1):
        out.append({"code": f"OBJ-{i}", "title": title, "success_criteria": crit,
                    "description": title})
    return out


# --------------------------------------------------------------------------- #
# Threat-actor profiles: an ordered kill-chain + preset objectives.
# --------------------------------------------------------------------------- #
THREAT_ACTORS: dict[str, dict] = {
    "ransomware_affiliate": {
        "name": "Ransomware affiliate",
        "label": "Financially motivated ransomware affiliate (phishing → ransomware)",
        "description": "Phishing-led intrusion escalating to domain compromise and ransomware.",
        "kill_chain": ["phish_invoice", "malware_exec", "lsass_dump", "lateral_smb",
                       "ransomware_deploy"],
        "objectives": _objs(
            ("Detect the initial intrusion", "Initial access identified and escalated within 30 game-minutes."),
            ("Triage and scope the compromise", "Compromised host identified and its crown-jewel dependency recognised."),
            ("Contain lateral movement", "Host isolated before the domain controller is reached."),
            ("Recover and communicate", "Recovery initiated from immutable backups; comms plan executed."),
        ),
    },
    "bec_actor": {
        "name": "Business email compromise actor",
        "label": "BEC / payment-fraud actor (credential theft → wire fraud)",
        "description": "Credential phishing leading to a fraudulent wire-transfer attempt.",
        "kill_chain": ["phish_credential", "insider_access", "bec_wire_request"],
        "objectives": _objs(
            ("Detect the credential phish", "Phishing identified and affected accounts reset."),
            ("Spot the account takeover", "Anomalous access recognised and investigated."),
            ("Prevent the financial loss", "Wire request verified out-of-band and stopped per policy."),
        ),
    },
    "malicious_insider": {
        "name": "Malicious insider",
        "label": "Privileged insider exfiltrating sensitive data",
        "description": "A trusted employee abuses access to collect and exfiltrate data.",
        "kill_chain": ["insider_access", "data_staging", "exfil_dns"],
        "objectives": _objs(
            ("Detect the anomalous access", "Out-of-pattern access flagged and reviewed."),
            ("Scope the collection", "Staged data identified and classified."),
            ("Contain the exfiltration", "Egress channel blocked and loss quantified."),
        ),
    },
    "apt_espionage": {
        "name": "Espionage-motivated intruder",
        "label": "Targeted intrusion for long-dwell data theft",
        "description": "External exploitation, quiet C2, credential theft, lateral movement, exfiltration.",
        "kill_chain": ["exploit_public", "c2_beacon", "lsass_dump", "lateral_smb", "exfil_dns"],
        "objectives": _objs(
            ("Detect the external intrusion", "Exploitation or C2 recognised early."),
            ("Triage and scope", "Compromised hosts and accounts identified."),
            ("Contain the intruder", "Lateral movement halted before crown jewels."),
            ("Eradicate and quantify", "Access removed and data-loss quantified."),
        ),
    },
}


# --------------------------------------------------------------------------- #
# Templates: named packaging of an actor + narrative + scope + RoE.
# --------------------------------------------------------------------------- #
SCENARIO_TEMPLATES: dict[str, dict] = {
    "ransomware_finance": {
        "name": "Ransomware — financial services",
        "actor": "ransomware_affiliate",
        "narrative": "A phishing-led ransomware intrusion tests detection, containment, and recovery.",
        "scope": "Discussion-based tabletop. No live systems are touched.",
        "roe": "Facilitated exercise only. 'Pause' halts play at any time. All actions are simulated.",
    },
    "bec_finance": {
        "name": "Business email compromise — payment fraud",
        "actor": "bec_actor",
        "narrative": "A BEC campaign pressures finance into a fraudulent wire transfer.",
        "scope": "Discussion-based tabletop focused on process and verification controls.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
    "insider_exfil": {
        "name": "Malicious insider — data exfiltration",
        "actor": "malicious_insider",
        "narrative": "A privileged insider collects and exfiltrates sensitive data.",
        "scope": "Discussion-based tabletop with HR and legal touchpoints.",
        "roe": "Facilitated exercise only. Handle personnel details with care.",
    },
    "apt_intrusion": {
        "name": "Targeted intrusion — long-dwell data theft",
        "actor": "apt_espionage",
        "narrative": "A patient intruder establishes C2 and moves toward crown-jewel data.",
        "scope": "Discussion-based tabletop across SOC, IR, and threat-intel.",
        "roe": "Facilitated exercise only. All actions are simulated.",
    },
}
