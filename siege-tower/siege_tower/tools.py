"""
Siege Tower — tooling suggestions.

Maps each ATT&CK technique in the playbook to the tools an authorized red team
would typically reach for to accomplish that step. This is the "suggests which
programs to use" layer of the planner.

It is reference metadata only. Siege Tower never runs any of these tools — it
names them so the operator can plan and document. Keeping the mapping in its
own data file (rather than inline on every play) means it is easy to review,
extend, or localize to a team's preferred toolkit without touching the engine.
"""
from __future__ import annotations

# technique_id → ordered list of commonly-used tools for that action.
TOOL_SUGGESTIONS: dict[str, list[str]] = {
    # Recon
    "T1595": ["nmap", "masscan", "httpx", "naabu"],
    # Initial access
    "T1190": ["nuclei", "Burp Suite", "Metasploit", "sqlmap"],
    "T1566": ["Gophish", "Evilginx", "King Phisher"],
    "T1566.002": ["Evilginx", "o365-attack-toolkit", "GraphRunner"],
    "T1110": ["NetExec (nxc)", "Hydra", "Kerbrute"],
    "T1078": ["NetExec (nxc)", "xfreerdp", "evil-winrm"],
    "T1078.004": ["MSOLSpray", "MFASweep", "TeamFiltration"],
    "T1133": ["evil-winrm", "openvpn", "xfreerdp"],
    "T1195": ["Syft", "dependency-track"],
    "T1199": ["NetExec (nxc)", "evil-winrm"],
    "T1189": ["BeEF", "Metasploit"],
    "T1200": ["Hak5 gear (authorized)", "Responder"],
    # Execution / persistence
    "T1059": ["Cobalt Strike", "Sliver", "Mythic", "PowerShell"],
    "T1505.003": ["antSword", "weevely"],
    "T1543": ["PowerUp", "sc.exe", "systemctl"],
    "T1053": ["schtasks", "cron", "PowerSploit"],
    # Privilege escalation
    "T1068": ["WinPEAS", "LinPEAS", "GTFOBins", "Metasploit"],
    "T1548": ["UACMe", "GTFOBins", "sudo"],
    # Credential access
    "T1003": ["Mimikatz", "nanodump", "secretsdump.py"],
    "T1003.006": ["secretsdump.py (DCSync)", "Mimikatz"],
    "T1552": ["Snaffler", "gpp-decrypt", "LaZagne"],
    "T1555": ["LaZagne", "SharpChrome", "KeePass tooling"],
    "T1187": ["Responder", "Inveigh", "ntlmrelayx.py"],
    "T1557": ["ntlmrelayx.py", "Responder", "PetitPotam"],
    "T1558.003": ["Rubeus", "GetUserSPNs.py", "hashcat"],
    "T1558.004": ["Rubeus", "GetNPUsers.py", "hashcat"],
    "T1649": ["Certipy", "Certify", "PKINITtools"],
    # Discovery
    "T1087": ["BloodHound", "SharpHound", "PingCastle"],
    "T1482": ["BloodHound", "nltest", "PowerView"],
    "T1526": ["ROADrecon", "AzureHound", "ScoutSuite", "PingCastle"],
    # Lateral movement / domain escalation
    "T1021.002": ["NetExec (nxc)", "psexec.py", "evil-winrm"],
    "T1210": ["Metasploit", "NetExec (nxc)"],
    "T1484.001": ["SharpGPOAbuse", "PowerView"],
    # Collection
    "T1005": ["Snaffler", "PowerView"],
    "T1039": ["NetExec (nxc) spider_plus", "Snaffler"],
    "T1213": ["MailSniper", "PowerView"],
    "T1114": ["MailSniper", "ExchangeFinder"],
    "T1114.002": ["GraphRunner", "AADInternals", "roadtx"],
    "T1530": ["ScoutSuite", "AzureHound", "cloud provider CLI"],
    # Exfiltration (simulated / measured egress to team-controlled sinks)
    "T1567": ["rclone", "curl"],
    "T1041": ["Cobalt Strike", "Sliver", "Mythic"],
    "T1048": ["dnscat2", "iodine"],
    # Cloud escalation / hybrid
    "T1552.005": ["Burp Suite", "curl", "SSRFmap"],
    "T1098": ["AzureHound", "MicroBurst", "roadtx"],
    "T1484.002": ["AADInternals", "roadtx"],
    # Impact (simulated only, with sign-off)
    "T1486": ["custom canary tooling (authorized)"],
    "T1490": ["vssadmin (canary only)", "custom tooling"],
    "T1485": ["custom canary tooling (authorized)"],
}

# Tactic-level fallback when a technique has no specific entry.
TACTIC_TOOL_FALLBACK: dict[str, list[str]] = {
    "reconnaissance": ["nmap", "recon-ng", "Amass"],
    "initial-access": ["Metasploit", "Burp Suite"],
    "execution": ["Cobalt Strike", "Sliver", "Mythic"],
    "persistence": ["PowerSploit", "SharPersist"],
    "privilege-escalation": ["WinPEAS", "LinPEAS", "GTFOBins"],
    "credential-access": ["Mimikatz", "Impacket"],
    "discovery": ["BloodHound", "PowerView"],
    "lateral-movement": ["NetExec (nxc)", "Impacket"],
    "collection": ["Snaffler", "PowerView"],
    "exfiltration": ["rclone"],
    "impact": ["custom canary tooling (authorized)"],
}


def tools_for(technique_id: str, tactic: str | None = None) -> list[str]:
    """Return suggested tools for a technique, falling back to its tactic."""
    if technique_id in TOOL_SUGGESTIONS:
        return list(TOOL_SUGGESTIONS[technique_id])
    if tactic and tactic in TACTIC_TOOL_FALLBACK:
        return list(TACTIC_TOOL_FALLBACK[tactic])
    return []
