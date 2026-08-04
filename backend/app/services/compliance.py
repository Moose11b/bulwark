"""
Compliance framework mappings.

Maps technical findings (by CWE, and by scanner source as a fallback) to
control identifiers across four frameworks:

  - PCI-DSS v4.0
  - ISO/IEC 27001:2022 (Annex A)
  - NIST CSF 2.0
  - CIS Controls v8

IMPORTANT — read CONTROL_MAPPING_DISCLAIMER below. These mappings indicate
which controls a finding is *relevant to*. They are an aid to remediation
prioritisation, NOT a compliance assessment, audit, or attestation. Many
controls (especially organisational / policy controls) cannot be evaluated
by an external vulnerability scanner at all.
"""

CONTROL_MAPPING_DISCLAIMER = (
    "These control mappings indicate which framework controls each technical "
    "finding is relevant to. They are intended to help prioritise remediation, "
    "not to assess, certify, or attest compliance. A vulnerability scan evaluates "
    "only a narrow slice of any framework — primarily technical security controls — "
    "and cannot assess organisational, policy, documentation, or process controls. "
    "This report is not an audit and does not constitute a compliance assessment. "
    "Formal compliance requires a qualified assessor and evaluation of controls "
    "beyond the scope of automated scanning."
)


# ── Framework control catalogues (names for display) ─────────────

ISO27001_CONTROLS = {
    # ISO/IEC 27001:2022 Annex A — selected technical controls
    "A.5.7":   "Threat intelligence",
    "A.5.14":  "Information transfer",
    "A.5.15":  "Access control",
    "A.5.17":  "Authentication information",
    "A.5.23":  "Information security for use of cloud services",
    "A.8.2":   "Privileged access rights",
    "A.8.3":   "Information access restriction",
    "A.8.5":   "Secure authentication",
    "A.8.8":   "Management of technical vulnerabilities",
    "A.8.9":   "Configuration management",
    "A.8.12":  "Data leakage prevention",
    "A.8.20":  "Networks security",
    "A.8.21":  "Security of network services",
    "A.8.23":  "Web filtering",
    "A.8.24":  "Use of cryptography",
    "A.8.25":  "Secure development life cycle",
    "A.8.26":  "Application security requirements",
    "A.8.28":  "Secure coding",
}

PCI_DSS_CONTROLS = {
    # PCI-DSS v4.0 — selected requirements
    "1.3":   "Restrict inbound/outbound traffic to the CDE",
    "2.2":   "Secure system configuration standards",
    "2.2.5": "Remove insecure services and protocols",
    "3.5":   "Protect stored account data (PAN) ",
    "4.2.1": "Strong cryptography for transmission over open networks",
    "6.2.4": "Address common software attacks in bespoke software",
    "6.3.1": "Identify and manage security vulnerabilities",
    "6.3.3": "Install applicable security patches",
    "6.4.1": "Protect public-facing web applications",
    "7.2.1": "Restrict access by business need to know",
    "8.3.1": "Strong authentication for all access",
    "11.3.1":"Internal vulnerability scans",
    "11.3.2":"External vulnerability scans",
}

NIST_CSF_CONTROLS = {
    # NIST CSF 2.0 — selected subcategories
    "ID.RA-01": "Asset vulnerabilities are identified and recorded",
    "PR.AA-01": "Identities and credentials are managed",
    "PR.AA-05": "Access permissions enforce least privilege",
    "PR.DS-01": "Data-at-rest is protected",
    "PR.DS-02": "Data-in-transit is protected",
    "PR.IR-01": "Networks and environments are protected",
    "PR.PS-01": "Configuration management practices are established",
    "PR.PS-02": "Software is maintained and patched",
    "DE.CM-01": "Networks are monitored to find adverse events",
    "DE.CM-09": "Computing hardware/software are monitored",
}

CIS_V8_CONTROLS = {
    # CIS Controls v8 — selected safeguards
    "3.10":  "Encrypt sensitive data in transit",
    "3.11":  "Encrypt sensitive data at rest",
    "4.1":   "Establish secure configuration process",
    "4.2":   "Establish secure network configuration",
    "5.2":   "Use unique passwords",
    "6.3":   "Require MFA for externally-exposed applications",
    "7.1":   "Establish vulnerability management process",
    "7.4":   "Perform automated application patch management",
    "7.5":   "Perform automated vulnerability scans of internal assets",
    "7.6":   "Perform automated vulnerability scans of external assets",
    "9.2":   "Use DNS filtering services",
    "12.2":  "Establish and maintain secure network architecture",
    "16.11": "Leverage vetted modules / secure coding",
}


# ── CWE → control mapping ─────────────────────────────────────────
# Each CWE maps to relevant controls in every framework.

COMPLIANCE_DB = {
    # Cross-site scripting
    "CWE-79": {
        "pci_dss": ["6.2.4", "6.4.1"], "iso_27001": ["A.8.26", "A.8.28"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # SQL injection
    "CWE-89": {
        "pci_dss": ["6.2.4", "6.4.1"], "iso_27001": ["A.8.26", "A.8.28"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # OS command injection
    "CWE-78": {
        "pci_dss": ["6.2.4", "6.4.1"], "iso_27001": ["A.8.26", "A.8.28"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # Information exposure
    "CWE-200": {
        "pci_dss": ["2.2", "7.2.1"], "iso_27001": ["A.8.3", "A.5.15"],
        "nist_csf": ["PR.AA-05"], "cis_v8": ["4.1", "3.11"],
    },
    # Cleartext storage of sensitive info
    "CWE-312": {
        "pci_dss": ["3.5"], "iso_27001": ["A.8.24", "A.8.12"],
        "nist_csf": ["PR.DS-01"], "cis_v8": ["3.11"],
    },
    # Cleartext transmission
    "CWE-319": {
        "pci_dss": ["4.2.1"], "iso_27001": ["A.8.24", "A.5.14"],
        "nist_csf": ["PR.DS-02"], "cis_v8": ["3.10"],
    },
    # Improper certificate validation
    "CWE-295": {
        "pci_dss": ["4.2.1"], "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"], "cis_v8": ["3.10"],
    },
    # Inadequate encryption strength
    "CWE-326": {
        "pci_dss": ["4.2.1", "2.2.5"], "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"], "cis_v8": ["3.10"],
    },
    # Broken/risky crypto algorithm
    "CWE-327": {
        "pci_dss": ["4.2.1", "2.2.5"], "iso_27001": ["A.8.24"],
        "nist_csf": ["PR.DS-02"], "cis_v8": ["3.10"],
    },
    # Improper restriction of rendered UI layers (clickjacking)
    "CWE-1021": {
        "pci_dss": ["6.2.4"], "iso_27001": ["A.8.26"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # Missing authentication
    "CWE-306": {
        "pci_dss": ["8.3.1", "7.2.1"], "iso_27001": ["A.8.5", "A.5.17"],
        "nist_csf": ["PR.AA-01"], "cis_v8": ["6.3", "5.2"],
    },
    # Weak password requirements
    "CWE-521": {
        "pci_dss": ["8.3.1"], "iso_27001": ["A.5.17", "A.8.5"],
        "nist_csf": ["PR.AA-01"], "cis_v8": ["5.2", "6.3"],
    },
    # Improper access control
    "CWE-284": {
        "pci_dss": ["7.2.1"], "iso_27001": ["A.5.15", "A.8.3"],
        "nist_csf": ["PR.AA-05"], "cis_v8": ["6.3"],
    },
    # Incorrect permission assignment
    "CWE-732": {
        "pci_dss": ["1.3", "7.2.1"], "iso_27001": ["A.8.3", "A.8.2"],
        "nist_csf": ["PR.AA-05", "PR.IR-01"], "cis_v8": ["4.2", "12.2"],
    },
    # Path traversal
    "CWE-22": {
        "pci_dss": ["6.2.4", "6.4.1"], "iso_27001": ["A.8.26"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # SSRF
    "CWE-918": {
        "pci_dss": ["6.2.4", "1.3"], "iso_27001": ["A.8.26", "A.8.20"],
        "nist_csf": ["PR.IR-01"], "cis_v8": ["12.2"],
    },
    # Directory listing
    "CWE-548": {
        "pci_dss": ["2.2"], "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["4.1"],
    },
    # DNS / spoofing weaknesses
    "CWE-350": {
        "pci_dss": ["1.3"], "iso_27001": ["A.8.21", "A.5.14"],
        "nist_csf": ["PR.IR-01"], "cis_v8": ["9.2"],
    },
    "CWE-345": {
        "pci_dss": ["1.3"], "iso_27001": ["A.8.21"],
        "nist_csf": ["PR.IR-01"], "cis_v8": ["9.2"],
    },
    # CORS misconfiguration
    "CWE-942": {
        "pci_dss": ["6.2.4"], "iso_27001": ["A.8.26"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # Missing security headers / protection mechanism
    "CWE-693": {
        "pci_dss": ["6.2.4"], "iso_27001": ["A.8.26"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["4.1"],
    },
    # Improper neutralization (generic)
    "CWE-116": {
        "pci_dss": ["6.2.4"], "iso_27001": ["A.8.28"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["16.11"],
    },
    # Use of outdated/vulnerable component
    "CWE-1104": {
        "pci_dss": ["6.3.1", "6.3.3"], "iso_27001": ["A.8.8"],
        "nist_csf": ["PR.PS-02", "ID.RA-01"], "cis_v8": ["7.4", "7.6"],
    },
    # Misconfiguration (generic)
    "CWE-16": {
        "pci_dss": ["2.2"], "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["4.1", "4.2"],
    },
    # Cross-site tracing / dangerous method
    "CWE-430": {
        "pci_dss": ["2.2", "2.2.5"], "iso_27001": ["A.8.9"],
        "nist_csf": ["PR.PS-01"], "cis_v8": ["4.1"],
    },
}

# Fallback by scanner source when a finding has no/unknown CWE
SOURCE_FALLBACK = {
    "nmap":             {"pci_dss": ["1.3", "11.3.2"], "iso_27001": ["A.8.20", "A.8.21"],
                          "nist_csf": ["PR.IR-01", "ID.RA-01"], "cis_v8": ["4.2", "7.6", "12.2"]},
    "ssl_scanner":      {"pci_dss": ["4.2.1"], "iso_27001": ["A.8.24"],
                          "nist_csf": ["PR.DS-02"], "cis_v8": ["3.10"]},
    "header_scanner":   {"pci_dss": ["6.2.4"], "iso_27001": ["A.8.26"],
                          "nist_csf": ["PR.PS-01"], "cis_v8": ["4.1"]},
    "dns_scanner":      {"pci_dss": ["1.3"], "iso_27001": ["A.8.21"],
                          "nist_csf": ["PR.IR-01"], "cis_v8": ["9.2"]},
    "nikto":            {"pci_dss": ["6.4.1", "11.3.2"], "iso_27001": ["A.8.8", "A.8.26"],
                          "nist_csf": ["PR.PS-01"], "cis_v8": ["7.6", "16.11"]},
    "nuclei":           {"pci_dss": ["6.3.1", "11.3.2"], "iso_27001": ["A.8.8"],
                          "nist_csf": ["ID.RA-01", "PR.PS-02"], "cis_v8": ["7.5", "7.6"]},
    "exposure_scanner": {"pci_dss": ["2.2", "7.2.1"], "iso_27001": ["A.8.3", "A.8.9"],
                          "nist_csf": ["PR.AA-05"], "cis_v8": ["4.1", "3.11"]},
    "shodan":           {"pci_dss": ["11.3.2", "1.3"], "iso_27001": ["A.8.8", "A.8.20"],
                          "nist_csf": ["ID.RA-01", "PR.IR-01"], "cis_v8": ["7.6", "12.2"]},
    "threat_intel":     {"pci_dss": ["6.3.1"], "iso_27001": ["A.5.7", "A.8.8"],
                          "nist_csf": ["ID.RA-01", "DE.CM-01"], "cis_v8": ["7.1"]},
}

FRAMEWORK_CATALOGUES = {
    "pci_dss":   PCI_DSS_CONTROLS,
    "iso_27001": ISO27001_CONTROLS,
    "nist_csf":  NIST_CSF_CONTROLS,
    "cis_v8":    CIS_V8_CONTROLS,
}

FRAMEWORK_LABELS = {
    "pci_dss":   "PCI-DSS v4.0",
    "iso_27001": "ISO/IEC 27001:2022",
    "nist_csf":  "NIST CSF 2.0",
    "cis_v8":    "CIS Controls v8",
}


def map_compliance(finding: dict) -> dict:
    """Return relevant control IDs across all frameworks for a finding."""
    cwe = (finding.get("cwe_id") or "").strip()
    source = (finding.get("source") or "").lower()

    mapping = COMPLIANCE_DB.get(cwe)
    if not mapping:
        mapping = SOURCE_FALLBACK.get(source, {})

    return {
        "pci_dss":   mapping.get("pci_dss", []),
        "iso_27001": mapping.get("iso_27001", []),
        "nist_csf":  mapping.get("nist_csf", []),
        "cis_v8":    mapping.get("cis_v8", []),
    }


def control_name(framework: str, control_id: str) -> str:
    """Look up the human-readable name of a control."""
    return FRAMEWORK_CATALOGUES.get(framework, {}).get(control_id, control_id)
