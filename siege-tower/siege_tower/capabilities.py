"""
Siege Tower — capability vocabulary.

Capabilities are the state tokens the planner reasons over. A play requires a
set of capabilities and provides another set; a plan is a chain of plays that
carries the operator from the engagement's starting capabilities to the goal
capability implied by the objective.

Keeping these as named constants (rather than bare strings scattered around)
means the playbook and the engine agree on spelling, and a team documenting
`provided_access` in the ROE can reference the same tokens.
"""

# Position / access
CAP_EXTERNAL_RECON = "external_recon"          # OSINT / attack-surface knowledge
CAP_INTERNAL_NETWORK = "internal_network"      # routable access to the internal LAN
CAP_PHYSICAL_ONSITE = "physical_onsite"        # physical presence in scope

# Footholds / execution
CAP_WEB_FOOTHOLD = "web_foothold"              # control of a web/app tier
CAP_CODE_EXEC_HOST = "code_exec_host"          # command execution on some host
CAP_C2 = "c2_established"                       # beacon / interactive channel

# Credentials / identity
CAP_DOMAIN_USER = "domain_user"                # valid low-priv domain credentials
CAP_HARVESTED_CREDS = "harvested_creds"        # additional creds looted from a host
CAP_LOCAL_ADMIN = "local_admin"                # admin on at least one host
CAP_DOMAIN_ADMIN = "domain_admin"              # domain-wide privileged control
CAP_CLOUD_ADMIN = "cloud_admin"                # tenant / cloud admin

# Cloud / SaaS identity
CAP_CLOUD_ACCOUNT = "cloud_account"            # valid cloud / Entra ID (Azure AD) creds
CAP_CLOUD_RECON = "cloud_recon"                # cloud tenant/service enumeration

# Knowledge
CAP_SOURCE_CODE = "source_code"                # access to application source
CAP_AD_RECON = "ad_recon"                       # internal AD/enumeration knowledge

# Footholds / staging (extended)
CAP_PERSISTENCE = "persistence"                # a durable re-entry mechanism

# End states
CAP_EMAIL_ACCESS = "email_access"              # mailbox / messaging access
CAP_SENSITIVE_DATA_ACCESS = "sensitive_data_access"
CAP_DATA_EXFILTRATED = "data_exfiltrated"
CAP_IMPACT_DEPLOYED = "impact_deployed"         # ransomware/impact objective met


# Baseline starting capabilities implied by each box type. `provided_access`
# from the ROE is unioned on top of these.
BOX_TYPE_BASELINE = {
    "black": {CAP_EXTERNAL_RECON},
    "grey": {CAP_EXTERNAL_RECON, CAP_INTERNAL_NETWORK, CAP_DOMAIN_USER},
    "white": {
        CAP_EXTERNAL_RECON, CAP_INTERNAL_NETWORK, CAP_DOMAIN_USER,
        CAP_SOURCE_CODE, CAP_AD_RECON,
    },
}

# Objective → the capability a finished plan must reach.
GOAL_CAPABILITY = {
    "initial_foothold": CAP_CODE_EXEC_HOST,
    "domain_admin": CAP_DOMAIN_ADMIN,
    "data_exfiltration": CAP_DATA_EXFILTRATED,
    "ransomware_simulation": CAP_IMPACT_DEPLOYED,
    "cloud_takeover": CAP_CLOUD_ADMIN,
    "email_compromise": CAP_EMAIL_ACCESS,
}

# Friendly names for capabilities in generated documentation.
CAPABILITY_LABELS = {
    CAP_EXTERNAL_RECON: "External attack-surface knowledge",
    CAP_INTERNAL_NETWORK: "Internal network access",
    CAP_PHYSICAL_ONSITE: "Physical on-site presence",
    CAP_WEB_FOOTHOLD: "Web/application foothold",
    CAP_CODE_EXEC_HOST: "Code execution on a host",
    CAP_C2: "Command-and-control channel",
    CAP_DOMAIN_USER: "Valid domain user credentials",
    CAP_HARVESTED_CREDS: "Harvested credentials",
    CAP_LOCAL_ADMIN: "Local administrator rights",
    CAP_DOMAIN_ADMIN: "Domain administrator control",
    CAP_CLOUD_ADMIN: "Cloud/tenant administrator control",
    CAP_SOURCE_CODE: "Application source code",
    CAP_AD_RECON: "Active Directory enumeration data",
    CAP_CLOUD_ACCOUNT: "Valid cloud / Entra ID credentials",
    CAP_CLOUD_RECON: "Cloud tenant enumeration data",
    CAP_PERSISTENCE: "Durable re-entry mechanism",
    CAP_EMAIL_ACCESS: "Mailbox / messaging access",
    CAP_SENSITIVE_DATA_ACCESS: "Access to sensitive data stores",
    CAP_DATA_EXFILTRATED: "Sensitive data exfiltrated",
    CAP_IMPACT_DEPLOYED: "Impact (e.g. ransomware) demonstrated",
}
