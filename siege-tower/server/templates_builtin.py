"""
Built-in engagement templates (reusable ROE presets).

Shipped read-only starting points so a fresh org has useful presets before it
saves its own. Each is returned with a "builtin": true flag and a "builtin:"
id; the API refuses to edit or delete them.
"""

BUILTIN_TEMPLATES = [
    {
        "id": "builtin:internal-ad",
        "builtin": True,
        "name": "Internal AD assessment",
        "description": "Assumed internal foothold; prove domain-wide control of Active Directory.",
        "objective": "domain_admin",
        "box_type": "grey",
        "scope_platforms": ["windows", "active_directory", "network"],
        "restrictions": [],
        "time_budget_hours": 40,
    },
    {
        "id": "builtin:external-web",
        "builtin": True,
        "name": "External web application",
        "description": "Black-box external test of a public web app; no DoS.",
        "objective": "initial_foothold",
        "box_type": "black",
        "scope_platforms": ["web"],
        "restrictions": ["no_denial_of_service"],
        "time_budget_hours": 24,
    },
    {
        "id": "builtin:cloud-tenant",
        "builtin": True,
        "name": "Cloud tenant review",
        "description": "Grey-box cloud/Entra ID assessment toward tenant admin.",
        "objective": "cloud_takeover",
        "box_type": "grey",
        "scope_platforms": ["cloud", "azure_ad"],
        "restrictions": [],
        "time_budget_hours": 32,
    },
    {
        "id": "builtin:assumed-breach-exfil",
        "builtin": True,
        "name": "Assumed breach — data exfiltration",
        "description": "Start from a low-priv foothold and demonstrate sensitive-data exfiltration.",
        "objective": "data_exfiltration",
        "box_type": "grey",
        "scope_platforms": ["windows", "network"],
        "restrictions": ["stealth_required"],
        "time_budget_hours": 24,
    },
    {
        "id": "builtin:email-compromise",
        "builtin": True,
        "name": "Email / M365 compromise",
        "description": "Objective: access to target mailboxes and messaging.",
        "objective": "email_compromise",
        "box_type": "black",
        "scope_platforms": ["web", "cloud", "azure_ad"],
        "restrictions": [],
        "time_budget_hours": 20,
    },
]
