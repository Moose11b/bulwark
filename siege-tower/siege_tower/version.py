"""
Playbook currency metadata.

Versions the ATT&CK-mapped technique library so a team can see how current it
is, and so the sync tool (`siege_tower.attack_sync`) can report drift against a
MITRE ATT&CK release. Bump these when you change the playbook or re-validate it
against a new ATT&CK version. See docs/PLAYBOOK.md.
"""
from __future__ import annotations

# The playbook's own revision (independent of the package version).
PLAYBOOK_VERSION = "1.0"

# The MITRE ATT&CK Enterprise release the library is curated/validated against.
ATTACK_VERSION = "14"

# ISO date the playbook was last reviewed against ATT&CK.
PLAYBOOK_UPDATED = "2026-09-07"


def playbook_meta() -> dict:
    return {
        "playbook_version": PLAYBOOK_VERSION,
        "attack_version": ATTACK_VERSION,
        "updated": PLAYBOOK_UPDATED,
    }
