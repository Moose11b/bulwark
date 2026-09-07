# Keeping the playbook current

Siege Tower's value depends on its ATT&CK-mapped technique library staying
honest as tradecraft — and ATT&CK itself — moves. This is the policy and the
tooling for that.

## Versioning

The playbook carries its own metadata in `siege_tower/version.py`:

| Field | Meaning |
| --- | --- |
| `PLAYBOOK_VERSION` | The library's own revision. Bump on any change to techniques, tools, or fallbacks. |
| `ATTACK_VERSION` | The MITRE ATT&CK **Enterprise** release the library was last validated against. |
| `PLAYBOOK_UPDATED` | ISO date of that validation. |

This metadata is surfaced to users: the API returns it as `playbook_meta` in
`/api/bootstrap`, and the app shows *"ATT&CK v… · playbook v…"* on the launch
screen, so a team always knows how current the library is.

## The currency check

`siege_tower.attack_sync` validates every technique ID in the playbook against a
MITRE ATT&CK STIX bundle and reports drift — techniques ATT&CK has **revoked**,
**deprecated**, or no longer knows (**unknown**: a bad or renumbered ID).

It is a maintainer / CI tool, kept deliberately *out* of the planning path: the
engine never imports it, and it only touches the network when you pass
`--fetch`.

```bash
# Validate against the latest Enterprise ATT&CK (downloads the STIX bundle):
python -m siege_tower.attack_sync --fetch

# …or against a local bundle you already have (fully offline):
python -m siege_tower.attack_sync --bundle enterprise-attack.json

# Machine-readable, and strict (deprecated also fails):
python -m siege_tower.attack_sync --fetch --json --strict
```

Exit codes: `0` all current (or only deprecations without `--strict`), `1` any
`unknown`/`revoked` (or deprecations with `--strict`), `2` bad usage.

## Cadence

1. **Automatically:** the `attack-currency` GitHub Action runs weekly (and on
   demand), fetches the latest ATT&CK, and runs the check. A failure means a
   shipped technique was revoked/renumbered and needs attention.
2. **On each ATT&CK release** (MITRE ships roughly twice a year): run the check,
   fix any drift, refresh `ATTACK_VERSION` / `PLAYBOOK_UPDATED`, and bump
   `PLAYBOOK_VERSION`.

## Editing the playbook

The library is **data**, not code: `siege_tower/playbook.py` and
`plays_ext.py` hold `Play` entries. Add or edit a `Play` and the API, the
drag-and-drop palette, the ranked plans, the follow-up suggestions, and the
Navigator export all pick it up. When you change it, bump `PLAYBOOK_VERSION` and
re-run the currency check. You can also bring your own `Play` list to replace
the shipped one entirely (see `build_plans(..., playbook=...)`).
