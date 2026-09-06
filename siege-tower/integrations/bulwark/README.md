# Integrating Siege Tower into Bulwark (or any host app)

Siege Tower's engine (`siege_tower/`) is a standalone, dependency-free package,
so a larger platform can import it directly instead of running this app's
server. That is exactly how [Bulwark](https://github.com/moose11b/bulwark)
embeds it.

## The pattern

1. **Make the package importable** — install it (`pip install siege-tower`) or
   mount it on `PYTHONPATH`. The host never needs the `server/` or `web/` parts.
2. **Map your engagement record → `EngagementInput`**, call `build_plans`, and
   serialize the result. See `adapter_example.py` (Bulwark's real adapter): it
   maps a Bulwark `Engagement` model to the engine and back, and exposes the
   reference + playbook catalogs to Bulwark's own UI.
3. **Compile the report** the same way — `report_example.py` shows Bulwark's
   pure report compiler over its ORM-backed engagement + log rows.

## Why the engine stays separate

The engine has no network or subprocess access of its own, so the planning
logic *cannot act on a target* — it plans and documents only. Keeping it a
standalone package is what makes that guarantee hold in every host.

The two `*_example.py` files are **reference copies** from the Bulwark backend
(they import `app.*` from Bulwark and are not meant to run here). They are the
canonical illustration of the adapter + report seam.
