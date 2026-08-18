# Contributing to Bulwark

Thanks for helping improve Bulwark. This guide covers how to get set up, run the
tests, and open a change that lands smoothly.

## Ways to contribute

- **Scanners & checks** — new detections, fewer false positives, better
  severity/OWASP mapping.
- **The CLI / Action** — pipeline ergonomics, output formats, gate behaviour.
- **Benchmarks** — new ground-truth targets or comparator improvements
  (see [`benchmarks/`](benchmarks/)).
- **Docs** — anything that made you stop and squint.

For anything large (a new scanner, a change to output format or exit codes),
open an issue first so we can agree on the approach before you build it.

## Project layout

```
backend/app/services/scanners/   individual scanners (header, ssl, nuclei, nikto, api, …)
backend/app/services/            engine, reconciliation, enrichment, sarif, baseline, …
backend/app/cli.py               the standalone CLI (bulwark scan …)
backend/tests/                   pytest suite (no network / DB needed for most)
benchmarks/                      Bulwark-vs-ZAP harness, ground-truth targets
frontend/                        Next.js dashboard (the hosted platform)
action.yml                       the GitHub Action wrapper
```

Two faces share one scan engine: the **CLI/Action** (free, standalone) and the
**platform** (the full web app). Most contributions touch the engine or a
scanner, which both use.

## Getting set up

### CLI / scanners (Python)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # or requirements-cli.txt for just the CLI

# Run the CLI from source
python -m app.cli scan http://localhost:3000 --profile web --allow-private
```

The external scanner binaries (nmap, nikto, nuclei) are only needed for those
specific scanners; header/ssl/api/exposure/dns checks run without them. The
`--allow-private` flag lets you scan localhost during development.

### Full stack (Docker)

```bash
cp .env.example .env
docker compose up --build
# dashboard -> http://localhost:3001   API docs -> http://localhost:8000/docs
```

## Running the tests

```bash
cd backend
pytest                                   # most tests need no network or DB
```

Some tests (`test_webhooks`, `test_migrations`, `test_scan_reports`, …) require a
Postgres and Redis; they are exercised in CI against service containers. The
pure tests — scanners, parsers, the engine, reconciliation, the gate pipeline,
the API scanner — run anywhere with just `pip install -r requirements.txt`.

Benchmark comparator tests:

```bash
python -m pytest benchmarks/test_compare.py
```

CI (`.github/workflows/ci.yml`) builds the backend image, runs `pytest` and
`alembic check`, then builds the CLI image and scans a live OWASP Juice Shop to
prove the scanner pipeline and gate exit codes still work end to end.

## Adding a scanner

1. Add `backend/app/services/scanners/<name>_scanner.py` with an async
   `scan(self, target, pinned_ip=None, port=None, ...)` returning a list of
   finding dicts. Use `pinned_async_client` for HTTP so SSRF pinning and
   credential confinement are handled for you.
2. Emit findings in the shape the other scanners use (`title`, `severity`,
   `source`, `cwe_id`, `owasp_category`, `description`, `evidence`,
   `remediation`, `references`).
3. Register it in `standalone_engine.py` (`_run_scanner` and a `PROFILES`
   entry).
4. **Never invent findings.** If the scanner can't run, return an
   `unavailable()` INFO finding (see `scanners/availability.py`) — a coverage
   gap must be visible, not hidden. Demo fixtures only appear under
   `DEMO_MODE=true` and are tagged as such.
5. Add tests that feed captured tool output through your parser.

## Pull request checklist

- [ ] Tests pass (`pytest`), and you added tests for new behaviour.
- [ ] No secrets, tokens, or real hostnames in the diff.
- [ ] Findings changes keep the honesty rules (no fabricated results; coverage
      gaps surfaced as INFO).
- [ ] User-facing changes are reflected in `README-cli.md` / `README.md`.
- [ ] One focused change per PR where possible.

## Security issues

Please do **not** open a public issue for a vulnerability in Bulwark itself.
See [SECURITY.md](SECURITY.md) for private disclosure.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
