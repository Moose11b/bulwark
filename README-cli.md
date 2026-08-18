# ⛨ Bulwark

**Fortify · Detect · Defend**

A lightweight dynamic application security (DAST) scanner built to run as a CI/CD pipeline gate. Point it at a running app, get findings mapped to OWASP / MITRE ATT&CK / compliance frameworks, and fail the build when something dangerous shows up — with native GitHub Security tab integration via SARIF.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)]() [![License](https://img.shields.io/badge/license-MIT-blue)]() [![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blue)]()

---

## Why Bulwark

Most pipeline security tooling is either heavyweight SAST/SCA (Snyk, Semgrep) or a security-team-owned DAST product that developers never touch. Bulwark fills the gap: **dynamic scanning of a running app that a developer can drop into a pipeline in three lines**, with no security team, no console, and no per-asset licensing required.

- **Pipeline-native** — single command, sensible exit codes, SARIF output
- **Zero infrastructure** — no database, no agents, no account needed for the core scan
- **Findings that mean something** — every result is mapped to OWASP Top 10, MITRE ATT&CK, the Cyber Kill Chain, and four compliance frameworks (PCI-DSS, ISO 27001:2022, NIST CSF 2.0, CIS Controls v8)
- **Real CVE intelligence** — CVSS from NVD, exploit probability from EPSS, active-exploitation flags from CISA KEV
- **SSRF-safe by design** — refuses to scan internal/loopback/metadata addresses

---

## Quick start

### GitHub Actions

```yaml
name: Security
on: [push, pull_request]

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ... start your app, e.g. docker compose up -d ...

      - name: Bulwark DAST gate
        uses: moose11b/bulwark@v1
        with:
          target: http://localhost:3000
          fail-on: high
          profile: web
```

Findings appear in your **Security → Code scanning** tab automatically. The build fails if anything `high` or above is found.

### CLI (any pipeline, or local)

```bash
docker run --rm --network host ghcr.io/moose11b/bulwark-cli:latest \
  scan http://localhost:3000 --fail-on high --sarif results.sarif
```

---

## Configuration

| Input | Description | Default |
|-------|-------------|---------|
| `target` | URL, domain, or IP to scan | *required* |
| `profile` | `headers` · `web` · `network` · `full` | `web` |
| `fail-on` | Fail build at/above: `critical` · `high` · `medium` · `low` · `never` | `high` |
| `sarif-file` | Path to write SARIF output | `bulwark-results.sarif` |
| `upload-sarif` | Upload to GitHub Security tab | `true` |
| `no-enrich` | Skip CVE enrichment (faster, offline) | `false` |
| `allow-private` | Permit scanning internal/loopback addresses — **trusted local/CI only** | `false` |
| `baseline-file` | Previous scan JSON to diff against (findings marked new/recurring/resolved) | — |
| `fail-on-new` | Gate only on **new** findings vs the baseline | `false` |
| `suppressions-file` | Suppression file path | `.bulwark.yml` |
| `api-spec` | OpenAPI 3.x / Swagger 2.0 spec (workspace path or URL) to drive API scanning | — |

### Scan profiles

- **`headers`** — security headers, HSTS, CSP, cookies (~10s, great for a fast PR gate)
- **`web`** — headers + TLS + Nikto + Nuclei (the default; balanced)
- **`network`** — port scan + TLS posture
- **`api`** — headers + TLS + OpenAPI-driven API checks (see below)
- **`full`** — everything, including DNS, sensitive-file exposure, and API checks

---

## API scanning (OpenAPI / Swagger)

Modern targets are mostly APIs, and the worst API flaws are authorization ones
a blind crawler can't reason about — it has no way to know that
`GET /accounts/{id}` is supposed to require a token. **The spec does.** Bulwark
reads your OpenAPI 3.x or Swagger 2.0 spec and uses it as an oracle: it checks
whether the endpoints your spec *declares* as secured are actually enforcing
that.

```bash
# Point it at a spec file…
bulwark scan https://api.example.com --profile api --api-spec openapi.yaml

# …or a URL, or let the 'api'/'full' profile auto-discover it on the target
bulwark scan https://api.example.com --profile api \
  --api-spec https://api.example.com/openapi.json
```

**Checks (all read-only by default):**

| Check | OWASP API | What it flags |
|-------|-----------|----------------|
| **Broken authentication** | API2 | A spec-secured endpoint that answers `2xx` to an *unauthenticated* request |
| **Broken object-level auth (BOLA/IDOR)** | API1 | The same, on an object-id endpoint (`/users/{id}`) returning a body — escalated to critical |
| **Improper error handling** | API8 | Bounded fuzzing of query params with edge-case values that trigger a `5xx` or leak a stack trace |

**Safety:** only `GET`/`HEAD`/`OPTIONS` are sent unless you pass
`--api-include-writes` (which can mutate data — disposable environments only).
Every request is pinned to the validated target IP, and **the spec's declared
host is ignored** — only its path templates are used — so a malicious spec
can't redirect the scanner. Endpoint count, concurrency, and body sizes are all
bounded.

Auto-discovery (no `--api-spec`) probes the usual spec locations —
`/openapi.json`, `/swagger.json`, `/v3/api-docs`, and similar.

---

## Diff-aware gating (baselines)

The first scan of a real application finds things — often many. A gate that
fails on *all* of them forever gets deleted from the pipeline. Diff-aware
gating answers the question a PR actually asks: **did this change make things
worse?**

```bash
# On your default branch: record the baseline
bulwark scan https://staging.example.com --json baseline.json --fail-on never

# On a PR: fail only if the change introduces NEW findings
bulwark scan https://staging.example.com \
  --baseline baseline.json --fail-on-new --fail-on high
```

Findings are matched across scans by a stable fingerprint (derived from what
the finding *is* — scanner, CVE, and the thing it names — not scan-specific
text), reported as `new` / `recurring`, and baseline findings that no longer
appear are listed as `resolved`. Recurring findings still show up in every
report; they just don't fail a PR that didn't cause them.

In GitHub Actions, store the baseline as an artifact or commit it, then:

```yaml
- uses: moose11b/bulwark@v1
  with:
    target: http://localhost:3000
    baseline-file: .bulwark/baseline.json
    fail-on-new: 'true'
    fail-on: high
```

---

## Suppressing findings (`.bulwark.yml`)

Accepted risks and false positives are declared in a reviewable file in your
repo instead of by loosening the gate. Every entry must say why; entries can
expire so "temporarily accepted" doesn't quietly become "forever".

```yaml
# .bulwark.yml — picked up automatically, or pass --suppressions FILE
suppressions:
  - fingerprint: 3f2a9c1b8e...        # exact ID, copy it from the JSON output
    reason: "CSP is set by the CDN in production; staging lacks it"

  - cve: CVE-2024-12345
    reason: "Not exploitable here: the vulnerable module is feature-flagged off"
    expires: 2026-12-31               # stops suppressing after this date

  - title: "Missing security header: X-Frame-Options*"   # case-insensitive glob
    reason: "Legacy admin UI; frame-ancestors is set instead"
```

Suppressed findings stay visible in all output — marked, never hidden — and
appear in the Security tab as dismissed alerts with their justification. They
never fail the gate. A malformed suppression file fails the run (exit 2)
rather than half-applying.

---

## Markdown summaries

`--markdown FILE` writes a GitHub-flavored summary of the scan — verdict,
severity counts, new/recurring/resolved breakdown, top findings. The GitHub
Action writes it to the workflow run's Summary page automatically, so the
verdict is readable without opening logs or the Security tab.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings at/above `--fail-on` |
| `1` | Findings met/exceeded the threshold — **gate failed** |
| `2` | Scan error (invalid target, scanner crash) |

---

## Example output

```
  ⛨  BULWARK  ·  Fortify · Detect · Defend

  Target:   http://localhost:3000
  Profile:  web
  Duration: 24.3s
  Findings: 4

      HIGH  TLS 1.0 protocol enabled  (ssl_scanner)
            CWE-326  CVSS 7.4  OWASP A02
    MEDIUM  Missing Content-Security-Policy header  (header_scanner)
            OWASP A05
    MEDIUM  Cookie without Secure flag  (header_scanner)
       LOW  Server version disclosed in header  (header_scanner)

  1 high  2 medium  1 low

  ✗ Gate failed: findings at or above 'high' severity.
```

---

## How findings are classified

Every finding is enriched through the same engine the full Bulwark platform uses:

1. **OWASP Top 10 (2021)** — category mapping by CWE, keywords, and CVE
2. **MITRE ATT&CK** — technique IDs from a live-synced ATT&CK dataset
3. **Cyber Kill Chain** — which attack phase the weakness enables
4. **Compliance** — relevant controls across PCI-DSS v4.0, ISO 27001:2022, NIST CSF 2.0, CIS Controls v8
5. **CVE intelligence** — CVSS (NVD), exploit probability (EPSS), active exploitation (CISA KEV)

> **Note on compliance:** control mappings indicate which framework controls a finding is *relevant to*. They aid remediation prioritisation and are **not** a compliance assessment, audit, or attestation.

---

## Local development

```bash
# Run the CLI directly from source
cd backend
pip install -r requirements-cli.txt
python -m app.cli scan http://localhost:3000 --profile web
```

---

## Responsible use

Only scan systems you own or have explicit written authorisation to test. Unauthorised scanning may be illegal. Bulwark blocks loopback, private, and cloud-metadata addresses by default, but you are responsible for ensuring you have permission to scan any target.

---

## License

MIT — see [LICENSE](LICENSE).

Bulwark wraps several open-source scanners (Nmap, Nikto, Nuclei). Their respective licenses apply to those components.
