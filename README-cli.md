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

### Scan profiles

- **`headers`** — security headers, HSTS, CSP, cookies (~10s, great for a fast PR gate)
- **`web`** — headers + TLS + Nikto + Nuclei (the default; balanced)
- **`network`** — port scan + TLS posture
- **`full`** — everything, including DNS and sensitive-file exposure

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
