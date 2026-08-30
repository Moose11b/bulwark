# Security Policy

Bulwark is a security tool, so we hold it to the standard it enforces. Thank you
for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Report privately through GitHub's **[Private Vulnerability
Reporting](https://github.com/moose11b/bulwark/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). If you cannot use that,
contact the maintainers at the address listed on the repository's Security tab.

Please include:

- the component (CLI, a specific scanner, the API/backend, the Action, or the
  frontend) and version / commit,
- a description and impact assessment,
- steps to reproduce (a proof of concept is ideal), and
- any suggested remediation.

We aim to acknowledge a report within **3 business days** and to agree on a
disclosure timeline with you. Please give us reasonable time to ship a fix
before any public disclosure; we're happy to credit you when the advisory
publishes.

## Scope

In scope — vulnerabilities **in Bulwark itself**, for example:

- SSRF or scan-target validation bypasses (reaching internal/loopback/metadata
  addresses despite the guards),
- authentication/authorization flaws in the backend API,
- credential handling (leakage of stored scan credentials or secrets),
- injection or RCE in the scanner pipeline or report generation,
- a malicious OpenAPI spec, scan target, or tool output causing Bulwark to act
  unsafely.

Out of scope:

- vulnerabilities in the **targets you scan** with Bulwark — that's the output,
  not a bug in the tool,
- issues in third-party scanners Bulwark wraps (nmap, nikto, nuclei); report
  those upstream, though we'll gladly bump a pinned version,
- findings that require `--allow-private` / `allow_private` (an explicit opt-out
  of SSRF protection for trusted local/CI use).

## Responsible use

Only scan systems you own or are explicitly authorised to test. Bulwark blocks
loopback, private, CGNAT, link-local, and cloud-metadata addresses by default;
unauthorised scanning may be illegal regardless. You are responsible for having
permission to scan any target.

## Supply-chain integrity

Because a security scanner is a high-value supply-chain target, Bulwark:

- pins the versions of the scanner binaries it bundles (nuclei, nikto) and
  installs Python dependencies from `requirements.txt` rather than an ad-hoc
  list, so image builds are reproducible;
- builds and publishes the CLI image from tagged releases via GitHub Actions
  (see [RELEASING.md](RELEASING.md)).

Planned hardening (contributions welcome): cosign signatures on released
images, an SBOM attached to each release, and pinned Action dependencies by
digest.

## Supported versions

Bulwark is pre-1.0-stable in spirit; security fixes target the latest `v2.x`
release and `main`. Older majors are not maintained — please upgrade.
