# Bulwark benchmarks

Reproducible, honestly-scored comparisons of Bulwark against [OWASP
ZAP](https://www.zaproxy.org/) (baseline scan) on known targets. The point is
not to declare a winner — DAST tools legitimately find different things — but to
show, with a method anyone can re-run, **what coverage each tool actually
provides**.

Every number here is produced by the [`Benchmark`
workflow](../.github/workflows/benchmark.yml), not typed by hand. Run it
yourself: Actions → Benchmark → *Run workflow*, or reproduce locally with the
steps below.

## The honest-metric problem

"Tool A reported 200 findings, tool B reported 20" tells you almost nothing —
higher counts often just mean more noise, and neither count is *truth*. So the
headline metric here is **detection rate against a ground-truth list**: a target
whose vulnerabilities are known in advance, so each tool's output can be scored
as caught / missed, with false positives counted against it.

Raw finding counts are still shown, but explicitly labelled as *context, not a
score*.

## Targets

### `vulnapi` — ground-truth (the headline)

A tiny, deliberately-vulnerable API ([`targets/vulnapi/`](targets/vulnapi/))
with a documented list of planted, black-box-detectable flaws
([`ground_truth.yaml`](targets/vulnapi/ground_truth.yaml)) and a published
OpenAPI spec. It runs on the Python standard library alone — no framework, no
container — so it starts in milliseconds and is trivially reproducible.

Planted vulnerabilities:

| Vulnerability | OWASP | Black-box detectable? |
|---|---|---|
| Broken object-level authorization (BOLA/IDOR) on `/api/users/{id}` | API1 / A01 | only *with the spec* — nothing marks it as protected otherwise |
| Missing authentication on `/api/admin/config` | API2 / A07 | only *with the spec* |
| Improper error handling / injection surface on `/api/search` | API8 / A05 | yes |
| Missing HTTP security headers | A05 | yes |

Plus one **control** — `/api/account/{id}`, which *does* enforce auth (401
without a token). A tool that flags it is producing a false positive, and the
scorer counts that against it.

### `juice-shop` — real-world coverage

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) is a large,
intentionally-insecure app. It has hundreds of issues with no enumerable
black-box ground-truth list, so this target is a **raw-coverage** comparison
only (counts by severity, no detection rate).

## Illustrative result — `vulnapi`

> **Provenance:** the **Bulwark** column below is a real local run against
> VulnAPI. The **ZAP** column is derived from a representative ZAP baseline
> report ([`fixtures/zap-vulnapi-sample.json`](fixtures/zap-vulnapi-sample.json))
> so the table renders here without a live ZAP run. The **authoritative**
> numbers — with ZAP actually executed — come from the CI workflow; see its run
> summary and the `benchmark-results` artifact. Do not cite the ZAP figures
> below as measured.

```
### Detection rate vs. ground truth

| Tool    | Detected | Detection rate | False positives |
|---------|----------|----------------|-----------------|
| bulwark | 4/4      | 100%           | 0               |
| zap     | 2/4      | 50%            | 0               |

| Planted vulnerability                          | OWASP | bulwark | zap |
|------------------------------------------------|-------|---------|-----|
| Broken object-level authorization /api/users   | A01   | ✅      | ❌  |
| Missing authentication /api/admin/config       | A07   | ✅      | ❌  |
| Improper error handling /api/search            | A05   | ✅      | ✅  |
| Missing HTTP security headers                  | A05   | ✅      | ✅  |
```

The gap is the expected one, not a trick: a black-box baseline **cannot** know
that `/api/users/{id}` and `/api/admin/config` are supposed to require auth, so
it can't tell that answering them unauthenticated is a flaw. Bulwark reads that
from the OpenAPI spec. On the two issues visible without a spec — error handling
and headers — both tools succeed.

## Reproduce locally

```bash
# 1. Start the ground-truth target
python3 benchmarks/targets/vulnapi/app.py --port 8000 &

# 2. Build the Bulwark CLI image
docker build -f backend/Dockerfile.cli -t bulwark-cli:bench ./backend

# 3. Run both scanners + score against ground truth
benchmarks/run.sh \
  --target vulnapi \
  --url http://127.0.0.1:8000 \
  --spec benchmarks/targets/vulnapi/openapi.yaml \
  --ground-truth benchmarks/targets/vulnapi/ground_truth.yaml \
  --bulwark-image bulwark-cli:bench

# Results land in benchmarks/results/vulnapi.md (+ .comparison.json)
```

`run.sh` drives [`compare.py`](compare.py), which normalises both tools'
output into one shape and scores it. Pass `--no-zap` to run Bulwark only.

## Methodology & caveats

- **Scope.** This compares Bulwark against ZAP's **baseline** (passive +
  spider, no active attack). ZAP's full active scan finds more but takes far
  longer and is not a fair CI-gate comparison; Bulwark's checks are likewise
  CI-speed. Like-for-like.
- **Matching.** A tool is credited for a planted vuln when its output contains a
  keyword naming that vulnerability *class* — never merely the URL path, since a
  finding located at `/api/users` (say, a timestamp disclosure) has not detected
  the BOLA there. Rules live in each target's `ground_truth.yaml`.
- **"Additional" findings.** Output matching no planted vuln is reported
  separately as *additional*, neither credited nor penalised: without manual
  triage we cannot say whether it is a true extra or a false positive. Only
  findings on the declared **controls** are scored as false positives.
- **DAST is not exhaustive.** A 100% detection rate here means "found every
  planted issue in this small target", not "finds every vulnerability". These
  are dynamic, black-box checks against a running app — they complement, and do
  not replace, SAST/SCA and manual review.
- **No cherry-picking.** The target, the ground truth, and the scoring code are
  all in this repo and run in CI. If a number looks wrong, re-run it.
