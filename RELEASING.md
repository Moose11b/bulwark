# Releasing Bulwark

## One-time setup

1. **Push the repo to GitHub** under `moose11b/bulwark` (public).

2. **Enable GitHub Actions** — Settings → Actions → General → allow workflows.

3. **Allow Actions to write packages & contents** —
   Settings → Actions → General → Workflow permissions →
   select **Read and write permissions**.

4. **(First release only) make the GHCR package public** so anyone can
   `docker pull` it without auth: after the first release runs, go to
   your profile → Packages → `bulwark-cli` → Package settings →
   Change visibility → Public.

## Cutting a release

Releases are tag-driven. To ship `v1.0.0`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `release.yml` workflow then automatically:
- builds the lean CLI image for amd64 + arm64
- pushes it to `ghcr.io/moose11b/bulwark-cli` tagged `v1.0.0`, `v1`, and `latest`
- force-moves the `v1` git tag so `uses: moose11b/bulwark@v1` resolves here
- creates a GitHub Release with auto-generated notes

## Versioning

Use semver: `vMAJOR.MINOR.PATCH`.
- Patch (`v1.0.1`) — bug fixes, no interface change
- Minor (`v1.1.0`) — new scan profiles / flags, backward compatible
- Major (`v2.0.0`) — breaking changes to flags or output format

The `v1` Action tag always tracks the latest `v1.x`, so consumers pinning
`@v1` get non-breaking updates automatically. Breaking changes go to `v2`
and consumers opt in by changing their `uses:` line.

## Verifying a release

```bash
# Pull and smoke-test the published image
docker run --rm ghcr.io/moose11b/bulwark-cli:latest --version
docker run --rm ghcr.io/moose11b/bulwark-cli:latest scan example.com --profile headers --fail-on never
```
