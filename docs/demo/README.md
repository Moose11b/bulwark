# Demo assets

`demo.gif` is the animated terminal demo shown in the project README. It is
generated from [`demo.tape`](demo.tape) with [VHS](https://github.com/charmbracelet/vhs),
so it is reproducible and always reflects the current CLI rather than a stale
hand-recorded clip.

## How it's produced

The [`Demo` workflow](../../.github/workflows/demo.yml) records it in CI against
the in-repo [VulnAPI](../../benchmarks/targets/vulnapi/) target — no external
images needed — and commits the refreshed GIF back. It runs on demand
(*Actions → Demo → Run workflow*) and on each release.

The committed `demo.gif` starts as a placeholder card; the first run of the
Demo workflow replaces it with the real recording.

## Regenerating locally

```bash
# 1. Install VHS: https://github.com/charmbracelet/vhs#installation
# 2. Install the lean CLI deps and start the target
pip install -r backend/requirements-cli.txt
python3 benchmarks/targets/vulnapi/app.py --port 8000 &
cp benchmarks/targets/vulnapi/openapi.yaml openapi.yaml

# 3. Put a `bulwark` command on PATH (matches the CI shim)
printf '#!/usr/bin/env bash\nexec env PYTHONPATH="%s/backend" BULWARK_VERSION=demo python -m app.cli "$@"\n' "$PWD" \
  | sudo tee /usr/local/bin/bulwark >/dev/null && sudo chmod +x /usr/local/bin/bulwark

# 4. Record
vhs docs/demo/demo.tape
```

## Editing the demo

Change what's shown by editing [`demo.tape`](demo.tape) (typed commands, timing,
theme, size). Keep it short (~15s) and readable; see the VHS docs for the tape
syntax.
