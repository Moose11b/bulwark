<!--
Thanks for contributing to Bulwark! Keep PRs focused and small where possible.
See CONTRIBUTING.md for setup and the full checklist.
-->

## What & why

<!-- What does this change do, and what problem does it solve? Link any issue. -->

## Type of change

- [ ] New scanner / detection
- [ ] Fix (false positive, crash, incorrect severity/mapping)
- [ ] CLI / Action ergonomics
- [ ] Benchmarks
- [ ] Docs
- [ ] Other:

## How it was tested

<!-- Commands you ran; new tests you added; a target you scanned. -->

## Checklist

- [ ] `pytest` passes and I added tests for new behaviour
- [ ] No secrets, tokens, or real hostnames in the diff
- [ ] No fabricated findings — coverage gaps surface as INFO (see `availability.py`)
- [ ] User-facing changes documented in `README-cli.md` / `README.md`
