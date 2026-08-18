# Bulwark demo — a VHS tape (https://github.com/charmbracelet/vhs).
#
# Recorded automatically by .github/workflows/demo.yml against the in-repo
# VulnAPI target, so it needs no external images and always reflects the
# current CLI. To regenerate locally:
#
#   pip install -r backend/requirements-cli.txt
#   python3 benchmarks/targets/vulnapi/app.py --port 8000 &
#   cp benchmarks/targets/vulnapi/openapi.yaml openapi.yaml
#   #  put a `bulwark` wrapper on PATH (see the workflow), then:
#   vhs docs/demo/demo.tape
#
# The scan below hits a running API, reads its OpenAPI spec to test what the
# spec says should be authenticated, finds a broken-auth + BOLA flaw, and
# fails the CI gate (exit 1).

Output docs/demo/demo.gif

Require bulwark

Set Shell bash
Set FontSize 18
Set Width 1120
Set Height 780
Set Theme "Dracula"
Set TypingSpeed 55ms
Set Margin 18
Set MarginFill "#1b1b26"
Set BorderRadius 10
Set WindowBar Colorful
Set Padding 16

Sleep 600ms
Type "# A running API. Bulwark reads its OpenAPI spec to test what should be protected."
Enter
Sleep 1200ms

Type "bulwark scan http://127.0.0.1:8000 --profile api --api-spec openapi.yaml --fail-on high --allow-private"
Sleep 700ms
Enter
Sleep 6500ms

Type 'echo "gate exit code: $?"'
Enter
Sleep 3500ms
