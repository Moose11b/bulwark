#!/usr/bin/env bash
#
# Run Bulwark and OWASP ZAP (baseline) against one target and produce a
# ground-truth-scored comparison. Designed to run in CI, where the container
# images can be pulled and the target can be started (see benchmark.yml), but
# also runnable locally.
#
# The target itself must already be running and reachable at --url; this script
# only drives the two scanners and the comparator, so it stays agnostic about
# how each target is launched.
#
# Usage:
#   benchmarks/run.sh \
#     --target vulnapi \
#     --url http://127.0.0.1:8000 \
#     --spec benchmarks/targets/vulnapi/openapi.yaml \
#     --ground-truth benchmarks/targets/vulnapi/ground_truth.yaml \
#     --outdir benchmarks/results \
#     [--bulwark-image ghcr.io/moose11b/bulwark-cli:latest] \
#     [--zap-image ghcr.io/zaproxy/zaproxy:stable] \
#     [--no-zap]
#
set -euo pipefail

TARGET="" URL="" SPEC="" GROUND_TRUTH="" OUTDIR="benchmarks/results"
BULWARK_IMAGE="ghcr.io/moose11b/bulwark-cli:latest"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
RUN_ZAP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --spec) SPEC="$2"; shift 2 ;;
    --ground-truth) GROUND_TRUTH="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --bulwark-image) BULWARK_IMAGE="$2"; shift 2 ;;
    --zap-image) ZAP_IMAGE="$2"; shift 2 ;;
    --no-zap) RUN_ZAP=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$TARGET" ] && [ -n "$URL" ] || { echo "--target and --url are required" >&2; exit 2; }
mkdir -p "$OUTDIR"
BW_JSON="$OUTDIR/$TARGET.bulwark.json"
ZAP_JSON="$OUTDIR/$TARGET.zap.json"

echo "== Bulwark scan of $URL =="
# Profile 'api' when a spec is available (adds the API checks), else 'full'.
BW_ARGS=(scan "$URL" --fail-on never --allow-private --no-enrich --quiet --json /out/$(basename "$BW_JSON"))
if [ -n "$SPEC" ]; then
  BW_ARGS+=(--profile api --api-spec "/spec/$(basename "$SPEC")")
else
  BW_ARGS+=(--profile full)
fi

bw_start=$(date +%s)
docker run --rm --network host \
  -v "$(cd "$OUTDIR" && pwd):/out" \
  ${SPEC:+-v "$(cd "$(dirname "$SPEC")" && pwd):/spec"} \
  "$BULWARK_IMAGE" "${BW_ARGS[@]}"
bw_secs=$(( $(date +%s) - bw_start ))
echo "Bulwark finished in ${bw_secs}s -> $BW_JSON"

CMP_ARGS=(--target "$TARGET" --bulwark "$BW_JSON" --bulwark-seconds "$bw_secs")
[ -n "$GROUND_TRUTH" ] && CMP_ARGS+=(--ground-truth "$GROUND_TRUTH")

if [ "$RUN_ZAP" = "1" ]; then
  echo "== ZAP baseline scan of $URL =="
  # zap-baseline.py exits 1 when it reports warnings/fails — expected, not an
  # error, so it must not abort the run.
  zap_start=$(date +%s)
  docker run --rm --network host \
    -v "$(cd "$OUTDIR" && pwd):/zap/wrk:rw" \
    "$ZAP_IMAGE" zap-baseline.py \
    -t "$URL" -J "$(basename "$ZAP_JSON")" -I -m 2 || true
  zap_secs=$(( $(date +%s) - zap_start ))
  echo "ZAP finished in ${zap_secs}s -> $ZAP_JSON"
  if [ -f "$ZAP_JSON" ]; then
    CMP_ARGS+=(--zap "$ZAP_JSON" --zap-seconds "$zap_secs")
  else
    echo "WARNING: ZAP produced no report; comparing Bulwark only." >&2
  fi
fi

echo "== Comparison =="
python3 benchmarks/compare.py "${CMP_ARGS[@]}" \
  --out-md "$OUTDIR/$TARGET.md" \
  --out-json "$OUTDIR/$TARGET.comparison.json"
echo "Wrote $OUTDIR/$TARGET.md"
