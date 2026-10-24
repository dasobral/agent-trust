#!/usr/bin/env bash
# Runs experiments N times each on one backend; one line per run plus a summary.
#   scripts/stability.sh N [backend] [experiment ...]     (default: E1)
set -uo pipefail
cd "$(dirname "$0")/.."
N="${1:-10}"; BACKEND="${2:-local}"; shift 2 2>/dev/null || shift $#
EXPERIMENTS=("${@:-e1-revocation-fence}")
TOTAL=0; PASS=0
for experiment in "${EXPERIMENTS[@]}"; do
  ok=0
  for i in $(seq 1 "$N"); do
    line=$(./attctl run "experiments/$experiment.toml" --backend "$BACKEND" 2>&1 | grep -E '^\[FAIL\]|^result:' | sed 's#; report .*##' | tr '\n' ' ')
    echo "$experiment run $i: $line"
    case "$line" in *"result: PASS"*) ok=$((ok + 1));; esac
  done
  echo "summary $experiment: $ok/$N passed on $BACKEND"
  TOTAL=$((TOTAL + N)); PASS=$((PASS + ok))
done
echo "summary: $PASS/$TOTAL passed on $BACKEND"
[ "$PASS" -eq "$TOTAL" ]
