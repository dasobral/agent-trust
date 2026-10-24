#!/usr/bin/env bash
# Runs E1 N times on one backend and prints one line per run plus a summary.
#   scripts/stability.sh 20 [local|compose]
set -uo pipefail
cd "$(dirname "$0")/.."
N="${1:-10}"; BACKEND="${2:-local}"; PASS=0
for i in $(seq 1 "$N"); do
  line=$(./attctl run experiments/e1-revocation-fence.toml --backend "$BACKEND" 2>&1 | grep -E '^\[FAIL\]|^result:' | tr '\n' ' ')
  echo "run $i: $line"
  case "$line" in *"result: PASS"*) PASS=$((PASS + 1));; esac
done
echo "summary: $PASS/$N passed on $BACKEND"
[ "$PASS" -eq "$N" ]
