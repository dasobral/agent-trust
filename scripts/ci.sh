#!/usr/bin/env bash
# The full verification of the testbed: unit tests of both layers, then E1 on the
# local backend. Exit status 0 only if every gate passed.
#   scripts/ci.sh            # local backend
#   BACKEND=compose scripts/ci.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BACKEND="${BACKEND:-local}"

echo "== gate 1: att-node build and unit tests"
cargo test --locked -p att-node
./attctl build

echo "== gate 2: control plane unit tests"
python3 -m unittest discover -s tests -v

if [ "$BACKEND" = "compose" ]; then
  echo "== gate 3a: container image"
  ./attctl image --base "${BASE_IMAGE:-ubuntu:24.04}"
fi

echo "== gate 3: experiment E1 on the $BACKEND backend"
./attctl run experiments/e1-revocation-fence.toml --backend "$BACKEND" ${RECORD:+--record "$RECORD"}
