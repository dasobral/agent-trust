#!/usr/bin/env bash
# The verification of the testbed: unit tests of both layers, then the experiments on
# one backend. Exit status 0 only if every gate passed.
#   scripts/ci.sh                          # local backend, E1 to E4, E7, E1 over mTLS
#   SCALE=1 scripts/ci.sh                  # also E5 (about four minutes)
#   BACKEND=compose scripts/ci.sh          # containers (builds the image first)
#   BACKEND=k8s scripts/ci.sh              # Kubernetes (cluster and image ready, see deploy/k3s)
#   RECORD=results scripts/ci.sh           # copy each run's evidence into results/<id>/<date>-<backend>
set -euo pipefail
cd "$(dirname "$0")/.."
BACKEND="${BACKEND:-local}"
EXPERIMENTS="${EXPERIMENTS:-e1-revocation-fence e1-revocation-fence-mtls e2-entropy-outage e3-restarts e4-hostile-commits e7-confused-deputy}"
[ "${SCALE:-0}" = 1 ] && EXPERIMENTS="$EXPERIMENTS e5-scale"
[ "$BACKEND" = k8s ] && EXPERIMENTS="k8s-isolation $EXPERIMENTS"

echo "== gate 1: att-node build and unit tests"
cargo test --locked -p att-node
./attctl build

echo "== gate 2: control plane unit tests"
python3 -m unittest discover -s tests -v

if [ "$BACKEND" = "compose" ]; then
  echo "== gate 3a: container image"
  ./attctl image --base "${BASE_IMAGE:-ubuntu:24.04}"
fi

failed=0
for experiment in $EXPERIMENTS; do
  echo "== gate 3: $experiment on the $BACKEND backend"
  id=$(python3 -c "import tomllib,sys; print(tomllib.load(open(sys.argv[1],'rb'))['experiment']['id'])" "experiments/$experiment.toml")
  record=()
  [ -n "${RECORD:-}" ] && record=(--record "$RECORD/$id/$(date -u +%F)-$BACKEND")
  ./attctl run "experiments/$experiment.toml" --backend "$BACKEND" "${record[@]}" || failed=1
done
exit $failed
