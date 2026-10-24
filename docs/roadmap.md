# Roadmap

| Item | Kind | Status |
|---|---|---|
| E1 revocation fence, repair, rekey | Experiment | Done: local, compose, k3s; also over mTLS |
| E2 entropy outage | Experiment | Done |
| E3 APF and agent restarts | Experiment | Done |
| E4 hostile commit distribution | Relay feature and experiment | Done |
| E5 scale | Topology and experiment | Done at 8 agents; found F-8 (kernel cost grows with the square of the history) |
| E7 confused deputy over the network | Experiment | Done |
| Agent persistence | Upstream (F-2) and sidecar | Done; upstream on branch `feat/durable-lab-provider`, waiting for merge |
| mTLS between services | Services | Done, with transport identity bound to protocol identity |
| Kubernetes backend | Backend | Done, tested on k3s, with NetworkPolicy checks (`experiments/k8s-isolation.toml`) |
| E6 live Entropy Core | Topology | **Open**: needs a reachable Entropy Core. Set `entropy.url` (and the `AGENT_TRUST_QRNG_*` secrets) in a topology; no code change. |
| F-8 kernel history cost | Upstream | **Open**: proposal in `docs/findings.md`, needs approval before implementation |
| F-1, F-3, F-4, F-5 | Upstream | Open proposals in `docs/findings.md` |

Next experiments that the infrastructure supports without new code: larger groups
(`scripts/make-topology.py N`) once F-8 is resolved, E1 to E7 on a multi-node k3s
cluster (push the image to a registry), and mTLS with a real Entropy Core.
