# Roadmap

| Item | Kind | Status |
|---|---|---|
| E1 revocation fence, repair, rekey | Experiment | Done: local, compose, k3s; also over mTLS |
| E2 entropy outage | Experiment | Done |
| E3 APF and agent restarts | Experiment | Done |
| E4 hostile commit distribution | Relay feature and experiment | Done |
| E5 scale | Topology and experiment | Done at 8 agents in the `classical` suite; found F-8 (kernel cost grows with the square of the history). In the `pq` suite one round exceeds the bound (F-8) |
| E8 suites | Experiment | Done: the same scenario in `pq` and `classical`, with sizes |
| E7 confused deputy over the network | Experiment | Done |
| Agent persistence | Upstream (F-2) and sidecar | Done; upstream on branch `feat/durable-lab-provider`, waiting for merge |
| mTLS between services | Services | Done, with transport identity bound to protocol identity |
| Kubernetes backend | Backend | Done, tested on k3s, with NetworkPolicy checks (`experiments/k8s-isolation.toml`) |
| E6 live Entropy Core | Topology | **Open**: needs a reachable Entropy Core. Set `entropy.url` (and the `AGENT_TRUST_QRNG_*` secrets) in a topology; no code change. |
| F-8 kernel history cost | Upstream | **Open**: proposal in `docs/findings.md`, needs approval before implementation. More urgent since F-9: ML-DSA makes every persisted envelope about seven times larger, and E5 in the `pq` suite exceeds its round bound |
| F-1, F-3, F-4, F-5 | Upstream | Open proposals in `docs/findings.md` |
| F-9 post quantum | Upstream and testbed | **Done** (D-13, 2026-10-25): PQ-1 and PQ-3 in agent-trust C-42 (`pq` suite, the default), PQ-2 in openmls-qrand and `att-node` (X25519MLKEM768 on every link), PQ-4 in `att-node pki` (ML-DSA-44 certificates). E8 compares both suites. E5 in the `pq` suite waits for F-8 |

Next experiments that the infrastructure supports without new code: larger groups
(`scripts/make-topology.py N`) once F-8 is resolved, E1 to E7 on a multi-node k3s
cluster (push the image to a registry), and mTLS with a real Entropy Core.
