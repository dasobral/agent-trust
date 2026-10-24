# Roadmap

E1 is the first experiment. The infrastructure is built so that each item below is a
new topology, a new experiment file, or a new backend, not a new framework.

| Item | Kind | What it adds |
|---|---|---|
| E2 entropy outage | Experiment | `qrng` outage (`POST /control/outage`) during admission, send and rekey: each node must fail closed with `entropy_unavailable`, change nothing, and recover when the source returns (agent-trust C-40 over the network) |
| E3 APF restart | Experiment | Stop and restart the `apf` service between and during flows: the adapter reopens its state (C-32) and the group continues |
| E4 hostile commit distribution | Relay feature and experiment | Hide, reorder and forge handshake entries; members must never merge an unacked or wrong-parent commit (§4.6), and a hidden commit must only cost liveness |
| E5 scale | Topology and experiment | N agents and message rates; latency and throughput per flow; APF as the bottleneck |
| E6 live Entropy Core | Topology | `entropy.url` set to a real endpoint; closes agent-trust's `live_entropy_core` gate |
| E7 confused deputy over the network | Experiment | `invoke` chains across agents (agent-trust `docs/confused-deputy.md`) |
| Agent persistence | Upstream (F-2) and sidecar | Restartable agents and the B1–B8 barriers at network scale |
| mTLS between services | Services | Transport authentication in addition to request signatures |
| Kubernetes backend | Backend | `controller/attctl/deploy/k8s.py`, same `deploy.json` |
