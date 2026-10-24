# K8S: Kubernetes network isolation of the testbed services

- Result: **PASS**
- Backend: `k8s`; topology `three-agents`; entropy `qrng`
- Duration: 2.832 s; steps run: 8; steps not run: 0

Hypothesis: (H1) Agents reach the APF, the relay and the QRNG service, and nothing else reaches an agent: not another agent, not the relay, not the APF. (H2) The relay cannot reach the APF. (H3) With these policies the group works end to end.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | I1 allowed and denied service paths | pass | 1.843 | {"alice->apf": "connects", "alice->bob": "blocked", "alice->relay": "connects", "apf->alice": "blocked", "apf->qrng": "connects", "bob->carol": "blocked", "b... |
| 1 | I2 alice founds the group | pass | 0.063 | {"branch": "39d2458e281d340e5119ff57562313858bb1bc7b230a8ae9e3c36f0516745aaf", "epoch": 0} |
| 2 | I3 delegate bob | pass | 0.02 | {"revision": 1} |
| 3 | I4 admit bob | pass | 0.222 | {"branch": "a444b15778b0529bd3dfb1e8ea96e3e70adda7110e8fa97071bd5193ec5c720e", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | I5 alice sends m1 | pass | 0.039 | {"epoch": 1, "op": "alice-000001", "recipients": ["bob"], "sent_ms": 1792860112283} |
| 5 | I6 drain | pass | 0.32 | {"dropped": 0, "duplicated": 0, "fetched": 1, "held": [], "posted": 1, "queued": {}, "tapped": 0} |
| 6 | I7 bob received m1 | pass | 0.006 | {"agent": "bob", "delivered": ["alice-000001"]} |
| 7 | I8 the oracle accepts the trace | pass | 0.319 | {"events": 11, "kinds": {"admit": 1, "allocate": 1, "allow": 3, "consume": 1, "emit": 1, "init": 1, "persist": 1, "recover": 1, "release": 1}, "oracle": "ora... |

## Final state

- APF roster: ['alice', 'bob']; epoch 1; policy revision 1; read fenced False
- Relay: posted 1, fetched 1, dropped 0, duplicated 0, tapped 0
