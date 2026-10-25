# K8S: Kubernetes network isolation of the testbed services

- Result: **PASS**
- Backend: `k8s`; topology `three-agents`; entropy `qrng`
- Duration: 3.449 s; steps run: 8; steps not run: 0

Hypothesis: (H1) Agents reach the APF, the relay and the QRNG service, and nothing else reaches an agent: not another agent, not the relay, not the APF. (H2) The relay cannot reach the APF. (H3) With these policies the group works end to end.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | I1 allowed and denied service paths | pass | 2.209 | {"alice->apf": "connects", "alice->bob": "blocked", "alice->relay": "connects", "apf->alice": "blocked", "apf->qrng": "connects", "bob->carol": "blocked", "b... |
| 1 | I2 alice founds the group | pass | 0.066 | {"branch": "3d499f2c2b6a225df298c47c5d8549e24d68d53ea11efc945f75fdf3793d68ae", "epoch": 0} |
| 2 | I3 delegate bob | pass | 0.026 | {"revision": 1} |
| 3 | I4 admit bob | pass | 0.266 | {"branch": "742ed0d2f86fd58fe174c9ed9c1274a33676bc415d83ecdb8ec434f00c10d96e", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | I5 alice sends m1 | pass | 0.062 | {"epoch": 1, "op": "alice-000001", "recipients": ["bob"], "sent_ms": 1792923852155} |
| 5 | I6 drain | pass | 0.381 | {"dropped": 0, "duplicated": 0, "fetched": 1, "held": [], "posted": 1, "queued": {}, "tapped": 0} |
| 6 | I7 bob received m1 | pass | 0.013 | {"agent": "bob", "delivered": ["alice-000001"]} |
| 7 | I8 the oracle accepts the trace | pass | 0.425 | {"events": 11, "kinds": {"admit": 1, "allocate": 1, "allow": 3, "consume": 1, "emit": 1, "init": 1, "persist": 1, "recover": 1, "release": 1}, "oracle": "ora... |

## Final state

- APF roster: ['alice', 'bob']; epoch 1; policy revision 1; read fenced False
- Relay: posted 1, fetched 1, dropped 0, duplicated 0, tapped 0
