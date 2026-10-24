# E2: QRNG outage over the network: fail closed, change nothing, recover

- Result: **PASS**
- Backend: `k8s`; topology `three-agents`; entropy `qrng`
- Duration: 96.696 s; steps run: 34; steps not run: 0

Hypothesis: (H1) While the QRNG service refuses requests, every step that needs fresh randomness on an agent (send, add, rekey) is refused with entropy_unavailable and nothing falls back to another source. (H2) A refused step changes neither the frontier, the roster nor the registered keys; a released but unprotected operation is abandoned at the APF (barrier B2). (H3) A node cannot start during the outage. (H4) When the source returns, every refused step succeeds without operator repair, and the oracle accepts the whole trace.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.057 | {"branch": "3d9eb89b8803d86109f6a76815fc92de06f7889ee62639bd50f44625cd2805d8", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.021 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.016 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.203 | {"branch": "480474ae9d8cc1126fd1bd84624b2a6d98392dfb519183f10b3406ced9e00183", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 carol publishes a certified KeyPackage (not yet added) | pass | 0.018 | {"published": true, "rights": [{"generation": 0, "right": "read"}, {"generation": 0, "right": "write"}, {"generation": 0, "right": "admit"}], "subject": "car... |
| 5 | A6 alice sends m1 | pass | 0.034 | {"epoch": 1, "op": "alice-000001", "recipients": ["bob"], "sent_ms": 1792865116423} |
| 6 | A7 drain | pass | 0.395 | {"dropped": 0, "duplicated": 0, "fetched": 1, "held": [], "posted": 1, "queued": {}, "tapped": 0} |
| 7 | B1 the QRNG service starts refusing every request | pass | 0.007 | {"available": false} |
| 8 | B2 alice cannot send: the MLS message needs fresh randomness | pass | 0.04 | {"error": "entropy_unavailable", "refused": "entropy_unavailable"} |
| 9 | B3 alice cannot add carol: the commit needs fresh path secrets | pass | 0.01 | {"error": "entropy_unavailable", "refused": "entropy_unavailable"} |
| 10 | B4 alice revokes bob's write (the APF draws nothing) | pass | 0.011 | {"read_fenced": false, "revision": 11} |
| 11 | B5 alice offers write at generation 1 | pass | 0.011 | {"pending": true} |
| 12 | B6 bob cannot rekey: the new key needs fresh randomness | pass | 0.01 | {"error": "entropy_unavailable", "refused": "entropy_unavailable"} |
| 13 | B7 nothing changed: roster and epoch | pass | 0.009 | {"epoch": 1, "policy_revision": 3, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob"]} |
| 14 | B8 alice and bob are still on the APF frontier | pass | 0.017 | {"agents": ["alice", "bob"], "epoch": 1} |
| 15 | B9 bob stops | pass | 30.862 | {"stopped": "bob"} |
| 16 | B10 bob cannot start without its entropy source (fail closed) | pass | 60.21 | {"reason": "bob did not become ready: Waiting for deployment \"bob\" rollout to finish: 0 of 1 updated replicas are available...\n", "service": "bob", "start... |
| 17 | C1 the QRNG service recovers | pass | 0.007 | {"available": true} |
| 18 | C2 bob starts and resumes from its data directory | pass | 2.866 | {"service": "bob", "started": true} |
| 19 | C3 bob is the same member on the frontier | pass | 0.012 | {"epoch": 1, "future": 0, "membership": "member", "restarts": 1, "skipped_entries": 0, "waiting": []} |
| 20 | C4 alice sends m2 | pass | 0.035 | {"epoch": 1, "op": "alice-000003", "recipients": ["bob"], "sent_ms": 1792865210924} |
| 21 | C4b drain before the epoch changes (finding F-7: consume binds to the APF's current epoch) | pass | 0.314 | {"dropped": 0, "duplicated": 0, "fetched": 2, "held": [], "posted": 2, "queued": {}, "tapped": 0} |
| 22 | C5 alice adds carol with the same KeyPackage | pass | 0.209 | {"branch": "4c3b3e6031f97d81e9c22ee31c477b97bd87d13cd1c077dee4ae5a969f80e424", "epoch": 2, "index": 1, "subject": "carol"} |
| 23 | C6 bob completes the pending rekey | pass | 0.104 | {"branch": "3d01ccdb211b0d630b07dbc385b3ee3f657588ec1a53580b4806de02fd4009bb", "epoch": 3, "generation": 1, "public_key": "6d7a26d445a4af129f80ede873bd0be2c6... |
| 24 | C7 bob sends m3 with its new key | pass | 0.043 | {"epoch": 3, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792865211594} |
| 25 | C8 carol sends m4 | pass | 0.063 | {"epoch": 3, "op": "carol-000001", "recipients": ["alice", "bob"], "sent_ms": 1792865211657} |
| 26 | C9 drain | pass | 0.383 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 27 | D1 final roster and epoch: add plus rekey | pass | 0.007 | {"epoch": 3, "policy_revision": 4, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 28 | D2 every agent is on the APF frontier | pass | 0.025 | {"agents": ["alice", "bob", "carol"], "epoch": 3} |
| 29 | D3 every message reached every certified reader exactly once | pass | 0.018 | {"excluded": [], "optional": 0, "pairs": 6} |
| 30 | D4 no delivery without APF consumption | pass | 0.033 | {"consumed": 6, "deliveries": 6, "lost_after_consume": 0} |
| 31 | D5 the oracle accepts the trace, the abandoned release included | pass | 0.346 | {"events": 40, "kinds": {"abandon": 1, "admit": 2, "allocate": 5, "allow": 6, "consume": 6, "deny": 1, "emit": 4, "init": 1, "persist": 4, "recover": 4, "rek... |
| 32 | D6 the oracle rejects the broken controls that apply to this trace | pass | 0.269 | {"rejected": {"rekey that reuses another member's key": "stale_key", "release cover that omits a reader": "unsound_cover", "replayed consumption": "replay", ... |
| 33 | D7 alice's counter shows the refused draws (bob's counter restarted with bob; B6 asserts its refusal); nothing else failed | pass | 0.031 | {"nodes": {"alice": {"bytes": 328, "failures": 2, "requests": 12, "source": "qrng"}, "apf": {"bytes": 96, "failures": 0, "requests": 3, "source": "qrng"}, "b... |

## Final state

- APF roster: ['alice', 'bob', 'carol']; epoch 3; policy revision 4; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
