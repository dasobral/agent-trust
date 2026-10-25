# E8-pq: Admission, revocation, repair and rekey in the pq suite

- Result: **PASS**
- Backend: `compose`; topology `three-agents`; entropy `qrng`
- Duration: 3.04 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the pq suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.067 | {"branch": "132b5aabf9bb6b27613e8f54548885ef50577de8de2ba0e5dc142e07af085776", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.012 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.012 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.179 | {"branch": "e2647451c4eae95bb0828e60623ffd0266a0e5a7a3e1f22a86377840bef50f3e", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.189 | {"branch": "c8d0d8914a9acc0f0c1cf88501b7ebab18c53db428efe69e9e92a1d5226a2027", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the pq suite | pass | 0.004 | {"public_key_bytes": 1312, "services": {"alice": "pq", "apf": "pq", "bob": "pq", "carol": "pq"}, "suite": "pq"} |
| 6 | B1 alice sends m1 | pass | 0.074 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792923753415} |
| 7 | B2 bob sends m2 | pass | 0.075 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792923753490} |
| 8 | B3 drain | pass | 0.345 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.003 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.019 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.173 | {"branch": "a9a09c4929389b035e42d0921cea83c7f60290d8015c1b356c26dd2ca3d0562a", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.06 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792923754091} |
| 13 | C4 drain | pass | 0.339 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.02 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.021 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.114 | {"branch": "985ff5ad2c5115bcb116f36b78b7d5d089d33e46c5db657a2d5d3e7a6e15c6c1", "epoch": 4, "generation": 1, "public_key": "cfad8ab0b41717c6b1f8dfdd20ea981104... |
| 18 | D4 bob sends m4 with his new key | pass | 0.095 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792923754681} |
| 19 | D5 drain | pass | 0.336 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.03 | {"ack": {"count": 4, "max": 2666, "min": 2666}, "commit": {"count": 4, "max": 22551, "min": 10054}, "key_package": {"count": 2, "max": 11261, "min": 11255}, ... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.459 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.406 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.003 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
