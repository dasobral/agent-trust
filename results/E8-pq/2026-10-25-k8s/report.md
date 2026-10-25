# E8-pq: Admission, revocation, repair and rekey in the pq suite

- Result: **PASS**
- Backend: `k8s`; topology `three-agents`; entropy `qrng`
- Duration: 3.474 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the pq suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.063 | {"branch": "856ab302d90c8ab34d0ae7e3730fbec05e2de3da5cd66154aefa59c17e784bf3", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.027 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.024 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.286 | {"branch": "55f75bf362407a216410bc397edee1ea8230765adb892428c724cafdb1c08e58", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.255 | {"branch": "0fc585b3880d056e1cf021c94290aab158993d8ce1d4ac0ea8383593ca81bd2a", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the pq suite | pass | 0.032 | {"public_key_bytes": 1312, "services": {"alice": "pq", "apf": "pq", "bob": "pq", "carol": "pq"}, "suite": "pq"} |
| 6 | B1 alice sends m1 | pass | 0.046 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792924984295} |
| 7 | B2 bob sends m2 | pass | 0.078 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792924984373} |
| 8 | B3 drain | pass | 0.42 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.023 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.021 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.22 | {"branch": "d6e5dbc00da818e6e2b906ec338320628243530629b834f94ec34fbbe87ea3ff", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.076 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792924985132} |
| 13 | C4 drain | pass | 0.422 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.007 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.024 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.034 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.142 | {"branch": "119d4094ae9782616cd075146907666dd6351dff6282a528573576b8145d76af", "epoch": 4, "generation": 1, "public_key": "1c24bc6d8123eb019459287a65cbd1884a... |
| 18 | D4 bob sends m4 with his new key | pass | 0.088 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792924985851} |
| 19 | D5 drain | pass | 0.361 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.007 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.033 | {"ack": {"count": 4, "max": 2666, "min": 2666}, "commit": {"count": 4, "max": 22551, "min": 10054}, "key_package": {"count": 2, "max": 11261, "min": 11255}, ... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.363 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.405 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.018 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
