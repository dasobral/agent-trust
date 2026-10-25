# E8-pq: Admission, revocation, repair and rekey in the pq suite

- Result: **PASS**
- Backend: `local`; topology `three-agents`; entropy `qrng`
- Duration: 2.831 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the pq suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.051 | {"branch": "1ecd6b84f3f052cbe2b08075fe878618d09f75ab8692b19274c95128a5c31db9", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.007 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.009 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.171 | {"branch": "8b63f7fae9a13844e508623a0731bca83a0b2f9c3c696bf801b546b94b74d53b", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.192 | {"branch": "01b7124b2ab570c0fc67c834b0fa03ad29883f58d4d205e59df1371548c8adca", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the pq suite | pass | 0.004 | {"public_key_bytes": 1312, "services": {"alice": "pq", "apf": "pq", "bob": "pq", "carol": "pq"}, "suite": "pq"} |
| 6 | B1 alice sends m1 | pass | 0.038 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792922568930} |
| 7 | B2 bob sends m2 | pass | 0.052 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792922568982} |
| 8 | B3 drain | pass | 0.374 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.003 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.014 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.14 | {"branch": "675bd6f300b5f775b3f4ff669357c37b68ea40211bfcc8d6c27b2d9a28fe0cec", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.054 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792922569567} |
| 13 | C4 drain | pass | 0.317 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.017 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.022 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.087 | {"branch": "3e128fea1851129f8046903ac5103b205ba2028d4f6a56e1ec86690fe6649faf", "epoch": 4, "generation": 1, "public_key": "e31c18767321a9f4576b520741280ae2f6... |
| 18 | D4 bob sends m4 with his new key | pass | 0.079 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792922570091} |
| 19 | D5 drain | pass | 0.423 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.004 | {"ack": {"count": 4, "max": 2666, "min": 2666}, "commit": {"count": 4, "max": 22551, "min": 10054}, "key_package": {"count": 2, "max": 11261, "min": 11255}, ... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.387 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.381 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.002 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
