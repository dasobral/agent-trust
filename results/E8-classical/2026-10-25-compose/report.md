# E8-classical: Admission, revocation, repair and rekey in the classical suite

- Result: **PASS**
- Backend: `compose`; topology `three-agents-classical`; entropy `qrng`
- Duration: 2.683 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the classical suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.05 | {"branch": "b54a0e5727c1979e203e7bdb7f819ed36d96f704d7a19de99105d6541f8fe20b", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.009 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.011 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.163 | {"branch": "2f65ad975fb3def24f55bb25c8426a916f5426096b82df98d6643a89361660c7", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.173 | {"branch": "83ca8767107fd6869ed106b66e76b43d3096095753e94e8763dbe252c49ccf69", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the classical suite | pass | 0.005 | {"public_key_bytes": 32, "services": {"alice": "classical", "apf": "classical", "bob": "classical", "carol": "classical"}, "suite": "classical"} |
| 6 | B1 alice sends m1 | pass | 0.049 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792923791431} |
| 7 | B2 bob sends m2 | pass | 0.049 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792923791480} |
| 8 | B3 drain | pass | 0.338 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.003 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.012 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.118 | {"branch": "56c59535cbeded5e2c05f2efbc901b4c703ce4847b1c92cfdf50fe9b5830031c", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.049 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792923792000} |
| 13 | C4 drain | pass | 0.329 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.013 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.014 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.074 | {"branch": "3503af1cd41ddb7fc94d4e110f4b9c2950d0b7ba900a905b201cd39e9bced6bc", "epoch": 4, "generation": 1, "public_key": "4c42a82544e275dc0b988cd4c1b98c8fee... |
| 18 | D4 bob sends m4 with his new key | pass | 0.049 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792923792480} |
| 19 | D5 drain | pass | 0.333 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.004 | {"ack": {"count": 4, "max": 310, "min": 310}, "commit": {"count": 4, "max": 1130, "min": 537}, "key_package": {"count": 2, "max": 542, "min": 536}, "welcome"... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.432 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.4 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.004 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
