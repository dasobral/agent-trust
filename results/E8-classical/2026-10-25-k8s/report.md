# E8-classical: Admission, revocation, repair and rekey in the classical suite

- Result: **PASS**
- Backend: `k8s`; topology `three-agents-classical`; entropy `qrng`
- Duration: 3.61 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the classical suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.076 | {"branch": "db538e3de1dab327d7aa696c9d1d3c954a7871b1fd0cf8b9f763673ad59cff1d", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.022 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.025 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.235 | {"branch": "512929c6cb6268cb1e46c597f001d1fe2c6a5e16ebe408ee5733a47297590487", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.257 | {"branch": "bfd310359aac4f2a6130c07a5fe4a224e090e2a22fc90271d2a2bf022c50f79b", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the classical suite | pass | 0.031 | {"public_key_bytes": 32, "services": {"alice": "classical", "apf": "classical", "bob": "classical", "carol": "classical"}, "suite": "classical"} |
| 6 | B1 alice sends m1 | pass | 0.043 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792925095819} |
| 7 | B2 bob sends m2 | pass | 0.057 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792925095876} |
| 8 | B3 drain | pass | 0.544 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.026 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.019 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.229 | {"branch": "2f3716ab98eaabbdfd05fefc7167b37564d07d4680b95ee92ee4b9feff941644", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.063 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792925096758} |
| 13 | C4 drain | pass | 0.433 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.008 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.02 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.02 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.148 | {"branch": "96da235e9ad94b67fe82df8a86c0708fb0217f1e42f389c9673e98a6c5c185eb", "epoch": 4, "generation": 1, "public_key": "0d20eacead2b4636cdc83c4d2a33f2dec6... |
| 18 | D4 bob sends m4 with his new key | pass | 0.063 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792925097450} |
| 19 | D5 drain | pass | 0.355 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.008 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.034 | {"ack": {"count": 4, "max": 310, "min": 310}, "commit": {"count": 4, "max": 1130, "min": 537}, "key_package": {"count": 2, "max": 542, "min": 536}, "welcome"... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.468 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.403 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.021 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
