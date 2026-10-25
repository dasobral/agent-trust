# E8-classical: Admission, revocation, repair and rekey in the classical suite

- Result: **PASS**
- Backend: `local`; topology `three-agents-classical`; entropy `qrng`
- Duration: 2.57 s; steps run: 25; steps not run: 0

Hypothesis: (H1) Every node of the deployment runs the classical suite, with keys of its size. (H2) Admission, delivery, revocation with repair and rekey behave exactly as in the other suite, and the oracle accepts the trace and rejects every broken control. (H3) The report records the size of every MLS object on the relay, for comparison.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.075 | {"branch": "f31762d12b18187b5fa718141f3983419b8417254ca28e0714de8dc94df14896", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.008 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.006 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.162 | {"branch": "55944a39718d6a689aaf741172d09dfe0cef65a644a0fb4799f88a387fa4c0d0", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.15 | {"branch": "3afef50b6194fa9a9f912b8620ad1186fabe34f9be4727d58fafecbe0e098627", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 the APF and every agent run the classical suite | pass | 0.002 | {"public_key_bytes": 32, "services": {"alice": "classical", "apf": "classical", "bob": "classical", "carol": "classical"}, "suite": "classical"} |
| 6 | B1 alice sends m1 | pass | 0.027 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792922572537} |
| 7 | B2 bob sends m2 | pass | 0.046 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792922572583} |
| 8 | B3 drain | pass | 0.324 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 9 | B4 m1 and m2 reached every reader exactly once | pass | 0.002 | {"excluded": [], "optional": 0, "pairs": 4} |
| 10 | C1 alice revokes carol's read right | pass | 0.01 | {"read_fenced": true, "revision": 15} |
| 11 | C2 alice commits the repair; bob confirms; the fence reopens | pass | 0.107 | {"branch": "99f07fbade388369b8362715faf9ade3b8ea6ad738ca73cd9751a5b39529efcd", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 12 | C3 alice sends m3 after the repair | pass | 0.037 | {"epoch": 3, "op": "alice-000002", "recipients": ["bob"], "sent_ms": 1792922573063} |
| 13 | C4 drain | pass | 0.32 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": [], "posted": 5, "queued": {}, "tapped": 0} |
| 14 | C5 bob received m3 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000002"]} |
| 15 | D1 alice revokes bob's write right | pass | 0.011 | {"read_fenced": false, "revision": 22} |
| 16 | D2 alice re-grants write at generation 1: a rekey offer | pass | 0.012 | {"pending": true} |
| 17 | D3 bob commits a new signature key and incarnation | pass | 0.11 | {"branch": "d2b70b3e79db53493549fdc70cb47fd3012b5c8f2bb0ed4ce57aa9c42594233d", "epoch": 4, "generation": 1, "public_key": "75406897ff58a1585f308137e54b084b2c... |
| 18 | D4 bob sends m4 with his new key | pass | 0.045 | {"epoch": 4, "op": "bob-000002", "recipients": ["alice"], "sent_ms": 1792922573562} |
| 19 | D5 drain | pass | 0.319 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 20 | D6 alice received m4 | pass | 0.0 | {"agent": "alice", "delivered": ["bob-000002"]} |
| 21 | F1 sizes of KeyPackages, commits, acks and Welcome messages on the relay | pass | 0.002 | {"ack": {"count": 4, "max": 310, "min": 310}, "commit": {"count": 4, "max": 1130, "min": 537}, "key_package": {"count": 2, "max": 542, "min": 536}, "welcome"... |
| 22 | F2 the independent oracle accepts the exported APF trace | pass | 0.413 | {"events": 43, "kinds": {"admit": 2, "allocate": 4, "allow": 6, "confirm": 2, "consume": 6, "deny": 2, "emit": 4, "init": 1, "persist": 4, "recover": 5, "rek... |
| 23 | F3 the oracle rejects every broken control derived from the trace | pass | 0.378 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 24 | F4 the honest agents logged no processing error | pass | 0.002 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 6, fetched 6, dropped 0, duplicated 0, tapped 0
