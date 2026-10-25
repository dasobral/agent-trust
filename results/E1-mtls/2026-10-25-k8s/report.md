# E1-mtls: Revocation fence, repair and rekey across a faulty network

- Result: **PASS**
- Backend: `k8s`; topology `three-agents-mtls`; entropy `qrng`
- Duration: 18.989 s; steps run: 57; steps not run: 0

Hypothesis: With the APF, the agents and the relay as separate network services, and the relay dropping, duplicating and reordering traffic: (H1) every authorized message reaches each current reader exactly once and only after an APF consumption; (H2) a read revocation stops new releases and in-flight deliveries until a repair commit removes the reader; (H3) a removed member that keeps its keys can neither decrypt nor consume later traffic; (H4) a re-granted write right needs fresh keys; (H5) the independent oracle accepts the exported trace and rejects every broken control.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group with the APF | pass | 0.098 | {"branch": "901cbbad6b1a739093336c9110214f6acc8e0a8fb18e9918116ae3acf955b90d", "epoch": 0} |
| 1 | A2 alice delegates read, write, admit to bob | pass | 0.04 | {"revision": 1} |
| 2 | A3 alice delegates read, write, admit to carol | pass | 0.103 | {"revision": 2} |
| 3 | A4 bob joins through a certified KeyPackage | pass | 0.397 | {"branch": "c657f699c3ee1bfc51a395885dbd7caad3881f710830aa06e3c22800523519ba", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 carol joins through a certified KeyPackage | pass | 0.366 | {"branch": "5a985378a5002194d76b7019e48ab40b057ef3f7916fe9bed660c5c2295f402d", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 APF roster and frontier after admission | pass | 0.015 | {"epoch": 2, "policy_revision": 2, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 6 | A7 every agent is on the APF frontier | pass | 0.058 | {"agents": ["alice", "bob", "carol"], "epoch": 2} |
| 7 | B1 relay drops 25%, duplicates 25%, reorders | pass | 0.013 | {"drop": 25, "duplicate": 25, "reorder": true, "seed": 11} |
| 8 | B2 alice sends m1 | pass | 0.071 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792924085095} |
| 9 | B3 bob sends m2 | pass | 0.082 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792924085177} |
| 10 | B4 carol sends m3 | pass | 0.107 | {"epoch": 2, "op": "carol-000001", "recipients": ["alice", "bob"], "sent_ms": 1792924085284} |
| 11 | B5 burst: 4 interleaved messages from each agent | pass | 5.016 | {"seconds": 5.016, "sends_per_second": 2.4, "sent": 12} |
| 12 | B5b relay drains (retransmissions and duplicates included) | pass | 0.655 | {"dropped": 12, "duplicated": 5, "fetched": 35, "held": [], "posted": 30, "queued": {}, "tapped": 0} |
| 13 | B6 alice received m2 and m3 exactly once | pass | 0.011 | {"agent": "alice", "delivered": ["bob-000001", "carol-000001"]} |
| 14 | B7 bob received m1 and m3 exactly once | pass | 0.01 | {"agent": "bob", "delivered": ["alice-000001", "carol-000001"]} |
| 15 | B8 carol received m1 and m2 exactly once | pass | 0.01 | {"agent": "carol", "delivered": ["alice-000001", "bob-000001"]} |
| 16 | B9 every burst message reached every reader exactly once | pass | 0.036 | {"excluded": [], "optional": 0, "pairs": 30} |
| 17 | B10 every rejected copy was a duplicate of a delivered message | pass | 0.07 | {"alice": {"undecryptable": 3}, "bob": {"undecryptable": 2}, "carol": {}} |
| 18 | B11 no duplicate delivery, no delivery without APF consumption | pass | 0.216 | {"consumed": 30, "deliveries": 30, "lost_after_consume": 0} |
| 19 | C1 relay holds carol's mailbox (message in flight) | pass | 0.012 | {"held": true, "mailbox": "carol"} |
| 20 | C2 alice sends m4 before the revocation | pass | 0.574 | {"epoch": 2, "op": "alice-000006", "recipients": ["bob", "carol"], "sent_ms": 1792924091891} |
| 21 | C3 bob's copy drains; carol's copy stays in flight | pass | 0.601 | {"dropped": 12, "duplicated": 5, "fetched": 36, "held": ["carol"], "posted": 32, "queued": {"carol": 1}, "tapped": 0} |
| 22 | C4 alice revokes carol's read right | pass | 0.186 | {"read_fenced": true, "revision": 84} |
| 23 | C5 the APF read fence is closed | pass | 0.018 | {"epoch": 2, "policy_revision": 3, "read_fenced": true, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 24 | C6 alice cannot release while fenced | pass | 0.375 | {"error": "read_fenced", "refused": "read_fenced"} |
| 25 | C7 bob cannot release while fenced | pass | 0.365 | {"error": "read_fenced", "refused": "read_fenced"} |
| 26 | C8 relay releases carol's mailbox | pass | 0.013 | {"held": false, "mailbox": "carol"} |
| 27 | C9 carol processes the in-flight m4 | pass | 0.649 | {"dropped": 12, "duplicated": 5, "fetched": 37, "held": [], "posted": 32, "queued": {}, "tapped": 0} |
| 28 | C10 carol decrypts m4 but the APF refuses its consumption | pass | 0.011 | {"agent": "carol", "duplicates": [], "first": "read_fenced", "op": "alice-000006"} |
| 29 | C11 carol's application never sees m4 | pass | 0.024 | {"agent": "carol", "not_delivered": ["alice-000006"]} |
| 30 | C12 bob received m4 | pass | 0.018 | {"agent": "bob", "delivered": ["alice-000006"]} |
| 31 | D1 carol turns adversary: keeps its epoch keys, ignores its removal | pass | 0.018 | {"retain": true} |
| 32 | D2 alice commits the repair; bob confirms; the fence reopens | pass | 0.968 | {"branch": "484683d7af6118f4db394483b9f1d2e2ee14192ad74a887f5ca3b0cc9752d36b", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 33 | D3 carol is out of the roster and the fence is open | pass | 0.011 | {"epoch": 3, "policy_revision": 3, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob"]} |
| 34 | D4 the relay leaks every copy for bob to carol | pass | 0.01 | {"enabled": true, "observer": "carol", "victim": "bob"} |
| 35 | D5 alice sends m6 after the repair | pass | 0.66 | {"epoch": 3, "op": "alice-000008", "recipients": ["bob"], "sent_ms": 1792924095822} |
| 36 | D6 relay drains | pass | 0.841 | {"dropped": 12, "duplicated": 5, "fetched": 39, "held": [], "posted": 33, "queued": {}, "tapped": 1} |
| 37 | D7 bob received m6 | pass | 0.016 | {"agent": "bob", "delivered": ["alice-000008"]} |
| 38 | D8 carol's retained keys cannot decrypt m6 and the APF refuses it | pass | 0.013 | {"agent": "carol", "attempts": [{"consume": "unauthorized", "decrypted": false, "from": "alice", "mls": "refused: ValidationError(WrongEpoch)", "op": "alice-... |
| 39 | E1 alice revokes bob's write right | pass | 0.224 | {"read_fenced": false, "revision": 93} |
| 40 | E2 bob cannot release without write | pass | 0.437 | {"error": "unauthorized", "refused": "unauthorized"} |
| 41 | E3 alice re-grants write at generation 1: a rekey offer only | pass | 0.361 | {"pending": true} |
| 42 | E4 the offer alone does not restore write | pass | 0.551 | {"error": "unauthorized", "refused": "unauthorized"} |
| 43 | E5 bob commits a new signature key and incarnation | pass | 0.56 | {"branch": "26eaa6de2f35baf0ddb8fca00fc04bbb051a948789a8895805d993f7e29552bc", "epoch": 4, "generation": 1, "public_key": "e0233971568a9bd6bbd23bf1eb1691a904... |
| 44 | E6 bob sends m8 with its new key | pass | 0.807 | {"epoch": 4, "op": "bob-000009", "recipients": ["alice"], "sent_ms": 1792924099632} |
| 45 | E7 relay drains | pass | 0.709 | {"dropped": 12, "duplicated": 5, "fetched": 40, "held": [], "posted": 34, "queued": {}, "tapped": 1} |
| 46 | E8 alice received m8 | pass | 0.012 | {"agent": "alice", "delivered": ["bob-000009"]} |
| 47 | F1 alice and bob are on the APF frontier | pass | 0.037 | {"agents": ["alice", "bob"], "epoch": 4} |
| 48 | F2 every message reached every certified reader exactly once, except the fenced m4 | pass | 0.039 | {"excluded": ["carol:alice-000006"], "optional": 0, "pairs": 33} |
| 49 | F2b the honest agents rejected only duplicates | pass | 0.063 | {"alice": {"undecryptable": 3}, "bob": {"undecryptable": 2}} |
| 50 | F2c no delivery without APF consumption, over the whole run | pass | 0.305 | {"consumed": 33, "deliveries": 33, "lost_after_consume": 0} |
| 51 | F3 the independent oracle accepts the exported APF trace | pass | 0.588 | {"events": 130, "kinds": {"admit": 2, "allocate": 22, "allow": 6, "confirm": 2, "consume": 33, "deny": 2, "emit": 18, "init": 1, "persist": 18, "recover": 5,... |
| 52 | F4 the oracle rejects every broken control derived from the trace | pass | 0.478 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 53 | F5 every node drew its randomness from the QRNG service, with no failure | pass | 0.063 | {"nodes": {"alice": {"bytes": 556, "failures": 0, "requests": 19, "source": "qrng"}, "apf": {"bytes": 96, "failures": 0, "requests": 3, "source": "qrng"}, "b... |
| 54 | F6 the honest agents logged no processing error | pass | 0.025 | {"agents": ["alice", "bob"]} |
| 55 | F7 transport controls: no certificate, wrong peer, foreign CA, classical key exchange and a classical certificate for a service name are all refused | pass | 0.885 | {"a certificate from a foreign CA": "refused: Network Error", "a classical certificate that claims alice": "HTTP 403", "alice publishes bob's KeyPackage": "H... |
| 56 | F8 every service link, the QRNG link included, is ML-DSA-44 over X25519MLKEM768 | pass | 0.086 | {"connections": {"alice": {"alice": ["pq/X25519MLKEM768"], "attctl": ["classical/X25519"]}, "apf": {"alice": ["pq/X25519MLKEM768"], "apf": ["pq/X25519MLKEM76... |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 34, fetched 40, dropped 12, duplicated 5, tapped 1
