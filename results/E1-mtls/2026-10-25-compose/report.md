# E1-mtls: Revocation fence, repair and rekey across a faulty network

- Result: **PASS**
- Backend: `compose`; topology `three-agents-mtls`; entropy `qrng`
- Duration: 17.212 s; steps run: 57; steps not run: 0

Hypothesis: With the APF, the agents and the relay as separate network services, and the relay dropping, duplicating and reordering traffic: (H1) every authorized message reaches each current reader exactly once and only after an APF consumption; (H2) a read revocation stops new releases and in-flight deliveries until a repair commit removes the reader; (H3) a removed member that keeps its keys can neither decrypt nor consume later traffic; (H4) a re-granted write right needs fresh keys; (H5) the independent oracle accepts the exported trace and rejects every broken control.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group with the APF | pass | 0.092 | {"branch": "1caac45a57e0a07aa4a5c7a72bac3bacfa4edfedb44d45719a57bb7e3afb5248", "epoch": 0} |
| 1 | A2 alice delegates read, write, admit to bob | pass | 0.017 | {"revision": 1} |
| 2 | A3 alice delegates read, write, admit to carol | pass | 0.017 | {"revision": 2} |
| 3 | A4 bob joins through a certified KeyPackage | pass | 0.245 | {"branch": "b4bfe988f390bc03b109ec2293456153e990f4051ed912abbf3277c3d93ae5db", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 carol joins through a certified KeyPackage | pass | 0.234 | {"branch": "de1d9193f4ce9761df03367fd3e4ee9464c9f81628728c53309ecb3a5b112d17", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 APF roster and frontier after admission | pass | 0.004 | {"epoch": 2, "policy_revision": 2, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 6 | A7 every agent is on the APF frontier | pass | 0.015 | {"agents": ["alice", "bob", "carol"], "epoch": 2} |
| 7 | B1 relay drops 25%, duplicates 25%, reorders | pass | 0.004 | {"drop": 25, "duplicate": 25, "reorder": true, "seed": 11} |
| 8 | B2 alice sends m1 | pass | 0.052 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792923521179} |
| 9 | B3 bob sends m2 | pass | 0.051 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792923521230} |
| 10 | B4 carol sends m3 | pass | 0.103 | {"epoch": 2, "op": "carol-000001", "recipients": ["alice", "bob"], "sent_ms": 1792923521333} |
| 11 | B5 burst: 4 interleaved messages from each agent | pass | 5.089 | {"seconds": 5.089, "sends_per_second": 2.4, "sent": 12} |
| 12 | B5b relay drains (retransmissions and duplicates included) | pass | 0.704 | {"dropped": 11, "duplicated": 6, "fetched": 36, "held": [], "posted": 30, "queued": {}, "tapped": 0} |
| 13 | B6 alice received m2 and m3 exactly once | pass | 0.009 | {"agent": "alice", "delivered": ["bob-000001", "carol-000001"]} |
| 14 | B7 bob received m1 and m3 exactly once | pass | 0.007 | {"agent": "bob", "delivered": ["alice-000001", "carol-000001"]} |
| 15 | B8 carol received m1 and m2 exactly once | pass | 0.006 | {"agent": "carol", "delivered": ["alice-000001", "bob-000001"]} |
| 16 | B9 every burst message reached every reader exactly once | pass | 0.017 | {"excluded": [], "optional": 0, "pairs": 30} |
| 17 | B10 every rejected copy was a duplicate of a delivered message | pass | 0.028 | {"alice": {"undecryptable": 2}, "bob": {"undecryptable": 3}, "carol": {"undecryptable": 1}} |
| 18 | B11 no duplicate delivery, no delivery without APF consumption | pass | 0.173 | {"consumed": 30, "deliveries": 30, "lost_after_consume": 0} |
| 19 | C1 relay holds carol's mailbox (message in flight) | pass | 0.004 | {"held": true, "mailbox": "carol"} |
| 20 | C2 alice sends m4 before the revocation | pass | 0.599 | {"epoch": 2, "op": "alice-000006", "recipients": ["bob", "carol"], "sent_ms": 1792923527968} |
| 21 | C3 bob's copy drains; carol's copy stays in flight | pass | 0.449 | {"dropped": 11, "duplicated": 6, "fetched": 37, "held": ["carol"], "posted": 32, "queued": {"carol": 1}, "tapped": 0} |
| 22 | C4 alice revokes carol's read right | pass | 0.174 | {"read_fenced": true, "revision": 84} |
| 23 | C5 the APF read fence is closed | pass | 0.006 | {"epoch": 2, "policy_revision": 3, "read_fenced": true, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 24 | C6 alice cannot release while fenced | pass | 0.356 | {"error": "read_fenced", "refused": "read_fenced"} |
| 25 | C7 bob cannot release while fenced | pass | 0.358 | {"error": "read_fenced", "refused": "read_fenced"} |
| 26 | C8 relay releases carol's mailbox | pass | 0.004 | {"held": false, "mailbox": "carol"} |
| 27 | C9 carol processes the in-flight m4 | pass | 0.557 | {"dropped": 11, "duplicated": 6, "fetched": 38, "held": [], "posted": 32, "queued": {}, "tapped": 0} |
| 28 | C10 carol decrypts m4 but the APF refuses its consumption | pass | 0.003 | {"agent": "carol", "duplicates": [], "first": "read_fenced", "op": "alice-000006"} |
| 29 | C11 carol's application never sees m4 | pass | 0.003 | {"agent": "carol", "not_delivered": ["alice-000006"]} |
| 30 | C12 bob received m4 | pass | 0.004 | {"agent": "bob", "delivered": ["alice-000006"]} |
| 31 | D1 carol turns adversary: keeps its epoch keys, ignores its removal | pass | 0.007 | {"retain": true} |
| 32 | D2 alice commits the repair; bob confirms; the fence reopens | pass | 0.974 | {"branch": "2cb72e63bfac4fb034eb65bc3c2fe5dcbe64ffb2164521e29d65b90c85f5c0bf", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 33 | D3 carol is out of the roster and the fence is open | pass | 0.005 | {"epoch": 3, "policy_revision": 3, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob"]} |
| 34 | D4 the relay leaks every copy for bob to carol | pass | 0.004 | {"enabled": true, "observer": "carol", "victim": "bob"} |
| 35 | D5 alice sends m6 after the repair | pass | 0.795 | {"epoch": 3, "op": "alice-000008", "recipients": ["bob"], "sent_ms": 1792923531670} |
| 36 | D6 relay drains | pass | 0.868 | {"dropped": 11, "duplicated": 7, "fetched": 41, "held": [], "posted": 33, "queued": {}, "tapped": 1} |
| 37 | D7 bob received m6 | pass | 0.004 | {"agent": "bob", "delivered": ["alice-000008"]} |
| 38 | D8 carol's retained keys cannot decrypt m6 and the APF refuses it | pass | 0.004 | {"agent": "carol", "attempts": [{"consume": "unauthorized", "decrypted": false, "from": "alice", "mls": "refused: ValidationError(WrongEpoch)", "op": "alice-... |
| 39 | E1 alice revokes bob's write right | pass | 0.209 | {"read_fenced": false, "revision": 93} |
| 40 | E2 bob cannot release without write | pass | 0.458 | {"error": "unauthorized", "refused": "unauthorized"} |
| 41 | E3 alice re-grants write at generation 1: a rekey offer only | pass | 0.271 | {"pending": true} |
| 42 | E4 the offer alone does not restore write | pass | 0.401 | {"error": "unauthorized", "refused": "unauthorized"} |
| 43 | E5 bob commits a new signature key and incarnation | pass | 0.57 | {"branch": "ddecd47074f2fa94cc14dbc689527de5347848423d33f81bd68727490e13838c", "epoch": 4, "generation": 1, "public_key": "6fee882fa9e736912002b48c6d6504fb9b... |
| 44 | E6 bob sends m8 with its new key | pass | 0.795 | {"epoch": 4, "op": "bob-000009", "recipients": ["alice"], "sent_ms": 1792923535249} |
| 45 | E7 relay drains | pass | 0.654 | {"dropped": 11, "duplicated": 8, "fetched": 43, "held": [], "posted": 34, "queued": {}, "tapped": 1} |
| 46 | E8 alice received m8 | pass | 0.003 | {"agent": "alice", "delivered": ["bob-000009"]} |
| 47 | F1 alice and bob are on the APF frontier | pass | 0.013 | {"agents": ["alice", "bob"], "epoch": 4} |
| 48 | F2 every message reached every certified reader exactly once, except the fenced m4 | pass | 0.012 | {"excluded": ["carol:alice-000006"], "optional": 0, "pairs": 33} |
| 49 | F2b the honest agents rejected only duplicates | pass | 0.013 | {"alice": {"undecryptable": 3}, "bob": {"undecryptable": 4}} |
| 50 | F2c no delivery without APF consumption, over the whole run | pass | 0.227 | {"consumed": 33, "deliveries": 33, "lost_after_consume": 0} |
| 51 | F3 the independent oracle accepts the exported APF trace | pass | 0.489 | {"events": 130, "kinds": {"admit": 2, "allocate": 22, "allow": 6, "confirm": 2, "consume": 33, "deny": 2, "emit": 18, "init": 1, "persist": 18, "recover": 5,... |
| 52 | F4 the oracle rejects every broken control derived from the trace | pass | 0.45 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 53 | F5 every node drew its randomness from the QRNG service, with no failure | pass | 0.025 | {"nodes": {"alice": {"bytes": 556, "failures": 0, "requests": 19, "source": "qrng"}, "apf": {"bytes": 96, "failures": 0, "requests": 3, "source": "qrng"}, "b... |
| 54 | F6 the honest agents logged no processing error | pass | 0.01 | {"agents": ["alice", "bob"]} |
| 55 | F7 transport controls: no certificate, wrong peer, foreign CA, classical key exchange and a classical certificate for a service name are all refused | pass | 0.539 | {"a certificate from a foreign CA": "refused: Network Error", "a classical certificate that claims alice": "HTTP 403", "alice publishes bob's KeyPackage": "H... |
| 56 | F8 every service link, the QRNG link included, is ML-DSA-44 over X25519MLKEM768 | pass | 0.023 | {"connections": {"alice": {"attctl": ["classical/X25519"]}, "apf": {"alice": ["pq/X25519MLKEM768"], "attctl": ["classical/X25519"], "bob": ["pq/X25519MLKEM76... |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 34, fetched 43, dropped 11, duplicated 8, tapped 1
