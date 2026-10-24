# E1: Revocation fence, repair and rekey across a faulty network

- Result: **PASS**
- Backend: `compose`; topology `three-agents`; entropy `qrng`
- Duration: 7.071 s; steps run: 55; steps not run: 0

Hypothesis: With the APF, the agents and the relay as separate network services, and the relay dropping, duplicating and reordering traffic: (H1) every authorized message reaches each current reader exactly once and only after an APF consumption; (H2) a read revocation stops new releases and in-flight deliveries until a repair commit removes the reader; (H3) a removed member that keeps its keys can neither decrypt nor consume later traffic; (H4) a re-granted write right needs fresh keys; (H5) the independent oracle accepts the exported trace and rejects every broken control.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group with the APF | pass | 0.049 | {"branch": "84082c420eb58c29975cb3fbbaffdc072d1b15200993765e48d03016c311e8ca", "epoch": 0} |
| 1 | A2 alice delegates read, write, admit to bob | pass | 0.007 | {"revision": 1} |
| 2 | A3 alice delegates read, write, admit to carol | pass | 0.006 | {"revision": 2} |
| 3 | A4 bob joins through a certified KeyPackage | pass | 0.076 | {"branch": "b2ffab0de5af119530655e44ad51aad2acec0b91877852c11133910190a84f16", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 carol joins through a certified KeyPackage | pass | 0.158 | {"branch": "97002296eafa38eeeb655c7e331fe6dfb6845d8e88e88d11103b3fbb0ded651c", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 APF roster and frontier after admission | pass | 0.001 | {"epoch": 2, "policy_revision": 2, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 6 | A7 every agent is on the APF frontier | pass | 0.005 | {"agents": ["alice", "bob", "carol"], "epoch": 2} |
| 7 | B1 relay drops 25%, duplicates 25%, reorders | pass | 0.001 | {"drop": 25, "duplicate": 25, "reorder": true, "seed": 11} |
| 8 | B2 alice sends m1 | pass | 0.033 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792863632886} |
| 9 | B3 bob sends m2 | pass | 0.033 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792863632919} |
| 10 | B4 carol sends m3 | pass | 0.064 | {"epoch": 2, "op": "carol-000001", "recipients": ["alice", "bob"], "sent_ms": 1792863632983} |
| 11 | B5 burst: 4 interleaved messages from each agent | pass | 1.516 | {"seconds": 1.516, "sends_per_second": 7.9, "sent": 12} |
| 12 | B5b relay drains (retransmissions and duplicates included) | pass | 0.435 | {"dropped": 11, "duplicated": 5, "fetched": 35, "held": [], "posted": 30, "queued": {}, "tapped": 0} |
| 13 | B6 alice received m2 and m3 exactly once | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000001", "carol-000001"]} |
| 14 | B7 bob received m1 and m3 exactly once | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000001", "carol-000001"]} |
| 15 | B8 carol received m1 and m2 exactly once | pass | 0.001 | {"agent": "carol", "delivered": ["alice-000001", "bob-000001"]} |
| 16 | B9 every burst message reached every reader exactly once | pass | 0.003 | {"excluded": [], "optional": 0, "pairs": 30} |
| 17 | B10 every rejected copy was a duplicate of a delivered message | pass | 0.005 | {"alice": {"undecryptable": 2}, "bob": {"undecryptable": 2}, "carol": {"undecryptable": 1}} |
| 18 | B11 no duplicate delivery, no delivery without APF consumption | pass | 0.044 | {"consumed": 30, "deliveries": 30, "lost_after_consume": 0} |
| 19 | C1 relay holds carol's mailbox (message in flight) | pass | 0.001 | {"held": true, "mailbox": "carol"} |
| 20 | C2 alice sends m4 before the revocation | pass | 0.167 | {"epoch": 2, "op": "alice-000006", "recipients": ["bob", "carol"], "sent_ms": 1792863635158} |
| 21 | C3 bob's copy drains; carol's copy stays in flight | pass | 0.334 | {"dropped": 11, "duplicated": 5, "fetched": 36, "held": ["carol"], "posted": 32, "queued": {"carol": 1}, "tapped": 0} |
| 22 | C4 alice revokes carol's read right | pass | 0.059 | {"read_fenced": true, "revision": 84} |
| 23 | C5 the APF read fence is closed | pass | 0.003 | {"epoch": 2, "policy_revision": 3, "read_fenced": true, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 24 | C6 alice cannot release while fenced | pass | 0.097 | {"error": "read_fenced", "refused": "read_fenced"} |
| 25 | C7 bob cannot release while fenced | pass | 0.105 | {"error": "read_fenced", "refused": "read_fenced"} |
| 26 | C8 relay releases carol's mailbox | pass | 0.001 | {"held": false, "mailbox": "carol"} |
| 27 | C9 carol processes the in-flight m4 | pass | 0.536 | {"dropped": 11, "duplicated": 6, "fetched": 38, "held": [], "posted": 32, "queued": {}, "tapped": 0} |
| 28 | C10 carol decrypts m4 but the APF refuses its consumption | pass | 0.001 | {"agent": "carol", "duplicates": ["undecryptable"], "first": "read_fenced", "op": "alice-000006"} |
| 29 | C11 carol's application never sees m4 | pass | 0.001 | {"agent": "carol", "not_delivered": ["alice-000006"]} |
| 30 | C12 bob received m4 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000006"]} |
| 31 | D1 carol turns adversary: keeps its epoch keys, ignores its removal | pass | 0.003 | {"retain": true} |
| 32 | D2 alice commits the repair; bob confirms; the fence reopens | pass | 0.297 | {"branch": "f32bf129fc984e7263af85fef19edfdc374a0ceb1eafce0a549ebb87a706d417", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 33 | D3 carol is out of the roster and the fence is open | pass | 0.002 | {"epoch": 3, "policy_revision": 3, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob"]} |
| 34 | D4 the relay leaks every copy for bob to carol | pass | 0.001 | {"enabled": true, "observer": "carol", "victim": "bob"} |
| 35 | D5 alice sends m6 after the repair | pass | 0.188 | {"epoch": 3, "op": "alice-000008", "recipients": ["bob"], "sent_ms": 1792863636790} |
| 36 | D6 relay drains | pass | 0.435 | {"dropped": 11, "duplicated": 7, "fetched": 41, "held": [], "posted": 33, "queued": {}, "tapped": 1} |
| 37 | D7 bob received m6 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000008"]} |
| 38 | D8 carol's retained keys cannot decrypt m6 and the APF refuses it | pass | 0.001 | {"agent": "carol", "attempts": [{"consume": "unauthorized", "decrypted": false, "from": "alice", "mls": "refused: ValidationError(WrongEpoch)", "op": "alice-... |
| 39 | E1 alice revokes bob's write right | pass | 0.056 | {"read_fenced": false, "revision": 93} |
| 40 | E2 bob cannot release without write | pass | 0.147 | {"error": "unauthorized", "refused": "unauthorized"} |
| 41 | E3 alice re-grants write at generation 1: a rekey offer only | pass | 0.086 | {"pending": true} |
| 42 | E4 the offer alone does not restore write | pass | 0.126 | {"error": "unauthorized", "refused": "unauthorized"} |
| 43 | E5 bob commits a new signature key and incarnation | pass | 0.179 | {"branch": "51b35d40e9a72938fafac44e7e2384f644964c7507757a28ffc7646088b79a94", "epoch": 4, "generation": 1, "public_key": "626dfe75cfce184f16cb3ebda7d422ffdd... |
| 44 | E6 bob sends m8 with its new key | pass | 0.234 | {"epoch": 4, "op": "bob-000009", "recipients": ["alice"], "sent_ms": 1792863638055} |
| 45 | E7 relay drains | pass | 0.644 | {"dropped": 13, "duplicated": 7, "fetched": 42, "held": [], "posted": 34, "queued": {}, "tapped": 1} |
| 46 | E8 alice received m8 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000009"]} |
| 47 | F1 alice and bob are on the APF frontier | pass | 0.004 | {"agents": ["alice", "bob"], "epoch": 4} |
| 48 | F2 every message reached every certified reader exactly once, except the fenced m4 | pass | 0.003 | {"excluded": ["carol:alice-000006"], "optional": 0, "pairs": 33} |
| 49 | F2b the honest agents rejected only duplicates | pass | 0.004 | {"alice": {"undecryptable": 2}, "bob": {"undecryptable": 3}} |
| 50 | F2c no delivery without APF consumption, over the whole run | pass | 0.072 | {"consumed": 33, "deliveries": 33, "lost_after_consume": 0} |
| 51 | F3 the independent oracle accepts the exported APF trace | pass | 0.374 | {"events": 130, "kinds": {"admit": 2, "allocate": 22, "allow": 6, "confirm": 2, "consume": 33, "deny": 2, "emit": 18, "init": 1, "persist": 18, "recover": 5,... |
| 52 | F4 the oracle rejects every broken control derived from the trace | pass | 0.454 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 53 | F5 every node drew its randomness from the QRNG service, with no failure | pass | 0.006 | {"nodes": {"alice": {"bytes": 412, "failures": 0, "requests": 19, "source": "qrng"}, "apf": {"bytes": 96, "failures": 0, "requests": 3, "source": "qrng"}, "b... |
| 54 | F6 the honest agents logged no processing error | pass | 0.002 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 34, fetched 42, dropped 13, duplicated 7, tapped 1
