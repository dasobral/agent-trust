# E1: Revocation fence, repair and rekey across a faulty network

- Result: **PASS**
- Backend: `compose`; topology `three-agents`; entropy `qrng`
- Duration: 8.876 s; steps run: 55; steps not run: 0

Hypothesis: With the APF, the agents and the relay as separate network services, and the relay dropping, duplicating and reordering traffic: (H1) every authorized message reaches each current reader exactly once and only after an APF consumption; (H2) a read revocation stops new releases and in-flight deliveries until a repair commit removes the reader; (H3) a removed member that keeps its keys can neither decrypt nor consume later traffic; (H4) a re-granted write right needs fresh keys; (H5) the independent oracle accepts the exported trace and rejects every broken control.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group with the APF | pass | 0.037 | {"branch": "03e47eed9744b4c21d7ef6a0e5dcec629d133008b1ec8cac05965514ba57c655", "epoch": 0} |
| 1 | A2 alice delegates read, write, admit to bob | pass | 0.007 | {"revision": 1} |
| 2 | A3 alice delegates read, write, admit to carol | pass | 0.007 | {"revision": 2} |
| 3 | A4 bob joins through a certified KeyPackage | pass | 0.175 | {"branch": "a0e5600a84bdb5d769060686b8d88923ca6e9dc00d3842367c76da56bf1b013e", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 carol joins through a certified KeyPackage | pass | 0.182 | {"branch": "4aba58fca83701b4760dea785872f692046d959ec6c39e9b4f9ae5a15cf49046", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 APF roster and frontier after admission | pass | 0.002 | {"epoch": 2, "policy_revision": 2, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 6 | A7 every agent is on the APF frontier | pass | 0.004 | {"agents": ["alice", "bob", "carol"], "epoch": 2} |
| 7 | B1 relay drops 25%, duplicates 25%, reorders | pass | 0.001 | {"drop": 25, "duplicate": 25, "reorder": true, "seed": 11} |
| 8 | B2 alice sends m1 | pass | 0.111 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"]} |
| 9 | B3 bob sends m2 | pass | 0.11 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"]} |
| 10 | B4 carol sends m3 | pass | 0.112 | {"epoch": 2, "op": "carol-000001", "recipients": ["alice", "bob"]} |
| 11 | B5 burst: 4 interleaved messages from each agent | pass | 2.547 | {"sent": 12} |
| 12 | B5b relay drains (retransmissions and duplicates included) | pass | 0.405 | {"dropped": 10, "duplicated": 7, "fetched": 37, "held": [], "posted": 30, "queued": {}, "tapped": 0} |
| 13 | B6 alice received m2 and m3 exactly once | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000001", "carol-000001"]} |
| 14 | B7 bob received m1 and m3 exactly once | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000001", "carol-000001"]} |
| 15 | B8 carol received m1 and m2 exactly once | pass | 0.001 | {"agent": "carol", "delivered": ["alice-000001", "bob-000001"]} |
| 16 | B9 every burst message reached every reader exactly once | pass | 0.007 | {"excluded": [], "pairs": 30} |
| 17 | B10 every rejected copy was a duplicate of a delivered message | pass | 0.007 | {"alice": {"undecryptable": 5}, "bob": {"undecryptable": 1}, "carol": {"undecryptable": 1}} |
| 18 | B11 no duplicate delivery, no delivery without APF consumption | pass | 0.055 | {"consumed": 30, "deliveries": 30} |
| 19 | C1 relay holds carol's mailbox (message in flight) | pass | 0.001 | {"held": true, "mailbox": "carol"} |
| 20 | C2 alice sends m4 before the revocation | pass | 0.316 | {"epoch": 2, "op": "alice-000006", "recipients": ["bob", "carol"]} |
| 21 | C3 bob's copy drains; carol's copy stays in flight | pass | 0.402 | {"dropped": 10, "duplicated": 7, "fetched": 38, "held": ["carol"], "posted": 32, "queued": {"carol": 1}, "tapped": 0} |
| 22 | C4 alice revokes carol's read right | pass | 0.045 | {"read_fenced": true, "revision": 84} |
| 23 | C5 the APF read fence is closed | pass | 0.032 | {"epoch": 2, "policy_revision": 3, "read_fenced": true, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 24 | C6 alice cannot release while fenced | pass | 0.157 | {"error": "read_fenced", "refused": "read_fenced"} |
| 25 | C7 bob cannot release while fenced | pass | 0.141 | {"error": "read_fenced", "refused": "read_fenced"} |
| 26 | C8 relay releases carol's mailbox | pass | 0.001 | {"held": false, "mailbox": "carol"} |
| 27 | C9 carol processes the in-flight m4 | pass | 0.349 | {"dropped": 10, "duplicated": 7, "fetched": 39, "held": [], "posted": 32, "queued": {}, "tapped": 0} |
| 28 | C10 carol decrypts m4 but the APF refuses its consumption | pass | 0.001 | {"agent": "carol", "duplicates": [], "first": "read_fenced", "op": "alice-000006"} |
| 29 | C11 carol's application never sees m4 | pass | 0.001 | {"agent": "carol", "not_delivered": ["alice-000006"]} |
| 30 | C12 bob received m4 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000006"]} |
| 31 | D1 carol turns adversary: keeps its epoch keys, ignores its removal | pass | 0.001 | {"retain": true} |
| 32 | D2 alice commits the repair; bob confirms; the fence reopens | pass | 0.305 | {"branch": "80ba117379c40cd246ecb996784386a07a732d80d6d43d0b869f1e68c7a42ad0", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 33 | D3 carol is out of the roster and the fence is open | pass | 0.042 | {"epoch": 3, "policy_revision": 3, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob"]} |
| 34 | D4 the relay leaks every copy for bob to carol | pass | 0.002 | {"enabled": true, "observer": "carol", "victim": "bob"} |
| 35 | D5 alice sends m6 after the repair | pass | 0.322 | {"epoch": 3, "op": "alice-000008", "recipients": ["bob"]} |
| 36 | D6 relay drains | pass | 0.494 | {"dropped": 12, "duplicated": 7, "fetched": 41, "held": [], "posted": 33, "queued": {}, "tapped": 1} |
| 37 | D7 bob received m6 | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000008"]} |
| 38 | D8 carol's retained keys cannot decrypt m6 and the APF refuses it | pass | 0.001 | {"agent": "carol", "attempts": [{"consume": "unauthorized", "decrypted": false, "from": "alice", "mls": "refused: ValidationError(WrongEpoch)", "op": "alice-... |
| 39 | E1 alice revokes bob's write right | pass | 0.052 | {"read_fenced": false, "revision": 93} |
| 40 | E2 bob cannot release without write | pass | 0.151 | {"error": "unauthorized", "refused": "unauthorized"} |
| 41 | E3 alice re-grants write at generation 1: a rekey offer only | pass | 0.065 | {"pending": true} |
| 42 | E4 the offer alone does not restore write | pass | 0.155 | {"error": "unauthorized", "refused": "unauthorized"} |
| 43 | E5 bob commits a new signature key and incarnation | pass | 0.143 | {"branch": "99e2a170085af4328753224b0711f54556bcffaa456131736bb2417ef26d86af", "epoch": 4, "generation": 1, "public_key": "4dfe4448a22be0d77886f30b8b7658c9f3... |
| 44 | E6 bob sends m8 with its new key | pass | 0.317 | {"epoch": 4, "op": "bob-000009", "recipients": ["alice"]} |
| 45 | E7 relay drains | pass | 0.672 | {"dropped": 13, "duplicated": 8, "fetched": 43, "held": [], "posted": 34, "queued": {}, "tapped": 1} |
| 46 | E8 alice received m8 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000009"]} |
| 47 | F1 alice and bob are on the APF frontier | pass | 0.063 | {"agents": ["alice", "bob"], "epoch": 4} |
| 48 | F2 every message reached every certified reader exactly once, except the fenced m4 | pass | 0.004 | {"excluded": ["carol:alice-000006"], "pairs": 33} |
| 49 | F2b the honest agents rejected only duplicates | pass | 0.004 | {"alice": {"undecryptable": 6}, "bob": {"undecryptable": 1}} |
| 50 | F2c no delivery without APF consumption, over the whole run | pass | 0.073 | {"consumed": 33, "deliveries": 33} |
| 51 | F3 the independent oracle accepts the exported APF trace | pass | 0.373 | {"events": 130, "kinds": {"admit": 2, "allocate": 22, "allow": 6, "confirm": 2, "consume": 33, "deny": 2, "emit": 18, "init": 1, "persist": 18, "recover": 5,... |
| 52 | F4 the oracle rejects every broken control derived from the trace | pass | 0.4 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "rekey that reuses another... |
| 53 | F5 every node drew its randomness from the QRNG service, with no failure | pass | 0.007 | {"nodes": {"alice": {"bytes": 412, "failures": 0, "requests": 19, "source": "qrng"}, "apf": {"bytes": 96, "failures": 0, "requests": 3, "source": "qrng"}, "b... |
| 54 | F6 the honest agents logged no processing error | pass | 0.003 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 4; policy revision 5; read fenced False
- Relay: posted 34, fetched 43, dropped 13, duplicated 8, tapped 1
