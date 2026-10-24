# E3: APF and agent restarts, outages and offline members

- Result: **PASS**
- Backend: `compose`; topology `three-agents`; entropy `qrng`
- Duration: 11.393 s; steps run: 54; steps not run: 0

Hypothesis: (H1) An APF restart keeps the policy state, the frontier and every registered key; members continue without any change. (H2) While the APF is down no release happens and no message is delivered; a message decrypted during the outage is delivered once the APF returns (delay, not loss). (H3) A restarted agent resumes as the same member with the same key, frontier and request sequence, and receives the traffic sent while it was down. (H4) An offline member does not block a revocation and repair; when it returns it applies its own removal and receives nothing sent after it. (H5) The oracle accepts the trace and rejects the broken controls.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 alice founds the group | pass | 0.067 | {"branch": "7b0d9892209a2727b44f3c5fba5b38ee59c9e87dae78745328b4b02c3fa01f30", "epoch": 0} |
| 1 | A2 delegate bob | pass | 0.01 | {"revision": 1} |
| 2 | A3 delegate carol | pass | 0.007 | {"revision": 2} |
| 3 | A4 admit bob | pass | 0.161 | {"branch": "05d80cf0727f4f99e53cfe0c268ee7bbc32ac94c9e645140ac1c1c5065acf374", "epoch": 1, "index": 0, "subject": "bob"} |
| 4 | A5 admit carol | pass | 0.167 | {"branch": "cf6062851663361a58bfe337692a93fd8fae75b24ac61c1047c876421f30e821", "epoch": 2, "index": 1, "subject": "carol"} |
| 5 | A6 alice sends m1 | pass | 0.032 | {"epoch": 2, "op": "alice-000001", "recipients": ["bob", "carol"], "sent_ms": 1792863762603} |
| 6 | A7 drain | pass | 0.283 | {"dropped": 0, "duplicated": 0, "fetched": 2, "held": [], "posted": 2, "queued": {}, "tapped": 0} |
| 7 | B1 the APF crashes (SIGKILL) and restarts from its state directory | pass | 0.859 | {"service": "apf", "started": true, "stopped": "apf"} |
| 8 | B2 roster, epoch and fence survive the restart | pass | 0.002 | {"epoch": 2, "policy_revision": 2, "read_fenced": false, "repair_pending": null, "roster": ["alice", "bob", "carol"]} |
| 9 | B3 bob sends m2 through the restarted APF (keys and sequences survived) | pass | 0.046 | {"epoch": 2, "op": "bob-000001", "recipients": ["alice", "carol"], "sent_ms": 1792863763792} |
| 10 | B4 drain | pass | 0.436 | {"dropped": 0, "duplicated": 0, "fetched": 4, "held": [], "posted": 4, "queued": {}, "tapped": 0} |
| 11 | B5 alice received m2 | pass | 0.001 | {"agent": "alice", "delivered": ["bob-000001"]} |
| 12 | C1 hold carol's mailbox | pass | 0.001 | {"held": true, "mailbox": "carol"} |
| 13 | C2 alice sends m3 | pass | 0.043 | {"epoch": 2, "op": "alice-000002", "recipients": ["bob", "carol"], "sent_ms": 1792863764273} |
| 14 | C3 bob's copy drains | pass | 0.278 | {"dropped": 0, "duplicated": 0, "fetched": 5, "held": ["carol"], "posted": 6, "queued": {"carol": 1}, "tapped": 0} |
| 15 | C4 the APF goes down | pass | 0.396 | {"stopped": "apf"} |
| 16 | C5 no release without the APF | pass | 0.007 | {"error": "transport: Dns Failed", "refused": "transport"} |
| 17 | C6 carol's copy of m3 is delivered by the relay | pass | 0.001 | {"held": false, "mailbox": "carol"} |
| 18 | C7 carol decrypts m3; its consumption waits for the APF | pass | 0.341 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 19 | C8 carol's application has not seen m3 | pass | 0.001 | {"agent": "carol", "not_delivered": ["alice-000002"]} |
| 20 | C9 the APF comes back | pass | 0.569 | {"service": "apf", "started": true} |
| 21 | C10 the waiting consumption completes | pass | 0.229 | {"dropped": 0, "duplicated": 0, "fetched": 6, "held": [], "posted": 6, "queued": {}, "tapped": 0} |
| 22 | C11 carol received m3 once, after the outage | pass | 0.001 | {"agent": "carol", "delivered": ["alice-000002"]} |
| 23 | D1 bob crashes and restarts from its data directory | pass | 0.757 | {"service": "bob", "started": true, "stopped": "bob"} |
| 24 | D2 bob is the same member on the APF frontier | pass | 0.004 | {"epoch": 2, "future": 0, "membership": "member", "restarts": 1, "skipped_entries": 0, "waiting": []} |
| 25 | D3 alice sends m4 to the restarted bob | pass | 0.047 | {"epoch": 2, "op": "alice-000004", "recipients": ["bob", "carol"], "sent_ms": 1792863766905} |
| 26 | D4 the restarted bob sends m5 (its request sequence survived) | pass | 0.069 | {"epoch": 2, "op": "bob-000002", "recipients": ["alice", "carol"], "sent_ms": 1792863766974} |
| 27 | D4b drain | pass | 0.332 | {"dropped": 0, "duplicated": 0, "fetched": 10, "held": [], "posted": 10, "queued": {}, "tapped": 0} |
| 28 | D5 bob goes down | pass | 0.388 | {"stopped": "bob"} |
| 29 | D6 alice sends m6 while bob is down | pass | 0.056 | {"epoch": 2, "op": "alice-000005", "recipients": ["bob", "carol"], "sent_ms": 1792863767750} |
| 30 | D7 bob comes back | pass | 0.478 | {"service": "bob", "started": true} |
| 31 | D8 drain | pass | 0.173 | {"dropped": 0, "duplicated": 0, "fetched": 12, "held": [], "posted": 12, "queued": {}, "tapped": 0} |
| 32 | D9 bob received m4 and m6, including the message sent while it was down | pass | 0.001 | {"agent": "bob", "delivered": ["alice-000004", "alice-000005"]} |
| 33 | D10 alice and carol received m5 | pass | 0.001 | {"agent": "carol", "delivered": ["bob-000002"]} |
| 34 | D11 alice sends a burst of 10 to bob and carol | pass | 1.528 | {"seconds": 1.528, "sends_per_second": 6.5, "sent": 10} |
| 35 | D12 bob is killed in the middle of the burst and restarts | pass | 0.846 | {"service": "bob", "started": true, "stopped": "bob"} |
| 36 | D13 drain (the relay retransmits every unacknowledged message) | pass | 0.232 | {"dropped": 0, "duplicated": 0, "fetched": 32, "held": [], "posted": 32, "queued": {}, "tapped": 0} |
| 37 | D14 bob received each burst message at most once; losses are reported | pass | 0.001 | {"agent": "bob", "delivered": 10, "lost": 0, "sent": 10} |
| 38 | D15 carol received the whole burst | pass | 0.002 | {"agent": "carol", "delivered": ["alice-000006", "alice-000007", "alice-000008", "alice-000009", "alice-000010", "alice-000011", "alice-000012", "alice-00001... |
| 39 | E1 carol goes offline | pass | 0.403 | {"stopped": "carol"} |
| 40 | E2 alice revokes carol's read right | pass | 0.054 | {"read_fenced": true, "revision": 85} |
| 41 | E3 the repair completes without carol (bob confirms) | pass | 0.313 | {"branch": "fe8ad95f7d1367dc846b966706694058a315602ec14c76cbe54bbae4e3b218e5", "epoch": 3, "evidence": "pair", "index": 2, "opened": false, "read_fenced_afte... |
| 42 | E4 alice sends m7 after the repair | pass | 0.196 | {"epoch": 3, "op": "alice-000016", "recipients": ["bob"], "sent_ms": 1792863771978} |
| 43 | E5 carol comes back | pass | 0.48 | {"service": "carol", "started": true} |
| 44 | E6 drain | pass | 0.176 | {"dropped": 0, "duplicated": 0, "fetched": 33, "held": [], "posted": 33, "queued": {}, "tapped": 0} |
| 45 | E7 carol applied its own removal from the log | pass | 0.001 | {"epoch": null, "future": 0, "membership": "removed", "restarts": 1, "skipped_entries": 0, "waiting": []} |
| 46 | E8 carol never received m7 | pass | 0.001 | {"agent": "carol", "not_delivered": ["alice-000016"]} |
| 47 | F1 alice and bob are on the APF frontier | pass | 0.004 | {"agents": ["alice", "bob"], "epoch": 3} |
| 48 | F2 every message reached every certified reader exactly once (bob's crash burst aside) | pass | 0.004 | {"excluded": [], "optional": 10, "pairs": 23} |
| 49 | F3 no duplicate, no delivery without APF consumption | pass | 0.065 | {"consumed": 33, "deliveries": 33, "lost_after_consume": 0} |
| 50 | F4 the oracle accepts the trace exported after two APF restarts | pass | 0.359 | {"events": 119, "kinds": {"admit": 2, "allocate": 17, "allow": 6, "confirm": 2, "consume": 33, "deny": 1, "emit": 17, "init": 1, "persist": 17, "recover": 4,... |
| 51 | F5 the oracle rejects the broken controls | pass | 0.473 | {"rejected": {"fence opened by API only (no repair commit)": "invalid_repair", "fence opened without confirmation": "unconfirmed", "release after the read de... |
| 52 | F6 every node drew from the QRNG service without failure | pass | 0.007 | {"nodes": {"alice": {"bytes": 444, "failures": 0, "requests": 27, "source": "qrng"}, "apf": {"bytes": 64, "failures": 0, "requests": 2, "source": "qrng"}, "b... |
| 53 | F7 alice and bob logged no processing error | pass | 0.002 | {"agents": ["alice", "bob"]} |

## Final state

- APF roster: ['alice', 'bob']; epoch 3; policy revision 3; read fenced False
- Relay: posted 33, fetched 33, dropped 0, duplicated 0, tapped 0
