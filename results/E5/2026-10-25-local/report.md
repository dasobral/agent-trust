# E5: Eight agents in parallel: latency, APF cost growth and safety at scale

- Result: **FAIL**
- Backend: `local`; topology `scale-8`; entropy `qrng`
- Duration: 466.35 s; steps run: 15; steps not run: 7

Hypothesis: (H1) Admission, release and delivery keep working as the group grows to eight members; their cost is measured, not assumed. (H2) With all eight agents sending in parallel, with and without relay faults, every message reaches every reader exactly once and only after an APF consumption. (H3) A revocation and repair with seven continuing members completes and excludes the revoked member. (H4) The APF's time per request grows with its kernel history, because the kernel validates its whole hash chain of full snapshots on every request; E5 measures the growth. (H5) The oracle accepts the full trace.

| # | Step | Result | Seconds | Detail |
|---|------|--------|---------|--------|
| 0 | A1 agent01 founds the group | pass | 0.054 | {"branch": "90a233e1e919a0b60a3ff72dead530e9ed4481de7d79490e1fcb85d67b518b11", "epoch": 0} |
| 1 | A2 delegate and admit the seven other agents, one at a time | pass | 1.47 | {"admissions": [{"group_size": 2, "member": "agent02", "ms": 169.8}, {"group_size": 3, "member": "agent03", "ms": 187.1}, {"group_size": 4, "member": "agent0... |
| 2 | A3 eight members at epoch 7 | pass | 0.001 | {"epoch": 7, "policy_revision": 7, "read_fenced": false, "repair_pending": null, "roster": ["agent01", "agent02", "agent03", "agent04", "agent05", "agent06",... |
| 3 | A4 every agent is on the APF frontier | pass | 0.011 | {"agents": ["agent01", "agent02", "agent03", "agent04", "agent05", "agent06", "agent07", "agent08"], "epoch": 7} |
| 4 | B1 four rounds: all eight agents send one message each in parallel (32 messages, 224 deliveries) | pass | 209.32 | {"apf_p50_growth": 20.1, "rounds": [{"apf_p50_ms": 66.5, "apf_requests": 88, "history_from": 15, "history_to": 94, "round": 1, "seconds": 6.41}, {"apf_p50_ms... |
| 5 | B2 every message reached its seven readers exactly once | pass | 0.007 | {"excluded": [], "optional": 0, "pairs": 224} |
| 6 | B3 no delivery without APF consumption | pass | 1.717 | {"consumed": 224, "deliveries": 224, "lost_after_consume": 0} |
| 7 | B4 latency without faults | pass | 0.009 | {"admit_ms": {"max": 238.0, "n": 7, "p50": 198.8, "p95": 235.8}, "apf_ms_by_history": [{"history_up_to": 33, "p50": 8.75, "requests": 40}, {"history_up_to": ... |
| 8 | C1 relay drops 10%, duplicates 10%, reorders | pass | 0.001 | {"drop": 10, "duplicate": 10, "reorder": true, "seed": 3} |
| 9 | C2 one round under faults | pass | 173.174 | {"apf_p50_growth": 1.0, "rounds": [{"apf_p50_ms": 2014.3, "apf_requests": 88, "history_from": 335, "history_to": 414, "round": 1, "seconds": 173.17}]} |
| 10 | C3 every message reached every reader exactly once despite the faults | pass | 0.01 | {"excluded": [], "optional": 0, "pairs": 280} |
| 11 | C4 every refused copy was a duplicate | pass | 0.014 | {"agent01": {}, "agent02": {"undecryptable": 1}, "agent03": {"undecryptable": 1}, "agent04": {"undecryptable": 1}, "agent05": {}, "agent06": {"undecryptable"... |
| 12 | D1 agent01 revokes agent08's read right | pass | 2.382 | {"read_fenced": true, "revision": 415} |
| 13 | D2 repair with seven continuing members | pass | 18.118 | {"branch": "11a5780d695e1c9c39b7d2cd755a6a15dc96ebcd159a1d367c55219837e0bddc", "epoch": 8, "evidence": "pair", "index": 7, "opened": false, "read_fenced_afte... |
| 14 | D3 one round from the seven continuing members | fail | 60.061 | agent02: expected ok, got transport: agent02: timed out; agent01: expected ok, got transport: agent01: timed out; agent04: expected ok, got transport: agent04: timed out |

## Final state

- APF roster: ['agent01', 'agent02', 'agent03', 'agent04', 'agent05', 'agent06', 'agent07']; epoch 8; policy revision 8; read fenced False
- Relay: posted 322, fetched 316, dropped 11, duplicated 6, tapped 0
