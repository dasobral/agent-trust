# E4: Hostile commit distribution

Spec: [`experiments/e4-hostile-commits.toml`](../../experiments/e4-hostile-commits.toml) ·
Evidence: [`results/E4/`](../../results/E4/)

## Question

E1 kept the handshake log reliable and in order. Commit distribution goes through the
untrusted relay. What can a hostile relay do to it?

## Hypotheses

| | Hypothesis | Basis |
|---|---|---|
| H1 | A member merges a commit only under a valid APF ack whose parent is its own frontier; replayed, garbage and spliced entries change nothing | §4.6 parent compare-and-swap |
| H2 | A member from which a commit is hidden stays at its old epoch: it cannot release, and newer envelopes wait instead of being decrypted or lost; once the commit appears it catches up and delivers them | |
| H3 | Entries served out of order are applied in parent order | |
| H4 | The trace stays acceptable to the oracle | |

## Method

Relay control `POST /control/handshake`:

- `replay` of bob's admission (index 2), `inject` of a garbage ack (index 3), `splice`
  of carol's commit with bob's ack (index 4).
- `hide` index 5 (carol's rekey) from bob, then `splice` the old admission commit
  with the new rekey ack (index 6): an entry whose ack *does* name bob's frontier as
  parent, but whose commit bytes do not match the ack.
- `hide` from index 7 for carol, two rekeys by bob (indices 7 and 8), then `reverse`
  and `show`: carol receives both commits at once, in reverse order.

## Results

All 48 steps pass (5 of 5 local runs; compose and k3s in `results/E4/`):

- Bob skips the three forged entries and the splice (`skipped_entries` 4) and logs
  errors only for the garbage ack and the splice; alice and carol log only the
  garbage ack.
- While hidden, bob's send is refused `not_ready`; alice's m2 for bob waits in bob's
  future-epoch buffer; after `show`, bob applies index 5 and delivers m2 once.
- Carol applies indices 7 and 8 in parent order and returns to the APF frontier.

## Design changes found by E4

- The first sidecar advanced its log cursor past an invalid entry, so an entry hidden
  *before* it could never be fetched again. The cursor now advances only over a
  contiguous run of resolved indices, and an entry is applied only when its ack's
  parent equals the member's frontier (older: skipped; newer: wait).
