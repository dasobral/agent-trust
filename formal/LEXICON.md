# Lexicon

Approved by Daniel on 25 October 2026: "may–can concordance" replaces
"authorization–capability coherence", and the rename reaches the code.
Every document and identifier is edited against this table.

## The idea in one line

An authority decides who **may** act on a group. MLS decides who **can**.
A protocol is *concordant* when, for every action, whoever can exercise a
capability on it may do so at the action's *cut*: the ledger revision at
which the action was released.

The name follows the paper's own image. Two clocks (the ledger's revision
and the group's epoch) run independently, and the cut is the event that
makes them comparable. When the two descriptions agree at the cut they are
in concordance. When they disagree, the protocol is *discordant*, and the
interval where that can happen is the *discordance window*. "Coherence"
was dropped because it has a precise meaning in quantum physics, which
readers of a Quside paper would expect.

## Concepts and results

| Old | New | Notes |
|---|---|---|
| authorization–capability coherence (ACC) | may–can concordance; *concordance* for short | the headline property |
| coherent, incoherent | concordant, discordant | adjectives on a protocol |
| read coherence, write coherence | read concordance, write concordance | read-concordant, write-concordant |
| incoherence; "the window" | discordance; the discordance window | Fig. 1 |
| naive composition | oblivious composition | a release that ignores the roster |
| Proposition 1 (naive composition is incoherent) | Proposition 1, **no-go for oblivious composition** | |
| Lemma 1 (fence) | Lemma 1, **fence lemma** | unchanged |
| Lemma 2 (roster coherence) | Lemma 2, **roster inclusion** | $M_{e(a)} \subseteq \mathrm{Rd}_{v(a)}(g)$ |
| key confinement, K1–K5 | key confinement; **confinement conditions** K1–K5 | unchanged noun |
| Theorem 1 (read coherence) | Theorem 1, **factorization theorem** | read concordance = roster inclusion composed with key confinement |
| Theorem 2 (write coherence) | Theorem 2, **write concordance** | |
| Proposition 4 (progress) | Proposition 4, **progress** | unchanged |
| Proposition 5 (price of the cut) | Proposition 5, **no-go for offline release** | |
| commit-immediate cut | **release cut** | causal and lease cuts stay as future work |
| `Bridge_remove^ETK` | **computational key confinement** (Proposition 3) | the Third Edition's open bridge |
| LAP-MLS (Linearized Authorization-Permit MLS) | **the construction** (Rules F, C, R, A) | the paper does not re-acronym it |

Unchanged on purpose: cut, fence, roster record, ledger, justification,
locality, Rules F, C, R, A, key confinement. "Cut" already reads as
physics, and "confinement" is kept because the theorem chain reads as
nested confinements: keys inside the roster, the roster inside the readers
at the cut.

## Identifiers

Class A changes names only. Every encoded byte, every TLS label and the
extension code point `0xf043` stay. Class B changes a field that a program
reads from JSON. Each Class B row is listed in correction C-43
(`docs/adapter-contract.md` §10).

| Class | Old | New | Where |
|---|---|---|---|
| A | `AccContext` | `ApfAnchor` | `src/wire.rs`, `src/adapter.rs`, `src/client.rs`, tests |
| A | `ACC_CONTEXT_EXTENSION_TYPE` (`0xf043`) | `APF_ANCHOR_EXTENSION_TYPE` (`0xf043`) | same |
| A | `acc_context` (Rust locals, methods) | `apf_anchor` | same |
| B | `acc_context` (lab repair plan field) | `apf_anchor` | `src/lab.rs:717`, lab clients |
| B | `full_lap_mls` | `full_construction_mls` | `evidence/manifest.json`, `scripts/verify.py`, `src/main.rs`, `harness/` |
| B | `bridge_remove_etk: "open"` | `key_confinement_computational: "conditional"` | `evidence/manifest.json`, `scripts/verify.py`, `harness/test_verify.py` |
| file | `formal/paper/coherence.tex` | `formal/paper/concordance.tex` | |
| file | `formal/model/coherence_model.py` | `formal/model/concordance_model.py` | |

The extension is named for its role after R-11 (D-11): a constant
extension, fixed at genesis, that names the APF's key and the group and
anchors the group's identity to the authority. R-11 changes its contents,
not its name.

Not renamed: `authz_incarnation`, `frontier`, `cover`, `fence`. They are
request and contract fields shared with the kernel contract, and the term
mapping in [`notes/alignment-2026-10-25.md`](notes/alignment-2026-10-25.md)
§C relates them to the paper.

Historical records keep their words: `evidence/*.txt` logs, quoted
approvals in `docs/adapter-contract.md` §13, the Third Edition baseline and
dated plans under `docs/superpowers/plans/`.
