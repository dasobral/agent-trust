# Formal companion: authorization–capability coherence

This folder replaces the Third Edition package (article draft, study notes and
bounded artifact of 5 September 2026) as the formal statement of the theory
behind this implementation.

- `paper/coherence.tex`, `paper/coherence.pdf`: the paper. It has 8 pages,
  uses revtex (APS style) and is self-contained.
- `model/coherence_model.py`: an exhaustive finite-state check. It uses only the
  Python standard library.
- `model/results.txt`, `model/results.json`: the recorded run.
- `baseline/Authorization-Capability-Coherence-Third-Edition-Package.zip`: the Third Edition package (study notes, article draft, bounded checker) that this folder repairs. It is kept unchanged as the baseline.
- `notes/etk-gce-extension.tex`, `.pdf`: a proof sketch, separate from the paper, that ETK's theorem extends to opaque GroupContextExtensions proposals. It is a basis for discussion with ETK's authors.
- `R-11-proposal.md`: a draft contract correction that aligns the code with the analyzed construction. Approved as D-11 and merged into the adapter contract; implementation is pending.

## Reproduce

```bash
python3 formal/model/coherence_model.py
```

```bash
latexmk -pdf -cd formal/paper/coherence.tex
```

The checker exits with 0 only if all of these hold:

- The good model has no violation.
- A repair is always enabled when the paper's progress precondition holds.
- Every non-vacuity witness is reached.
- Every mutant produces a counterexample.

The run takes about 20 seconds.

## Status of each claim

| Claim | Status |
|---|---|
| Lemma 1 (fence), Lemma 2 (roster coherence) | Proved by hand, by induction over ledger steps. Checked exhaustively within bounds. |
| Theorem 1 (read coherence) | Symbolic: proved, given K1–K5. Computational: proved for the construction, given the ETK theorem. |
| Key confinement, symbolic (Proposition 2) | Corollary of the machine-checked TreeKEM DY\* theorem (Wallez thesis Sec. 6.4.3, IEEE S&P 2025). The 10-case match is in Appendix A. |
| Key confinement, computational (Proposition 3) | Follows from ETK Theorem 1 through ETK's `safe` predicate (Fig. 7 there). The construction keeps the policy binding in the ledger's acknowledgement, so every commit is an operation ETK models. |
| Theorem 2 (write, admin and admit coherence) | Proved, given atomic ledger, signature unforgeability and collision resistance. |
| Delegation, invocation, cascading revocation | Follows from the locality property, Eq. (2). Checked within bounds. |
| Proposition 2 (progress) | Proved under stated assumptions. Enabledness of repair is checked within bounds. |
| Proposition 3 (price of the cut) | Elementary indistinguishability argument. |
| Code versus construction | **Pending R-11.** The repair commit in the code still carries a GroupContextExtensions proposal, which ETK does not model. [`R-11-proposal.md`](R-11-proposal.md) moves the binding into the canonical acknowledgement and was approved as D-11 and merged into the adapter contract. Its implementation is pending. The symbolic result already covers the code. |
| ETK proof scope | I matched the conference text of ETK, not the full version's Appendix J. Extending ETK to group-context changes is a possible topic for ETK's authors; it is not pursued here. |
| Mechanized proofs | None yet. The model checker is evidence within bounds, not a proof. |

## Repair ledger against the Third Edition

| Third Edition problem | Repair |
|---|---|
| The central theorem was a two-line set inclusion. The real content was unproved. | The main results are now Lemma 1 and Lemma 2, inductive invariants over the protocol's transitions with full proofs. Theorems 1 and 2 compose them with one cryptographic hypothesis each. |
| Confidentiality was a trace predicate over "recover" events. Plaintext guessing makes such events non-negligible, and an adversary's derivation path is not observable. | Read coherence is now symbolic key derivability (Eq. 5) plus an indistinguishability game, with the coalition of non-readers at the cut as the corrupted set. Integrity stays event-based, because honest acceptance is observable. |
| Bad events were negations of the good-trace clauses, so the probability bound was tautological. | The bound has three game hops (Eq. 11) and two terms (Eq. 12). Each term is a named primitive or Hypothesis K. |
| The bounded checker's exhaustive run reached 0 successful uses. Consumption was gated on the cover. There was no adversary. | The new model searches every reachable state within resource bounds (1,556,555 states, of which 1,457,995 hold read releases). The adversary is a retained-key holder that nothing gates. The 9 mutants (8 rules plus condition K2) are found by search, not scripted. |
| The TLA+ companion was never parsed. | Dropped. The Python model is executed and recorded. A TLA+ or proof-assistant mechanization is listed as open step 2. |
| Delegation, invocation, resources and cascading revocation were absent. | Covered by justifications and Eq. (2). Invocation is the union of the origin's chain, the executor's chain and the invocation fact. The confused-deputy mutant shows that the origin's chain is needed. |
| Positioning was weak and prior art was missing. | The paper adds A-CGKA (Balbás, Collins and Vaudenay), MIMI, Keyhive, the Signal private group system, TreeKEM DY* and the reference monitor. The novelty claim is narrowed to the factorization, the cut and the construction. |
| The "open ETK bridge" was framed as a research problem. | Key confinement is now derived under conditions K1–K5. The symbolic form is a corollary of the machine-checked TreeKEM theorem. The computational form rests on ETK's `safe` predicate, with one named gap. ETK's external-commit rejoin attack is now a mutant that the model finds. |
| Notation clashes and undefined terms ("admissible trace", g as both group and guard, kappa, rho). | New, minimal notation with no reused symbols. |
| Four cuts were defined, but only one was used. | Only the commit-immediate cut remains. Causal and lease cuts are listed as future work. |
| Jargon: nine clauses, covers, carry and dispose, bottom support, frontiers. | Replaced by four rules (F, C, R, A), a roster record and a fence. The "sound cover" idea survives as the pessimistic roster record. |

## Sources for key confinement

- TreeKEM DY\*: T. Wallez's PhD thesis, Chapter 6 (https://www.twal.org/pdf/thesis.pdf).
  That chapter is the IEEE S&P 2025 paper (ePrint 2025/410). The confidentiality
  theorem is in Sec. 6.4.3 and the remove-security corollary in Sec. 6.4.4.
- ETK: the Eurocrypt 2026 version on CISPA's repository
  (https://publications.cispa.de/articles/conference_contribution/ETK_External-Operations_TreeKEM_and_the_Security_of_MLS_in_RFC_9420/32779785).
  The `safe` predicate is Fig. 7, Theorem 1 is in Sec. 5.2, and the
  external-commit rejoin attack is at the end of Sec. 5.2.
  The full version (ePrint 2025/229 v2) sits behind a bot check and was not read.

## Implementation observation from the theory

Eq. (2) requires every change of authorization to be a ledger event. In
`src/authority.rs`, delegations carry wall-clock validity windows, and `release`
evaluates them at the request time. An expired reader therefore makes releases
fail, which is safe. But `revoke` never ran, so the fence never closed, and
`repair_stage` requires a closed fence. Its removal set also ignores time.
The group can stay blocked for read releases until an admin explicitly
revokes the reader.

This was inferred from reading the code. No test has run it. Recording expiry
as a ledger revocation would restore Eq. (2).
