# ETK full version against the construction

25 October 2026. Source: ETK, IACR ePrint 2025/229, version 2.0 of
11 April 2026, 109 pages (Daniel placed a copy at `formal/baseline/etk-2025-229-v2.pdf`). The paper's Proposition 3 had been matched against the
conference text only. This note records the check against the full version.

Page numbers are those of the full version. "F" is the functionality
F_ECGKA, "Z" the environment.

## 1. What was read

| Part | Read | Use here |
|---|---|---|
| Sec. 5.2, Theorem 1 (p. 23) | in full | the statement used by Proposition 3 |
| Fig. 7, predicates `safe`, `know`, `*can-traverse`, `*secrets-replaced`, `*state-directly-leaks`, `*secrets-injected`, `inj-allowed` (p. 18) | in full | §3 below |
| Fig. 15, interfaces `Expose` and `CorrRand` (p. 45) | in full | §2 below |
| App. B.4, random oracle (p. 36) | in full | `notes/etk-qrom.tex` |
| App. C, simplifications (pp. 38–39) | in full | §4 below |
| App. E, protocol: group context, key schedule, `tbs` (pp. 50–59) | the parts cited in §5 | §5 below |
| App. J.1–J.3, proof of Theorem 1 (pp. 64–90) | structure, lemma statements, the extraction steps of J.2 (pp. 78–81), Lemmas 3–5 | §6 below |
| App. K, proof of Theorem 2 (PSK variant) | not read | not used |

Not done: a line-by-line re-verification of every case in Appendix J.

## 2. Theorem 1 is unchanged, and our adversary is a legal environment

Theorem 1 in version 2 states the hypotheses of the conference version:
IND-CCA public-key encryption, SUF-CMA signatures, and HKDF.Expand,
HKDF.Extract and MAC replaced by a global random oracle. The changelog
says "extended security results in Section 5.2"; the theorem statement
itself reads as in the conference text.

The paper's computational game fixes a challenge action `a` and gives the
adversary everything that the coalition `C_a` (all non-readers at the cut)
ever holds. In F, this is the following schedule of inputs:

- `Expose(r)` for every `r` in `C_a`, at every step;
- `CorrRand(r, bad)` for every `r` in `C_a`;
- no `Expose` and good randomness for every reader at the cut (K1);
- one challenge, on the epoch `c = e(a)`, with `C_a ∩ M_c = ∅` (Lemma 2 of
  the paper).

Each incarnation is a distinct ETK identity (K5). The ledger, the adapters
and the adversary together form Z, as in game G2 of the paper. Honest
clients merge only acknowledged commits, so the filter is part of Z and
restricts which ETK inputs it issues; it adds no protocol behavior.

The schedule is legal in F:

- **`CorrRand` has no restriction** (Fig. 15).
- **`Expose` is refused only if some challenged node is then unsafe**
  (Fig. 15: "disallowed if ∃c : Node[c].chall ∧ ¬safe(c)"). Section 3 shows
  that `c` stays safe under every exposure of `C_a`, before or after the
  challenge. No other node is challenged.
- **Exposure also reaches key packages.** For every key package of `r`, F
  adds `(r, true)` to every commit that added `r` with it (Fig. 15). Those
  commits have `r` in their roster, so none of them is `c`.

## 3. `safe(c)` holds for every epoch that excludes the coalition

`safe(c) ⇔ ¬[(∗, true) ∈ Node[c].exp ∨ *can-traverse(c)]` (Fig. 7). Let
`c` be a canonical epoch with `C_a ∩ M_c = ∅`. Its committer is an honest
member with good randomness, and its commit is an admission (Add only), a
repair (Remove and a path) or a rekey (no proposals, a path, a new
signature key).

| Condition | Why it is false for `c` |
|---|---|
| `(∗, true) ∈ Node[c].exp` | Exposure is recorded at `Ptr[r]` and at commits that added `r`. Members of `C_a` are not in `M_c`, so no exposure lands in `c`. Members of `M_c` are never exposed. |
| a) orphan root with exposed key | `c` has a parent: the ledger installs only children of `e*`. |
| b) `c` adds a member with exposed `spk` | Added members are in `M_c`; their keys are fresh (K5) and never exposed. |
| c) a member added by `c` is exposed later without an update | Added members are in `M_c`, hence readers at the cut, hence never exposed in this game. |
| d) `know(c, ∗)` with a known parent epoch | Needs some `id` with `know(c, id)`. Directly: no member of `M_c` is exposed, and `*secrets-injected(c, id)` fails because the sender is honest with good randomness, no update proposal is injected, and no added `spk` is exposed. From the parent: `know(p, r)` for `r ∈ C_a` does not pass to `c`, because `c` either removes `r`, which makes `*secrets-replaced(c, r)` true by clause b), or `r` was already outside the parent. Honest members' states at the parent are not known, by the same argument one epoch earlier. From a child: a child `c′` of `c` cannot know `r`'s state, because `r` is not in `M_c` and `c′` does not add `r`; a re-admission adds a new identity (K5), not `r`. |
| e) external commit with leaked or injected secret | `c` is a member commit (K2). |

This is the row-by-row content of the ETK table in Appendix A of the paper, now checked
against the exact definitions of version 2. One point of the conference
reading becomes precise: for a removed party, the propagation stops at the
removing commit because clause b) of `*secrets-replaced` lists `rem-id`.

The induction in row d) runs along the canonical chain. Its base is the
genesis epoch, whose roster is the creator alone, an honest reader.

## 4. Simplifications of ETK against the construction

| ETK omits (App. C) | The construction |
|---|---|
| external proposals other than self-add; external group-context extensions | none are accepted (K2) |
| exporter secrets | none are used (K3) |
| private handshake messages | handshakes are `PublicMessage` (D-2), the case ETK models |
| cipher suites and protocol version in key packages | the suite is fixed per group (C-42), outside the model as in ETK |
| labels on primitives | outside the model; the implementation follows RFC 9420 labels |
| expiration of key packages and certificates | delegation expiry must become an explicit removal (R-12, alignment A-5); ETK gives no help here |
| order of proposal application | commits carry one proposal type |
| group re-initialization and branching | none (K2) |

## 5. The group context in ETK's model

The conference text never mentions the group context. The full version
does. `γ.groupCtxt()` returns `(groupId, epoch, treeHash, confTransHash)`
(App. E). It is an input of `HKDF.Expand` for the joiner secret and of
`HKDF.Extract` for the epoch secret, and the first component of every
signed `tbs`. The extension list is not part of it.

Two consequences:

- The constant `apf_anchor` extension, after R-11, is outside the model in
  the same way as the cipher suite and protocol version (App. C). It is
  not an operation, and it does not enter a modeled input. Lemma 1 of
  `notes/etk-gce-extension.tex` stands, and its first open check is now
  answered: the group context is a public input of random-oracle calls and
  of signatures, which is the "refined model" of Sec. V of that note,
  without the extensions.
- The repair commit of the code, before R-11, changes the extension list.
  The modeled `groupCtxt` does not contain that list, so the change touches
  no modeled input either. But the commit carries a GroupContextExtensions
  proposal, and ETK's proposal set (up, add, rem, extAdd, psk) does not
  contain one. The gap that R-11 closes is the proposal type, not the
  key-schedule input.

## 6. The proof, at the level read

- **J.1 (Lemma 1), consistency.** Shows, operation by operation, that the
  real protocol halts whenever an assertion of F would, so that parties that
  process the same message reach the same state. It is stated for every Z;
  we read its statement and approach, not its cases.
- **J.2 (Lemma 2), confidentiality.** Sub-hybrids over epochs. Each hop
  reduces to the GSD security of the PKE (Theorem 3 of App. B, from
  Ref. [4] of ETK), for every node `c` with `safe(c)`. The reduction is
  stated for any Z within F's rules, so the schedule of §2 is a special
  case. The reduction uses the random oracle by **searching Z's query
  history** at three places (pp. 78–81): a forged confirmation tag yields
  `confKey`, then `joinerSec`; an injected Welcome yields `joinerSec` by
  testing candidate queries; a copied external-commit KEM output yields
  `ext-initSec`. There is no programming and no rewinding.
- **J.3 (Lemmas 3–5), authenticity.** Needs SUF-CMA (Lemma 4: a mauled
  signature is a forgery because `tbs` and the confirmation tag determine
  the node) and MAC unforgeability (Lemma 5). The default suite's SUF-CMA
  is the subject of `notes/ml-dsa-suf.tex`.

## 7. Status

| Item | Before | After |
|---|---|---|
| Theorem 1 statement in the full version | unread | read; unchanged hypotheses |
| Static coalition is a legal environment | assumed | checked against Fig. 15 |
| `safe(c)` for coalition-free epochs | matched on the conference text | checked against Fig. 7 of version 2 |
| Group context in the model | "never mentioned" | modeled without extensions; GCE-note check 1 answered |
| Proof of Theorem 1 | not read | structure and the extraction steps read; case analyses not re-verified |
| Proposition 3 for the code | pending R-11 | covered since R-11 (commit `0db5f6f`): no commit carries a GroupContextExtensions proposal |
