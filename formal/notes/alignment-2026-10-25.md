# Alignment review: formal companion against the implementation

25 October 2026. Scope: `formal/paper/coherence.tex` (now `concordance.tex`), `formal/README.md`,
`formal/notes/etk-gce-extension.tex`, `formal/model/coherence_model.py` (now `concordance_model.py`),
against `main` at `209feaa` and the project documents.

Status markers: **fixed** (changed in this pass), **decision** (needs
Daniel's call), **open** (tracked work).

## A. The paper is stale against the code

### A-1. K4 cites Ed25519, but the default suite is post quantum (**fixed**, one item open)

- Paper: K4 (`coherence.tex:238`) and Table IV (`coherence.tex:514`) name
  Ed25519 with `verify_strict` and cite Brendel et al.
- Code: since C-42 (D-13) the lab default is MLS `0x0052`: X-Wing
  (ML-KEM-768 with X25519) for HPKE and ML-DSA-44 for every signature,
  including the APF (`src/suite.rs:30`, `src/suite.rs:143`). `classical`
  (`0x0001`, Ed25519) stays available.
- Effect: ETK's Theorem 1 needs SUF-CMA signatures and IND-CCA public-key
  encryption. Write coherence needs EUF-CMA for the ledger key. Nothing in
  the paper cites either property for ML-DSA-44 or for HPKE over X-Wing.
- Decision (25 October): research and cite. K4 now reads "strong
  primitives", and the paper instantiates it for both suites after
  Proposition 3:
  - ML-DSA-44: FIPS 204 Sec. 3.1 states SUF-CMA as a design goal. The
    Dilithium specification (v3.1, Sec. 6.2) restates the KLS18 bound
    (Eurocrypt 2018): SUF-CMA in the quantum random-oracle model under
    MLWE, SelfTargetMSIS and MSIS, for deterministic signing, which is the
    variant the code uses (`docs/adapter-contract.md` §8.3).
  - Barbosa et al. (Crypto 2023, ePrint 2023/246) found and corrected a gap
    in the chosen-message step of that proof, for ordinary unforgeability
    only (their footnote 2). **Written out** in `ml-dsa-suf.tex`: the strong
    case reduces to MSIS, and both verifiers reject non-canonical hints.
    A reduction by hand, not mechanized.
  - X-Wing: IND-CCA if either X25519 (strong Diffie–Hellman, ROM) or
    ML-KEM-768 is (Barbosa et al., IACR CiC 2024). HPKE base mode is a
    KEM–DEM composition (Cramer–Shoup 2003).
  - **Open:** ETK's Theorem 1 is proved in the classical random-oracle
    model, so with the post-quantum suite Proposition 3 holds against
    classical adversaries only. `etk-qrom.tex` locates the one
    classical-only step and states the quantum version as a conjecture.

### A-2. The HPKE randomness bullet is stale (**fixed**)

- Paper: Sec. VI (`coherence.tex:408` before the rename) says HPKE encapsulation uses an
  internal OpenMLS generator.
- Code and contract: since phase 4.8, HPKE encapsulation draws from the lab
  crypto provider's HMAC-DRBG, seeded from the selected entropy source
  (`docs/adapter-contract.md` §8, rows "HPKE seal").
- K1 still holds. Only the provenance statement changes.

### A-3. Sec. VI says "three differences" and lists four (**fixed**)

`coherence.tex:404`.

### A-4. Every content-bearing release is both a read and a write (**fixed**: stated in Sec. VI)

- Paper: Rule R treats a read release (fence open, current epoch) and a
  write release (`J ⊩ α`) as different actions.
- Code: `release` (`src/authority.rs:563`) requires, for either right, that
  the actor holds `write`, that the fence is open, that the frontier is
  current, and that every roster member holds an active `read` generation
  at `now` (the `cover`). An application message is therefore a write by
  its sender and a read-protected action for the group at the same cut.
- Effect: the code checks both Rule R conditions on every message, and it
  checks the conclusion of Lemma 2 directly at release. That is stricter
  than the model. Theorems 1 and 2 hold a fortiori.

### A-5. Delegation expiry is not a ledger event (**fixed** 2026-10-25: R-12, D-16)

- Paper: Eq. (2) requires every change of authorization to be a ledger
  event (`coherence.tex:114`, `coherence.tex:407`).
- Code: delegations carry `not_before` and `expires_at`, evaluated at the
  request's `now` (`src/authority.rs:1198`; release certificates carry
  `not_after`, checked at `src/adapter.rs:2078`). Expiry never runs
  `revoke`, so the fence never closes (`src/authority.rs:370`).
- Predicted consequence, confirmed by reading A-4: an expired delegated
  reader in the roster makes every release fail with `unauthorized`.
  That is safe. But no repair removes the reader, because `repair_stage`
  needs a closed fence. The group stops making progress until an admin
  revokes the reader.
- No test had run this. Correction R-12 (D-16): the first mutating kernel
  step past `expires_at` records an `expire` event with `revoke`'s cascade
  and fence rule, even when the step fails. The red test confirmed the
  stall (`evidence/r12-red.txt`); after the fix the expired reader is
  removed by an ordinary repair (`evidence/r12-green.txt`,
  `docs/adapter-contract.md` C-45).

### A-6. R-11 is approved and not implemented (**fixed** 2026-10-25)

Tracked in `docs/adapter-contract.md` §10 and §13 (D-11). Until it landed,
Proposition 3 covered the construction, not the repair commit of the code;
Proposition 2 covered both. R-11 is implemented (C-44): no commit carries a
GroupContextExtensions proposal, the anchor is static, and the policy
binding is in the canonical ack. Proposition 3 now covers the code's
commits, with the one remaining open item named in `formal/README.md`.

## B. The project documents are two generations behind the paper

### B-1. The headline claim contradicts itself (**fixed**)

- `README.md:28`, `docs/adapter-contract.md:13`, `docs/adapter-contract.md:765`
  and `evidence/manifest.json:57` say `Bridge_remove^ETK` is an **open**
  proof obligation.
- `formal/README.md` says key confinement is derived: symbolically as a
  corollary of TreeKEM DY\*, computationally from ETK with named gaps.
- Both cannot stand. Both now say **conditional** and name the same open
  items. After the proof work and R-11 of 25 October, one remains: the
  quantum version of ETK (`etk-qrom.tex`). The full-version check is in
  `etk-full-check.md` and the ML-DSA strong case in `ml-dsa-suf.tex`.
- `Bridge_remove^ETK` and `full_lap_mls` are also names from the Third
  Edition. `full_lap_mls` is a field in `evidence/manifest.json` and
  `scripts/verify.py`; its rename is a schema change, listed in C-43.

### B-2. Legacy vocabulary (**fixed** by the rename, see `formal/LEXICON.md`)

"Authorization–Capability Coherence (ACC)", "LAP-MLS" and "Third Edition
Study Notes" remain in `README.md:5`, `Cargo.toml:14`, `CITATION.cff:15`,
`docs/specification.md:7`, `docs/specification.md:37` and
`docs/implementation-plan.md:5`. `docs/specification.md` still names the
Third Edition as the theory source; `formal/` replaces it.

### B-3. Numbering errors in `formal/README.md` (**fixed**)

The claim table called progress "Proposition 2" and the price of the cut
"Proposition 3". In the paper they are Propositions 4 and 5.

## C. Term mapping

The paper, the contracts and the code use three vocabularies. This table is
the bridge. The names of this table that come from "coherence" or "LAP-MLS" are
renamed by C-43 (`formal/LEXICON.md`). The others stay, and this table
relates them to the paper.

| Paper | Contracts | Code |
|---|---|---|
| ledger | kernel, APF (Authority, Permit and Fence) | `src/authority.rs`, `Adapter` |
| revision $v$ | `policy_revision` (R-3) | `policy_revision` |
| live set $L_v$ | active grants at their generations | `grants`, `active_generation` |
| justification $J$, Scope | grant plus delegation chain, R-8 resource attenuation | `delegations`, `resource_held` |
| invocation, Eq. (8) | invocation record | `invoke`, `invocation_valid` |
| readers $\mathrm{Rd}_v(g)$ | roster readers with an active read generation | `cover` in a release request |
| roster record $\mathcal R$ | roster plus admission certificates | `roster` |
| fence $\varphi$ | read fence | `read_fenced`, `repair_pending` |
| canonical epoch $e^\ast$ | canonical frontier (epoch, branch) | `Frontier`, `epoch`, `branch` |
| Rule F | revoke with descendant cascade | `revoke` |
| Rule C, repair | repair stage, confirm, open (D-10 stacked) | `repair_stage`, `repair_open` |
| Rule C, admission | admission certificate | `admission_certificate`, `admit` |
| acknowledgement | `CanonicalAck` (§4.6) | `CanonicalAckTBS` |
| Rule R, certificate | release certificate (§4.5) | `release`, `release_certificate` |
| Rule A, spent pair | consumption | `consume` |
| incarnation (K5) | identity and generation vector | `authz_incarnation` |
| constant context extension | `apf_anchor`, formerly `acc_context` (static after R-11) | `ApfAnchor` |
| cut | revocation cut, the successful `AuthorizeRelease` | release event in the history |

Two code terms survive that the paper dropped as jargon: `cover` (about 46
uses in `src/`) and `frontier` (over 200). The table above is what tells a
reader that they implement the paper's readers and canonical epoch.

## D. What this changes in the claims

Nothing in the proofs changes. A-1 and B-1 change what may be claimed for
the default post-quantum suite. A-4 makes the code stricter than the model.
A-5 was a progress gap, not a safety gap, and the theory predicted it; R-12 closes it.
