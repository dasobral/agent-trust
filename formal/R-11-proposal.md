# Proposed correction R-11: move the policy binding out of the group context

Status: **approved by Daniel on 23 October 2026 (D-11)**: "I approve D-11: R-11 as proposed in formal/R-11-proposal.md, to be merged into docs/adapter-contract.md and implemented test-first after the current phase." Merged into `docs/adapter-contract.md` (§10 and §13) by the adapter session; implementation is pending.
After approval, the coordinator copies the R-11 row into §10 of
`docs/adapter-contract.md` and the D-11 entry into §13. Schedule it after
the phase now in progress.

## Why

The formal companion (`formal/paper/coherence.pdf`, Sec. V B and Appendix A)
derives key confinement computationally from the ETK theorem for RFC 9420.
ETK models commits with add, remove, update and pre-shared-key proposals,
external self-add proposals and external commits. It does not model the
GroupContextExtensions proposal.

The repair commit (§5.4) carries exactly such a proposal, to write
`policy_revision` and `policy_digest` into `acc_context` (§4.2). As a result,
the computational theorem covers the construction but not the code as it is
built today.

No proof in the formal companion uses the group-context binding. Rule R
already binds every release to the epoch that the ledger acknowledged, and a
client merges only acknowledged commits (§4.6). The binding can therefore move
into the canonical acknowledgement without weakening any proved property.

## Change

| ID | Change | Effect on existing tests |
|---|---|---|
| R-11 | (a) `acc_context` becomes static. Set at genesis, it carries only `version = 2`, `apf_key_id` and `group`, and no commit changes it. (b) No commit carries a GroupContextExtensions proposal, and the sequencer rejects any commit that does. (c) `CanonicalAckTBS` (§4.6) gains `policy_revision` and `policy_digest`. They are set from the kernel at the canonical step. For `kind = repair` the existing rule moves here unchanged: `policy_revision ≥ fence_revision`, and `policy_digest` equals the kernel digest at that revision. | Assertions that read `policy_revision` or `policy_digest` from `acc_context`, or that expect a GroupContextExtensions proposal in the repair commit, are rewritten by the test author against the ack. |

### Details

1. **§4.2.** `AccContext` becomes `{ version = 2; apf_key_id; group }`.
   - Rule 1 (exactly one, listed in `required_capabilities`) stays.
   - Rule 2 becomes: "every successor `GroupContext` contains the genesis
     `acc_context`, byte for byte".
   - Rule 3 (the repair commit sets `policy_revision ≥ fence_revision`) moves
     to §4.6.
   - The joiner check in `src/client.rs` already compares only `apf_key_id`
     and `group`, so it is unchanged.
2. **§4.6.** Append `uint64 policy_revision; opaque policy_digest<V>;` to
   `CanonicalAckTBS`, and state the repair rule above. A client that merges a
   commit stores the ack, so its local record of the policy revision comes
   from a ledger-signed object.
3. **§5.4 step 2.** The repair commit is built with `propose_removals` and
   `force_self_update(true)` only. Drop `propose_group_context_extensions`.
4. **§5.4 step 3.** The sequencer check "the `acc_context` satisfies §4.2"
   becomes two checks:
   - the commit contains no GroupContextExtensions proposal;
   - the successor context still holds the genesis `acc_context`.
   The revision check moves to the ack issued at step 4.
5. **Sequencer, all commit kinds.** Admission, repair and rekey commits may
   contain only Add or Remove proposals, or none, plus the update path that
   the kind requires. Rekey keeps its existing rule: no proposals, a path and
   a new signer. With this rule, every commit the system produces is an
   operation that ETK models:
   - admission is a commit with Add proposals;
   - repair is a commit with Remove proposals and a path;
   - rekey is a commit with no proposals and a path, under a new signature
     key.

### Code locations (for orientation, not a prescription)

- `src/wire.rs`: `AccContext` struct and its encoding.
- `src/adapter.rs`: genesis construction of `acc_context`, the sequencer's
  `acc_context` check, and `CanonicalAck` signing.
- `src/client.rs`: the repair commit builder, which today calls
  `propose_group_context_extensions`, and the joiner `acc_context` check,
  which stays.
- Tests that mention `acc_context`: `adapter_admission`, `adapter_compat`,
  `adapter_entropy`, `adapter_rekey`, `adapter_recovery`, `adapter_release`,
  `adapter_repair`, `adapter_repair_stacked`. Test authors own these
  assertions (AGENTS.md).

## What is given up

MLS's own confirmation tag no longer covers the policy revision. Before
R-11, members confirmed it cryptographically as part of the group context.
After R-11 they learn it from the ledger-signed acknowledgement. Under the
trusted-ledger profile, the ack is already the source of truth for the parent
compare-and-swap, so the trust base does not change.

A constant `acc_context` fixed at genesis adds no operation. It acts as part
of the group's identity. If a reviewer reads ETK's model more strictly, the
extension can be removed entirely, and the joiner check then moves to the
Welcome's ack.

## Not done, for later

Extending ETK's proof to GroupContextExtensions proposals would let the
binding return to the group context. That is a question for ETK's authors
rather than for this project. It is noted in the paper's discussion.

## Decision requested

- **D-11:** Approve R-11 (a)–(c), to be implemented test-first after the
  current phase.
