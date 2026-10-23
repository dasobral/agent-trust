# Independent trace contract, version 1

This is the deterministic test oracle interface, not the production protocol or a cryptographic proof. `harness.oracle.check_trace(events)` returns an ordered list of `{index, code}` violations. It must not import production modules. Every event has a unique nonempty string `event_id`. Integer revisions, epochs and generations are nonnegative; booleans are not integers. Unknown/malformed events are violations, never silently discarded. Invalid events do not advance accepted oracle state.

The controlled fixture starts with `init`: group string, revision 0, epoch 0, branch string, roster list of distinct incarnation strings, and `grants` list of `{subject,right,generation}`; right is read/write/admin/admit. Every roster member requires an active read grant. This contract handles one group per trace.

Subsequent event shapes:

- `deny`: subject, right. Advances revision by one; closes that exact active generation. For read, closes the central fence and records removal obligations for every affected roster member. Denying an inactive grant is idempotent and does not increment again.
- `allow`: subject, right, generation, fresh_keys (boolean). Advances revision and creates a strictly higher generation after denial; requires fresh_keys true. For read it does not add the subject back to the roster. Old typed grants never revive.
- `allocate`: op (unique string). Creates a reservation only.
- `release`: op, actor, right (read or write), revision, epoch, branch, digest (nonempty immutable content/context identifier), cover (list of supports, each support a nonempty list of grant dictionaries). Requires allocated op, exact current revision/frontier and unfenced group for all fresh releases in this conservative fixture profile. For read the cover must include each roster member's singleton read grant; for write it must include actor's current singleton write grant. Additional supports are allowed only if every member is currently authorized. Duplicate complete supports and duplicate grants within a support are malformed; the same grant may occur in different distinct supports. A released op can never release twice. The oracle checks a sound cover against known fixture constructors rather than trusting the client. Release state freezes digest, epoch, branch, actor, right and relevant generations.
- `persist`: op, envelope (nonempty exact byte representation as a string), digest. Requires released, non-abandoned op and exact frozen digest. First persist fixes bytes; later different bytes violate binding.
- `emit`: op, envelope. Requires exact persisted bytes and released, non-abandoned state. Historical release remains valid after a later deny; emission itself is not a new cut. Byte-identical repeats are allowed. A fresh release after denial must still fail. Emission across a changed epoch/branch is rejected under the conservative fixture profile.
- `consume`: op, recipient. Requires released op, persisted envelope, locally ready recipient, current canonical epoch/branch matching release, current applicable actor right generation (write operations), active current recipient read generation matching the release snapshot, and unused (op,recipient). Consume never changes historical authorization or permits another payload. Record at most one accepted effect per pair.
- `crash`: client. Clears local readiness; loses that client's local progress only, not authority release/spent state.
- `recover`: client, epoch, branch. Sets ready only at exact current canonical frontier; otherwise fails. Authority history is never rolled back by this event.
- `abandon`: op. Released but not persisted operation becomes permanently abandoned; repeated abandonment idempotent; persisted operation cannot be abandoned in this fixture. Models the post-release/pre-persist crash gap.
- `repair`: parent_branch, new_branch, epoch, revision, removed (list of subjects), update_path, confirmed, durable (booleans). Requires closed central fence, exact current parent, distinct new branch, next epoch, current policy revision, complete pending removals, no removal of continuing authorized readers, and all flags true. Changes canonical frontier and roster, clears central fence, and leaves all clients locally unready until recover. This models trusted adapter evidence; flags are NOT evidence of real MLS processing.
- `admit`: subject, generation, fresh_keys. Requires currently allowed read generation matching the event and fresh_keys true; subject must not already be rostered; no fence/pending removal; adds subject and leaves existing epoch unchanged only in this abstract constructor fixture. This event is not an RFC Commit and must never be described as the concrete admission protocol.

Initial roster clients are locally ready. A central read fence makes all delivery locally blocked until repair and recovery. Non-read denial does not globally fence unrelated readers. Empty trace, absent/multiple init, invalid IDs, duplicate operation IDs, stale frontier, empty/omitted provenance, unknown right, and invalid schema are rejected.

Violation codes: `malformed`, `duplicate_event`, `not_initialized`, `duplicate_operation`, `invalid_generation`, `unauthorized_release`, `unsound_cover`, `stale_frontier`, `read_fenced`, `invalid_transition`, `binding_mismatch`, `not_persisted`, `replay`, `not_ready`, `invalid_repair`.

The independent test author defines exact scenarios first. Broken controls are trace fixtures such as post-denial fresh release, API-only removal with old roster, omitted-reader cover, re-encryption under one operation, spent-cell replay, and reopening without a path. Passing this oracle proves only the listed finite trace checks, not MLS or authority implementation conformance.

# Independent trace contract, version 2 (R-5)

Version 2 extends the version 1 oracle for the real adapter, where every canonical MLS commit (admission, repair, rekey) advances the epoch and changes the branch by parent compare-and-swap (CAS). Version 1 above is unchanged. This section is normative for `harness.oracle.check_trace` on version 2 traces. The independent tests are `harness/test_oracle_v2.py`. Passing this oracle proves only the listed finite trace checks. It does not prove MLS, the adapter or the kernel conformant.

## V2.1 Selection and general rules

- The `init` event selects the version. An `init` without a `version` field is a version 1 trace, and version 1 behavior is unchanged. An `init` with `version` equal to the integer `2` is a version 2 trace. Any other `version` value (for example `1`, `"2"`, `true` or `3`) is `malformed`, and the trace stays uninitialized.
- All version 1 general rules apply: unique nonempty string `event_id`; nonnegative integers that are not booleans; exact field sets (a missing or extra field is `malformed`); unknown event types are `malformed`; a rejected event does not advance oracle state; one group per trace; violations are ordered `{index, code}` items; at most one violation per event.
- Each event describes a transition that the system claims to have accepted. A violation means that the system accepted a transition that this contract forbids. An exporter MUST NOT emit a refused request as a version 2 event.
- Every version 2 event must be expressible from adapter-observable facts: kernel requests and responses, sequencer-validated commits, canonical acknowledgements, release certificates and signed confirmations. Version 2 events carry no evidence booleans. The fields `fresh_keys`, `update_path`, `confirmed` and `durable` do not exist in version 2, and an event that contains one is `malformed`. Evidence is recorded as identifiers and events that the oracle checks.
- Version 2 has no state `revision`. It tracks `policy_revision` (R-3).
- The version 1 event `repair` is not part of version 2. In a version 2 trace it is `malformed`.
- Resources (R-8, R-9), delegations, invocations and expiry are out of scope for version 2. Every operation is implicitly on the group resource. A trace that carries a `resource` field is `malformed`.

## V2.2 Oracle state

The oracle keeps:

- `policy_revision`, `epoch`, `branch`, the set `seen_branches` (the init branch and every accepted new branch), and `roster`;
- grant records `(subject, right) → {generation, active}`;
- `keys` (the current key of each roster member), `key_owner` (every key ever seen → the subject that it was first bound to), and `seen_key_packages`;
- `fenced` (boolean), `fence_revision` (integer or null), and `repair_pending` (null, or `{branch, committer, confirmations}`, where `confirmations` maps an actor to a hash);
- operations, local readiness, and spent `(op, recipient)` pairs, as in version 1.

The **required removals** `R` are, at any point, the roster members whose read grant is not active.

The **grant rule** for a generation `g` of `(subject, right)`: if no record exists, `g` must be `0`; if the record is inactive, `g` must be exactly the old generation plus one; if the record is active, every `g` fails. A failure is `invalid_generation`.

A **frontier advance** (by `admit`, `repair_stage` or `rekey`) sets `epoch` and `branch` to the event values, adds the new branch to `seen_branches`, and makes every client locally unready.

## V2.3 Event shapes and rules

For each event, the checks run in the listed order. The first failing check gives the violation code.

- `init`: `event_id`, `type`, `version` (2), `group` (string), `policy_revision` (0), `epoch` (0), `branch` (string), `roster` (list of distinct strings), `keys` (object), `grants` (list of `{subject, right, generation}`). The `keys` object has exactly the roster members as names, and its values are nonempty, pairwise distinct strings. Every roster member requires an active read grant. Grant pairs `(subject, right)` are unique. Anything else is `malformed`. Roster members start locally ready. The group starts unfenced, with `fence_revision` null and no pending repair.
- `deny`: `subject`, `right`. The shape and effect are as in version 1, with one change. An effective deny advances `policy_revision` by one. A deny of an active read grant of a roster member closes the fence and sets `fence_revision` to the new `policy_revision`. A deny is never refused because the group is fenced or a repair is pending. A deny of an inactive or absent grant changes nothing.
- `allow`: `subject`, `right`, `generation`. Checks:
  1. the subject is in the roster: `invalid_transition` (a current member is reauthorized only by `rekey`, or by removal and readmission);
  2. the grant rule: `invalid_generation`.

  Effect: the grant becomes active at `generation`, and `policy_revision` advances by one. A read allow does not add the subject to the roster.
- `allocate`, `persist`, `emit`, `crash`, `abandon`: as in version 1.
- `recover`: `client`, `epoch`, `branch`. As in version 1: the client is ready only at the exact current frontier (`stale_frontier`), and only if it is a roster member (`not_ready`). In version 2, `recover` also records that a client has applied the canonical acknowledgement of the current frontier. This is a client-side fact that a client harness exports.
- `admit`: `actor`, `subject`, `generation`, `parent_branch`, `new_branch`, `epoch`, `key`, `key_package`. It records a sequencer-validated Add commit (adapter C-11) and the kernel R-1 admission. `key` is the joiner's leaf signature key identifier. `key_package` is the identifier (for example a hash) of the added KeyPackage. Checks:
  1. the group is fenced, a repair is pending, or `R` is not empty: `read_fenced`;
  2. the actor is not a roster member, or has no active admin grant: `unauthorized`;
  3. the subject is in the roster: `invalid_transition`;
  4. the subject's read grant is not active, or its generation differs from `generation`: `invalid_generation`;
  5. the subject has no active admit grant: `unauthorized`;
  6. `parent_branch` differs from the current branch, or `epoch` differs from the current epoch plus one: `stale_frontier`;
  7. `new_branch` equals `parent_branch` or is in `seen_branches`: `invalid_transition`;
  8. `key_package` was seen before, or `key` is already bound to a different subject in `key_owner`: `stale_key`.

  Effect: the subject joins the roster with current key `key`, `key_owner` binds `key` to the subject, `key_package` is recorded, and the frontier advances. The subject may rejoin later with its own earlier key (adapter C-26), but never with a used KeyPackage. `policy_revision` is unchanged.
- `release`: `op`, `actor`, `right` (read or write), `policy_revision`, `epoch`, `branch`, `digest`, `cover`. The field `revision` does not exist in version 2 (`malformed`). The cover well-formedness rules of version 1 apply (`malformed`). Checks:
  1. the op is not allocated, already released, or abandoned: `invalid_transition`;
  2. the group is fenced (which includes a pending repair): `read_fenced`;
  3. `policy_revision`, `epoch` or `branch` differs from the current value: `stale_frontier`;
  4. the actor is not a roster member, or has no active write grant: `unauthorized_release`;
  5. the cover is not exactly the set of singleton supports made of the actor's active write grant and the active read grant of every roster member: `unsound_cover`. Both rights need the writer singleton, as in the kernel and the release certificate (adapter C-14). No other support, and no joint support, is allowed in version 2.

  Effect: as in version 1. The release freezes the digest, the frontier, the actor, the right, the writer generation and the generation of every roster reader.
- `consume`: `op`, `recipient`. As in version 1, with one change: the writer's write generation must be unchanged for both rights (a read release is also sent by a writer). Checks in order: `read_fenced` (fenced or a pending repair); `invalid_transition`; `not_persisted`; `stale_frontier`; `not_ready` (the recipient is not ready, or is not a roster member); `unauthorized_release` (the writer's write grant is not active at the frozen generation, or the recipient's read grant is not active at its frozen generation, or the recipient was not a roster reader at release); `replay`.
- `repair_stage`: `actor`, `parent_branch`, `new_branch`, `epoch`, `policy_revision`, `removed` (list of distinct strings). It records a sequencer-validated repair commit (adapter C-22) by the committer `actor`, and the kernel `repair_stage` (D-3). Checks:
  1. the group is not fenced: `invalid_repair`;
  2. `parent_branch` differs from the current branch, or `epoch` differs from the current epoch plus one: `stale_frontier`;
  3. the actor is not a roster member, or is in `R` (the committer must be a continuing member, adapter C-21): `invalid_repair`;
  4. `policy_revision` differs from the current `policy_revision`, or `fence_revision` is not null and `policy_revision` is lower than it: `invalid_repair`;
  5. `R` is empty, or the set `removed` differs from `R`: `invalid_repair`. This forbids both an omitted revoked reader and the removal of a continuing reader. On a pending repair, it also means that a stacked repair is allowed only when new removals exist (adapter C-27);
  6. `new_branch` equals `parent_branch` or is in `seen_branches`: `invalid_repair`.

  Effect: the removed members leave the roster and `keys` (their keys stay in `key_owner`), and the frontier advances. The fence stays closed. `repair_pending` becomes `{branch: new_branch, committer: actor, confirmations: {}}`. A stacked repair replaces the earlier pending repair, so confirmations of a superseded branch never count. `policy_revision` is unchanged.
- `confirm`: `actor`, `branch`, `hash`. It records a signed repair confirmation (adapter §4.7, C-23) accepted by the adapter. `hash` is the `epoch_authenticator_hash`. Checks:
  1. no repair is pending, `branch` differs from the pending branch (for example a superseded branch), or the actor is not a roster member: `invalid_repair`;
  2. the actor already has a stored hash that differs from `hash`, or the actor is not the committer and the committer's stored hash differs from `hash`: `binding_mismatch`.

  Effect: the oracle stores `hash` for the actor. An identical resend changes nothing. A non-committer that confirms first is stored and counts once the committer's equal hash arrives (adapter C-26).
- `repair_open`: `branch`, `evidence` (`"pair"` or `"single"`; any other value is `malformed`). It records the kernel `repair_open`. Checks:
  1. no repair is pending, or `branch` differs from the pending branch: `invalid_repair`;
  2. `R` is not empty (a continuing roster reader has no active read grant): `invalid_repair`;
  3. the evidence fails: `unconfirmed`. Let `C` be the committer and `h` its stored hash. `"pair"` requires at least two roster members, a stored `h`, and a roster member other than `C` whose stored hash equals `h`. `"single"` requires the roster to be exactly `{C}` and a stored `h`. The evidence label must match the roster: `"single"` with two or more continuing members is `unconfirmed`, and so is `"pair"` with one.

  Effect: the fence opens, `fence_revision` becomes null, and `repair_pending` becomes null. The frontier and local readiness are unchanged. `policy_revision` is unchanged.
- `rekey`: `actor`, `subject`, `right` (write, admin or admit; read or any other value is `malformed`), `generation`, `parent_branch`, `new_branch`, `epoch`, `new_key`. It records a sequencer-validated update commit (adapter C-28) and the kernel `rekey` (R-10). `new_key` is the new leaf signature key identifier. Checks:
  1. the actor has no active admin grant: `unauthorized`;
  2. the grant rule for `(subject, right, generation)`: `invalid_generation`;
  3. the subject is not in the roster: `invalid_transition`;
  4. the group is fenced, or a repair is pending: `read_fenced`;
  5. `parent_branch` differs from the current branch, or `epoch` differs from the current epoch plus one: `stale_frontier`;
  6. `new_branch` equals `parent_branch` or is in `seen_branches`: `invalid_transition`;
  7. `new_key` is in `key_owner` (it was seen before as a key of any subject, the subject's own current or retired keys included): `stale_key`.

  Effect: the grant becomes active at `generation`, `policy_revision` advances by one, the subject's current key becomes `new_key` (bound in `key_owner`), and the frontier advances.

## V2.4 Violation codes

Version 2 uses the version 1 codes and adds three:

- `unauthorized`: an `admit` or `rekey` actor without an active admin grant, or an admission candidate without an active admit grant.
- `unconfirmed`: a `repair_open` without the required confirmation evidence.
- `stale_key`: a reused key package, a key bound to another subject at admission, or a rekey key seen before.

The complete version 2 list is: `malformed`, `duplicate_event`, `not_initialized`, `duplicate_operation`, `invalid_generation`, `unauthorized_release`, `unsound_cover`, `stale_frontier`, `read_fenced`, `invalid_transition`, `binding_mismatch`, `not_persisted`, `replay`, `not_ready`, `invalid_repair`, `unauthorized`, `unconfirmed`, `stale_key`.

## V2.5 Broken controls

The version 2 oracle MUST reject each of these trace fixtures at the stated event:

| Broken control | Rejected event | Code |
|---|---|---|
| Fresh release after a read denial | `release` | `read_fenced` |
| Fresh release after the actor's write denial | `release` | `unauthorized_release` |
| Release at the policy revision before a denial | `release` | `stale_frontier` |
| API-only removal: `repair_open` without a staged repair | `repair_open` | `invalid_repair` |
| Repair that omits a revoked reader | `repair_stage` | `invalid_repair` |
| Re-encryption under one operation (two different persisted envelopes) | second `persist` | `binding_mismatch` |
| Spent-cell replay | second `consume` | `replay` |
| Reopening without confirmation | `repair_open` | `unconfirmed` |
| Opening on a superseded branch's confirmations | `repair_open` | `unconfirmed` |
| Rekey that reuses a key | `rekey` | `stale_key` |
| Admission that does not advance the epoch (version 1 shape of a real commit) | `admit` | `stale_frontier` |
