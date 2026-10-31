# Authority kernel contract

Rust crate `agent_trust`, module `authority`. Public API:

```rust
pub struct Authority { /* private */ }
impl Authority {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String>;
    pub fn execute(&mut self, request: serde_json::Value) -> Result<serde_json::Value, String>;
}
```

This API is a trusted local kernel called by authenticated adapters, not an unauthenticated remote service. Caller authentication and actual MLS transition validation are integration requirements; passing `actor` alone is not authentication. All mutations run in SQLite immediate transactions, reloading committed state to serialize independent handles. Persist one logical state plus append-only hash-chained event records if that is simplest. No in-memory state can override the database after another handle commits. Errors leave state unchanged. JSON unknown fields may be rejected; missing required fields and wrong types must be rejected. IDs are nonempty bounded strings; u64 excludes negative/floating/bool values.

Requests use `command` discriminator. Error strings begin a stable code followed by optional detail. All responses are JSON objects.

- `init`: `group`, `root` strings. One initialization only. Creates epoch 0, branch `genesis`, revision 0, roster [root], active root grants read/write/admin/admit at generation 0, root delegation record with all rights and depth 8, expires_at u64::MAX. Response `{revision,epoch,branch}`. Distinct independently keyed client identities are adapter-layer objects; kernel IDs denote incarnations.
- `checkpoint`: response `{group,revision,epoch,branch,read_fenced,roster,grants,history_root,history}`. R-13a (D-17): an optional `history` selects the events: absent or `"all"` returns every event (this response); `"none"` omits `history`; `{"since": s}` returns the events with `sequence > s`, and `stale_frontier` if `s` is past the last sequence. Any other value is `malformed`. Each request validates the chain once, at the start of its transaction. R-13d.1 (D-17): `"none"` also omits `invocations`, and `{"since": s}` returns the stored events as they are; only the default `"all"` adds each event's v1 `snapshot`, rebuilt from the events. Events written from R-13d on are v2: `{v: 2, kind, revision, request, cause, before, after, head_hash}`. `request` is the kernel request with a persisted envelope replaced by `envelope_digest`; `before` and `after` hold the old and new values of exactly the head fields, operation rows and new invocations the event changed; `head_hash` is SHA-256 of the head row after it. A v2 event hash is SHA-256 over `"agent-trust/kernel-event/v2\0" ‖ sequence (u64, big-endian) ‖ previous ‖ 0x00 ‖ the stored event bytes`; v1 events keep their hash. The bounded head (group, revision, epoch, branch, flags, roster, grants, delegations, policy and fence revisions, repair_pending, and an invocation count and running commitment) is the `state` row; operations (with their consumers) and invocations are rows of their own, and a request loads only the rows it names. `policy_digest` covers the invocations through their commitment, `SHA-256(root ‖ SHA-256(record))` in creation order. `open` validates the whole chain once and migrates a v1 store from its last snapshot; each request then validates from the tip its handle validated last, rehashes the tip, and checks the head row against `head_hash`. grants array has `{subject,right,generation,active}`; history is ordered `{sequence,previous,hash,event}`. SHA256 canonical event hash chaining; persistence replay validates chain before use. A corrupted chain must return `corrupt_history`. Signature/checkpoint certificate belongs to adapter integration; do not claim this unsigned kernel snapshot is authentic outside trusted process.
- `grant`: `actor` root/admin, `subject`, `right`, `generation`, `fresh_keys` bool, `now` u64. Requires active admin delegation chain at now. Initial grant generation is 0 with fresh_keys true; reallow after denial strictly increments generation and fresh_keys true. Direct grants to fresh subjects create separate root-anchored records; giving grant does not add reader to MLS roster. Advances revision. Response `{revision}`.
- `delegate`: `actor`, `subject` (new identity), `rights` array, `resources` array, `expires_at`, `not_before`, `depth`, `now`. Parent must have all rights being delegated, resources subset (initial root resource is group ID), child validity contained in parent's validity, depth strictly lower. No existing subject, cycles or empty rights/resources. Creates generation 0 grants and record with parent actor; advances revision. Does not add roster. Response `{revision}`.
- `revoke`: `actor`, `subject`, `right`, `now`. Requires admin actor. Closes target and dependent descendant grants for that right atomically; unrelated rights stay active. Advances revision only on a change. If affected active or pending roster readers exist closes read fence. Response `{revision,read_fenced}`. Requesting root revoke itself allowed while it still has admin; revoking a nonexisting grant errors.
- `admit`: `actor`, `subject`, `now`. Trusted adapter has already processed a valid winning Add; kernel requires authorizer admin and candidate admit AND read active with chains valid. Adds candidate to roster, advances epoch by one, sets branch `admit:<new_epoch>:<subject>`, leaves existing fence state unchanged (reject if fenced). Response `{epoch,branch}`. This kernel simplification is not a substitute for real MLS admission validation; integration must bind real branch through the adapter.
- `allocate`: `actor`, `op`. Unique reservation bound to actor, no authorization decision. Response `{op}`.
- `release`: `actor`, `op`, `right` read/write, `revision`, `epoch`, `branch`, `digest`, `cover` list of supports of `{subject,right,generation}`, `now`. Actor must have write for write release; read release is performed by actor with write as a sender and additionally requires sound cover of every current roster reader. Require actor in roster, active effective grants at now, exact current frontier, group read fence open for any content-bearing release (both write and read). For write the cover must include the writer singleton AND every current reader singleton because this prototype's write also exposes encrypted content. For read likewise writer and all readers. Reject missing, extra unauthorized, duplicate, empty supports. Atomic released state binds all fields; immutable payload represented by digest. Response `{op,revision,epoch,branch,digest}`.
- `persist`: `op`, `digest`, `envelope` hex string. Only released non-abandoned op, exact digest, nonempty valid hex; repeat same bytes idempotent; different bytes rejected. Response `{op}`.
- `emit`: `op`, `envelope`. Exact persisted bytes, same canonical epoch/branch; no new authorization decision on old release. Response `{op,envelope}`. Repeats same bytes permitted.
- `consume`: `op`, `recipient`, `now`. Must have persisted envelope, current epoch/branch, unfenced group, recipient in release roster and current roster with same active read generation and valid chain, actor same active write generation, and unused `(op,recipient)` pair. Response `{op,recipient}`. At-most-once internal consumption only.
- `abandon`: `op`. Released but not persisted reservation becomes permanently abandoned, repeated call idempotent. Persisted op rejects abandonment. No reuse of op.
- `repair`: `parent_branch`, `new_branch`, `epoch`, `revision`, `removed`, `update_path`, `confirmed`, `durable`. Trusted adapter-only transition. Requires fence closed, exact current parent, next epoch, current revision, distinct child, removed exactly all inactive/invalid pending roster readers (explicit revoked states; expiry must be reconciled before repair), booleans true. Keeps remaining roster, opens central fence. Caller booleans are fixture validation inputs ONLY; integration must derive these from real MLS processing, never expose this command to workers.

Errors: `malformed`, `uninitialized`, `already_initialized`, `unauthorized`, `invalid_generation`, `invalid_delegation`, `duplicate_operation`, `invalid_transition`, `stale_frontier`, `read_fenced`, `unsound_cover`, `binding_mismatch`, `not_persisted`, `replay`, `invalid_repair`, `corrupt_history`.

Expiry is evaluated from trusted adapter time `now` at release and consume. If any roster read grant's chain has expired, new content releases fail closed even before an explicit revoke. Since R-12, the first mutating step past the expiry also records it as a ledger event that drives removal (below). Do not allow expired ancestor grants to authorize descendants. Production time-source trust and authentication are separate adapter gates.

## Requirement corrections for the adapter (approved 2026-10-23)

Daniel approved these corrections on 23 October 2026 (`docs/adapter-contract.md` §10 and §13). They are additive. A request without the new fields behaves exactly as described above, and every existing assertion stays valid. The trusted adapter always supplies the new fields. Kernel fixtures and tests may still omit them.

- **R-2 `init`:** optional `branch` (identifier string). When present, the genesis branch is that value instead of `genesis`. The response is `{revision:0, epoch:0, branch}`.
- **R-1 `admit`:** optional `parent_branch`, `new_branch` (identifier strings) and `epoch` (u64). Either all three are present or none; a partial set is `malformed`. The existing authorization, fence and roster checks run first, unchanged. Then the kernel requires `parent_branch == branch` and `epoch == current epoch + 1`, otherwise `stale_frontier`. It also requires `new_branch != parent_branch`, otherwise `invalid_transition`. On success it sets epoch and branch to the supplied values instead of `admit:<epoch>:<subject>`. The response is `{epoch, branch}`.
- **R-3 policy revision:** the state gains `policy_revision` (u64, 0 at init) and `fence_revision` (u64 or null, null at init).
  - `policy_revision` advances by exactly one on each successful `grant`, `delegate` and `invoke`, and on a `revoke` that changes a grant. Nothing else advances it: allocate, release, persist, emit, consume, abandon, admit, repair, `repair_stage`, `repair_open` and failed requests leave it unchanged.
  - `policy_digest` is the lowercase hex SHA-256 of the canonical serialization of `{group, policy_revision, grants, delegations, invocations}`, in stored order. It changes exactly when `policy_revision` changes.
  - When a revoke closes the read fence, `fence_revision` becomes the `policy_revision` after that revoke. Opening the fence resets it to null.
  - `checkpoint` adds `policy_revision`, `policy_digest` and `fence_revision`.
  - `release` accepts `policy_revision` in place of `revision`. Supplying both is `malformed`; supplying neither is `malformed`. With `policy_revision`, the kernel requires equality with the current `policy_revision` (otherwise `stale_frontier`) and does not compare state `revision`. The epoch, branch and every other check are unchanged.
  - Every successful `release` response adds `policy_revision` and `event_hash`. `event_hash` is the history hash of the event that recorded this release, and it equals that entry's `hash` in `checkpoint.history` (supports R-4). In the `policy_revision` form, the response `revision` is the state revision at which the release was evaluated.
- **R-6 envelope bound:** `persist` and `emit` accept an `envelope` hex string of up to 2,097,152 characters (1 MiB of bytes, `MAX_ENVELOPE`). A longer string is `malformed`. All other fields keep their existing bounds.
- **D-3 two-step repair:** two adapter-only commands are added next to the unchanged `repair`.
  - `repair_stage`: `parent_branch`, `new_branch`, `epoch`, `policy_revision`, `removed`, `update_path`, `durable`. It applies the existing `repair` checks, except two. `policy_revision` must equal the current `policy_revision` and be at least `fence_revision`, and state `revision` is not compared. On success it advances epoch and branch, removes the readers, keeps the read fence closed, and records `repair_pending = new_branch`. While a repair is pending, every content release and consume stays `read_fenced`. The response is `{epoch, branch, policy_revision}`.
  - `repair_open`: `branch`, `confirmed`. It requires a pending repair, `branch` equal to both the current branch and `repair_pending`, `confirmed` true, and no remaining roster reader without an active read grant. Otherwise it returns `invalid_repair`. On success it opens the fence, clears `repair_pending` and resets `fence_revision`. The response is `{epoch, branch}`.
  - `checkpoint` adds `repair_pending` (string or null).
  - As with `repair`, the booleans are fixture inputs for the kernel alone. In integration, the adapter derives them from checked MLS evidence, and these commands are never exposed to workers.
- **R-8 resource attenuation (approved 2026-10-23, amendment A-1):**
  - `release` requires the operation resource to be in the `resources` of every delegation on the actor's chain, from the actor's own record up to the root record. Otherwise it returns `unauthorized` and the reservation stays `allocated`.
  - For an operation bound to an invocation, the same check also applies to the chain of every origin and executor in the invocation chain.
  - A subject without a delegation record (a direct root-anchored `grant`) holds only `[group]`.
  - `allocate` is unchanged and makes no authorization decision.
  - `init` accepts an optional `resources` array of identifier strings, without duplicates, for the root delegation. It must contain `group`, otherwise the request is `malformed`. The default is `[group]`.
- **R-9 invocation resources (approved 2026-10-23, amendment A-2):** a root invocation, one without `parent_invocation`, requires every requested resource to be held by the origin (the R-8 chain check). This replaces the earlier subset-of-`[group]` rule. A violation is `invalid_invocation`. Nested invocations are unchanged: they stay a subset of their parent invocation's resources.
- **R-10 rekey (approved 2026-10-23, D-9):** an adapter-only command, never exposed to workers.
  - Fields: `actor`, `subject`, `right`, `generation`, `parent_branch`, `new_branch`, `epoch`, `now`.
  - It applies the checks of `grant` with `fresh_keys` true (actor has effective `admin`; generation 0 for a new grant record, otherwise exactly the old generation + 1 on an inactive grant).
  - It also requires:
    - `right` is write, admin or admit (otherwise `malformed`);
    - `subject` is in the roster (otherwise `invalid_transition`);
    - the group is not read-fenced and no repair is pending (otherwise `read_fenced`);
    - `parent_branch == branch` and `epoch == current + 1` (otherwise `stale_frontier`);
    - `new_branch != parent_branch` (otherwise `invalid_transition`).
  - In one transaction, it applies the grant, advances `policy_revision` by one, and sets epoch and branch. The response is `{epoch, branch, policy_revision}`.
  - A failure leaves the state unchanged.
- **R-7 fresh keys:** there is no kernel change. In integration, the adapter derives `grant.fresh_keys` from a new KeyPackage or a new-signer update commit.

Clarifications made during the phase 4.0 implementation. They only affect a store with a pending staged repair, or one fenced before the upgrade.

- Legacy `repair` while `repair_pending` is set returns `invalid_repair`. Another `repair_stage` on top of the staged branch is allowed, but only if a new revocation has created new required removals.
- While `repair_pending` is set, `consume` returns `read_fenced` before its frontier binding check.
- A second fencing revoke while the fence is closed moves `fence_revision` to the newer policy revision.
- If `fence_revision` is null when `repair_stage` runs (a store fenced before the upgrade), only the check that `policy_revision` equals the current value applies.
- Before R-6, envelopes were also limited by the shared 256-character identifier bound. `MAX_ENVELOPE` replaces that limit for `persist` and `emit` only.
- R-13c (D-17) resolves the envelope part of this cost: the kernel keeps `envelope_digest = SHA-256(envelope bytes)`, not the envelope, and `persist` and `emit` compare through the digest. The remaining cost of a snapshot per event is R-13d.
- Known cost: every history event stores a full state snapshot, envelopes included. Large envelopes therefore grow the history roughly quadratically. Phase 4.3 should keep exact envelope bytes in the adapter store and give the kernel only bounded data. This is a candidate follow-up correction; it does not affect the R-6 tests.

## R-12: delegation expiry is a ledger event (D-16, 2026-10-25)

- Before each `grant`, `delegate`, `revoke`, `admit`, `invoke`, `release`, `consume` and `rekey`, in the same transaction, the kernel records one history event of kind `expire` for each delegation with `now > expires_at` whose subject or a descendant still holds an active grant of one of the delegation's rights.
- Each `expire` event deactivates those grants for the subject and its descendants, as `revoke` does for each right, and advances `revision` and `policy_revision` by one. If it deactivates the read grant of a roster member, it closes the fence and sets `fence_revision` to the new `policy_revision`.
- The `expire` events stay recorded when the step itself fails: the step rolls back to a savepoint after them.
- `subject_status` and `checkpoint` record nothing. The root delegation never expires.
- The R-3 rule "nothing else advances `policy_revision`" gains this one exception.
