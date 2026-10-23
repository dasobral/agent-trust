# APF↔MLS adapter contract

23 October 2026 · Revision 0.1 · **Approved by Daniel on 23 October 2026 (D-1 to D-6 as proposed in §13).** Implementation starts with plan phase 4.0.

This document designs implementation-plan Task 4. It couples the durable APF kernel (`src/authority.rs`) to the real OpenMLS laboratory (`src/mls.rs`). It is normative for test authors and implementers once it is approved. The test-first execution plan is `docs/superpowers/plans/2026-10-23-apf-mls-adapter.md`.

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose and claim boundary

The adapter replaces caller-supplied MLS facts with facts that the adapter derives from real OpenMLS processing. After Task 4, the kernel's `epoch`, `branch`, admission and repair inputs come only from validated MLS commits. Every protected application message is bound to an APF-signed release certificate.

This contract does not discharge the open `Bridge_remove^ETK` cryptographic proof obligation. Tests show behavior in the executed schedules only. `full_lap_mls` changes to `true` only under the gate in §11. A gate never changes it because a boolean field says so.

The adapter is in-process in Task 4. Network transport, mTLS and containers are Task 5. The interfaces below are transport-agnostic: every message between parties is an opaque byte string plus a signed request envelope (§4.8).

## 2. Current gap

These are verified source facts at commit `3e332a2`:

| Gap | Evidence |
|---|---|
| Kernel and MLS lab share no code | No `mls` reference in `src/authority.rs`, no `authority` reference in `src/mls.rs` |
| Synthetic frontier | `admit` increments `epoch` and sets `branch = "admit:<epoch>:<subject>"` (`src/authority.rs:356-361`); `init` uses `"genesis"` (`src/authority.rs:138`) |
| Repair trusts booleans | `update_path`, `confirmed`, `durable` are request fields (`src/authority.rs:719-721`) |
| Caller-supplied identity and time | `actor` and `now` are request fields on every command (for example `src/authority.rs:193-198`, `497-507`) |
| Revision conflates policy and state | `bump` runs on allocate, persist and consume too (`src/authority.rs:414`, `610`, `681`); release and repair require `revision == s.revision` (`src/authority.rs:514`, `729`). The oracle advances `revision` only on policy events (`harness/oracle.py:178`, `190`). An unrelated allocate therefore causes a spurious `stale_frontier`. |
| Unsigned release records | Release stores a digest only (`src/authority.rs:573`); the history is hash-chained but not signed (`src/authority.rs:890-898`) |
| Lab owns the APF key | `MlsLab::new` generates `apf_signer` (`src/mls.rs:218`) |
| Fixed generation, uncertified founder | Admission certificates always carry generation 0 (`src/mls.rs:248`); the founder has no admission evidence (`src/mls.rs:232-233`) |
| Memory-only, stock randomness | `MemoryStorage` and `RustCrypto` rand (`src/mls.rs:33-36`, `57-58`) |
| No ACC extensions | Only the KeyPackage binding type `0xf042` exists (`src/mls.rs:23`) |
| Convenience commits | `add_members` and `remove_members` (`src/mls.rs:271`, `386`); no policy-binding proposal in the same commit |
| No receive-side binding | `decrypt` returns payload and AAD without checks (`src/mls.rs:334-350`) |

## 3. Architecture

```text
              signed requests (§4.8)                 kernel JSON (in-process)
 Client ───────────────────────────────▶ Adapter ─────────────────────────────▶ Kernel
 (MlsGroup,                              (APF key,        ◀─── results ────────  (SQLite,
  own keys,      ◀── canonical acks ───   Sequencer =                              hash chain)
  own storage)       release certs        PublicGroup,
     ▲  │                                 Clock, trace)
     │  ▼
  Delivery simulator (seeded: reorder, drop, duplicate)
```

| Component | Owns | Never owns |
|---|---|---|
| **Kernel** (`src/authority.rs`) | Policy, generations, delegations, invocations, reservations, releases, consumption, frontier, hash-chained history | Keys, MLS state, time, caller authentication |
| **Adapter** (`src/adapter.rs`, new) | APF Ed25519 signing key, request verification, trusted clock, the sequencer, certificate issuance, trace export | Group secrets, client signing keys |
| **Sequencer** (inside the adapter) | An OpenMLS `PublicGroup` that mirrors the public group state | Epoch secrets. It cannot check confirmation tags. |
| **Client endpoint** (`src/mls.rs`, refactored) | One `MlsGroup`, its signature key, its storage provider, its local readiness | APF key, kernel access |
| **Delivery simulator** (`src/adapter.rs` test support) | Seeded queues of opaque messages | Any authorization decision |

The adapter MUST be generic over `P: OpenMlsProvider` for every client endpoint. The kernel MUST stay key-free and MLS-free; the kernel contract already assigns signatures to the adapter (`docs/authority-contract.md`, `checkpoint`).

Workers never call the kernel. Only the adapter calls `Authority::execute`, and only after it has authenticated the request and derived every MLS fact itself.

## 4. Objects and encodings

All structures use the TLS presentation language (`tls_codec`), with `opaque x<V>` variable-length vectors. Every signed or hashed structure starts with a distinct ASCII domain-separation label. All hashes are SHA-256. All signatures are Ed25519 under the APF key unless stated otherwise. `apf_key_id = SHA-256(APF public key)`.

### 4.1 Canonical frontier

```text
struct {
  opaque label<V> = "agent-trust/frontier/v1";
  opaque group_id<V>;
  uint64 epoch;
  opaque tree_hash<V>;
  opaque confirmed_transcript_hash<V>;
} FrontierInput;
```

`branch = lowercase hex SHA-256(FrontierInput)`. `epoch` is the MLS `GroupContext` epoch. The values come from `GroupContext::tree_hash` and `GroupContext::confirmed_transcript_hash` (fork `openmls/src/group/group_context.rs:200-205`). The adapter MUST NOT use the feature-gated `MlsGroup::tree_hash()` helper.

The kernel stores the frontier as `(epoch, branch)`. A 64-character hex string fits the kernel identifier bound (`MAX_ID`, `src/authority.rs:9`).

### 4.2 `acc_context` (GroupContext extension, proposed type `0xf043`)

```text
struct {
  uint8  version = 1;
  opaque apf_key_id<V>;
  opaque group<V>;            // kernel group identifier
  uint64 policy_revision;     // R-3
  opaque policy_digest<V>;    // R-3, SHA-256 of the kernel policy snapshot
} AccContext;
```

- The group MUST be created with exactly one `acc_context` and MUST list `0xf043` in `required_capabilities`. Every member and every KeyPackage then has to declare support.
- After every canonical commit, the successor `GroupContext` MUST contain exactly one well-formed `acc_context` with the configured `apf_key_id` and `group`. Its `policy_revision` MUST NOT decrease.
- A repair commit (§5.4) MUST carry a GroupContextExtensions proposal that sets `policy_revision ≥ fence_revision` (the policy revision of the read denial that closed the fence). `policy_digest` MUST equal the kernel digest at that revision.
- OpenMLS preserves unknown extension bytes but does not interpret them. Every rule above is an adapter check.

### 4.3 `authz_incarnation` (LeafNode extension, proposed type `0xf044`)

```text
struct { uint8 right; uint64 generation; } RightGeneration;  // read=1 write=2 admin=3 admit=4
struct {
  uint8  version = 1;
  opaque subject<V>;
  RightGeneration rights<V>;      // the subject's active rights, sorted, no duplicates
  opaque admission_cert_hash<V>;  // SHA-256 of the admission or founder certificate
} AuthzIncarnation;
```

- A joiner MUST place this extension in its KeyPackage leaf node with `KeyPackageBuilder::leaf_node_extensions` (fork `openmls/src/key_packages/mod.rs:838`). The leaf node is inside the stripped KeyPackage preimage, so the admission certificate (§4.4) also covers the incarnation.
- The extension carries the hash of the admission certificate. That certificate carries the hash of the preimage that contains this extension. To break the cycle, `admission_cert_hash` is a placeholder of 32 zero bytes, and the binding goes one way: certificate → preimage → incarnation. The verifier checks that the placeholder is exactly 32 zero bytes. The leaf in the ratchet tree does not carry KeyPackage extensions, so the sequencer retains each admitted member's certificate, indexed by leaf signature key, for later audit. The founder uses the real hash of its founder certificate, because no KeyPackage is involved (§5.1).
- The sequencer and every receiving client MUST check that a sender's leaf `authz_incarnation` matches the release certificate (§5.3).

### 4.4 Admission certificate v2 (KeyPackage extension `0xf042`)

v1 (`src/mls.rs:457-474`) binds the group, subject, generation and the preimage hash. v2 adds three fields and keeps the same placement inside the final KeyPackage:

```text
struct {
  opaque magic<V> = "AT-APF-KP"; uint8 version = 2;
  opaque apf_key_id<V>; opaque group<V>; opaque subject<V>;
  uint64 read_generation; uint64 admit_generation;
  uint64 policy_revision; uint64 not_after;
  opaque key_package_preimage_hash<V>;
} AdmissionCertificateTBS;
```

- The APF issues a certificate only if the kernel shows active `read` and `admit` grants with valid chains at the trusted `now`, at exactly those generations.
- `not_after` MUST NOT exceed the subject's delegation `expires_at`.
- Issuing a certificate is not admission. Admission happens only through §5.2.

### 4.5 Release certificate (R-4)

```text
struct { opaque subject<V>; uint64 generation; } ReaderGeneration;
struct {
  opaque label<V> = "agent-trust/release/v1";
  opaque apf_key_id<V>; opaque group<V>; opaque op<V>;
  opaque actor<V>; uint8 right; opaque resource<V>; opaque invocation<V>; // empty if none
  uint64 epoch; opaque branch<V>; uint64 policy_revision;
  opaque digest<V>;                 // frozen content and context (§5.3)
  uint64 writer_generation; ReaderGeneration readers<V>;
  opaque kernel_event_hash<V>;      // history hash of the release event
} ReleaseCertificateTBS;
struct { ReleaseCertificateTBS tbs; opaque signature<V>; } ReleaseCertificate;
```

- The APF MUST sign the certificate inside the same adapter step that observes the committed kernel `release`.
- `kernel_event_hash` ties the certificate to one entry of the authenticated history.
- The certificate is immutable. Later denials do not invalidate it retroactively. They only change the delivery predicate (§5.3).

### 4.6 Canonical acknowledgement

```text
struct {
  opaque label<V> = "agent-trust/canonical/v1";
  opaque apf_key_id<V>; opaque group<V>;
  uint64 parent_epoch; opaque parent_branch<V>;
  uint64 epoch; opaque branch<V>;
  opaque commit_hash<V>;            // SHA-256 of the exact commit MlsMessage bytes
  uint8  kind;                      // admit=1 repair=2 update=3
} CanonicalAckTBS;
```

A client MUST merge a commit only if it holds a valid canonical ack for those exact commit bytes, its own parent frontier equals `parent_*`, and its computed successor frontier equals `(epoch, branch)`. Otherwise the client discards the commit and stays at its parent frontier. Within the trusted-authority profile, this is the parent compare-and-swap: at most one successor per parent.

### 4.7 Repair confirmation

```text
struct {
  opaque label<V> = "agent-trust/confirm/v1";
  opaque group<V>; uint64 epoch; opaque branch<V>;
  opaque epoch_authenticator_hash<V>; // SHA-256(label ‖ branch ‖ MlsGroup::epoch_authenticator)
} ConfirmationTBS;                    // signed by the confirming member's leaf signature key
```

The designated continuing repair member sends this after `process_message` and merge succeed, which verifies the confirmation tag. `MlsGroup::epoch_authenticator` is at fork `openmls/src/group/mls_group/exporting.rs:218`. Only a hash of the authenticator leaves the client.

### 4.8 Signed client request

```text
struct {
  opaque label<V> = "agent-trust/request/v1";
  opaque group<V>; opaque actor<V>;
  uint64 sequence;                  // strictly increasing per actor; persisted by the adapter
  opaque body<V>;                   // canonical JSON of the requested operation
} RequestTBS;                       // signed by the actor's registered signature key
```

- The registered key is the founder's leaf signature key, or a member's admitted leaf signature key. A not-yet-admitted candidate uses the signature key inside its prepared KeyPackage, and only for the `admission_certificate` request.
- The adapter MUST reject a bad signature, an unknown actor, a stale key after removal, or a non-increasing `sequence`, and MUST do so before calling the kernel.
- The adapter, never the caller, fills `actor` and `now` in kernel requests.
- `now` comes from an adapter `Clock` trait. Tests inject a deterministic clock.

### 4.9 Phase 4.1 interface (coordinator clarifications C-1 to C-6)

These clarifications fill in §4.8 for plan phase 4.1. C-1 refines the approved design and is flagged to Daniel in the phase report.

- **C-1, key registration.** A subject's request key is registered when the subject is created:
  - `delegate` MUST carry `subject_key`: the child's Ed25519 public key, 32 bytes, lowercase hex.
  - A `grant` that creates a previously unknown subject MUST carry `subject_key`. A `grant` to a known subject MUST NOT carry it.
  - The adapter removes `subject_key` before calling the kernel.
  - A key registered to one subject MUST NOT be registered again, for that subject or any other.
  - A missing, malformed or unexpected `subject_key` is `malformed: subject_key`. A key that is already registered is `binding_mismatch`. In both cases the kernel is not called.
  - The child generates its own key (§8). The parent only submits the public half.
  - Phase 4.2 binds admitted leaf keys to this registered key.
- **C-2, reserved fields.** A request body is one JSON object with a `command` string. A body containing `actor` or `now` is `malformed: reserved field`, and the kernel is not called. The adapter sets both from the authenticated actor and the `Clock`.
- **C-3, routed commands.** In phase 4.1, `handle` routes only `grant`, `delegate`, `revoke`, `invoke` and `allocate`.
  - Adapter-only commands (`init`, `admit`, `repair`, `repair_stage`, `repair_open`) are `unauthorized`.
  - `release`, `persist`, `emit`, `consume` and `abandon` are `malformed: unsupported command` until phase 4.3 routes them.
  - Any other command is `malformed: unknown command`.
  - `checkpoint` is a trusted local read through `Adapter::checkpoint`, not a request.
- **C-4, order of checks.** The adapter applies these checks in this order:
  1. It decodes the request and requires a registered actor (`unauthenticated`).
  2. It verifies the signature over `RequestTBS` (§4.8) with the actor's registered key (`unauthenticated`).
  3. It requires `sequence` to be greater than the actor's last accepted sequence (`unauthenticated`).
  4. It durably records the sequence.
  5. It parses and checks the body (`malformed`).
  6. It calls the kernel.

  A sequence that passes step 3 stays consumed even if a later step fails. Failures at steps 1–3 leave the adapter store and the kernel unchanged.
- **C-5, storage layout.** `Adapter::create(dir, …)` creates three files and fails if any of them already exists:
  - `authority.sqlite`, the kernel;
  - `adapter.sqlite`, with registered keys, sequences and the trace;
  - `apf-signing-key`, the 32-byte Ed25519 seed, with mode `0600` on Unix.

  `Adapter::open` reloads them. The seed MUST NOT be written to either database or to the trace. Each handled request appends one trace event `{actor, sequence, command, outcome}`, where `outcome` is `"ok"` or the error code. A request that fails before its actor is known is traced with `actor: null`.
- **C-6, key generation.** `ClientIdentity::generate` and the APF key both take a 32-byte seed from `OpenMlsRand::random_array` and build `SignatureKeyPair::from_raw(ED25519, seed, public)`. `public` is derived with `ed25519_dalek::SigningKey::from_bytes`. A rand failure is `entropy_unavailable`, and nothing is created.

## 5. Flows

### 5.1 Genesis

Genesis is one adapter transaction. Nothing is persisted unless every step succeeds.

1. The adapter generates the APF key (§7).
2. The root client generates its signature key (§8) and sends a signed founder request. The adapter issues a founder certificate. It has label `"agent-trust/founder/v1"` and binds the group, the root, the generation-0 rights that kernel `init` will create, and the root signature public key.
3. The root creates the group with `MlsGroup::builder()`:
   - `acc_context` at `policy_revision` 0;
   - `required_capabilities` that include `0xf042`, `0xf043` and `0xf044`;
   - a leaf `authz_incarnation` that carries the founder certificate hash;
   - `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` for outgoing handshake messages (fork `openmls/src/group/mls_group/config.rs:670`). Application messages remain `PrivateMessage`.
4. The root exports GroupInfo and the ratchet tree. The adapter builds the sequencer with `PublicGroup::from_external` (fork `openmls/src/group/public_group/mod.rs:125`), validates the root leaf and `acc_context`, and computes the epoch-0 frontier.
5. The adapter calls kernel `init` with `group`, `root`, and `branch` set to that frontier (R-2). Then it persists the sequencer and the APF key.

### 5.2 Admission

1. **Candidate:** with active `read` and `admit` grants, it runs `prepare` with `authz_incarnation` in the leaf, then sends a signed `admission_certificate` request carrying the canonical stripped bytes.
2. **Adapter:** checks the kernel grants at `now` and issues certificate v2 (§4.4).
3. **Candidate:** embeds the certificate, runs `finalize` and publishes the KeyPackage.
4. **Admin member:** stages exactly one Add commit with a forced path, for that KeyPackage, through `CommitBuilder`, without merging. It submits the commit and Welcome bytes with its parent frontier.
5. **Sequencer:** runs `PublicGroup::process_message` (fork `openmls/src/group/public_group/process.rs:170`) and requires all of the following:
   - the sender is the requesting admin's leaf;
   - the commit contains only Add proposals, each with a v2 certificate that verifies against the independently recomputed preimage (existing `verify_admission_key_package` logic, `src/mls.rs:476-552`);
   - each joiner's `authz_incarnation` matches the certificate and its zero placeholder;
   - the successor `acc_context` is unchanged.

   The successor frontier is taken from `StagedCommit::group_context()` (fork `openmls/src/group/mls_group/staged_commit.rs:1002`).
6. **Kernel:** `admit` with `parent_branch`, `new_branch` and `epoch` (R-1). The kernel performs the CAS and the authorization checks it already has.
7. **Adapter:** merges the staged commit into the sequencer (fork `openmls/src/group/public_group/staged_commit.rs:439`), persists the sequencer, and signs the canonical ack.
8. **Clients:** existing members merge under §4.6. The candidate joins from the Welcome and MUST check that its joined frontier and `acc_context` equal the ack.

If step 6 fails, the adapter discards the staged commit, the committer clears its pending commit (`MlsGroup::clear_pending_commit`, fork `openmls/src/group/mls_group/mod.rs:445`), and no client merges.

### 5.3 Release, protection and delivery

1. `allocate` (unchanged; it may carry an invocation).
2. **Freeze.** The client computes `digest = SHA-256(TLS("agent-trust/operation/v1", op, resource, content_type, SHA-256(payload), epoch, branch, policy_revision))` and sends the signed release request with its cover.
3. **Kernel:** `release`, with `policy_revision` in place of state `revision` (R-3).
4. **Adapter:** signs the release certificate (§4.5).
5. **Client:** calls `set_aad(SHA-256(ReleaseCertificate))` (fork `openmls/src/group/mls_group/mod.rs:329`) immediately before exactly one `create_message`. It builds `envelope = TLS(ReleaseCertificate, mls_wire)`.
6. **Persist and emit:** the client persists the exact envelope bytes through the adapter (kernel `persist`, R-6), then emits through the delivery simulator. Retransmission MUST be byte-identical.
7. **Receiver:** decrypts with `process_message` and holds the plaintext without delivering it. Delivery requires all of the following, and the client checks the first six before it calls `consume`:
   - the receiver is locally ready;
   - the receiver's current frontier equals the certificate's `(epoch, branch)`, and the APF frontier equals it too (checked in the kernel by `consume`);
   - the certificate signature is valid under the pinned APF key;
   - the AAD equals `SHA-256(ReleaseCertificate)`;
   - the MLS sender leaf's credential subject equals `actor`, and its `authz_incarnation` write generation equals `writer_generation`;
   - the receiver and its generation appear in `readers`;
   - kernel `consume(op, receiver)` succeeds.

   Only then is the plaintext delivered to the application. On any failure the plaintext is dropped.

A pre-cut release whose envelope arrives after a denial is still a valid release. Under the conservative profile, delivery fails if the epoch or generations changed (`docs/specification.md` §2).

### 5.4 Read revocation and repair

1. `revoke(read)` on a roster reader or an affected descendant closes the central fence. The adapter records `fence_revision = policy_revision` after the revoke.
2. **Designated continuing repair member R:** builds one commit through `CommitBuilder` with:
   - `propose_removals` for the exact leaves of every reader the kernel reports as removed;
   - `propose_group_context_extensions` (fork `openmls/src/group/mls_group/commit_builder.rs:316`) with the new `acc_context`;
   - `force_self_update(true)`.

   R stages it and submits it.
3. **Sequencer:** checks that the sender is R, the Remove set equals the kernel's required set exactly (no more, no less), an UpdatePath is present (`update_path_leaf_node`, fork `openmls/src/group/public_group/staged_commit.rs:39`), and the `acc_context` satisfies §4.2. It computes the successor frontier.
4. **Kernel, canonical step:** the repair commit becomes canonical under CAS, but the central fence stays closed. This needs R-1/R-3 changes to `repair`, or a two-step `repair` (stage then open; open decision D-3). The adapter persists the sequencer and signs the canonical ack.
5. **Confirmation step:** a designated continuing member C ≠ R processes the acked commit and sends a confirmation (§4.7). R reports its own `epoch_authenticator_hash`. The adapter requires the two hashes to be equal and both signatures to be valid. Only then does the kernel open the central fence. The kernel's `update_path`, `confirmed` and `durable` inputs are set from these checked facts and from the adapter's durable write. If only one member continues, R alone confirms. The trace records this weaker evidence explicitly.
6. **Clients:** every other client stays locally fenced until it merges the acked commit and durably saves its storage. An offline client does not block the central transition.

The removed endpoint's retained state MUST fail to process successor application messages. The test exercises a byte copy of its SQLite storage file, outside the adapter (§6).

### 5.5 Non-read revocation and reauthorization

- Revoking `write`, `admin` or `admit` closes that generation. It does not fence the group and does not remove a reader.
- A receiver detects a stale writer through `writer_generation` (§5.3).
- Reauthorization strictly increments the generation (existing kernel rule). It also requires fresh keys, now proven by evidence instead of the `fresh_keys` boolean:
  - for read, re-admission with a new KeyPackage (§5.2);
  - for other rights, an update commit through `self_update_with_new_signer` (fork `openmls/src/group/mls_group/updates.rs:80`) with a new signature key and a new `authz_incarnation`, sequenced as `kind = update`.
- The adapter derives the kernel `fresh_keys` input from that evidence.

## 6. Durability and crash barriers

Each client uses `openmls_sqlite_storage::SqliteStorageProvider` 0.3.0 from the pinned fork, which uses the same rusqlite 0.37 as the kernel. The adapter persists, in its own SQLite file, the sequencer `PublicGroup`, the request sequence numbers, the issued certificates and the exact envelopes.

| Barrier | Crash point | Required recovery |
|---|---|---|
| B1 | After allocate, before release | Reservation stays allocated; release may proceed |
| B2 | After kernel release, before persist | Terminal `abandon` at the APF; the op id is never reused; never re-protected |
| B3 | After persist, before emit | Re-emit the exact persisted bytes |
| B4 | After decrypt, before consume | No delivery. The MLS ratchet has advanced, so the message is lost. At-most-once is accepted (spec §2). |
| B5 | After consume, before application delivery | Lost delivery accepted; replay rejected by `consume` |
| B6 | Commit staged, before canonical ack | The committer clears its pending commit; no client merges |
| B7 | Canonical ack issued, before a client merges | The client stays locally fenced until it merges that exact acked commit |
| B8 | Client storage rolled back to an older snapshot | Client is unready; recovery only at the exact current frontier |

Crash tests use explicit barrier hooks. They do not use sleeps.

## 7. APF signing key

- The adapter generates one Ed25519 key at genesis, from a seed drawn through the configured rand provider (§8).
- The key is stored in a separate file next to the adapter state, with owner-only permissions. It is never written to the kernel database, traces, evidence, logs or docs.
- Tests generate a fresh key in a temporary directory.
- Task 5 MAY move the key to a hardware-backed or external signer behind the same `Signer` trait.

## 8. Entropy seam

| Randomness consumer | Path | Covered by the configured `OpenMlsRand` |
|---|---|---|
| Path secrets, init and encryption key derivation | `OpenMlsRand` | Yes |
| Client and APF signature keys | Seed from `provider.rand()`, then `SignatureKeyPair::from_raw` (fork `basic_credential/src/lib.rs:203`) | Yes, by construction in the adapter |
| `SignatureKeyPair::new` | `OsRng` (fork `basic_credential/src/lib.rs:17`, `145`) | No. The adapter MUST NOT call it. |
| RustCrypto `signature_key_gen` | Internal `ChaCha20Rng::from_entropy` (fork `openmls_rust_crypto/src/provider.rs:50`) | No. The adapter MUST NOT call it. |
| HPKE seal (UpdatePath and Welcome encapsulation) | hpke-rs internal PRNG (fork `openmls_rust_crypto/src/provider.rs:673`) | No. This is a known limitation, documented and not claimed. |

- `openmls-qrand` comes in through `[patch.crates-io] openmls_traits = { git = <fork>, rev = 6daabe33… }`, so that its `QrngOpenMlsProvider` implements the fork's trait.
- Fail-closed behavior is tested against a loopback mock QRNG Open API server labelled as a mock.
- A live Entropy Core run remains an unmet gate until a real endpoint is reachable. No quantum-origin claim is made for consumers marked "No".

## 9. Traces and the independent oracle

- The adapter exports every accepted and rejected transition as trace events.
- Kernel-level events map to `docs/trace-contract.md` version 1.
- Real admission advances the epoch, but the v1 oracle `admit` does not (`docs/trace-contract.md`, `admit`). The oracle's test author therefore owns a trace contract v2 for real-commit admission (R-5).
- The adapter MUST NOT import the oracle, and the oracle MUST NOT import production modules.

## 10. Requirement corrections

Each correction changes an accepted requirement. Daniel must approve it before tests change. All of them are additive: existing assertions stay valid unless stated.

| ID | Change | Effect on existing tests |
|---|---|---|
| R-1 | `admit` accepts `parent_branch`, `new_branch` and `epoch` from the adapter. The kernel requires `parent_branch == branch` and `epoch == current + 1`. Without these fields, the current fixture behavior stays. | None |
| R-2 | `init` accepts an optional `branch` (the genesis frontier) and keeps `"genesis"` as the default | None |
| R-3 | The kernel adds `policy_revision` and `policy_digest`. They advance only on grant, delegate, invoke and an effective revoke, and appear in `checkpoint` and the release response. `release` and `repair` accept `policy_revision` instead of state `revision` and then ignore state `revision`. | None. Old requests keep the strict state-revision check. |
| R-4 | Signed release certificates (§4.5), issued by the adapter. The kernel exposes the release event's history hash. | None |
| R-5 | Trace contract v2 for real-commit admission and repair confirmation. Owned by the oracle's test author. | v1 tests unchanged |
| R-6 | Envelope bound: an envelope carries an MLS message plus a certificate, which can exceed `MAX_PAYLOAD` (4096 hex characters, `src/authority.rs:10`). Introduce a separate `MAX_ENVELOPE` (proposed 1 MiB) for `persist` and `emit`. | None |
| R-7 | Fresh-key evidence: in adapter mode, the kernel `fresh_keys` input is derived by the adapter from a new KeyPackage or a new-signer update (§5.5) | None |
| R-8 | **Approved 2026-10-23 (D-7)**, with amendment A-1 below. Resource attenuation on every release path. Found by the Task 5 design session and confirmed in source. Details below this table. | One new red test; existing tests use only the group resource |

**R-8 details.**

Gap: `allocate` accepts any resource (`src/authority.rs:374-381`). A non-invocation `release` checks only rights and chain validity, through `effective` (`src/authority.rs:563`). `chain_valid` never reads `Delegation.resources` (`src/authority.rs:933-959`). Invocation releases check the invocation's resources but not the origin's or the executor's delegated resources (`src/authority.rs:976-984`).

Reproduced by the peer session with the CLI at `3e332a2`: a sibling delegated `[read, write, admit]` on `["g"]` was released a write on `backend:kv`.

Proposed correction:

- **R-8a.** `allocate` and `release` require the operation resource to be in the `resources` of every delegation on the actor's chain, up to the root. Otherwise the request is `unauthorized`, and a failed release leaves the reservation unchanged.
- **R-8b.** For an invocation release, the same check applies to both the origin's chain and the executor's chain.
- **R-8c.** `init` accepts an optional `resources` list for the root delegation. The default is `[group]`, and the group must be in the list. Without R-8c, no subject could ever hold a non-group resource such as `backend:kv`, because `delegate` already requires a subset of the parent's resources.

Amendment A-1 (coordinator, 2026-10-23): the R-8a check applies at `release` only. `allocate` stays a reservation that makes no authorization decision, as the kernel contract states. The existing assertion `tests/confused_deputy_red.rs::child_cannot_launder_parent_only_resource` allocates on a resource outside the delegation and expects only the release to be refused. Checking at `allocate` would break that assertion. A refused release leaves the reservation `allocated`. A subject that has no delegation record (a direct root-anchored `grant`) is bounded to `[group]`.

## 11. Claim gate for `full_lap_mls`

`full_lap_mls` MAY be reported `true` only when all of the following hold in one recorded run:

- every kernel frontier came from the sequencer;
- admission, release, delivery, revocation, repair, confirmation and reauthorization pass their positive and negative tests;
- the retained-key adversary fails on successor traffic;
- the crash barriers B1–B8 pass;
- the oracle accepts the exported trace and rejects the named broken controls.

Even then, the README states that `Bridge_remove^ETK` is an open proof obligation, and it lists the HPKE randomness limitation (§8).

## 12. New error codes

`unauthenticated` (bad or stale request signature or sequence) · `binding_mismatch` (reused: certificate, AAD, incarnation or frontier mismatch) · `noncanonical_commit` (sequencer rejection) · `unconfirmed` (confirmation absent or inconsistent) · `entropy_unavailable` (rand provider failed closed).

## 13. Decisions requested from Daniel

- **D-1:** Approve R-1 to R-7.
- **D-2:** Approve the APF holding an OpenMLS `PublicGroup` as a public sequencer, with handshake messages sent as `PublicMessage`. The alternative is that the APF trusts a member's report of the frontier, which is weaker. Sending handshake messages in plaintext exposes membership changes to the delivery path. That is acceptable for this laboratory.
- **D-3:** Two-step repair (canonical but still fenced, then confirmed and open) as two kernel commands, or as one adapter transaction that holds the canonical commit durably until confirmation. Recommendation: two kernel commands, so the history shows both cuts.
- **D-4:** Confirmation by a designated member C ≠ committer R with matching `epoch_authenticator_hash`. Proposed fallback when R is the only continuing member: R alone confirms, recorded as weaker evidence.
- **D-5:** Accept the HPKE randomness limitation (§8) for Task 4. The alternative is a fork change that routes hpke-rs randomness through `OpenMlsRand`. That change belongs to the separate OpenMLS fork project.
- **D-6:** Proposed extension codepoints `0xf043` and `0xf044` (private-use range, next to the existing `0xf042`).
- **D-8 (open, proposed R-9):** `invoke` still limits a root invocation's resources to `[group]` (`src/authority.rs`, `invoke`). With R-8c, a subject can hold a non-group resource such as `backend:kv` but cannot delegate work on it through an invocation. The proposal is to bound a root invocation's resources by the origin's delegated resources instead of `[group]`. This was found by the R-8 test author. It is not approved and not implemented.
- **D-7 (approved 2026-10-23):** R-8a–c, with amendment A-1. The approval was relayed by the parent session, quoting Daniel: "I approve R-8 (D-7). Forward it to the adapter session to implement test-first."
