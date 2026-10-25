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

- **C-1, key registration** (amended by C-42 for the `pq` suite). A subject's request key is registered when the subject is created:
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
- **C-5, storage layout** (amended by C-42). `Adapter::create(dir, …)` creates three files and fails if any of them already exists:
  - `authority.sqlite`, the kernel;
  - `adapter.sqlite`, with registered keys, sequences and the trace;
  - `apf-signing-key`, the 32-byte Ed25519 seed, with mode `0600` on Unix.

  `Adapter::open` reloads them. The seed MUST NOT be written to either database or to the trace. Each handled request appends one trace event `{actor, sequence, command, outcome}`, where `outcome` is `"ok"` or the error code. A request that fails before its actor is known is traced with `actor: null`.
- **C-6, key generation** (amended by C-42 for ML-DSA-44). `ClientIdentity::generate` and the APF key both take a 32-byte seed from `OpenMlsRand::random_array` and build `SignatureKeyPair::from_raw(ED25519, seed, public)`. `public` is derived with `ed25519_dalek::SigningKey::from_bytes`. A rand failure is `entropy_unavailable`, and nothing is created.

### 4.10 Phase 4.2 interface (coordinator clarifications C-7 to C-12)

These fill in §4.1–§4.6, §5.1 and §5.2 for plan phase 4.2. C-7 adds a read-only kernel command. C-8 keeps the phase 4.1 constructor as a policy-only mode. Both are flagged to Daniel in the phase report.

- **C-7, kernel `subject_status`.** This is an adapter-only, read-only command with fields `subject` and `now`.
  - It returns `{subject, known, rights, expires_at}`.
  - `rights` lists the subject's grant records in the order read, write, admin, admit. Each entry is `{right, generation, active, effective}`, where `effective` is the kernel's chain-valid check at `now`.
  - `expires_at` is the subject's delegation `expires_at`, or null when the subject has no delegation record.
  - An unknown subject gives `known: false` and `rights: []`.
  - It changes neither `revision` nor `policy_revision`, and appends no history event. A worker request for it is `unauthorized`.
- **C-8, two constructors.**
  - `Adapter::create` (phase 4.1) stays a policy-only adapter with no MLS group. On it, `admission_certificate` and `submit_commit` are `uninitialized: no group`.
  - The full adapter comes from `Adapter::begin_genesis`, which returns a `GenesisPending`, followed by `GenesisPending::complete`. `begin_genesis` writes no file: it refuses an existing file as `create` does, draws the APF seed, and computes the founder certificate and the genesis `acc_context`.
  - `policy_digest` comes from an in-memory kernel initialized with the same `group` and `root`. `complete(group_info, ratchet_tree)` builds the sequencer and validates the group (§5.1 step 4). It then writes the files of C-5 plus `sequencer.sqlite` (the sequencer's `openmls_sqlite_storage`) and calls kernel `init` with `branch` set to the genesis frontier. Finally it checks that the kernel `policy_digest` equals the digest in `acc_context`. On any failure nothing remains.
  - `Adapter::open` reloads either kind.
- **C-9, encodings** (`src/wire.rs`; signature length amended by C-42).
  - Every structure in §4.1–§4.6 is encoded with the TLS presentation language: `VLBytes` for each `opaque<V>`, big-endian fixed-width integers, and a vector of structs as a `VLBytes` of their concatenation.
  - The certificates (§4.4, founder, §4.6) are `struct { TBS tbs; opaque signature<V>; }` and are signed over the TLS encoding of `tbs`.
  - Right codes: read 1, write 2, admin 3, admit 4.
  - `AuthzIncarnation.rights` is sorted by right code.
  - The founder certificate TBS is `{ opaque label<V> = "agent-trust/founder/v1"; opaque apf_key_id<V>; opaque group<V>; opaque subject<V>; RightGeneration rights<V>; opaque signature_key<V>; }`.
  - The MLS group id is the UTF-8 kernel group name.
- **C-10, routed requests.** `handle` routes two new commands. They are adapter flows, not kernel commands.
  - `admission_certificate {key_package_preimage}`, with lowercase hex. It is sent by the candidate, signed with its registered key. The adapter calls `subject_status` at `now` and requires `read` and `admit` to be active and effective, otherwise `unauthorized`. It returns `{certificate}` in hex: a v2 certificate with the current generations, `policy_revision`, `not_after` = `expires_at` (or `u64::MAX` when null), and `SHA-256(preimage)`.
  - `submit_commit {kind: "admit", parent_epoch, parent_branch, commit}`, with the commit as lowercase hex `MlsMessage` bytes. It returns `{epoch, branch, ack}`, where `ack` is the hex canonical acknowledgement.
- **C-11, sequencer checks for `submit_commit`**, in this order. Failures 2–7 leave the sequencer and the kernel unchanged.
  1. Without a group, the result is `uninitialized`. If `parent_epoch` and `parent_branch` differ from the current kernel frontier, the result is `stale_frontier`.
  2. The commit must be a `PublicMessage` commit for this group and epoch that `PublicGroup::process_message` accepts.
  3. The sender leaf's credential identity must equal the authenticated actor, and its signature key must equal the actor's registered key.
  4. The commit must contain exactly one Add proposal and no other proposal, with an UpdatePath.
  5. The added KeyPackage must pass every certificate check:
     - exactly one `0xf042` extension that decodes as a v2 certificate and verifies under the APF key;
     - `apf_key_id` and `group` match;
     - the hash of `KeyPackage::canonical_binding_bytes(0xf042)` equals the certified hash;
     - the credential identity equals the certificate subject, and the leaf signature key equals that subject's registered key;
     - the certified `read_generation` and `admit_generation` equal the current kernel generations, and those grants are effective at `now`;
     - `not_after ≥ now`;
     - the leaf has exactly one `authz_incarnation`, whose `subject` equals the certificate subject, whose `rights` equal the subject's active kernel generations exactly, and whose `admission_cert_hash` is 32 zero bytes.
  6. The successor `GroupContext` must carry the same `acc_context` bytes as the parent.

  Failures at steps 2–6 are `noncanonical_commit`.
  7. Kernel `admit {actor, subject, parent_branch, new_branch, epoch}`, with the successor frontier from `StagedCommit::group_context()`. Kernel errors pass through, for example `unauthorized` for a sender without `admin`, or `stale_frontier`.
  8. The adapter merges into the sequencer, keeps the certificate indexed by the leaf signature key, signs the canonical ack with `kind` = admit, and returns it.
- **C-12, client rules** (`src/client.rs`, `ClientEndpoint<P>`).
  - A member's MLS signature key is its registered request key (`ClientIdentity`).
  - `stage_add` stages, without merging, a commit with one Add and a forced UpdatePath. It does not validate the certificate: the sequencer is the gate.
  - `apply_ack(commit, ack)` follows these rules, and on any error leaves the client unchanged at its parent frontier:
    - An invalid APF signature is `unauthenticated`.
    - If `commit_hash` differs from `SHA-256(commit)`, or the parent differs from the client's frontier, the result is `binding_mismatch`.
    - The client merges its own pending commit when the bytes match. Otherwise it processes the commit, and a computed successor frontier that differs from the ack is `binding_mismatch`.
  - `JoinCandidate::join(welcome, ack)` verifies the ack. It requires `kind` = admit, a joined frontier equal to the ack, and exactly one `acc_context` whose `apf_key_id` matches the pinned APF key. Otherwise it returns `binding_mismatch`, or `unauthenticated` for a bad signature.
  - `mls_parts_mut` exposes the raw OpenMLS group, provider and signer. It exists for adversarial tests only, and honest code never uses it.
- **C-13, resolved while authoring the phase 4.2 tests.**
  - In every TLS structure, a `branch` field is the 64-character lowercase hex string as ASCII bytes. This applies to `CanonicalAck` parent and successor and to `ConfirmationTBS`.
  - `subject_status` is adapter-only (C-3), so a worker request for it is `unauthorized`.
  - Certificate issuance (C-10) does not parse the preimage. It certifies the hash of the bytes an authorized candidate sends, and the sequencer (C-11 step 5) is the only structural gate.
  - The root's `expires_at` in `subject_status` is `u64::MAX`, the value of its self-anchored record. It is null only for a subject without a delegation record.
  - Each `admission_certificate` and `submit_commit` request adds exactly one trace event (C-5).

### 4.11 Phase 4.3 interface (coordinator clarifications C-14 to C-18)

These fill in §4.5 and §5.3 for plan phase 4.3. C-15 adds a signed consume receipt, and C-17 limits who may act on an operation. Both are flagged to Daniel in the phase report.

- **C-14, frozen content and digest** (`src/wire.rs`).
  - The MLS application plaintext is `FrozenContent { opaque content_type<V>; opaque payload<V>; }`, so the receiver can recompute the digest.
  - `digest` is the lowercase hex SHA-256 of `TLS { opaque label<V> = "agent-trust/operation/v1"; opaque op<V>; opaque resource<V>; opaque content_type<V>; opaque payload_hash<V>; uint64 epoch; opaque branch<V>; uint64 policy_revision; }`, where `payload_hash = SHA-256(payload)` as raw bytes.
  - Hash strings that the kernel stores as hex (`branch`, `digest`, the kernel event hash) are carried in TLS structures as ASCII hex (C-13). Hashes that exist only on the wire (`apf_key_id`, `commit_hash`, certificate hashes) are raw bytes.
  - `ReleaseCertificate` (§4.5) has these field encodings:
    - `right` is the right code;
    - `invocation` is empty when there is none;
    - `readers` is sorted by subject;
    - `kernel_event_hash` is the kernel release response's `event_hash`.
  - `writer_generation` and `readers` come from the release request's `cover`, which the kernel has verified equals exactly the writer singleton plus every roster reader singleton.
  - `Envelope = TLS { opaque certificate<V>; opaque mls_message<V>; }`, holding the signed certificate and the exact `MlsMessage` bytes.
- **C-15, consume receipt.**
  - `ConsumeReceipt` TBS is `{ opaque label<V> = "agent-trust/consume/v1"; opaque apf_key_id<V>; opaque group<V>; opaque op<V>; opaque recipient<V>; opaque release_certificate_hash<V>; }`, signed by the APF.
  - A client delivers plaintext only after it has verified a receipt for its own name and that exact certificate.
  - Without the receipt, a client would deliver on an unauthenticated "ok".
- **C-16, routed content commands.** `handle` now routes `release`, `persist`, `emit`, `consume` and `abandon`. For all five, the adapter fills `actor` and `now` and forbids any reserved field (C-2).
  - `release {op, right, resource?, digest, cover, policy_revision, epoch, branch}` uses only the R-3 `policy_revision` form; a body with `revision` is `malformed`. After the kernel accepts, the adapter signs the release certificate and stores it under `op`. It returns the kernel response plus `certificate` in hex.
  - `persist {op, envelope}` (hex) applies these checks:
    - the envelope must decode, otherwise `malformed`;
    - its certificate must be byte-identical to the one stored for `op`, otherwise `binding_mismatch`;
    - its MLS message must be a `PrivateMessage` for this group at the certificate's epoch whose AAD equals `SHA-256(certificate)`, otherwise `binding_mismatch`.

    The adapter then calls kernel `persist` with the certificate's `digest`.
  - `emit {op, envelope}` runs kernel `emit`.
  - `consume {op}` runs kernel `consume` with `recipient` set to the authenticated actor; a body containing `recipient` is `malformed`. It returns `{op, recipient, receipt}`.
  - `abandon {op}` runs kernel `abandon`.
- **C-17, operation ownership.** The adapter records the allocating actor of every operation it routes. Only that actor may `release`, `persist`, `emit` or `abandon` the operation; any other actor is `unauthorized`. Any roster reader may `consume`.
- **C-18, client content rules** (`ClientEndpoint`).
  - **`protect(certificate, content_type, payload)`** returns the envelope. It requires:
    - the certificate verifies under the pinned APF key;
    - `actor` is this member;
    - `(epoch, branch)` equals the member's frontier;
    - `digest` equals the digest it recomputes.

    A bad signature is `unauthenticated`; any other failure is `binding_mismatch`. It then calls `set_aad(SHA-256(certificate))` immediately before exactly one `create_message(FrozenContent)`.
  - **`receive(envelope)`** returns a `PendingDelivery` that holds the plaintext privately. It requires:
    - the certificate verifies (otherwise `unauthenticated`);
    - the MLS message processes as an application message (otherwise `undecryptable`);
    - the AAD equals the certificate hash;
    - the sender leaf's credential is `actor` and its `authz_incarnation` write generation equals `writer_generation`;
    - this member appears in `readers` with its own incarnation read generation;
    - the member's frontier equals the certificate's;
    - the digest recomputed from the decrypted `FrozenContent` equals the certificate's.

    Failures among the last five are `binding_mismatch`.
  - **`PendingDelivery::deliver(receipt)`** verifies the consume receipt (C-15) and only then returns `(content_type, payload)`. A bad receipt is `unauthenticated` or `binding_mismatch`.
  - New error code: `undecryptable`.
- **C-19, resolved during the phase 4.3 implementation.**
  - On a policy-only adapter (C-8), the five content commands stay `malformed: unsupported command`, because there is no group to bind content to.
  - An operation with no recorded allocator (C-17) is `unauthorized` for `release`, `persist`, `emit` and `abandon`. This fails closed.
  - `consume` of an operation with no stored release certificate is `not_persisted`, and the kernel is not called.
  - `persist` of an operation that was allocated but never released is `invalid_transition`.
  - `emit` also decodes the envelope, so undecodable bytes are `malformed`.
  - An undecodable envelope at `receive` is `malformed`.
  - The client verifies consume receipts with Ed25519 `verify_strict`, so delivery draws no provider randomness.

### 4.12 Phase 4.4a interface (coordinator clarifications C-20 to C-25)

These fill in §4.7, §5.4 and the read part of §5.5 for plan phase 4.4a. Non-read re-authorization of a current member (§5.5, the second bullet) waits for phase 4.4b and the open correction R-10 (D-9). C-21 and C-25 are flagged to Daniel.

- **C-20, repair plan.** `repair_plan {}` is a routed request that any current roster member may send.
  - When the kernel is read-fenced and no repair is pending, it returns `{removed, acc_context, policy_revision, parent_epoch, parent_branch}`.
    - `removed` is the sorted list of roster members whose read grant is inactive.
    - `acc_context` is the hex payload `{1, apf_key_id, group, current policy_revision, current policy_digest}`.
  - Otherwise it is `invalid_repair`.
- **C-21, repair committer.** Any continuing member may commit the repair: a roster member that is not in `removed`. The commit's content is fixed exactly by the APF plan, so the committer has no discretion. This replaces "designated", which the specification leaves unspecified.
- **C-22, sequencer checks for `submit_commit {kind: "repair", parent_epoch, parent_branch, commit}`**, in this order. Failures at steps 1–5 leave the sequencer and the kernel unchanged.
  1. Without a group, the result is `uninitialized`. If the parent differs from the kernel frontier, it is `stale_frontier`. If the kernel is not fenced or a repair is already pending, it is `invalid_repair`.
  2. The commit must be a `PublicMessage` that `PublicGroup::process_message` accepts.
  3. The sender must be the actor's leaf with its registered key, and the actor must be a continuing member.
  4. The commit must contain exactly one Remove for each leaf whose credential is in `removed`, no other Remove, exactly one GroupContextExtensions proposal, no other proposal, and an UpdatePath.
  5. The successor `GroupContext` extensions must equal the parent's, with `acc_context` replaced by exactly the planned bytes.

  Failures at steps 2–5 are `noncanonical_commit`.
  6. The adapter calls kernel `repair_stage` with the successor frontier, the current `policy_revision`, `removed`, `update_path: true` (proven in step 4) and `durable: true`. Kernel errors pass through.
  7. The sequencer merges. The adapter records the pending repair with its committer, signs an ack with `kind` = repair, and returns `{epoch, branch, ack}`.
- **C-23, confirmation.** `ConfirmationTBS` (§4.7) is `{ opaque label<V>; opaque group<V>; uint64 epoch; opaque branch<V>; opaque epoch_authenticator_hash<V>; }`.
  - It is signed with the member's registered key. The branch is ASCII hex.
  - `epoch_authenticator_hash = SHA-256(label ‖ branch ‖ epoch_authenticator)`, a plain concatenation with the branch as ASCII hex.
  - `ClientEndpoint::confirmation()` produces it for the member's current frontier.
  - `confirm_repair {confirmation}` (hex) requires all of the following, otherwise `invalid_repair`:
    - a pending repair;
    - the actor is a current roster member;
    - the confirmation's frontier is the current kernel frontier.
  - A signature that does not verify under the actor's key is `unauthenticated`.
  - The adapter stores one hash per actor. It opens the fence through kernel `repair_open {branch, confirmed: true}` once it holds the committer's confirmation and one from another continuing member with an equal hash. When the committer is the only continuing member, its own confirmation suffices; the response then reports `evidence: "single"`, otherwise `"pair"`.
  - Unequal hashes are `binding_mismatch`, and the fence stays closed.
  - The response is `{opened, evidence}`.
- **C-24, local fencing.** A client that has not applied the repair ack stays at the parent frontier. Its `protect` and `receive` then fail on the frontier binding (`binding_mismatch`), or fail to decrypt (`undecryptable`), until it applies the ack. A removed member that applies the repair ack becomes inactive, and every later `protect` or `receive` fails.
- **C-25, grants on a full adapter.**
  - A `grant` whose subject is a current roster member is `unauthorized: requires rekey`, and the kernel is not called. Phase 4.4b (R-10) will add a rekey path.
  - For any other subject, the adapter sets `fresh_keys: true` itself, whatever the worker sent. The evidence comes later: the subject can join only with a new KeyPackage certified at the new generation (C-11).
  - A policy-only adapter keeps the phase 4.1 behavior.
- **C-27, stacked repair (D-10, approved 2026-10-23).** This amends C-20, C-22 and C-23.
  - **C-20:** `repair_plan` is available whenever the kernel is read-fenced and the removal set is not empty, whether or not a repair is pending. A pending repair with nothing more to remove is still `invalid_repair` (C-26).
  - **C-22 step 1:** a pending repair no longer refuses a `kind: "repair"` commit. The commit must build on the current kernel frontier, which is the pending repair's successor, and its plan is computed at that frontier. Steps 2–7 are unchanged; step 6's kernel `repair_stage` stacks on the pending branch.
  - **C-23:** confirmations count only for the latest pending repair. A confirmation of a superseded repair names a frontier that is no longer current, so it is `invalid_repair`. Confirmations stored for a superseded repair never count toward opening.
  - **Revocation:** a read revocation is never refused because a repair is pending.
- **C-28, rekey for current members (R-10, D-9, approved 2026-10-23).** This amends C-25 through amendment A-3.
  - **Offer.** On a full adapter, a `grant` whose subject is a current roster member no longer reaches the kernel and is no longer refused. The right must be write, admin or admit; read is `malformed`. The adapter records a pending offer `{subject, right, generation, admin: actor}` and returns `{pending: true}`. At most one pending offer exists per subject, and a newer offer replaces the older one. The kernel is unchanged at this point.
  - **Update commit.** The subject stages it with `ClientEndpoint::stage_rekey(new_identity, rights)`, using `self_update_with_new_signer`. The new leaf keeps the subject's credential identity and carries the new signature key. Its leaf `authz_incarnation` carries `rights` and keeps the existing `admission_cert_hash`.
  - **Sequencer checks for `submit_commit {kind: "update", parent_epoch, parent_branch, commit}`**, in this order. Failures 1–5 leave the sequencer, the kernel and the key registry unchanged.
    1. Without a group, the result is `uninitialized`. If the parent differs from the kernel frontier, it is `stale_frontier`. If the kernel is read-fenced or a repair is pending, it is `read_fenced`. If no offer is pending for the actor, it is `unauthorized`.
    2. The commit must be a `PublicMessage` that `PublicGroup::process_message` accepts.
    3. The sender must be the actor's leaf with its registered key.
    4. The commit must have no proposals and must have an UpdatePath.
    5. The path leaf must meet all of the following:
       - its credential identity is the actor;
       - its signature key is new, and not registered to anyone;
       - it declares `0xf042`–`0xf044`;
       - it has exactly one `authz_incarnation` with subject = actor, rights = the actor's active kernel rights with the offered `(right, generation)` set, and `admission_cert_hash` = the previous leaf's value.

       The successor `acc_context` must also be unchanged. Failures 2–5 are `noncanonical_commit`.
    6. The adapter calls kernel `rekey` (R-10) with the offer's admin as `actor`. Kernel errors pass through, and the offer stays pending.
    7. The sequencer merges. The subject's registered key is replaced by the new key, so the old key no longer authenticates. The offer is cleared, and the adapter signs an ack with `kind` = update and returns `{epoch, branch, ack}`.
  - **Client.** After applying its own ack, the subject's `identity()` is the new identity.
- **C-29, resolved while authoring the phase 4.4b tests.**
  - `rekey` joins the adapter-only commands (C-3), so a worker request for it is `unauthorized`.
  - The kernel `rekey` validates `right` as a field before any semantic check, so `read` is `malformed`.
  - A rekey offer can only re-authorize a right that the kernel's chain check allows. A delegated member is limited to the rights its delegation names, and those already exist at generation 0. A new right at generation 0 is therefore meaningful only for a subject with direct root-anchored grants.
  - The offer response is exactly `{pending: true}`, with one trace event whose outcome is `ok`.
- **C-30, resolved during the phase 4.4b implementation.** Both rules are stricter than C-28 and close a real gap.
  - **Offer prechecks.** At offer time, the adapter requires the offering actor to hold an effective `admin` right (`unauthorized`) and the generation to follow the grant rule (`invalid_generation`). It checks this through a read-only `subject_status`. Without it, any authenticated worker could overwrite an admin's pending offer. The kernel repeats both checks at `rekey`.
  - **Offer body.** The body may contain only `command`, `subject`, `right`, `generation` and an optional boolean `fresh_keys`, which is ignored.
  - **A "new" key.** A key is new only if it is not currently registered and has never been a leaf key of this group, so a retired key cannot come back. The path leaf's other extensions must be unchanged.
  - **Rotation.** The subject's registered key changes in the same store transaction as the trace event. The retained admission certificate is re-indexed under the new leaf key.
- **C-26, resolved during the phase 4.4a implementation.**
  - **`repair_plan`:** from an actor that is not a roster member it is `unauthorized`. On a policy-only adapter, `repair_plan` and `confirm_repair` are `uninitialized`. A plan that would remove nobody is `invalid_repair`.
  - **Removed member applying the repair ack:** OpenMLS stops the removed member's processing before the confirmed transcript hash. The client therefore accepts its own removal only under an ack of `kind` = repair, and recomputes the successor frontier through its public group, as the sequencer does, before it merges into the inactive state.
  - **Hash rules:**
    - The committer's confirmation hash is the reference. A non-committer whose hash differs from it is `binding_mismatch` and is not stored.
    - A non-committer that confirms first is stored and counts once the committer's matching hash arrives.
    - A resend with a different hash is `binding_mismatch`; an identical resend changes nothing.
    - When the fence does not open, the response is `{opened: false, evidence: null}`.
  - **Committer's leaf:** its UpdatePath leaf must keep its credential, signature key and extensions, as in admission.
  - **Registered keys after removal:** a removed member keeps its registered request key. Its requests still authenticate, and the kernel refuses them on roster grounds. Rejoin (C-11) requires the same key. This amends the §4.8 phrase "stale key after removal" for the laboratory profile.

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

### 6.1 Phase 4.5 recovery interface (coordinator clarifications C-31 to C-34)

- **C-31, write-ahead intents.** The adapter is the kernel's only writer. Before any kernel mutation, it durably writes an intent to `adapter.sqlite`, in the same store transaction that consumes the request's sequence (C-4).
  - The intent records the command kind, the request body, the kernel `revision` before the call, and every input needed to finish the request without the client: for example the exact commit bytes for `submit_commit`, or the subject key for a registration.
  - After the kernel call, the sequencer merge and the final store transaction (effects plus trace event), the intent is deleted in that same final transaction.
- **C-32, recovery on `open`.** For each remaining intent, `Adapter::open` decides whether the kernel applied it. The kernel applied it if and only if its `revision` is exactly the recorded revision plus one and the last history event's `kind` matches the intent's kernel command.
  - **If applied,** the adapter finishes the remaining steps:
    - it merges the stored commit into the sequencer when the sequencer is still at the parent;
    - it re-signs the release certificate, consume receipt or ack deterministically from kernel state (Ed25519 is deterministic, so the bytes are identical);
    - it applies the store effects (owner row, certificate, key registration or rotation, repair record, confirmation, offer deletion);
    - it appends a trace event with outcome `recovered`.
  - **If not applied,** it deletes the intent and appends a trace event with outcome `crashed`.
  - With these rules, `open` succeeds after a crash at any adapter crash point, and the kernel, the sequencer and the store agree afterwards. `binding_mismatch: sequencer frontier` remains only for states that recovery cannot explain.
- **C-33, crash points and client restart.**
  - `Adapter::crash_after(point)` arms a one-shot crash at `CrashPoint::AfterIntent`, `AfterKernel`, `AfterSequencer`, or `GenesisAfterKernel` (inside `GenesisPending::complete`).
  - The next request that reaches that point stops there and returns `crashed`. Every later call on that adapter value also returns `crashed`, so the test must drop it and reopen.
  - The crash points can only make the adapter stop early. They never change what a completed step does.
  - `ClientEndpoint::load(group, subject, identity, provider, apf_public_key, pending_commit, pending_identity)` reloads a member from its provider's storage. The application supplies the exact bytes of a commit it staged and submitted, because the client keeps them only in memory. It also supplies the new identity of a staged rekey whose ack was not yet applied.
  - After a reload, a client reaches an acked successor only through `apply_ack`, and it discards a pending commit that was never acked through `discard_pending`.
  - A client whose storage was rolled back to an older frontier is unready: `protect` and `receive` fail on the frontier binding. It can catch up only by applying the missing acks in order.
- **C-34, interrupted genesis.**
  - `GenesisPending::complete` first writes a `genesis.incomplete` marker and removes it last.
  - `begin_genesis` and `create` treat a directory holding that marker as interrupted. They remove exactly the adapter files and their sidecars, then proceed.
  - `open` on such a directory is `uninitialized: interrupted genesis`.

- **C-35, resolved while authoring the phase 4.5 tests.**
  - `AfterSequencer` on a command with no sequencer step (for example `delegate`, `release` or `confirm_repair`) means after the kernel call and before the final store transaction.
  - Nothing is traced at crash time. The intent keeps the actor, the sequence and the command, and recovery appends exactly one trace event with outcome `recovered` or `crashed`.
  - A crashed request's sequence stays consumed, so replaying it is `unauthenticated`.
  - Recovery leaves every pre-existing store row unchanged. New tables are allowed.

## 7. APF signing key

- The adapter generates one Ed25519 key at genesis, from a seed drawn through the configured rand provider (§8).
- The key is stored in a separate file next to the adapter state, with owner-only permissions. It is never written to the kernel database, traces, evidence, logs or docs.
- Tests generate a fresh key in a temporary directory.
- Task 5 MAY move the key to a hardware-backed or external signer behind the same `Signer` trait.

## 8. Entropy seam

| Randomness consumer | Path | Covered by the configured source |
|---|---|---|
| Path secrets, init and encryption key derivation | `OpenMlsRand` | Yes |
| Client and APF signature keys | Seed from `provider.rand()`, then `SignatureKeyPair::from_raw` (fork `basic_credential/src/lib.rs:271`) | Yes, by construction in the adapter |
| `SignatureKeyPair::new` | The OS RNG, `SysRng` (fork `basic_credential/src/lib.rs:187`) | No. The adapter MUST NOT call it. |
| Crypto provider `signature_key_gen` | The lab crypto provider's HMAC-DRBG | Derived: DRBG output seeded from the source. The adapter still MUST NOT call it, so that every key is a direct draw. |
| HPKE seal (UpdatePath and Welcome encapsulation) | The lab crypto provider's HMAC-DRBG: a fresh seed per encapsulation (fork `libcrux_crypto/src/crypto.rs:126`, `hpke_sender`) | Derived: DRBG output seeded from the source |

- **Lab crypto provider.** Since phase 4.8 the lab's `OpenMlsCrypto` is the OpenMLS libcrux provider, not RustCrypto. `crate::entropy` builds one per lab source with `CryptoProvider::with_entropy_source` (fork `libcrux_crypto/src/crypto.rs:102`): its HMAC-DRBG is seeded from the selected source when the source is connected, through openmls-qrand `EntropyRng`, and reseeds from it when its reseed interval is reached. For `os`, the source is the OS RNG. Every lab provider shares that crypto provider. Randomness drawn inside crypto operations is therefore DRBG output derived from the source, not raw source bytes. The HPKE receiver side draws no randomness and reads no other source (fork `libcrux_crypto/src/crypto.rs:698`, `NoRandomness`).
- **Draws.** Connecting a `mock` or `qrng` source draws 64 bytes (two requests) to seed the crypto provider. Creating a provider draws nothing. During a mid-session outage, `rand()` draws fail closed as before; crypto-internal draws keep coming from the already-seeded DRBG.
- **Fork.** All OpenMLS crates, `openmls_libcrux_crypto` included, are pinned to `dasobral/openmls` `agent-trust/integration` (`dd332780`): current upstream `main` with the staged KeyPackage API and the libcrux provider entropy source merged in. `openmls-qrand` comes in through `[patch.crates-io] openmls_traits = { git = <fork>, rev = dd332780… }`, so that its `QrngOpenMlsProvider` implements the fork's trait.
- Fail-closed behavior is tested against a loopback mock QRNG Open API server labelled as a mock.
- A live Entropy Core run remains an unmet gate until a real endpoint is reachable. No quantum-origin claim is made for consumers marked "No", or for DRBG output beyond what its seeding provides.

### 8.1 Lab entropy selection (C-40, D-12)

- **C-40, one source per lab run.** `agent-trust lab` selects one entropy source before it reads any request (`src/entropy.rs`). Every adapter and client provider and every lab identity key, rekey keys included, draws from that source. A failure to select or reach the source exits nonzero with `entropy_unavailable: <reason>` on stderr and processes no request. Nothing falls back to another source.
  - **Sources.**
    - `os` (the default): the OS-seeded RustCrypto rand for direct draws, and the OS RNG for the lab crypto provider's DRBG (§8).
    - `mock`: openmls-qrand `MockEntropy`, a seeded in-process SplitMix64 stream. **It is not an entropy source.** It is for development and tests only, and it carries no entropy claim.
    - `qrng`: a QRNG Open API endpoint through openmls-qrand `QrngClient`.
  - **Selection.**
    - `AGENT_TRUST_ENTROPY_CONFIG` names a TOML file (`config/entropy.example.toml`). Unknown fields are rejected, and an API secret is named by variable (`auth_secret_env`), never stored in the file.
    - Without a file, `AGENT_TRUST_ENTROPY_SOURCE` is `os`, `mock` or `qrng`. `mock` reads `AGENT_TRUST_MOCK_SEED` (u64, default 0). `qrng` reads the live gate's `AGENT_TRUST_QRNG_*` variables (`tests/adapter_entropy.rs`).
    - Setting both variables, an unknown source or an incomplete QRNG setting is an error. With neither variable set, the source is `os`.
  - **Lab requests (additive to C-36).**
    - `entropy {}` returns `{source}` for `os`, and `{source, requests, bytes, failures}` for `mock` and `qrng`.
    - `entropy_outage {available}` switches a simulated outage of the `mock` source and returns the same report. With any other source it is `unsupported`.
    - `summary` and the exported trace are unchanged.
  - **Errors.** Neither stderr nor a lab error names the endpoint or a secret. QRNG errors are reduced to their category.
  - **Mid-session outage, as observed with `mock` on 2026-10-24.** A failed step changes neither the frontier nor the roster, the lab keeps processing, and the trace exported after recovery is accepted by the oracle. `harness/test_entropy_lab.py` checks the two rules below, within the limits stated there; `evidence/lab-entropy-outage-red.txt` records the limitations they close.
    - **Error code.** A refused draw is `entropy_unavailable` (§12), with no provider text, for identity draws (`genesis`, `delegate`, `rekey`) and for MLS draws (KeyPackage, commit, `send`) alike. Two mechanisms give this code:
      - The client endpoint maps an OpenMLS error that carries `CryptoError::InsufficientRandomness` to `entropy_unavailable` (`src/client.rs`). OpenMLS keeps that `CryptoError` in a private field of `LibraryError`, so the client recognizes it by the variant name in the error's debug form. This covers the KeyPackage and commit paths (`KeyPackageNewError`, `TreeSyncAddLeaf`) for any provider.
      - OpenMLS reduces some refusals to another error: a `send` whose reuse-guard draw fails is `LibraryError … Malformed plaintext`. The lab therefore also reports `entropy_unavailable` for any step that fails while the selected source's failure count increases.
      - **Residual limitation.** The `os` source keeps no failure count. With `os`, a refused draw that OpenMLS reduces to another error stays `malformed: OpenMLS …`.
    - **Candidate identity.** Until the admission's Add is acked, a refused `admit` leaves the subject a candidate with the identity whose key the kernel registered at `delegate`. A later `admit` of the same subject uses that identity. The client API gives the identity and provider back: `PreparedJoin::try_prepare` on a refused preparation, and `PreparedJoin::abandon` / `JoinCandidate::abandon` after one. After a finalized KeyPackage is dropped, the lab gives the candidate a new provider, because the old provider's storage holds the dropped KeyPackage's private keys. `finalize` draws no randomness; a `finalize` failure still drops the candidate. The harness exercises only the refused KeyPackage draw. The restore paths after a refused admission certificate request or a refused Add submission exist by construction and are not yet exercised, and no test checks that the kernel issues a second admission certificate for the same subject.
  - **Determinism.** With `mock` and a fixed seed, every identity key the lab exports is a function of that seed. `harness/test_entropy_lab.py` checks this, rekey included. HPKE encapsulation randomness now derives from the same seed through the lab crypto provider (§8); whether ciphertexts are reproducible is not checked.
  - **Claim boundary.** A `mock` run exercises the real `QrngRand` / provider wiring, not the QRNG HTTP client, transport or Open API parsing. `tests/adapter_entropy.rs` keeps covering those against its loopback mock server. `live_entropy_core` stays `unmet` until a run against a real endpoint is recorded.
  - **Dependency.** `openmls_qrand` is a normal dependency with the `mock` feature, pinned at openmls-qrand `66026082b1badea0ca82c6739238bfe7bd6dcec7` (post quantum TLS, C-42), which keeps `EntropyRng` (§8, from `a102450`) on top of the `EntropyBackend` seam and `MockEntropy` of `fe9ea13`. This replaces the phase 4.6 plan's `entropy-qrng` cargo feature: one build selects its source at run time.

### 8.2 Durable client storage and identity restore (C-41, proposed)

**Flagged to Daniel: proposed 2026-10-24, not yet approved.** It adds two interfaces and changes no existing behavior. The source is finding F-2 of agent-trust-testbed: a networked agent must survive a restart, and the lab provider has memory storage only.

- **C-41, durable lab provider and identity restore.**
  - `LabEntropy::durable_provider(path)` returns a `DurableLabProvider`: the shared lab crypto provider (§8), a rand over the selected source (C-40), and `openmls_sqlite_storage` storage in the one file at `path`. The file is created if missing and its migrations run. Opening draws nothing from the source. Reopening the same path gives the stored groups and keys back for `ClientEndpoint::load` (C-33). An unusable path is `malformed: client storage file`.
  - `ClientIdentity::restore(key_pair)` rebuilds a stored identity (amended by C-42 for ML-DSA-44). It accepts only an Ed25519 pair whose public key derives from its private seed, checked by a signature over a fixed probe verified with `verify_strict`; anything else is `binding_mismatch`. It creates no key: new keys still come only from `ClientIdentity::generate` (C-6).
  - The stored form of an identity is the application's choice. The testbed writes the key pair's serde JSON to an owner-only file. The key is outside the APF and the kernel, as for every client key (§3).
  - Tests: `tests/lab_durable.rs`. Evidence: `evidence/durable-provider-red.txt` (interface build failure) and `evidence/durable-provider-green.txt` (the tests and the full verifier pass; `full_lap_mls` stays `true`).

### 8.3 Post quantum suite (C-42, D-13)

**Approved by Daniel on 25 October 2026 (D-13).** Source: agent-trust-testbed finding F-9, steps PQ-1 (post quantum MLS key exchange) and PQ-3 (post quantum signatures). PQ-2 (post quantum TLS) and PQ-4 (post quantum certificates) are transport changes in openmls-qrand and the testbed; they do not touch this contract.

- **C-42, one suite per group.**
  - **Suites.** Defined in one place, `src/suite.rs`.

    | Suite | MLS ciphersuite | Key exchange (HPKE KEM) | AEAD, hash | Signatures |
    |---|---|---|---|---|
    | `classical` | `0x0001` `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | DHKEM X25519 | AES-128-GCM, SHA-256 | Ed25519 |
    | `pq` | `0x0052` `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44` | X-Wing (draft 06): ML-KEM-768 combined with X25519 | ChaCha20-Poly1305, SHA-384 | ML-DSA-44 (FIPS 204) |

    The `pq` code point comes from `draft-ietf-mls-pq-ciphersuites` (OpenMLS feature of the same name, on every OpenMLS crate). It can change before the draft becomes an RFC.
  - **One signature scheme per group: the suite's.** Client identity keys (the MLS credential and the request key of C-1, which are the same key) and the APF key (certificates, acks, receipts, C-9) all use it.
  - **Selection.**
    - The founder's identity fixes the suite. `ClientIdentity::generate_for(suite, rand)` creates an identity of `suite`. `ClientIdentity::generate(rand)` stays the `classical` suite, so every existing caller and test is unchanged.
    - `Adapter::create` and `Adapter::begin_genesis` take the suite from `root_public_key`: a valid 32-byte Ed25519 key is `classical`, a valid 1312-byte ML-DSA-44 key is `pq`, anything else is `malformed: root_public_key`. The APF key is generated in the same suite.
    - The adapter records the suite in `adapter.sqlite` (`meta` key `suite`). `Adapter::open` reads it; a store without the key was written before C-42 and is `classical`. `Adapter::suite()` returns it.
    - `ClientEndpoint` builds its group, KeyPackages and capabilities with the ciphersuite of its identity's suite. The adapter's sequencer checks the group context against the stored suite.
  - **Amendment to C-1.** `subject_key` is a public key of the group's suite, lowercase hex: 32 bytes for `classical`, 1312 bytes for `pq`. A key of the other suite, or a key that does not decode, is `malformed: subject_key`.
  - **Amendment to C-5.** `apf-signing-key` stays the 32-byte seed. Its scheme is the stored suite.
  - **Amendment to C-6.** Every identity and the APF key still take exactly one 32-byte draw from `OpenMlsRand::random_array`. For Ed25519 the seed is the private key, as before. For ML-DSA-44 the seed is the FIPS 204 seed ξ: the key pair is `ML-DSA.KeyGen_internal(ξ)` (`ml_dsa::SigningKey::<MlDsa44>::from_seed`), stored as `SignatureKeyPair::from_raw(MLDSA44, seed, public)`. `SignatureKeyPair::new` and the provider's `signature_key_gen` stay forbidden.
  - **Amendment to C-9.** The trailing `opaque signature<V>` of a signed structure has the length of the signer's scheme: 64 bytes (prefix `0x40 0x40`) for Ed25519, 2420 bytes (prefix `0x49 0x74`) for ML-DSA-44. The verifier takes the scheme from the public key it verifies with; any other length is `malformed`. Holders without an OpenMLS provider (C-18) verify Ed25519 with `verify_strict` and ML-DSA-44 with the `ml-dsa` crate, empty context.
  - **Determinism.** `openmls_basic_credential` signs ML-DSA with the deterministic variant of FIPS 204 and an empty context (`ml-dsa` 0.1.1 `Signer`). Signing therefore draws no randomness, and a recovered response re-signs to identical bytes (C-32), as with Ed25519. The hedged variant is not used: it would break that byte identity. FIPS 204 allows the deterministic variant.
  - **Amendment to C-41.** `ClientIdentity::restore` accepts a pair of either suite whose public key derives from its seed: Ed25519 as before; ML-DSA-44 by deriving the public key from the seed again and comparing the bytes. Anything else is `binding_mismatch`.
  - **Hashes.** Values that agent-trust computes (branch, digests, `apf_key_id`, `epoch_authenticator_hash`) stay SHA-256. Values that MLS computes (tree hash, confirmed transcript hash, epoch authenticator) use the suite's hash, SHA-384 for `pq`, and are carried as `opaque<V>`.
  - **Lab (additive to C-36 and C-40).** `agent-trust lab` reads `AGENT_TRUST_SUITE` before any request: `pq` (the default) or `classical`. Any other value exits nonzero with `malformed: suite` on stderr and processes no request. Every lab identity uses the selected suite. A new request `suite {}` returns `{suite, ciphersuite}`, with the ciphersuite as a lowercase hex string such as `"0x0052"`. `run_lab_with` keeps the `classical` suite for existing callers; `run_lab_with_suite` takes the suite.
  - **Amendment to C-38.** `scripts/verify.py` runs the integration gate once per suite, `pq` first, then `classical`. `full_lap_mls` is `true` only when both pass, and the manifest names the suites.
  - **The QRNG link (PQ-2).** The entropy that the `qrng` source fetches becomes key material, so its TLS key exchange is post quantum too. openmls-qrand `66026082` configures rustls with aws-lc-rs: `key_exchange = "pq-only"` (the default) offers only `X25519MLKEM768` over TLS 1.3 and refuses a server without it; `"pq-preferred"` offers it first and accepts X25519, P-256 or P-384. It is set by `[qrng] key_exchange` in the entropy file or `AGENT_TRUST_QRNG_KEY_EXCHANGE`; any other value is an error, never a classical fallback. `QrngSettings.key_exchange` carries it; plain HTTP ignores it. The handshake itself is tested in openmls-qrand (`tests/pq_tls.rs`).
  - **Out of scope.** The legacy `MlsLab` (`agent-trust mls-demo`, `src/mls.rs`) stays `classical`; it is not on the adapter path. Composite signatures (Ed25519 and ML-DSA together) are not used: an MLS ciphersuite has one signature scheme, and the request key is the MLS key (C-1).
  - Tests: `tests/pq_suite.rs`, and `harness/test_integration.py` under both suites. Evidence: `evidence/pq-baseline.txt` (the feature alone changes nothing), `evidence/pq-suite-red.txt`, `evidence/pq-suite-green.txt`, `evidence/pq-qrng-tls.txt` (the QRNG link), `evidence/verify-2026-10-25-pq.txt` (the claim gate).

## 9. Traces and the independent oracle

- The adapter exports every accepted and rejected transition as trace events.
- Kernel-level events map to `docs/trace-contract.md` version 1.
- Real admission advances the epoch, but the v1 oracle `admit` does not (`docs/trace-contract.md`, `admit`). The oracle's test author therefore owns a trace contract v2 for real-commit admission (R-5).
- The adapter MUST NOT import the oracle, and the oracle MUST NOT import production modules.

### 9.1 Phase 4.7b interface (coordinator clarifications C-36 to C-38)

- **C-36, lab protocol** (`agent-trust lab --dir PATH --seed N`, implemented in `src/lab.rs`).
  - The lab drives one in-process adapter and in-memory client endpoints through their public APIs only. It reads line-delimited JSON requests `{"op": …}` on standard input and writes one line per request: `{"ok": …}` or `{"error": "<code…>"}`. Processing continues after an error, and the exit status is 0 at end of input.
  - The adapter, the clients and every lab identity key use the entropy source selected at startup (C-40, §8.1). The default is RustCrypto, OS-seeded. The seed drives only the delivery schedule, through a deterministic test-only generator that is not used for cryptography. Time comes from a fixed clock.
  - Requests:
    - `genesis {group, root}`;
    - `delegate {subject, rights}`, by the root on the group resource;
    - `admit {subject, by}`, the full candidate flow, with every current member applying the ack;
    - `send {from, op, payload}`: allocate, release with an honest cover, protect, persist and emit, then queue the envelope for every reader;
    - `deliver {}`: one seeded scheduling round over the queue (reorder, drop, duplicate). For each delivery attempt it runs receive, consume and deliver, and returns each attempt's `{to, op, outcome}`. A dropped attempt stays queued and is retransmitted byte-identically.
    - `revoke {subject, right}`;
    - `repair {by}`: plan, stage, submit, every member applies the ack, then confirmations from the committer and one other continuing member (or the committer alone);
    - `rekey {subject, right, generation}`: the offer by the root, `stage_rekey`, submit, every member applies the ack;
    - `export_trace {}`, which returns `{trace}` (C-37);
    - `summary {}`, which returns `{members, epoch, branch, delivered, duplicate_deliveries, deliveries_without_consume}`.
  - The lab never reports `full_lap_mls`.
  - `agent-trust export-trace --dir PATH` prints the C-37 trace of an existing adapter directory as JSON.
- **C-37, trace export.** `export_v2_trace(dir)` derives a trace contract v2 trace of accepted transitions only (V2.5). It reads only the persisted kernel history and the adapter store, never client state.
  - **Mapping from adapter and kernel records to v2 events:**
    - kernel `init` → v2 `init`, with the root's registered key under `keys`;
    - a non-member `grant` → `allow`;
    - `delegate` → one `allow` per delegated right, in right-code order;
    - an effective `revoke` → one `deny` per subject whose grant it deactivated, sorted by subject;
    - `invoke` → no event;
    - `admit` → `admit`, with the committer from the adapter trace, the subject's registered key, and the certificate hash as `key_package`;
    - `allocate`, `release`, `persist`, `emit` and `consume` → the same-named events, with the cover rebuilt from the stored release certificate;
    - `repair_stage` → `repair_stage`, with the committer from the repair record;
    - each stored confirmation → `confirm`;
    - `repair_open` → `repair_open`, with the recorded evidence;
    - `rekey` → `rekey`, with the offer's admin as actor and the new key.
  - **Policy revisions.** They are renumbered so each exported `release` and `repair_stage` carries the count of exported policy events, because the kernel's `invoke` advances `policy_revision` while v2 does not model it.
  - **Recovery events.** Before a recipient's first `consume` at a frontier, the export emits `recover {client, epoch, branch}`. The evidence is that the client's consume was accepted at that frontier.
  - **Ordering.** Events follow the adapter trace order, which matches kernel history order because the adapter is the kernel's only writer.
- **C-38, claim gate** (amended by C-42: one integration run per suite). `scripts/verify.py` runs every gate: `cargo test --locked --all-targets`, every Python harness test (not only `test_oracle*`), and the integration harness.
  - `evidence/manifest.json` gets `full_lap_mls: true` only when every gate passed in that run, the integration harness's exported lab traces were accepted by the oracle, and its mutated broken controls were rejected. Any unmet or failed gate makes it `false` and makes the verifier exit nonzero.
  - The manifest always records `bridge_remove_etk: "open"`, `live_entropy_core: "unmet"` and `hpke_randomness: "drbg_seeded_from_source"` (§8; `"excluded"` before phase 4.8).
  - `mls-demo` (the legacy `MlsLab`) keeps reporting `full_lap_mls: false`, because its claim concerns only that lab.

- **C-39, resolved while authoring the phase 4.7b tests.** These refine C-36 and C-38.
  - **Request encoding.** Every lab request is `{"op": "<request>", "args": {…}}`, so `send`'s own `op` field cannot collide with the request key.
  - **`deliver`.** It returns `{"ok": [{to, op, outcome}, …]}`, where `outcome` is `"delivered"`, `"dropped"` (the entry stays queued) or a rejection code. Only a copy of a pair that was already delivered may be rejected. An empty list means the queue is empty.
  - **Recipients.** A send's recipients are the roster readers other than the sender.
  - **Payloads.** They are even-length lowercase hex.
  - **Summary.** `summary.delivered` is an integer count.
  - **Faults.** Seeded reorder, drop and duplicate are observable per attempt. A seed is deterministic: rerunning it repeats its schedule.
  - **Lab directories.** A lab starts on a new adapter. `genesis` on an existing directory is an `error` and leaves that directory unchanged.
  - **Verifier gates.**
    - The gates run in this order: a cargo build or check, the `python-oracle` gate first among the Python gates, `cargo test --locked --all-targets`, a full harness discover, then `harness.test_integration` with a named-test check.
    - The integration gate counts as passed only if `test_lab_scenario_trace_is_accepted_by_oracle` and `test_broken_controls_are_rejected_by_oracle` ran and passed. A skipped or absent named test is a failure.
    - `verify.MANIFEST_PATH` is read at call time.
    - `claim_boundary` in the manifest carries `full_lap_mls` and the three fixed boundary fields on every run, and a stale `true` is overwritten by `false`.

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

**R-9 (approved 2026-10-23, D-8, with amendment A-2): root invocation resources.** This corrects one existing scenario (A-2). A root invocation (one without `parent_invocation`) may name only resources that the origin holds under R-8. The test is `resource_held(origin, resource)` for every requested resource; the earlier rule was a subset of `[group]`. Anything else is `invalid_invocation`. Nested invocations stay bounded by their parent invocation, and every release-time check from R-8 still applies.

Amendment A-2 (coordinator, 2026-10-23): `tests/authority_resource_contract.rs`, test `invocation_release_requires_resource_in_origin_and_executor_chains`, scenario C issues a root invocation on `g` from an origin that holds only `backend:kv`, and expects the later release to be refused. Under R-9 the invocation itself is refused with `invalid_invocation`, which is strictly tighter. A test author, not the implementer, updates that one scenario to assert the refusal at `invoke`. The release-time origin check stays in place as defense in depth.

Amendment A-3 (coordinator, 2026-10-23, with D-9): `tests/adapter_repair.rs` test `grant_to_a_current_member_requires_rekey` asserts that a grant to a current member is `unauthorized` (C-25). Under C-28 that grant becomes a pending offer, `{pending: true}`, with the kernel unchanged. A test author, not the implementer, updates that assertion and keeps the kernel-unchanged check.

**R-11 (approved 2026-10-23, D-11): the policy binding moves from `acc_context` into the canonical ack.** The source is `formal/R-11-proposal.md`, from the formalization review session.
- (a) `acc_context` becomes static: `{version = 2, apf_key_id, group}`, set at genesis and never changed by any commit. Every successor `GroupContext` contains the genesis `acc_context` byte for byte.
- (b) No commit carries a GroupContextExtensions proposal, and the sequencer rejects any commit that does. Admission, repair and rekey commits carry only Add or Remove proposals, or none, plus the update path their kind requires.
- (c) `CanonicalAckTBS` (§4.6) gains `uint64 policy_revision; opaque policy_digest<V>;`, set from the kernel at the canonical step. For `kind` = repair the rule moves here unchanged: `policy_revision ≥ fence_revision`, and `policy_digest` equals the kernel digest at that revision.
- Why: the formal companion derives key confinement from the ETK theorem for RFC 9420. ETK does not model GroupContextExtensions proposals, and no proof uses the group-context binding.
- What is given up: MLS's confirmation tag no longer covers the policy revision. Members learn it from the APF-signed ack, which is already the source of truth for the parent compare-and-swap.
- Effect on existing tests: assertions that read `policy_revision` or `policy_digest` from `acc_context`, or that expect a GroupContextExtensions proposal in a repair commit, are rewritten by their test authors against the ack, under a recorded amendment. The affected suites are `adapter_admission`, `adapter_compat`, `adapter_entropy`, `adapter_rekey`, `adapter_recovery`, `adapter_release`, `adapter_repair` and `adapter_repair_stacked`.
- It is implemented test-first after the current phase (4.5 and 4.7b). It is not yet implemented.

## 11. Claim gate for `full_lap_mls`

`full_lap_mls` MAY be reported `true` only when all of the following hold in one recorded run:

- every kernel frontier came from the sequencer;
- admission, release, delivery, revocation, repair, confirmation and reauthorization pass their positive and negative tests;
- the retained-key adversary fails on successor traffic;
- the crash barriers B1–B8 pass;
- the oracle accepts the exported trace and rejects the named broken controls.

Even then, the README states that `Bridge_remove^ETK` is an open proof obligation, and it states how HPKE randomness is covered (§8).

## 12. New error codes

`unauthenticated` (bad or stale request signature or sequence) · `binding_mismatch` (reused: certificate, AAD, incarnation or frontier mismatch) · `noncanonical_commit` (sequencer rejection) · `unconfirmed` (confirmation absent or inconsistent) · `entropy_unavailable` (rand provider failed closed).

## 13. Decisions requested from Daniel

- **D-1:** Approve R-1 to R-7.
- **D-2:** Approve the APF holding an OpenMLS `PublicGroup` as a public sequencer, with handshake messages sent as `PublicMessage`. The alternative is that the APF trusts a member's report of the frontier, which is weaker. Sending handshake messages in plaintext exposes membership changes to the delivery path. That is acceptable for this laboratory.
- **D-3:** Two-step repair (canonical but still fenced, then confirmed and open) as two kernel commands, or as one adapter transaction that holds the canonical commit durably until confirmation. Recommendation: two kernel commands, so the history shows both cuts.
- **D-4:** Confirmation by a designated member C ≠ committer R with matching `epoch_authenticator_hash`. Proposed fallback when R is the only continuing member: R alone confirms, recorded as weaker evidence.
- **D-5:** Accept the HPKE randomness limitation (§8) for Task 4. The alternative is a fork change that routes hpke-rs randomness through `OpenMlsRand`. That change belongs to the separate OpenMLS fork project.
  - **Resolved in phase 4.8 (2026-10-24).** The fork's libcrux provider draws HPKE encapsulation randomness from its HMAC-DRBG, which the lab seeds from the selected source (§8). It does not route through `OpenMlsRand`: the randomness is DRBG output derived from the source.
- **D-6:** Proposed extension codepoints `0xf043` and `0xf044` (private-use range, next to the existing `0xf042`).
- **D-9 (approved 2026-10-23 by Daniel: "I approve D-9: R-10 rekey as proposed in docs/adapter-contract.md. Implement phase 4.4b test-first after D-10."): rekey for non-read re-authorization.**
  - A current member whose write, admin or admit right is re-granted (or newly granted) must install fresh keys and a new `authz_incarnation` with an update commit (`self_update_with_new_signer`, §5.5). That commit advances the MLS epoch, but the kernel has no command that advances its frontier except `admit` and `repair`.
  - The proposal is an adapter-only kernel command `rekey {subject, right, generation, parent_branch, new_branch, epoch}`. It applies the grant with `fresh_keys` true and advances the frontier by CAS, in one transaction, after the sequencer has validated the update commit (`kind` = update). Validation covers: sender = subject, no proposals, a path, a new signature key, and an incarnation equal to the new active rights.
  - It is implemented in phase 4.4b, under C-28 and amendment A-3.
- **D-11 (approved 2026-10-23): R-11, the policy binding moves into the canonical ack.**
  - The approval was relayed by the formalization review session, quoting Daniel: "I approve D-11: R-11 as proposed in formal/R-11-proposal.md, to be merged into docs/adapter-contract.md and implemented test-first after the current phase."
  - The coordinator asks Daniel to confirm before implementation starts, because the relay came from outside the adapter's session group.
  - It is scheduled after phases 4.5 and 4.7b.
- **D-10 (approved 2026-10-23, option 1): stacked repair.**
  - The approval was relayed by the parent session, quoting Daniel: "I approve D-10 option 1: allow a stacked repair, confirm only the latest. Forward it to the adapter session to implement test-first."
  - The gap: a read revoke of a continuing member while a repair is pending used to leave the fence unable to reopen.
  - The fix: a plan and a repair commit may now stack on a pending repair (C-27), and only the latest pending repair can be confirmed. It needs no kernel change, because `repair_stage` already stacks and `repair_open` requires the latest pending branch.
- **D-8 (approved 2026-10-23):** R-9, with amendment A-2. The approval was relayed by the parent session, quoting Daniel: "I approve R-9 (D-8). Forward it to the adapter session to implement test-first."
- **D-13 (approved 2026-10-25 by Daniel): post quantum migration (C-42).** Daniel approved all four steps of testbed finding F-9: "All steps look reasonable and good to have. PQC is already an urgency for migration so there is no reason to not implement it from the start in New applications. Proceed with all the PQs". C-42 implements PQ-1 and PQ-3 here; PQ-2 and PQ-4 are in openmls-qrand and the testbed.
- **D-12 (approved 2026-10-24 by Daniel, in the adapter session): lab entropy selection (C-40).** Runtime selection of the lab's entropy source returns as a test-infrastructure requirement on top of the provider-generic adapter, replacing the archived 2026-10-08 `MlsLab` version (tag `archive/lap-mls-coupling-2026-10-08`). Daniel chose to build the mock into openmls-qrand as a backend (`EntropyBackend`, `MockEntropy`) rather than as a separate fake HTTP server, because no alternative entropy provider is reachable yet.
- **D-7 (approved 2026-10-23):** R-8a–c, with amendment A-1. The approval was relayed by the parent session, quoting Daniel: "I approve R-8 (D-7). Forward it to the adapter session to implement test-first."
