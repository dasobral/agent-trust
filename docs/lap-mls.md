# LAP-MLS coupling

This note describes how the durable APF kernel (`src/authority.rs`) is coupled to
the real OpenMLS laboratory (`src/mls.rs`) through the trusted in-process adapter
`src/lap.rs`. It realizes the specification's §2 contract for a laboratory
profile with a single authority.

## Profile and claim boundary

`full_lap_mls: true` (reported by `agent-trust lap-demo`) means that every
executable gate below passed, in this profile:

- one APF kernel process, whose SQLite store is trusted not to roll back;
- a trusted in-process adapter derives all transition evidence from real
  OpenMLS objects (staged and merged commits, group contexts, the ratchet tree)
  and passes it to the kernel. The kernel checks that evidence against policy,
  but it cannot verify MLS cryptography itself;
- the laboratory process holds the APF signing key (Ed25519);
- a designated honest continuing member supplies repair confirmation;
- crashes are simulated (B: a connection closed with a transaction open).

The flag does **not** discharge the `Bridge_remove^ETK` cryptographic proof
obligation, and makes no claim about replicated authorities, network
adversaries against the adapter, or production key custody. The plain
`mls-demo` laboratory is not coupled to the APF and keeps reporting
`full_lap_mls: false`.

## MLS bindings

| Binding | Where | Content (APF Ed25519 signature over all preceding fields) |
| --- | --- | --- |
| `acc_context` (`0xf043`) | GroupContext extension | magic `AT-ACC`, version, APF group, policy revision, sorted `(subject, read generation)` roster |
| `authz_incarnation` (`0xf044`) | LeafNode extension (set in the KeyPackage leaf, preserved across UpdatePath) | magic `AT-INC`, version, APF group, subject, generation, leaf signature key |
| APF admission certificate (`0xf042`) | KeyPackage extension (staged construction) | as in `docs/OPENMLS-INTEGRATION-READY.md` |

`RequiredCapabilities` makes `0xf043` and `0xf044` mandatory for every leaf.
After merging any commit or Welcome, every member runs the **coherence check**
before its SQLite COMMIT:

1. the `acc_context` signature is valid, its group is the APF group, and its
   revision does not decrease;
2. every leaf carries a valid `authz_incarnation` whose subject equals the leaf's
   credential identity and whose signature key equals the leaf's key;
3. the multiset of leaf incarnations equals the `acc_context` roster exactly.

If the check fails, the transaction rolls back and the endpoint stays at its
parent epoch.

## Canonical frontier and ordering

The kernel's `branch` in lap mode is
`SHA-256("AT-FRONTIER" ‖ group ‖ epoch ‖ tree_hash ‖ confirmed_transcript_hash)`,
which the kernel computes from the reported MLS group context. Release, emit,
and consume are therefore bound to the real MLS epoch.

A membership transition proceeds as follows:

1. The committer creates and merges the commit inside its MLS transaction. Its
   own coherence check runs before anything else happens.
2. The adapter derives the evidence: the parent frontier, the successor
   frontier, the removed subjects (from the actual Remove proposals and the
   leaves' incarnations), whether an UpdatePath is present, and the
   `acc_context` revision and roster.
3. The kernel `admit` / `repair` transaction is **the canonical decision**. It
   compares the parent with the current frontier (CAS), so at most one
   successor wins. It also records the canonical commit bytes in its
   hash-chained state, as the sequencer's delivery log.
4. Only after the kernel accepts does the committer COMMIT locally and the
   adapter deliver the commit and Welcome. On a kernel rejection, the
   committer's transaction rolls back to the parent.

**Not covered:** a committer whose local COMMIT fails *after* the kernel
accepted. OpenMLS does not let a member process its own commit, so that member
must rejoin. The other members install the transition from the canonical
commit log.

## Repair

A read revocation that affects a current reader closes the central fence and
records `denial_revision`. Repair has two kernel steps:

- `repair` accepts only a commit whose Remove set is exactly the set of
  affected readers, that carries an UpdatePath, and whose `acc_context` revision
  is the current revision and at least `denial_revision`. The fence stays
  closed.
- `confirm_repair` opens the fence only when the designated continuing member
  reports **its own** installed frontier, read from its merged group context
  after its durable COMMIT, and that frontier equals the canonical one.

Every other client stays locally fenced until it installs the successor: the
adapter delivers a release only when the recipient's own installed frontier
equals the frontier in the release certificate.

## Release binding

`send` follows this order: allocate, then `release` (kernel cover from the
current roster), then sign the release certificate, then protect once with
`AAD = SHA-256(certificate)`, then persist the envelope (certificate ‖
ciphertext), then emit.

`receive` checks the certificate signature, the local frontier, decrypts, and
checks `AAD = SHA-256(certificate)` and `SHA-256(plaintext) = digest`. Only
then does it call kernel `consume` (at most once per recipient), and only after
that is the plaintext delivered.
