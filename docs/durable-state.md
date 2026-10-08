# Durable MLS endpoint state

`MlsLab::open_durable(dir, entropy)` gives each laboratory endpoint its own
OpenMLS state file, `<dir>/<name>.sqlite`. `MlsLab::new()` and
`MlsLab::with_entropy()` use the same SQLite storage provider, but in memory.

## Storage

- Provider: `openmls_sqlite_storage` from the pinned OpenMLS fork
  (`6daabe33ddb616a6ed54b511d333e691db18a99f`), with a `serde_json` codec.
- Each file uses `journal_mode = DELETE` and `synchronous = FULL`.
- Existing state files are never reused or overwritten. If an admission fails,
  the file it created is removed, so the admission can be retried.
- Member names are restricted to `[A-Za-z0-9_-]`, because each name becomes a
  file name.
- State files contain private keys. `*.sqlite` is git-ignored. Never place state
  files in `evidence/`.

## Durability boundary

Every MLS operation on an endpoint runs in one SQLite transaction (`BEGIN
IMMEDIATE … COMMIT`): group creation, KeyPackage staging, Welcome join, commit
creation and merge, commit processing, and protecting or decrypting a message
(both of which advance the secret tree). An epoch transition is therefore either
installed completely or not at all. When an operation fails, its transaction
rolls back and the in-memory group is reloaded from storage, so memory never
runs ahead of the durable state.

## Restart and crash injection

- `restart_member(name)` drops every in-memory object for the member. It then
  reloads the group (`MlsGroup::load`) and the signing key
  (`SignatureKeyPair::read`) from the member's file and redelivers any commits
  the member missed. It returns the loaded epoch and the caught-up epoch.
- `arm_crash_before_commit(name)` makes the member's next commit processing
  write the successor state and then close the connection without COMMIT. The
  member goes offline, and the other members continue (an offline client cannot
  block continuing members). The crash is simulated by closing the connection
  while the transaction is still open, which makes SQLite roll it back on close.
  Hot-journal recovery after a hard process kill (`kill -9`, power loss) is not
  exercised.
- `retain_storage_copy(name, copy)` copies the member's quiescent file byte for
  byte and opens the copy in a fresh connection as a stale endpoint. This is the
  retained-state adversary from the compatibility matrix.

## Not covered

- A crash of the committing member between commit creation and COMMIT. This is
  the protect/persist/emit ordering and canonical-frontier (parent CAS) problem,
  and it belongs to the APF↔MLS coupling milestone.
- Laboratory metadata (roster names, the laboratory APF key, admission
  evidence) is held in memory, so a whole-laboratory restart is not provided.
- Durability against storage rollback or a compromised host. The specification
  does not cover this for the client role either.

`full_lap_mls` remains `false`.
