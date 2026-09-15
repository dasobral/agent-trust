# Authority implementation report

Implemented `src/authority.rs` as a durable trusted-local kernel backed by SQLite. Every request reloads and validates committed state; mutations run in immediate transactions. The persisted event stream is SHA-256 hash chained and each event embeds the post-transition snapshot, so replay binds the current snapshot to the durable history. The implementation validates untrusted JSON types, bounded IDs, generations, delegation closure and validity, roster/fence behavior, exact cover supports, and immutable operation payload bindings.

The command boundary remains intentionally local and trusted: actor identifiers and repair fixture booleans are not authentication or MLS proof.

## Test evidence

An initial focused run completed with 11/12 tests passing; the single failure was checkpoint history being returned as an empty array. That was corrected by reading the validated durable event table into the checkpoint response.

A subsequent focused run was blocked before authority tests by concurrent edits to the separately-owned `src/mls.rs` (OpenMLS trait/import compile errors). I did not modify that component.

At coordinator direction, I removed a premature `consume` implementation and left a compiling `invalid_transition` stub pending independent consume/adversarial tests and their red run. This is intentionally incomplete until those tests are supplied.
