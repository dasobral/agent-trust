# Authority adversarial contract coverage

`tests/authority_adversarial.rs` contributes ten independent contract tests. The
suite was written before reviewing production implementation and should be run
red before the corresponding implementation is accepted. If implementation
appears before that red run, treat these as regression-first coverage rather
than original TDD evidence.

## Expected failures before coverage

| Test | Required behavior | Expected rejection / result |
| --- | --- | --- |
| `persisted_operation_consumes_once_across_restarts_and_the_first_consume_progresses` | Persist consumption state durably; allow one valid consume and reject a replay after a second restart. | first consume succeeds; second is `replay` |
| `denied_release_from_an_independent_handle_cannot_poison_a_reserved_operation` | Reload committed state across handles and make denied releases atomic. | denied attempt is `unauthorized`; owner may still release |
| `release_requires_a_preexisting_reservation_and_leaves_no_operation_state_on_failure` | Bind releases only to allocated operations. | `invalid_transition` |
| `malformed_cover_is_rejected_without_consuming_the_reservation` | Validate cover structure before changing reservation state. | `malformed`; subsequent valid release succeeds |
| `delegation_rejects_child_validity_that_outlives_its_parent` | Attenuate delegation expiry. | `invalid_delegation` |
| `delegation_rejects_a_child_depth_that_is_not_strictly_lower` | Attenuate delegation depth. | `invalid_delegation` |
| `delegation_rejects_resources_outside_the_parent_grant` | Attenuate delegated resources. | `invalid_delegation` |
| `delegation_rejects_rights_the_parent_does_not_hold` | Attenuate delegated rights. | `invalid_delegation` |
| `stale_reader_generation_cannot_satisfy_a_release_cover_after_reallow` | Reject a cover with Alice's revoked generation after fresh-key reallow. | `unsound_cover` |
| `repair_cannot_be_replayed_against_its_former_parent_branch` | Make repair a one-time transition from the exact fenced parent. | `invalid_repair` |

These scenarios intentionally complement the baseline suite: consumption replay
and restart durability, release reservation integrity, independent-handle denial
history, malformed cover atomicity, all four delegation attenuation dimensions,
stale cover generation, and repair replay.
