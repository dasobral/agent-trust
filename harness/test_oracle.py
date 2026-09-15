"""Independent contract tests for harness.oracle.check_trace.

Run normally with: python -m unittest -v harness.test_oracle
Run the intentional negative control with: AGENT_TRUST_ORACLE=permissive ...
"""

from __future__ import annotations

import importlib
import os
import unittest

from harness.fixtures import init_event, permissive_check_trace, release_event


def check_trace(events):
    if os.environ.get("AGENT_TRUST_ORACLE") == "permissive":
        return permissive_check_trace(events)
    return importlib.import_module("harness.oracle").check_trace(events)


def alloc(op="op-1", event_id="e-allocate"):
    return {"event_id": event_id, "type": "allocate", "op": op}


def persist(op="op-1", envelope="bytes-1", digest="digest-1", event_id="e-persist"):
    return {"event_id": event_id, "type": "persist", "op": op,
            "envelope": envelope, "digest": digest}


def emit(op="op-1", envelope="bytes-1", event_id="e-emit"):
    return {"event_id": event_id, "type": "emit", "op": op,
            "envelope": envelope}


def consume(op="op-1", recipient="bob#1", event_id="e-consume"):
    return {"event_id": event_id, "type": "consume", "op": op,
            "recipient": recipient}


def deny(subject="bob#1", right="read", event_id="e-deny"):
    return {"event_id": event_id, "type": "deny", "subject": subject,
            "right": right}


def allow(subject="bob#1", right="read", generation=2, event_id="e-allow"):
    return {"event_id": event_id, "type": "allow", "subject": subject,
            "right": right, "generation": generation, "fresh_keys": True}


def recover(client, epoch=0, branch="main", event_id="e-recover"):
    return {"event_id": event_id, "type": "recover", "client": client,
            "epoch": epoch, "branch": branch}


def repair(removed, event_id="e-repair"):
    return {"event_id": event_id, "type": "repair", "parent_branch": "main",
            "new_branch": "repaired", "epoch": 1, "revision": 1,
            "removed": removed, "update_path": True, "confirmed": True,
            "durable": True}


class TraceContractTests(unittest.TestCase):
    maxDiff = None

    def violations(self, events):
        answer = check_trace(events)
        self.assertIsInstance(answer, list)
        for item in answer:
            self.assertEqual(set(item), {"index", "code"})
            self.assertIsInstance(item["index"], int)
            self.assertIsInstance(item["code"], str)
        return answer

    def assert_clean(self, events):
        self.assertEqual(self.violations(events), [])

    def assert_has(self, events, index, code):
        self.assertIn({"index": index, "code": code}, self.violations(events))

    def test_good_nonvacuous_write_trace_and_identical_repeat_emit(self):
        self.assert_clean([init_event(), alloc(), release_event(), persist(), emit(),
                           emit(event_id="e-emit-again"), consume()])

    def test_good_read_release_requires_reader_cover(self):
        events = [init_event(), alloc(), release_event(right="read"), persist(), emit(),
                  consume(recipient="bob#1")]
        self.assert_clean(events)

    def test_empty_malformed_and_unknown_traces_are_rejected(self):
        self.assert_has([], 0, "not_initialized")
        self.assert_has([init_event(), {"event_id": "e-malformed", "type": "allocate"}],
                        1, "malformed")
        self.assert_has([init_event(), {"event_id": "e-unknown", "type": "teleport"}],
                        1, "malformed")

    def test_duplicate_event_id_is_rejected(self):
        events = [init_event(), alloc(), {"event_id": "e-allocate", "type": "allocate", "op": "op-2"}]
        self.assert_has(events, 2, "duplicate_event")

    def test_duplicate_operation_allocation_is_rejected(self):
        self.assert_has([init_event(), alloc(), alloc(event_id="e-allocate-again")],
                        2, "duplicate_operation")

    def test_read_deny_fences_fresh_release_and_blocks_delivery(self):
        events = [init_event(), deny(), alloc(), release_event(), persist(), emit(), consume()]
        self.assert_has(events, 3, "read_fenced")
        self.assert_has(events, 5, "read_fenced")
        self.assert_has(events, 6, "read_fenced")

    def test_pre_cut_historical_release_can_emit_but_not_deliver_after_deny(self):
        events = [init_event(), alloc(), release_event(), persist(), deny(), emit(), consume()]
        self.assert_has(events, 6, "read_fenced")
        self.assertEqual(self.violations(events[:6]), [])

    def test_read_cover_omitting_roster_member_is_unsound(self):
        events = [init_event(), alloc(), release_event(right="read", cover=[
            [{"subject": "alice#1", "right": "read", "generation": 1}]
        ])]
        self.assert_has(events, 2, "unsound_cover")

    def test_denied_extra_cover_support_is_unsound(self):
        events = [init_event(), deny(subject="carol#1"), alloc(), release_event(revision=1,
            cover=[
                [{"subject": "alice#1", "right": "write", "generation": 1}],
                [{"subject": "carol#1", "right": "read", "generation": 1}],
            ])]
        self.assert_has(events, 3, "unsound_cover")

    def test_joint_support_with_denied_member_is_unsound_despite_valid_alternatives(self):
        initial = init_event()
        initial["grants"].append({"subject": "carol#1", "right": "write", "generation": 1})
        cover = [
            [{"subject": "alice#1", "right": "read", "generation": 1}],
            [{"subject": "bob#1", "right": "read", "generation": 1}],
            [
                {"subject": "alice#1", "right": "admin", "generation": 1},
                {"subject": "carol#1", "right": "write", "generation": 1},
            ],
        ]
        events = [initial, deny(subject="carol#1", right="write"), alloc(),
                  release_event(right="read", revision=1, cover=cover)]
        self.assert_has(events, 3, "unsound_cover")

    def test_release_digest_and_persisted_bytes_are_frozen(self):
        wrong_digest = [init_event(), alloc(), release_event(), persist(digest="other-digest")]
        self.assert_has(wrong_digest, 3, "binding_mismatch")
        changed_bytes = [init_event(), alloc(), release_event(), persist(),
                         persist(envelope="other-bytes", event_id="e-persist-other")]
        self.assert_has(changed_bytes, 4, "binding_mismatch")

    def test_abandon_is_terminal_and_idempotent(self):
        abandoned = {"event_id": "e-abandon", "type": "abandon", "op": "op-1"}
        self.assert_clean([init_event(), alloc(), release_event(), abandoned,
                           {**abandoned, "event_id": "e-abandon-again"}])
        self.assert_has([init_event(), alloc(), release_event(), abandoned, persist()],
                        4, "invalid_transition")

    def test_replay_of_consumed_cell_is_rejected(self):
        events = [init_event(), alloc(), release_event(), persist(), emit(), consume(),
                  consume(event_id="e-consume-again")]
        self.assert_has(events, 6, "replay")

    def test_crash_requires_exact_recovery_before_consume(self):
        events = [init_event(), alloc(), release_event(), persist(),
                  {"event_id": "e-crash", "type": "crash", "client": "bob#1"},
                  consume(), recover("bob#1"), consume(event_id="e-consume-after-recover")]
        self.assert_has(events, 5, "not_ready")
        self.assert_clean(events[:5] + events[6:])

    def test_malformed_boolean_and_numeric_frontier_are_rejected(self):
        malformed_init = init_event()
        malformed_init["revision"] = False
        self.assert_has([malformed_init], 0, "malformed")
        events = [init_event(), alloc(), release_event(revision=True)]
        self.assert_has(events, 2, "malformed")

    def test_stale_recovery_is_rejected(self):
        events = [init_event(), deny(), repair(["bob#1"]), recover("alice#1", epoch=0),]
        self.assert_has(events, 3, "stale_frontier")

    def test_emit_on_a_superseded_branch_is_rejected(self):
        events = [init_event(), alloc(), release_event(), persist(), deny(), repair(["bob#1"]),
                  emit()]
        self.assert_has(events, 6, "stale_frontier")

    def test_repair_requires_complete_removals_and_cannot_reopen_without_path(self):
        incomplete = [init_event(), deny(), repair([])]
        self.assert_has(incomplete, 2, "invalid_repair")
        no_path = repair(["bob#1"], event_id="e-repair-no-path")
        no_path["update_path"] = False
        self.assert_has([init_event(), deny(), no_path], 2, "invalid_repair")

    def test_repair_then_recovery_reopens_for_continuing_reader(self):
        events = [init_event(), deny(), repair(["bob#1"]), recover("alice#1", epoch=1, branch="repaired"),
                  alloc("op-2", "e-allocate-2"),
                  release_event("op-2", epoch=1, branch="repaired", revision=1,
                                digest="digest-2", event_id="e-release-2"),
                  persist("op-2", "bytes-2", "digest-2", "e-persist-2"),
                  emit("op-2", "bytes-2", "e-emit-2"),
                  consume("op-2", "alice#1", "e-consume-2")]
        self.assert_clean(events)

    def test_allow_requires_higher_new_generation_and_admit_reuses_active_generation(self):
        old_generation = [init_event(), deny(), allow(generation=1)]
        self.assert_has(old_generation, 2, "invalid_generation")
        admission = {"event_id": "e-admit", "type": "admit", "subject": "carol#1",
                     "generation": 1, "fresh_keys": True}
        events = [init_event(), deny(), repair(["bob#1"]),
                  allow(subject="bob#1", generation=2), admission]
        self.assert_clean(events)


if __name__ == "__main__":
    unittest.main()
