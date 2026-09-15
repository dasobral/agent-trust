"""Regression tests for strict repair validation in the trace oracle."""

from __future__ import annotations

import unittest

from harness.fixtures import init_event
from harness.oracle import check_trace


class RepairValidationTests(unittest.TestCase):
    def test_repair_cannot_remove_reallowed_pending_reader(self):
        events = [
            init_event(),
            {"event_id": "e-deny", "type": "deny", "subject": "bob#1", "right": "read"},
            {"event_id": "e-allow", "type": "allow", "subject": "bob#1", "right": "read",
             "generation": 2, "fresh_keys": True},
            {"event_id": "e-repair", "type": "repair", "parent_branch": "main",
             "new_branch": "repaired", "epoch": 1, "revision": 2, "removed": ["bob#1"],
             "update_path": True, "confirmed": True, "durable": True},
        ]

        self.assertIn({"index": 3, "code": "invalid_repair"}, check_trace(events))


if __name__ == "__main__":
    unittest.main()
