"""Black-box contract tests for the agent-trust command-line adapter."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"


class AuthorityCliTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"CLI binary is missing: {BINARY}")

    def run_cli(self, *args, stdin=""):
        try:
            return subprocess.run(
                [os.fspath(BINARY), *args],
                input=stdin,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"CLI timed out after 20 seconds: {exc}")

    @staticmethod
    def lines(*requests):
        return "".join(json.dumps(request) + "\n" for request in requests)

    def authority(self, state, *requests):
        result = self.run_cli("authority", "--state", os.fspath(state), stdin=self.lines(*requests))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        output = result.stdout.splitlines()
        self.assertEqual(len(output), len(requests), result.stdout)
        return [json.loads(line) for line in output]

    def test_malformed_json_returns_error_and_processing_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "authority.sqlite"
            result = self.run_cli(
                "authority", "--state", os.fspath(state),
                stdin='{broken json\n' + json.dumps({"command": "init", "group": "group-a", "root": "root"}) + "\n"
                + json.dumps({"command": "checkpoint"}) + "\n",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(responses[0], {"error": "malformed"})
            self.assertEqual(responses[1], {"ok": {"revision": 0, "epoch": 0, "branch": "genesis"}})
            self.assertEqual(responses[2]["ok"]["group"], "group-a")
            self.assertEqual(responses[2]["ok"]["roster"], ["root"])

    def test_state_persists_across_process_reopening(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "authority.sqlite"
            first = self.authority(state, {"command": "init", "group": "group-a", "root": "root"})
            self.assertEqual(first, [{"ok": {"revision": 0, "epoch": 0, "branch": "genesis"}}])
            second = self.authority(state, {"command": "checkpoint"})
            snapshot = second[0]["ok"]
            self.assertEqual(snapshot["group"], "group-a")
            self.assertEqual(snapshot["revision"], 0)
            self.assertEqual(snapshot["epoch"], 0)
            self.assertEqual(snapshot["branch"], "genesis")
            self.assertFalse(snapshot["read_fenced"])
            self.assertEqual(snapshot["roster"], ["root"])

    def test_replay_consume_round_trip_and_checkpoint_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "authority.sqlite"
            setup = self.authority(
                state,
                {"command": "init", "group": "group-a", "root": "root"},
                {"command": "grant", "actor": "root", "subject": "alice", "right": "read", "generation": 0, "fresh_keys": True, "now": 10},
                {"command": "grant", "actor": "root", "subject": "alice", "right": "admit", "generation": 0, "fresh_keys": True, "now": 10},
                {"command": "admit", "actor": "root", "subject": "alice", "now": 10},
                {"command": "grant", "actor": "root", "subject": "writer", "right": "read", "generation": 0, "fresh_keys": True, "now": 10},
                {"command": "grant", "actor": "root", "subject": "writer", "right": "write", "generation": 0, "fresh_keys": True, "now": 10},
                {"command": "grant", "actor": "root", "subject": "writer", "right": "admit", "generation": 0, "fresh_keys": True, "now": 10},
                {"command": "admit", "actor": "root", "subject": "writer", "now": 10},
            )
            self.assertTrue(all("ok" in response for response in setup))
            cover = [
                [{"subject": "writer", "right": "write", "generation": 0}],
                [{"subject": "writer", "right": "read", "generation": 0}],
                [{"subject": "root", "right": "read", "generation": 0}],
                [{"subject": "alice", "right": "read", "generation": 0}],
            ]
            allocated = self.authority(
                state,
                {"command": "allocate", "actor": "writer", "op": "op-1"},
            )
            self.assertEqual(allocated, [{"ok": {"op": "op-1"}}])
            checkpoint = self.authority(state, {"command": "checkpoint"})[0]["ok"]
            responses = self.authority(
                state,
                {"command": "release", "actor": "writer", "op": "op-1", "right": "write", "revision": checkpoint["revision"], "epoch": checkpoint["epoch"], "branch": checkpoint["branch"], "digest": "a1b2", "cover": cover, "now": 11},
                {"command": "persist", "op": "op-1", "digest": "a1b2", "envelope": "deadbeef"},
                {"command": "consume", "op": "op-1", "recipient": "alice", "now": 11},
            )
            self.assertEqual(responses[0]["ok"]["digest"], "a1b2")
            self.assertEqual(responses[1], {"ok": {"op": "op-1"}})
            self.assertEqual(responses[2], {"ok": {"op": "op-1", "recipient": "alice"}})
            final = self.authority(state, {"command": "checkpoint"})[0]["ok"]
            self.assertIn("history_root", final)
            self.assertIsInstance(final["history"], list)
            self.assertGreaterEqual(len(final["history"]), 1)
            # authority_contract.rs defines the durable history sequence as zero-based.
            self.assertEqual(final["history"][0]["sequence"], 0)

    def test_invalid_args_and_store_failure_are_nonzero_with_usage(self):
        unknown = self.run_cli("unknown-command")
        self.assertNotEqual(unknown.returncode, 0)
        self.assertIn("usage", unknown.stderr.lower())
        missing_state = self.run_cli("authority")
        self.assertNotEqual(missing_state.returncode, 0)
        bad_store = self.run_cli("authority", "--state", "/path/that/cannot/exist/authority.sqlite")
        self.assertNotEqual(bad_store.returncode, 0)

    def test_mls_demo_reports_the_required_experiment_summary(self):
        result = self.run_cli("mls-demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout),
            {
                "baseline_retained_reader_decrypts": True,
                "removed_reader_rejected": True,
                "continuing_reader_decrypts": True,
                "epoch_advanced": True,
                "full_lap_mls": False,
                "staged_keypackage_binding_verified": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
