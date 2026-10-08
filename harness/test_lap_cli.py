"""Black-box test of `agent-trust lap-demo`: the coupled APF/OpenMLS scenario.

Written after the adapter implementation (characterization of the CLI). The
behavioral reds for the underlying gates are in evidence/lap-*-red.txt.
"""

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"
GATES = {
    "members_bound_to_apf_frontier_and_acc_context",
    "authorized_release_delivered",
    "release_binding_enforced",
    "rolled_back_client_replay_rejected",
    "forged_acc_context_rejected",
    "fenced_until_qualifying_repair",
    "qualifying_repair_confirmed",
    "removed_retained_state_rejected",
    "continuing_reader_decrypts",
    "pre_cut_release_rejected_after_repair",
}


class LapCliTests(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"CLI binary is missing: {BINARY}")

    def test_lap_demo_reports_every_gate_and_the_profile(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("AGENT_TRUST_ENTROPY_CONFIG", "AGENT_TRUST_QRNG_BASE_URL")
        }
        result = subprocess.run(
            [os.fspath(BINARY), "lap-demo"],
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        summary = json.loads(result.stdout)
        self.assertEqual(set(summary["gates"]), GATES)
        for gate, passed in summary["gates"].items():
            self.assertIs(passed, True, gate)
        self.assertIs(summary["api_only_revocation_leaks"], True)
        self.assertIs(summary["full_lap_mls"], True)
        self.assertEqual(summary["entropy_source"], "os")
        self.assertIn("Bridge_remove^ETK proof obligation open", summary["profile"])

    def test_lap_demo_rejects_unexpected_arguments(self):
        result = subprocess.run(
            [os.fspath(BINARY), "lap-demo", "--bogus"],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
