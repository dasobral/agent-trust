"""Contract tests for the fail-closed public verification entrypoint."""

from __future__ import annotations

import io
import subprocess
import unittest
from unittest.mock import Mock

from scripts import verify


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class VerificationEntrypointTests(unittest.TestCase):
    def test_both_nonempty_public_gates_pass(self):
        runner = Mock(
            side_effect=[
                completed([], stdout="Ran 21 tests in 0.1s\n\nOK\n"),
                completed([], stdout="test result: ok. 30 passed; 0 failed\n"),
            ]
        )
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: "/bin/cargo", out=output)

        self.assertEqual(status, 0)
        self.assertIn("PASS python-oracle (21 tests)", output.getvalue())
        self.assertIn("PASS rust (30 tests)", output.getvalue())
        self.assertEqual(runner.call_count, 2)

    def test_missing_cargo_is_an_explicit_unmet_gate(self):
        runner = Mock()
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: None, out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("UNMET rust: cargo not found", output.getvalue())
        runner.assert_not_called()

    def test_python_gate_failure_stops_before_rust(self):
        runner = Mock(side_effect=[completed([], returncode=1, stderr="FAILED\n")])
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: "/bin/cargo", out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL python-oracle", output.getvalue())
        self.assertEqual(runner.call_count, 1)

    def test_rust_gate_failure_is_not_reported_as_success(self):
        runner = Mock(
            side_effect=[
                completed([], stdout="Ran 21 tests in 0.1s\n\nOK\n"),
                completed([], returncode=101, stderr="test result: FAILED\n"),
            ]
        )
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: "/bin/cargo", out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL rust", output.getvalue())

    def test_zero_test_success_codes_fail_closed(self):
        runner = Mock(
            side_effect=[
                completed([], stdout="Ran 0 tests in 0.0s\n\nOK\n"),
            ]
        )
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: "/bin/cargo", out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL python-oracle: no tests executed", output.getvalue())
        self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
