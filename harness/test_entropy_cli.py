"""Black-box tests: the CLI selects its entropy source through configuration.

The development fake QRNG server (scripts/fake_qrng.py) stands in for Entropy
Core. Pointing the same configuration at a real endpoint requires no code change.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"
FAKE = ROOT / "scripts" / "fake_qrng.py"
ENTROPY_VARIABLES = ("AGENT_TRUST_ENTROPY_CONFIG", "AGENT_TRUST_QRNG_BASE_URL")


def clean_env(**extra):
    env = {key: value for key, value in os.environ.items() if key not in ENTROPY_VARIABLES}
    env.update(extra)
    return env


class EntropyCliTests(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"CLI binary is missing: {BINARY}")
        self.fake = subprocess.Popen(
            [sys.executable, os.fspath(FAKE), "--port", "0"],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._stop_fake)
        self.base_url = self.fake.stdout.readline().strip()
        self.assertTrue(self.base_url.startswith("http://127.0.0.1:"), self.base_url)

    def _stop_fake(self):
        if self.fake.poll() is None:
            self.fake.terminate()
            self.fake.wait(timeout=10)
        self.fake.stdout.close()

    def stats(self):
        with urllib.request.urlopen(self.base_url + "/_fake/stats", timeout=5) as response:
            return json.load(response)

    def run_demo(self, *args, env=None):
        return subprocess.run(
            [os.fspath(BINARY), "mls-demo", *args],
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
            env=env if env is not None else clean_env(),
        )

    def write_config(self, directory, base_url):
        path = Path(directory) / "entropy.toml"
        path.write_text(
            f'source = "qrng"\n[qrng]\nbase_url = "{base_url}"\ntransport = "plain-http"\n'
        )
        return path

    def test_config_file_flag_routes_demo_entropy_through_the_fake_qrng(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.write_config(directory, self.base_url)
            result = self.run_demo("--entropy-config", os.fspath(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["entropy_source"], "qrng")
        self.assertTrue(summary["removed_reader_rejected"])
        self.assertFalse(summary["full_lap_mls"])
        self.assertGreater(self.stats()["entropy_posts"], 0)

    def test_environment_variables_select_the_fake_qrng(self):
        result = self.run_demo(env=clean_env(AGENT_TRUST_QRNG_BASE_URL=self.base_url))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["entropy_source"], "qrng")
        posts_after_url = self.stats()["entropy_posts"]
        self.assertGreater(posts_after_url, 0)

        with tempfile.TemporaryDirectory() as directory:
            config = self.write_config(directory, self.base_url)
            result = self.run_demo(env=clean_env(AGENT_TRUST_ENTROPY_CONFIG=os.fspath(config)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["entropy_source"], "qrng")
        self.assertGreater(self.stats()["entropy_posts"], posts_after_url)

    def test_no_configuration_uses_the_os_source(self):
        result = self.run_demo()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["entropy_source"], "os")
        self.assertEqual(self.stats()["entropy_posts"], 0)

    def test_unreachable_configured_qrng_fails_closed(self):
        self._stop_fake()
        with tempfile.TemporaryDirectory() as directory:
            config = self.write_config(directory, self.base_url)
            result = self.run_demo("--entropy-config", os.fspath(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("QRNG", result.stderr)

    def test_invalid_configuration_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "entropy.toml"
            config.write_text('source = "qrng"\n')
            result = self.run_demo("--entropy-config", os.fspath(config))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
