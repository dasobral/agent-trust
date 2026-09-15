import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"


class ConfusedDeputyCliTest(unittest.TestCase):
    def test_provenance_changes_write_decision(self):
        with tempfile.TemporaryDirectory(prefix="agent-trust-cli-") as directory:
            process = subprocess.Popen(
                [str(BINARY), "authority", "--state", str(pathlib.Path(directory) / "state.sqlite")],
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )

            def call(command):
                process.stdin.write(json.dumps(command) + "\n")
                process.stdin.flush()
                response = json.loads(process.stdout.readline())
                self.assertNotIn("error", response, response)
                return response["ok"]

            def frontier():
                return call({"command": "checkpoint"})

            def release(operation):
                current = frontier()
                return call({
                    "command": "release",
                    "actor": "parent",
                    "op": operation,
                    "right": "write",
                    "resource": "group-a",
                    "revision": current["revision"],
                    "epoch": current["epoch"],
                    "branch": current["branch"],
                    "digest": "aa",
                    "cover": [
                        [{"subject": "root", "right": "read", "generation": 0}],
                        [{"subject": "parent", "right": "read", "generation": 0}],
                        [{"subject": "parent", "right": "write", "generation": 0}],
                    ],
                    "now": 10,
                })

            call({"command": "init", "group": "group-a", "root": "root"})
            for right in ("read", "write", "admit"):
                call({
                    "command": "grant", "actor": "root", "subject": "parent",
                    "right": right, "generation": 0, "fresh_keys": True, "now": 10,
                })
            call({"command": "admit", "actor": "root", "subject": "parent", "now": 10})
            call({
                "command": "grant", "actor": "root", "subject": "child",
                "right": "read", "generation": 0, "fresh_keys": True, "now": 10,
            })
            invocation = call({
                "command": "invoke", "actor": "child", "executor": "parent",
                "rights": ["read"], "resources": ["group-a"], "now": 10,
            })["invocation"]
            call({
                "command": "allocate", "actor": "parent", "op": "child-write",
                "resource": "group-a", "invocation": invocation,
            })

            current = frontier()
            process.stdin.write(json.dumps({
                "command": "release", "actor": "parent", "op": "child-write",
                "right": "write", "resource": "group-a",
                "revision": current["revision"], "epoch": current["epoch"],
                "branch": current["branch"], "digest": "aa",
                "cover": [
                    [{"subject": "root", "right": "read", "generation": 0}],
                    [{"subject": "parent", "right": "read", "generation": 0}],
                    [{"subject": "parent", "right": "write", "generation": 0}],
                ],
                "now": 10,
            }) + "\n")
            process.stdin.flush()
            response = json.loads(process.stdout.readline())
            self.assertEqual(response, {"error": "unauthorized"})

            call({"command": "allocate", "actor": "parent", "op": "parent-write", "resource": "group-a"})
            allowed = release("parent-write")
            self.assertEqual(allowed["executor"], "parent")
            self.assertIsNone(allowed["invocation"])
            self.assertEqual(allowed["effective_right"], "write")

            process.stdin.close()
            self.assertEqual(process.wait(timeout=5), 0)
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
