"""Unit tests of the control plane. Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "controller"))

from attctl import experiment, oracle, topology  # noqa: E402
from attctl.deploy import compose  # noqa: E402

TOPOLOGY = REPO / "topologies" / "three-agents.toml"


class TopologyTests(unittest.TestCase):
    def test_three_agents_topology_plans_one_service_per_component(self):
        topo = topology.Topology.load(TOPOLOGY)
        plan = topology.plan(topo, lambda name, role: f"http://{name}:1")
        names = [s.name for s in plan.services]
        self.assertEqual(names, ["qrng", "apf", "relay", "alice", "bob", "carol"])
        root = plan.service("alice").env
        self.assertEqual(root["ATT_BOOTSTRAP_TOKEN"], plan.tokens["bootstrap"])
        self.assertNotIn("ATT_BOOTSTRAP_TOKEN", plan.service("bob").env)
        self.assertEqual(plan.service("bob").env["AGENT_TRUST_QRNG_BASE_URL"], "http://qrng:1")
        self.assertEqual(plan.service("apf").env["AGENT_TRUST_ENTROPY_SOURCE"], "qrng")

    def test_root_must_be_an_agent(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as handle:
            handle.write('name="x"\ngroup="g"\nroot="zed"\n[[agent]]\nname="a"\n')
        with self.assertRaises(ValueError):
            topology.Topology.load(handle.name)

    def test_external_qrng_url_replaces_the_mock_service(self):
        topo = topology.Topology.load(TOPOLOGY)
        topo.entropy = {"source": "qrng", "url": "https://entropy.example"}
        plan = topology.plan(topo, lambda name, role: f"http://{name}:1",
                             extra_env={"AGENT_TRUST_QRNG_API_KEY": "k"})
        self.assertNotIn("qrng", [s.name for s in plan.services])
        env = plan.service("alice").env
        self.assertEqual(env["AGENT_TRUST_QRNG_BASE_URL"], "https://entropy.example")
        self.assertEqual(env["AGENT_TRUST_QRNG_API_KEY"], "k")


class ComposeTests(unittest.TestCase):
    def test_compose_publishes_only_on_loopback(self):
        topo = topology.Topology.load(TOPOLOGY)
        plan = topology.plan(topo, lambda name, role: f"http://{name}:{topology.PORTS[role]}")
        ports = {s.name: 20000 + i for i, s in enumerate(plan.services)}
        text = compose.render(plan, ports, "img:tag", "att-test")
        self.assertIn('"127.0.0.1:20000:7200"', text)
        self.assertNotIn('"0.0.0.0:', text.replace('ATT_LISTEN: "0.0.0.0', ""))
        self.assertIn("apf-state:/var/lib/att/apf", text)


class ExperimentTests(unittest.TestCase):
    def test_every_experiment_step_has_a_handler(self):
        for path in sorted((REPO / "experiments").glob("*.toml")):
            exp = experiment.Experiment(path)
            self.assertTrue(exp.topology_path.is_file(), path)
            for step in exp.steps:
                handler = "do_" + step["do"].replace(".", "_")
                self.assertTrue(hasattr(experiment.Runner, handler), f"{path.name}: {step['do']}")


class OracleTests(unittest.TestCase):
    """The broken controls against the most recent recorded E1 trace."""

    def setUp(self):
        traces = sorted((REPO / "results").glob("E1/*/trace.json"))
        if not traces:
            self.skipTest("no recorded E1 trace yet")
        self.trace = json.loads(traces[-1].read_text())
        self.module, _ = oracle.load()

    def test_recorded_trace_is_accepted(self):
        self.assertEqual(self.module.check_trace(self.trace), [])

    def test_every_broken_control_is_rejected_with_its_code(self):
        controls, skipped = oracle.broken_controls(self.trace, "carol", "alice")
        self.assertEqual(skipped, [])
        self.assertGreaterEqual(len(controls), 8)
        for label, (events, index, code) in controls.items():
            with self.subTest(control=label):
                self.assertEqual(self.module.check_trace(events), [{"index": index, "code": code}])


if __name__ == "__main__":
    unittest.main()
