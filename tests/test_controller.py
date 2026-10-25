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
from attctl.deploy import compose, k8s  # noqa: E402

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


class SuiteTests(unittest.TestCase):
    """agent-trust C-42 through the topology: `pq` unless `[mls] suite` says otherwise."""

    def plan_env(self, name):
        topo = topology.Topology.load(REPO / "topologies" / name)
        plan = topology.plan(topo, lambda n, r: f"http://{n}:{topology.PORTS[r]}")
        return topo, {s.name: s.env for s in plan.services}

    def test_the_default_suite_is_pq_and_reaches_the_apf_and_every_agent(self):
        topo, env = self.plan_env("three-agents.toml")
        self.assertEqual(topo.suite, "pq")
        for name in ("apf", *topo.agents):
            self.assertEqual(env[name]["AGENT_TRUST_SUITE"], "pq", name)
        self.assertEqual(env["apf"]["AGENT_TRUST_QRNG_KEY_EXCHANGE"], "pq-only")

    def test_the_classical_topology_selects_classical(self):
        topo, env = self.plan_env("three-agents-classical.toml")
        self.assertEqual(topo.suite, "classical")
        self.assertEqual(env["bob"]["AGENT_TRUST_SUITE"], "classical")

    def test_unknown_suites_and_key_exchanges_are_rejected(self):
        base = topology.Topology.load(REPO / "topologies" / "three-agents.toml")
        base.suite = "kyber"
        with self.assertRaises(ValueError):
            base.validate()
        base.suite = "pq"
        base.entropy["key_exchange"] = "classical"
        with self.assertRaises(ValueError):
            base.validate()


class ComposeTests(unittest.TestCase):
    def test_compose_publishes_only_on_loopback(self):
        topo = topology.Topology.load(TOPOLOGY)
        plan = topology.plan(topo, lambda name, role: f"http://{name}:{topology.PORTS[role]}")
        ports = {s.name: 20000 + i for i, s in enumerate(plan.services)}
        text = compose.render(plan, ports, "img:tag", "att-test")
        self.assertIn('"127.0.0.1:20000:7200"', text)
        self.assertNotIn('"0.0.0.0:', text.replace('ATT_LISTEN: "0.0.0.0', ""))
        self.assertIn("apf-state:/var/lib/att/apf", text)


class TlsPlanTests(unittest.TestCase):
    def test_tls_topology_gives_every_service_its_certificate_and_qrng_mtls(self):
        topo = topology.Topology.load(REPO / "topologies" / "three-agents-mtls.toml")
        self.assertTrue(topo.tls)
        plan = topology.plan(topo, lambda n, r: f"https://{n}:1", tls_dir="/pki")
        for service in plan.services:
            self.assertEqual(service.env["ATT_TLS_NAME"], service.name)
            self.assertEqual(service.env["ATT_TLS_DIR"], "/pki")
        bob = plan.service("bob").env
        self.assertEqual(bob["AGENT_TRUST_QRNG_CLIENT_CERT_PEM"], "/pki/bob.crt")
        self.assertTrue(bob["AGENT_TRUST_QRNG_BASE_URL"].startswith("https://"))
        self.assertIn("bob-app", topo.pki_names())


class KubernetesRenderTests(unittest.TestCase):
    def render(self, tls=False):
        name = "three-agents-mtls.toml" if tls else "three-agents.toml"
        topo = topology.Topology.load(REPO / "topologies" / name)
        plan = topology.plan(topo, lambda n, r: f"http://{n}:{topology.PORTS[r]}",
                             tls_dir=k8s.PKI_PATH if tls else None)
        pki = None
        if tls:
            pki = {"ca.crt": "CA", "classical-ca.crt": "CLASSICAL CA"}
            for service in plan.services:
                for stem in (service.name, f"{service.name}.classical"):
                    pki[f"{stem}.crt"] = f"CRT {stem}"
                    pki[f"{stem}.key"] = f"KEY {stem}"
        return plan, k8s.render(plan, "att-test", "img:tag", pki=pki)["items"]

    def test_no_token_appears_in_a_deployment(self):
        plan, items = self.render()
        text = json.dumps([i for i in items if i["kind"] == "Deployment"])
        for token in plan.tokens.values():
            self.assertNotIn(token, text)

    def test_each_pod_mounts_only_its_own_key(self):
        plan, items = self.render(tls=True)
        secrets = {i["metadata"]["name"]: i for i in items if i["kind"] == "Secret"}
        bob = secrets["att-pki-bob"]["stringData"]
        self.assertEqual(sorted(bob), ["bob.classical.crt", "bob.classical.key", "bob.crt",
                                       "bob.key", "ca.crt", "classical-ca.crt"])
        self.assertFalse(any(name.endswith("ca.key") for name in bob), "no CA key in a pod")
        deployment = next(i for i in items if i["kind"] == "Deployment" and i["metadata"]["name"] == "bob")
        volumes = deployment["spec"]["template"]["spec"]["volumes"]
        self.assertIn({"name": "pki", "secret": {"secretName": "att-pki-bob", "defaultMode": 0o440}}, volumes)

    def test_pods_are_unprivileged_and_ingress_is_denied_by_default(self):
        _, items = self.render()
        for deployment in (i for i in items if i["kind"] == "Deployment"):
            context = deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"]
            self.assertTrue(context["runAsNonRoot"] and context["readOnlyRootFilesystem"])
            self.assertEqual(context["capabilities"], {"drop": ["ALL"]})
        policies = {i["metadata"]["name"]: i["spec"] for i in items if i["kind"] == "NetworkPolicy"}
        self.assertEqual(policies["default-deny-ingress"]["podSelector"], {})
        sources = policies["allow-to-apf"]["ingress"][0]["from"]
        self.assertEqual(sources, [{"podSelector": {"matchLabels": {"app.kubernetes.io/component": "agent"}}}])
        self.assertNotIn("allow-to-agent", policies)


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
