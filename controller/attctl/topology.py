"""Topology: the declarative description of one testbed deployment.

A topology names the group, the root agent, the agents, the cryptographic suite, the
entropy source and the relay seed. ``plan`` turns it into concrete services (role, environment, port) that
any deployment backend can start. Backends only decide *where* a service runs and
*how* its address is written; the services and their configuration are identical.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import tomllib
from pathlib import Path

ROLES = ("qrng-mock", "apf", "relay", "agent")
ENTROPY_SOURCES = ("os", "mock", "qrng")
# agent-trust C-42: `pq` (MLS 0x0052, X-Wing and ML-DSA-44) or `classical` (0x0001).
SUITES = ("pq", "classical")
# openmls-qrand: TLS key exchange of the QRNG link.
QRNG_KEY_EXCHANGES = ("pq-only", "pq-preferred")
# Container ports; the local backend maps each service to its own host port instead.
PORTS = {"qrng-mock": 7200, "apf": 7000, "relay": 7100, "agent": 7300}


@dataclass
class Topology:
    name: str
    group: str
    root: str
    agents: list[str]
    entropy: dict
    relay_seed: int
    tls: bool = False
    suite: str = "pq"
    path: Path | None = None

    @classmethod
    def load(cls, path) -> "Topology":
        path = Path(path)
        data = tomllib.loads(path.read_text())
        agents = [entry["name"] for entry in data.get("agent", [])]
        topology = cls(
            name=data["name"],
            group=data["group"],
            root=data["root"],
            agents=agents,
            entropy=dict(data.get("entropy", {"source": "os"})),
            relay_seed=int(data.get("relay", {}).get("seed", 0)),
            tls=bool(data.get("tls", {}).get("enabled", False)),
            suite=str(data.get("mls", {}).get("suite", "pq")),
            path=path,
        )
        topology.validate()
        return topology

    def validate(self):
        if self.root not in self.agents:
            raise ValueError(f"root {self.root!r} is not one of the agents {self.agents}")
        if len(set(self.agents)) != len(self.agents):
            raise ValueError("agent names must be unique")
        source = self.entropy.get("source", "os")
        if source not in ENTROPY_SOURCES:
            raise ValueError(f"entropy source must be one of {ENTROPY_SOURCES}")
        if source == "qrng" and "url" in self.entropy and self.entropy.get("mock_service"):
            raise ValueError("entropy: give either url (external QRNG) or mock_service, not both")
        if self.suite not in SUITES:
            raise ValueError(f"mls.suite must be one of {SUITES}")
        if self.entropy.get("key_exchange", "pq-only") not in QRNG_KEY_EXCHANGES:
            raise ValueError(f"entropy.key_exchange must be one of {QRNG_KEY_EXCHANGES}")

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    def pki_names(self):
        """Certificate names: every service, an application certificate per agent
        (``<agent>-app``) and ``attctl`` (added by ``att-node pki``)."""
        names = (["qrng"] if self.qrng_mock else []) + ["apf", "relay", *self.agents]
        return names + [f"{agent}-app" for agent in self.agents]

    @property
    def qrng_mock(self) -> bool:
        """True when the deployment runs its own mock QRNG service."""
        return self.entropy.get("source") == "qrng" and "url" not in self.entropy


@dataclass
class Service:
    name: str
    role: str
    env: dict
    port: int
    depends_on: list[str] = field(default_factory=list)


@dataclass
class Plan:
    topology: Topology
    services: list[Service]
    tokens: dict

    def service(self, name) -> Service:
        return next(s for s in self.services if s.name == name)


def new_tokens() -> dict:
    """Per-deployment secrets. They live only in the run directory, never in git."""
    return {kind: secrets.token_hex(16) for kind in ("control", "app", "bootstrap")}


def plan(topology: Topology, address, tokens=None, extra_env=None, tls_dir=None) -> Plan:
    """Builds the service list. ``address(service_name, role)`` returns the base URL
    under which *other services* reach that service (backend specific). With
    ``tls_dir`` (the PKI directory as the services see it) every service gets its
    certificate, and nodes reach the QRNG service over mutual TLS."""
    tokens = tokens or new_tokens()
    extra_env = extra_env or {}
    services = []

    entropy_env = {}
    source = topology.entropy.get("source", "os")
    entropy_env["AGENT_TRUST_ENTROPY_SOURCE"] = source
    # agent-trust C-42: the suite of every identity the services create.
    suite_env = {"AGENT_TRUST_SUITE": topology.suite}
    if source == "mock":
        entropy_env["AGENT_TRUST_MOCK_SEED"] = str(topology.entropy.get("seed", 0))
    if source == "qrng":
        if topology.qrng_mock:
            services.append(Service("qrng", "qrng-mock", {"ATT_CONTROL_TOKEN": tokens["control"]},
                                    PORTS["qrng-mock"]))
            entropy_env["AGENT_TRUST_QRNG_BASE_URL"] = address("qrng", "qrng-mock")
        else:
            entropy_env["AGENT_TRUST_QRNG_BASE_URL"] = topology.entropy["url"]
            # Secrets for a real endpoint are passed through by name, never stored.
            for key in ("AGENT_TRUST_QRNG_BEARER_TOKEN", "AGENT_TRUST_QRNG_API_KEY",
                        "AGENT_TRUST_QRNG_CA_PEM"):
                if key in extra_env:
                    entropy_env[key] = extra_env[key]
        # openmls-qrand: the TLS key exchange of the QRNG link (pq-only by default).
        entropy_env["AGENT_TRUST_QRNG_KEY_EXCHANGE"] = topology.entropy.get(
            "key_exchange", "pq-only")
    entropy_deps = ["qrng"] if topology.qrng_mock else []

    services.append(Service("apf", "apf", {
        "ATT_GROUP": topology.group,
        "ATT_ROOT": topology.root,
        "ATT_STATE_DIR": "/var/lib/att/apf",
        "ATT_CONTROL_TOKEN": tokens["control"],
        "ATT_BOOTSTRAP_TOKEN": tokens["bootstrap"],
        **entropy_env,
        **suite_env,
    }, PORTS["apf"], list(entropy_deps)))
    services.append(Service("relay", "relay", {
        "ATT_SEED": str(topology.relay_seed),
        "ATT_CONTROL_TOKEN": tokens["control"],
    }, PORTS["relay"]))
    for name in topology.agents:
        env = {
            "ATT_NAME": name,
            "ATT_GROUP": topology.group,
            "ATT_APF_URL": address("apf", "apf"),
            "ATT_RELAY_URL": address("relay", "relay"),
            "ATT_CONTROL_TOKEN": tokens["control"],
            "ATT_APP_TOKEN": tokens["app"],
            "ATT_DATA_DIR": "/var/lib/att/agent",
            **entropy_env,
            **suite_env,
        }
        if name == topology.root:
            env["ATT_BOOTSTRAP_TOKEN"] = tokens["bootstrap"]
        services.append(Service(name, "agent", env, PORTS["agent"],
                                ["apf", "relay", *entropy_deps]))
    if tls_dir:
        for service in services:
            service.env["ATT_TLS_DIR"] = tls_dir
            service.env["ATT_TLS_NAME"] = service.name
            if service.role in ("apf", "agent") and topology.qrng_mock:
                service.env["AGENT_TRUST_QRNG_CA_PEM"] = f"{tls_dir}/ca.crt"
                service.env["AGENT_TRUST_QRNG_CLIENT_CERT_PEM"] = f"{tls_dir}/{service.name}.crt"
                service.env["AGENT_TRUST_QRNG_CLIENT_KEY_PEM"] = f"{tls_dir}/{service.name}.key"
    return Plan(topology, services, tokens)
