"""Compose backend: every service is a container on one private Docker network.

``up`` writes ``<run_dir>/docker-compose.yml`` and starts it with
``docker compose``. Services reach each other by service name on the private
network. Only the control plane's view is published, on 127.0.0.1 host ports.
The image is built with ``attctl image`` (see deploy/docker).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .. import topology as topo
from .common import deployment_record, load, make_pki, write
from .local import free_port

DEFAULT_IMAGE = "agent-trust-testbed/att-node:local"
PKI_PATH = "/etc/att/pki"


def _yaml_scalar(value):
    # JSON strings are valid YAML scalars, so no YAML library is needed.
    return json.dumps(str(value))


def render(plan, host_ports, image, project, pki=None):
    lines = [f"name: {project}", "services:"]
    for service in plan.services:
        lines.append(f"  {service.name}:")
        lines.append(f"    image: {image}")
        lines.append(f"    command: [{_yaml_scalar(service.role)}]")
        lines.append("    restart: on-failure")
        lines.append("    environment:")
        env = dict(service.env)
        env["ATT_LISTEN"] = f"0.0.0.0:{service.port}"
        for key, value in sorted(env.items()):
            lines.append(f"      {key}: {_yaml_scalar(value)}")
        lines.append("    ports:")
        lines.append(f"      - {_yaml_scalar(f'127.0.0.1:{host_ports[service.name]}:{service.port}')}")
        if service.depends_on:
            lines.append("    depends_on:")
            lines.extend(f"      - {dep}" for dep in service.depends_on)
        volumes = []
        if service.role == "apf":
            volumes.append("apf-state:/var/lib/att/apf")
        if service.role == "agent":
            volumes.append(f"agent-{service.name}:/var/lib/att/agent")
        if pki:
            volumes.append(f"{pki}:{PKI_PATH}:ro")
        if volumes:
            lines.append("    volumes:")
            lines.extend(f"      - {_yaml_scalar(v)}" for v in volumes)
        lines.append("    networks: [testbed]")
    lines += ["networks:", "  testbed: {}", "volumes:", "  apf-state: {}"]
    lines += [f"  agent-{s.name}: {{}}" for s in plan.services if s.role == "agent"]
    lines.append("")
    return "\n".join(lines)


def up(topology, run_dir, image=DEFAULT_IMAGE, extra_env=None, binary=None):
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    project = "att-" + "".join(c for c in topology.name.lower() if c.isalnum())[:20]

    pki = make_pki(run_dir, topology, binary, world_readable=True) if topology.tls else None

    def address(name, role):
        return f"{topology.scheme}://{name}:{topo.PORTS[role]}"

    plan = topo.plan(topology, address, extra_env=extra_env, tls_dir=PKI_PATH if pki else None)
    host_ports = {service.name: free_port() for service in plan.services}
    compose_file = run_dir / "docker-compose.yml"
    compose_file.write_text(render(plan, host_ports, image, project, pki=pki))
    compose_file.chmod(0o600)
    endpoints = {name: f"{topology.scheme}://127.0.0.1:{port}" for name, port in host_ports.items()}
    deployment = deployment_record("compose", plan, run_dir, endpoints,
                                   {"project": project, "image": image,
                                    "compose_file": str(compose_file),
                                    "pki": str(pki) if pki else None})
    write(run_dir, deployment)
    _compose(deployment, "up", "-d", "--quiet-pull", capture=True)
    return deployment


def _compose(deployment, *args, capture=False):
    command = ["docker", "compose", "-f", deployment["compose_file"], "-p", deployment["project"], *args]
    return subprocess.run(command, check=True, text=True,
                          capture_output=capture).stdout


def stop(run_dir, name):
    """Stops one container (SIGKILL: a crash, not a clean shutdown)."""
    _compose(load(run_dir), "kill", name, capture=True)


def start(run_dir, name):
    """Starts one stopped container; its volume keeps its state."""
    _compose(load(run_dir), "start", name, capture=True)


def down(run_dir):
    _compose(load(run_dir), "down", "-v", "--remove-orphans", capture=True)


def logs(run_dir):
    deployment = load(run_dir)
    out = {}
    for name in deployment["endpoints"]:
        try:
            out[name] = _compose(deployment, "logs", "--no-color", "--no-log-prefix", name,
                                 capture=True)
        except subprocess.CalledProcessError as error:
            out[name] = f"<logs unavailable: {error}>"
    return out
