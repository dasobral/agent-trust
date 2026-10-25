"""Helpers shared by the deployment backends: the deploy.json record."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def load(run_dir) -> dict:
    path = Path(run_dir) / "deploy.json"
    if not path.is_file():
        raise FileNotFoundError(f"no deployment in {run_dir} (run `attctl up` first)")
    return json.loads(path.read_text())


def write(run_dir, deployment):
    path = Path(run_dir) / "deploy.json"
    path.write_text(json.dumps(deployment, indent=2))
    path.chmod(0o600)


def deployment_record(backend, plan, run_dir, endpoints, extra):
    topology = plan.topology
    return {
        "backend": backend,
        "topology": str(topology.path) if topology.path else None,
        "name": topology.name,
        "group": topology.group,
        "root": topology.root,
        "agents": topology.agents,
        "entropy": topology.entropy,
        "run_dir": str(run_dir),
        "endpoints": endpoints,
        "tokens": plan.tokens,
        **extra,
    }


# The two CA keys stay in the run directory only; no service ever gets them.
CA_KEYS = ("ca.key", "classical-ca.key")


def make_pki(run_dir, topology, binary, namespace=None, world_readable=False):
    """Creates the deployment CA and certificates in ``<run_dir>/pki`` with
    ``att-node pki``. Returns the directory. ``world_readable`` makes the keys readable
    by the unprivileged container user (compose backend only; a lab tradeoff)."""
    pki = (Path(run_dir) / "pki").resolve()
    command = [str(binary), "pki", "--dir", str(pki), "--names", ",".join(topology.pki_names())]
    if namespace:
        command += ["--namespace", namespace]
    subprocess.run(command, check=True, capture_output=True, text=True)
    if world_readable:
        pki.chmod(0o755)
        for path in pki.glob("*.key"):
            if path.name not in CA_KEYS:
                path.chmod(0o644)
    return pki
