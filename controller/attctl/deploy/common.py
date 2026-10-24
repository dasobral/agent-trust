"""Helpers shared by the deployment backends: the deploy.json record."""
from __future__ import annotations

import json
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
