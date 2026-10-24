"""Deployment backends.

A backend turns a ``topology.Plan`` into running services and writes
``<run_dir>/deploy.json``: the endpoints the control plane uses and the
per-deployment tokens. Everything above this layer (experiments, checks, the
oracle) reads only ``deploy.json`` and is therefore backend agnostic.

Backends:
- ``local``: one ``att-node`` process per service on 127.0.0.1.
- ``compose``: one container per service on a private Docker network.

A new backend (Kubernetes, Nomad, bare metal over SSH) implements ``up``,
``down`` and ``logs`` and writes the same ``deploy.json``.
"""
from __future__ import annotations

from . import compose, local
from .common import deployment_record, load, write  # noqa: F401

BACKENDS = {"local": local, "compose": compose}


def get(name):
    if name not in BACKENDS:
        raise ValueError(f"unknown backend {name!r}; choose one of {sorted(BACKENDS)}")
    return BACKENDS[name]
