"""Local backend: every service is an ``att-node`` process on 127.0.0.1.

No container runtime is needed. Each service gets a free port, its own log file
under ``<run_dir>/logs`` and, for the APF, a state directory under
``<run_dir>/state``. ``down`` stops the processes recorded in ``deploy.json``.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from .. import topology as topo
from .common import deployment_record, load, write


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def up(topology, run_dir, binary, extra_env=None):
    run_dir = Path(run_dir)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    ports = {}

    def address(name, role):
        ports.setdefault(name, free_port())
        return f"http://127.0.0.1:{ports[name]}"

    plan = topo.plan(topology, address, extra_env=extra_env)
    services, processes, endpoints = {}, {}, {}
    for service in plan.services:
        endpoints[service.name] = address(service.name, service.role)
        env = dict(service.env)
        env["ATT_LISTEN"] = f"127.0.0.1:{ports[service.name]}"
        if service.role == "apf":
            env["ATT_STATE_DIR"] = str((run_dir / "state" / "apf").resolve())
        if service.role == "agent":
            env["ATT_DATA_DIR"] = str((run_dir / "state" / service.name).resolve())
        services[service.name] = {"role": service.role, "env": env, "port": ports[service.name]}
        # Dependencies first: the APF and agents connect their entropy source at start.
        wait = service.role in ("qrng-mock", "apf", "relay")
        processes[service.name] = _spawn(run_dir, binary, service.name, services[service.name], wait)
    deployment = deployment_record("local", plan, run_dir, endpoints,
                                   {"pids": processes, "binary": str(binary), "services": services})
    write(run_dir, deployment)
    return deployment


def _spawn(run_dir, binary, name, spec, wait=True):
    log = open(Path(run_dir) / "logs" / f"{name}.log", "ab")
    process = subprocess.Popen(
        [str(binary), spec["role"]],
        env={**_base_env(), **spec["env"]},
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    if wait:
        _wait_port(spec["port"], name, process)
    return process.pid


def stop(run_dir, name):
    """Stops one service (SIGKILL: a crash, not a clean shutdown)."""
    deployment = load(run_dir)
    pid = deployment["pids"].get(name)
    if pid is None:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.05)
    deployment["pids"].pop(name)
    write(run_dir, deployment)


def start(run_dir, name):
    """Starts one stopped service with its recorded configuration. Raises when the
    service exits before it listens (for example, its entropy source is down)."""
    deployment = load(run_dir)
    if name in deployment["pids"] and _alive(deployment["pids"][name]):
        return
    pid = _spawn(run_dir, deployment["binary"], name, deployment["services"][name], wait=True)
    deployment["pids"][name] = pid
    write(run_dir, deployment)


def _base_env():
    keep = ("PATH", "HOME", "LANG", "RUST_BACKTRACE", "SSL_CERT_FILE")
    return {key: os.environ[key] for key in keep if key in os.environ}


def _wait_port(port, name, process, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited with status {process.returncode}; see its log")
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"{name} did not listen on port {port} within {timeout}s")


def down(run_dir):
    deployment = load(run_dir)
    for _name, pid in deployment.get("pids", {}).items():
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    for pid in deployment.get("pids", {}).values():
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.05)
        if _alive(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # Reap a child of this process, if it is one.
    try:
        finished, _ = os.waitpid(pid, os.WNOHANG)
        return finished == 0
    except ChildProcessError:
        return True


def logs(run_dir):
    return {path.stem: path.read_text(errors="replace")
            for path in sorted((Path(run_dir) / "logs").glob("*.log"))}
