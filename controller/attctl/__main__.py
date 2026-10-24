"""attctl: the control plane of the Agent Trust testbed.

    attctl build [--debug]                         build att-node
    attctl image [--base IMAGE] [--from-source]    build the container image
    attctl up TOPOLOGY [--backend B]               deploy a topology
    attctl status                                  health and state of every service
    attctl call SERVICE METHOD PATH [JSON]         one raw control call
    attctl trace [--out FILE]                      export the APF trace and run the oracle
    attctl render TOPOLOGY [--out FILE]            static Kubernetes manifests
    attctl logs [SERVICE]                          service logs
    attctl down                                    stop the deployment
    attctl run EXPERIMENT [--backend B] [--record DIR] [--keep]
                                                   deploy, run, verify, report, tear down

Every command works on one run directory (``--run-dir``, default ``runs/current``),
which holds ``deploy.json`` with the endpoints and the per-deployment tokens.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import deploy, experiment as exp_mod, oracle as oracle_mod
from .deploy import common as _common  # noqa: F401
from .api import ServiceError, Testbed
from .topology import Topology

REPO = Path(__file__).resolve().parents[2]
DEFAULT_RUN_DIR = REPO / "runs" / "current"
DEFAULT_BASE_IMAGE = "ubuntu:24.04"


def binary_path(profile):
    override = os.environ.get("ATT_NODE_BIN")
    if override:
        return Path(override)
    return REPO / "target" / profile / "att-node"


def cmd_build(args):
    command = ["cargo", "build", "--locked", "-p", "att-node"]
    if not args.debug:
        command.append("--release")
    subprocess.run(command, cwd=REPO, check=True)
    print(binary_path("debug" if args.debug else "release"))


def cmd_image(args):
    if args.from_source:
        dockerfile = REPO / "deploy" / "docker" / "Dockerfile"
    else:
        if not binary_path("release").is_file():
            sys.exit("build the release binary first: attctl build")
        dockerfile = REPO / "deploy" / "docker" / "Dockerfile.prebuilt"
    subprocess.run(["docker", "build", "-f", str(dockerfile), "--build-arg",
                    f"BASE_IMAGE={args.base}", "-t", args.tag, str(REPO)], check=True)
    print(args.tag)


def _up(topology_path, backend, run_dir, image, profile):
    topology = Topology.load(topology_path)
    run_dir = Path(run_dir)
    if (run_dir / "deploy.json").exists():
        sys.exit(f"{run_dir} already holds a deployment; run `attctl down` or pick --run-dir")
    run_dir.mkdir(parents=True, exist_ok=True)
    extra_env = {k: v for k, v in os.environ.items() if k.startswith("AGENT_TRUST_QRNG_")}
    module = deploy.get(backend)
    if backend == "local":
        binary = binary_path(profile)
        if not binary.is_file():
            sys.exit(f"missing {binary}; run `attctl build`")
        deployment = module.up(topology, run_dir, binary, extra_env=extra_env)
    else:
        binary = binary_path(profile)
        if topology.tls and not binary.is_file():
            sys.exit(f"missing {binary} (needed to create the PKI); run `attctl build`")
        deployment = module.up(topology, run_dir, image=image, extra_env=extra_env, binary=binary)
    testbed = Testbed(deployment)
    try:
        testbed.wait_healthy(timeout=90)
    except ServiceError:
        # A deployment that never became healthy is torn down; its logs stay.
        logs = deploy.get(deployment["backend"]).logs(run_dir)
        (run_dir / "service-logs").mkdir(exist_ok=True)
        for name, text in logs.items():
            (run_dir / "service-logs" / f"{name}.log").write_text(text)
        _down(run_dir)
        raise
    return deployment, testbed


def cmd_up(args):
    deployment, _ = _up(args.topology, args.backend, args.run_dir, args.image, args.profile)
    print(json.dumps({"backend": deployment["backend"], "endpoints": deployment["endpoints"]}, indent=2))


def _down(run_dir):
    deployment = deploy.load(run_dir)
    deploy.get(deployment["backend"]).down(run_dir)
    (Path(run_dir) / "deploy.json").rename(Path(run_dir) / "deploy.stopped.json")


def cmd_down(args):
    _down(args.run_dir)
    print("stopped")


def cmd_status(args):
    testbed = Testbed(deploy.load(args.run_dir))
    out = {"apf": None, "agents": {}}
    try:
        out["apf"] = testbed.apf.call("GET", "/v1/state")
    except ServiceError as error:
        out["apf"] = {"error": error.message}
    for name, agent in testbed.agents.items():
        try:
            s = agent.status()
            out["agents"][name] = {k: s[k] for k in ("membership", "epoch", "inbox", "retain", "polls")}
        except ServiceError as error:
            out["agents"][name] = {"error": error.message}
    try:
        out["relay"] = testbed.relay.call("GET", "/control/stats")
    except ServiceError as error:
        out["relay"] = {"error": error.message}
    print(json.dumps(out, indent=2))


def cmd_call(args):
    testbed = Testbed(deploy.load(args.run_dir))
    service = {s.name: s for s in testbed.services()}[args.service]
    body = json.loads(args.body) if args.body else None
    print(json.dumps(service.raw(args.method.upper(), args.path, body), indent=2))


def cmd_render(args):
    """Static Kubernetes manifests for a topology (GitOps, review, or kubectl apply).
    The Secret carries newly generated tokens; mTLS certificates are created in
    ``--pki-dir`` when the topology enables TLS."""
    from .deploy import k8s
    from . import topology as topo
    topology = Topology.load(args.topology)
    namespace = k8s.namespace_of(topology)
    pki = None
    if topology.tls:
        binary = binary_path(args.profile)
        pki_dir = deploy.common.make_pki(Path(args.pki_dir), topology, binary, namespace=namespace)
        pki = {p.name: p.read_text() for p in pki_dir.iterdir() if p.name != "ca.key"}

    def address(name, role):
        return f"{topology.scheme}://{name}:{topo.PORTS[role]}"
    plan = topo.plan(topology, address, tls_dir=k8s.PKI_PATH if pki else None)
    manifest = k8s.render(plan, namespace, args.image, args.pull_policy, pki=pki)
    text = json.dumps(manifest, indent=1)
    if args.out:
        Path(args.out).write_text(text)
        Path(args.out).chmod(0o600)
        print(f"wrote {args.out} (namespace {namespace}); it contains secrets")
    else:
        print(text)


def cmd_trace(args):
    testbed = Testbed(deploy.load(args.run_dir))
    trace = testbed.apf.call("GET", "/control/trace")["trace"]
    module, path = oracle_mod.load()
    violations = module.check_trace(trace)
    if args.out:
        Path(args.out).write_text(json.dumps(trace, indent=1))
    print(json.dumps({"events": len(trace), "oracle": str(path), "violations": violations}, indent=2))
    sys.exit(1 if violations else 0)


def cmd_logs(args):
    deployment = deploy.load(args.run_dir)
    logs = deploy.get(deployment["backend"]).logs(args.run_dir)
    for name, text in logs.items():
        if args.service and name != args.service:
            continue
        print(f"===== {name}\n{text}")


def cmd_run(args):
    experiment = exp_mod.Experiment(args.experiment)
    run_dir = Path(args.run_dir)
    if run_dir == DEFAULT_RUN_DIR:
        run_dir = REPO / "runs" / f"{experiment.id}-{time.strftime('%Y%m%dT%H%M%S')}-{args.backend}"
    print(f"experiment {experiment.id}: {experiment.title}")
    print(f"backend {args.backend}; run directory {run_dir}")
    deployment, testbed = _up(experiment.topology_path, args.backend, run_dir, args.image, args.profile)
    runner = exp_mod.Runner(testbed, run_dir,
                            lifecycle=(deploy.get(deployment["backend"]), run_dir))
    try:
        report = runner.run(experiment)
        observations = runner.collect()
    finally:
        logs = deploy.get(deployment["backend"]).logs(run_dir)
        if not args.keep:
            _down(run_dir)
    report["backend"] = deployment["backend"]
    report["topology"] = deployment["name"]
    report["entropy"] = deployment["entropy"]
    report["stack"] = stack_versions()
    (run_dir / "report.json").write_text(json.dumps({**report, "observations": observations}, indent=1))
    (run_dir / "report.md").write_text(exp_mod.render_markdown(report, deployment, observations))
    logs_dir = run_dir / "service-logs"
    logs_dir.mkdir(exist_ok=True)
    for name, text in logs.items():
        (logs_dir / f"{name}.log").write_text(text)
    if args.record:
        record(run_dir, Path(args.record))
    print(f"result: {report['result'].upper()} ({report['seconds']} s); report {run_dir / 'report.md'}")
    sys.exit(0 if report["result"] == "pass" else 1)


def record(run_dir, destination):
    """Copies the evidence of a run (no deploy.json: it holds the tokens)."""
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("report.md", "report.json", "trace.json"):
        if (run_dir / name).is_file():
            shutil.copy2(run_dir / name, destination / name)
    if (run_dir / "service-logs").is_dir():
        shutil.copytree(run_dir / "service-logs", destination / "service-logs", dirs_exist_ok=True)
    print(f"recorded in {destination}")


def stack_versions():
    """The exact revisions of the stack under test, from Cargo.lock."""
    lock = (REPO / "Cargo.lock").read_text()
    versions = {}
    for block in lock.split("[[package]]"):
        fields = dict(line.split(" = ", 1) for line in block.strip().splitlines() if " = " in line)
        name = fields.get("name", "").strip('"')
        if name in ("agent-trust", "openmls", "openmls_qrand", "openmls_libcrux_crypto"):
            source = fields.get("source", "").strip('"')
            versions[name] = source.split("#")[-1] if "#" in source else fields.get("version", "").strip('"')
    try:
        versions["testbed"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True,
                                             capture_output=True, text=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        versions["testbed"] = "unknown"
    return versions


def main(argv=None):
    parser = argparse.ArgumentParser(prog="attctl", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", default=str(DEFAULT_RUN_DIR))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build")
    p.add_argument("--debug", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("image")
    p.add_argument("--base", default=DEFAULT_BASE_IMAGE)
    p.add_argument("--tag", default=deploy.compose.DEFAULT_IMAGE)
    p.add_argument("--from-source", action="store_true")
    p.set_defaults(func=cmd_image)

    for name, func in (("up", cmd_up), ("run", cmd_run)):
        p = sub.add_parser(name)
        p.add_argument("experiment" if name == "run" else "topology")
        p.add_argument("--backend", default="local", choices=sorted(deploy.BACKENDS))
        p.add_argument("--image", default=deploy.compose.DEFAULT_IMAGE)
        p.add_argument("--profile", default="release", choices=["release", "debug"])
        if name == "run":
            p.add_argument("--record")
            p.add_argument("--keep", action="store_true")
        p.set_defaults(func=func)

    for name, func in (("down", cmd_down), ("status", cmd_status)):
        sub.add_parser(name).set_defaults(func=func)

    p = sub.add_parser("call")
    p.add_argument("service")
    p.add_argument("method")
    p.add_argument("path")
    p.add_argument("body", nargs="?")
    p.set_defaults(func=cmd_call)

    p = sub.add_parser("render", help="static Kubernetes manifests for a topology")
    p.add_argument("topology")
    p.add_argument("--image", default=deploy.compose.DEFAULT_IMAGE)
    p.add_argument("--pull-policy", default="IfNotPresent")
    p.add_argument("--pki-dir", default=str(REPO / "runs" / "render-pki"))
    p.add_argument("--profile", default="release", choices=["release", "debug"])
    p.add_argument("--out")
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("trace")
    p.add_argument("--out")
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("logs")
    p.add_argument("service", nargs="?")
    p.set_defaults(func=cmd_logs)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
