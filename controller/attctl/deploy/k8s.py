"""Kubernetes backend (tested on k3s): one Deployment and one Service per service.

``up`` renders the plan into Kubernetes objects, applies them with ``kubectl`` into a
namespace of their own, waits for every pod to be ready, and opens one
``kubectl port-forward`` per service on 127.0.0.1 for the control plane.

Objects per deployment (namespace ``att-<topology>``):

- ``Secret att-tokens``: the control, app and bootstrap tokens. Pods read them with
  ``secretKeyRef``; no token appears in a Deployment.
- ``Secret att-pki-<service>``: the CA and that service's own certificate and key, when
  the topology enables mutual TLS.
- One ``Deployment`` (one replica, ``Recreate``) and one ``ClusterIP Service`` per
  service, with readiness and liveness probes on ``/healthz`` (an ``exec`` probe
  under mTLS, since the kubelet has no client certificate).
- One ``PersistentVolumeClaim`` for the APF and one per agent (k3s ``local-path``).
- ``NetworkPolicy``: ingress is denied by default; agents may reach the APF and the
  relay, the APF and the agents may reach the QRNG service. The relay and the APF
  never reach an agent.

Pods run as the unprivileged ``att`` user with a read-only root filesystem, no
privilege escalation and no capabilities. ``stop`` and ``start`` scale one
Deployment to 0 or 1; its volume keeps its state.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

from .. import topology as topo
from .common import deployment_record, load, make_pki, write
from .local import free_port

DEFAULT_IMAGE = "agent-trust-testbed/att-node:local"
STATE_PATHS = {"apf": "/var/lib/att/apf", "agent": "/var/lib/att/agent"}
PKI_PATH = "/etc/att/pki"


def namespace_of(topology):
    return "att-" + "".join(c for c in topology.name.lower() if c.isalnum() or c == "-")[:40]


def _labels(name, role):
    return {"app.kubernetes.io/name": name, "app.kubernetes.io/component": role,
            "app.kubernetes.io/part-of": "agent-trust-testbed"}


def render(plan, namespace, image, pull_policy="IfNotPresent", pki=None, storage_class=None):
    """The Kubernetes objects of ``plan`` as a ``v1 List``. ``pki`` maps file names to
    PEM text when the deployment uses mTLS."""
    tokens = plan.tokens
    token_keys = {value: key for key, value in tokens.items()}
    items = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
         "labels": {"app.kubernetes.io/part-of": "agent-trust-testbed"}}},
        {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "att-tokens", "namespace": namespace},
         "type": "Opaque", "stringData": dict(tokens)},
    ]
    for service in plan.services:
        if pki:
            # Each pod gets the CA and only its own certificate and key.
            items.append({"apiVersion": "v1", "kind": "Secret",
                          "metadata": {"name": f"att-pki-{service.name}", "namespace": namespace},
                          "type": "Opaque", "stringData": {
                              "ca.crt": pki["ca.crt"],
                              f"{service.name}.crt": pki[f"{service.name}.crt"],
                              f"{service.name}.key": pki[f"{service.name}.key"]}})
        labels = _labels(service.name, service.role)
        env = []
        for key, value in sorted(service.env.items()):
            if value in token_keys:
                env.append({"name": key, "valueFrom": {"secretKeyRef": {
                    "name": "att-tokens", "key": token_keys[value]}}})
            else:
                env.append({"name": key, "value": str(value)})
        env.append({"name": "ATT_LISTEN", "value": f"0.0.0.0:{service.port}"})
        mounts, volumes = [{"name": "tmp", "mountPath": "/tmp"}], [{"name": "tmp", "emptyDir": {}}]
        if service.role in STATE_PATHS:
            claim = f"{service.name}-state"
            items.append({
                "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                "metadata": {"name": claim, "namespace": namespace, "labels": labels},
                "spec": {"accessModes": ["ReadWriteOnce"],
                         "resources": {"requests": {"storage": "256Mi"}},
                         **({"storageClassName": storage_class} if storage_class else {})},
            })
            mounts.append({"name": "state", "mountPath": STATE_PATHS[service.role]})
            volumes.append({"name": "state", "persistentVolumeClaim": {"claimName": claim}})
        if pki:
            mounts.append({"name": "pki", "mountPath": PKI_PATH, "readOnly": True})
            volumes.append({"name": "pki", "secret": {"secretName": f"att-pki-{service.name}",
                                                      "defaultMode": 0o440}})
        if pki:
            # The kubelet has no client certificate: probe from inside the pod.
            probe = {"exec": {"command": ["att-node", "probe", f"https://127.0.0.1:{service.port}/healthz"]}}
        else:
            probe = {"httpGet": {"path": "/healthz", "port": service.port}}
        container = {
            "name": "att-node",
            "image": image,
            "imagePullPolicy": pull_policy,
            "args": [service.role],
            "env": env,
            "ports": [{"containerPort": service.port, "name": "http"}],
            "readinessProbe": {**probe, "periodSeconds": 2, "failureThreshold": 3},
            "livenessProbe": {**probe, "periodSeconds": 10, "failureThreshold": 6,
                              "initialDelaySeconds": 10},
            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                          "limits": {"memory": "512Mi"}},
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                "readOnlyRootFilesystem": True,
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": mounts,
        }
        items.append({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": service.name, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 1,
                "strategy": {"type": "Recreate"},
                "selector": {"matchLabels": {"app.kubernetes.io/name": service.name}},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {"securityContext": {"fsGroup": 10001},
                             "automountServiceAccountToken": False,
                             "enableServiceLinks": False,
                             "containers": [container], "volumes": volumes},
                },
            },
        })
        items.append({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": service.name, "namespace": namespace, "labels": labels},
            "spec": {"selector": {"app.kubernetes.io/name": service.name},
                     "ports": [{"port": service.port, "targetPort": service.port, "name": "http"}]},
        })
    items += _network_policies(plan, namespace)
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _network_policies(plan, namespace):
    def component(role):
        return {"podSelector": {"matchLabels": {"app.kubernetes.io/component": role}}}

    def allow(role, port, sources):
        return {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": f"allow-to-{role}", "namespace": namespace},
            "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/component": role}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [component(s) for s in sources],
                                  "ports": [{"port": port}]}]},
        }
    policies = [{
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-ingress", "namespace": namespace},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
    }]
    policies.append(allow("apf", topo.PORTS["apf"], ["agent"]))
    policies.append(allow("relay", topo.PORTS["relay"], ["agent"]))
    if any(s.role == "qrng-mock" for s in plan.services):
        policies.append(allow("qrng-mock", topo.PORTS["qrng-mock"], ["apf", "agent"]))
    return policies


def kubeconfig():
    """The cluster: ``KUBECONFIG``, else k3s's own file when present, else kubectl's
    default. It is recorded in deploy.json, so later commands reach the same cluster."""
    if os.environ.get("KUBECONFIG"):
        return os.environ["KUBECONFIG"]
    if Path("/etc/rancher/k3s/k3s.yaml").is_file():
        return "/etc/rancher/k3s/k3s.yaml"
    return str(Path.home() / ".kube" / "config")


_KUBECONFIG = None


def _kubectl(*args, input_text=None, capture=True, check=True):
    command = ["kubectl", "--kubeconfig", _KUBECONFIG or kubeconfig(), *args]
    return subprocess.run(command, input=input_text, text=True,
                          capture_output=capture, check=check).stdout


def _use(deployment):
    global _KUBECONFIG
    _KUBECONFIG = deployment.get("kubeconfig")


def up(topology, run_dir, image=DEFAULT_IMAGE, extra_env=None, binary=None, pull_policy=None):
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    namespace = namespace_of(topology)
    if _namespace_exists(namespace):
        # A namespace that is still terminating would keep pods with the old tokens.
        _wait_namespace_gone(namespace, timeout=120)
    scheme = topology.scheme
    pki_dir = make_pki(run_dir, topology, binary, namespace=namespace) if topology.tls else None
    pki = ({p.name: p.read_text() for p in pki_dir.iterdir() if p.name != "ca.key"}
           if pki_dir else None)

    def address(name, role):
        return f"{scheme}://{name}:{topo.PORTS[role]}"

    plan = topo.plan(topology, address, extra_env=extra_env, tls_dir=PKI_PATH if pki else None)
    pull_policy = pull_policy or os.environ.get("ATT_K8S_PULL_POLICY", "IfNotPresent")
    manifest = render(plan, namespace, image, pull_policy, pki=pki,
                      storage_class=os.environ.get("ATT_K8S_STORAGE_CLASS"))
    manifest_file = run_dir / "k8s.json"
    manifest_file.write_text(json.dumps(manifest, indent=1))
    manifest_file.chmod(0o600)
    _kubectl("apply", "-f", str(manifest_file))
    deployment = deployment_record("k8s", plan, run_dir, {}, {
        "namespace": namespace, "image": image, "manifest": str(manifest_file),
        "services": {s.name: {"role": s.role, "port": s.port} for s in plan.services},
        "forwards": {},
        "pki": str(pki_dir) if pki_dir else None,
        "kubeconfig": _KUBECONFIG or kubeconfig(),
    })
    for service in plan.services:
        _kubectl("-n", namespace, "rollout", "status", f"deployment/{service.name}", "--timeout=180s")
    for service in plan.services:
        _forward(deployment, service.name, scheme)
    write(run_dir, deployment)
    return deployment


def _forward(deployment, name, scheme=None):
    """One ``kubectl port-forward`` per service; the endpoint is 127.0.0.1:<port>. A
    restarted service keeps its local port, so clients keep their endpoint."""
    scheme = scheme or deployment["endpoints"].get(name, "http://").split(":", 1)[0]
    ports = deployment.setdefault("ports", {})
    port = ports.get(name) or free_port()
    ports[name] = port
    service_port = deployment["services"][name]["port"]
    log = open(Path(deployment["run_dir"]) / f"port-forward-{name}.log", "ab")
    process = subprocess.Popen(
        ["kubectl", "--kubeconfig", deployment["kubeconfig"], "-n", deployment["namespace"],
         "port-forward", f"svc/{name}",
         f"{port}:{service_port}", "--address", "127.0.0.1"],
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 30
    import socket
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.2)
    deployment["forwards"][name] = process.pid
    deployment["endpoints"][name] = f"{scheme}://127.0.0.1:{port}"


def _stop_forward(deployment, name):
    pid = deployment["forwards"].pop(name, None)
    if pid:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def stop(run_dir, name):
    deployment = load(run_dir)
    _use(deployment)
    _kubectl("-n", deployment["namespace"], "scale", f"deployment/{name}", "--replicas=0")
    _kubectl("-n", deployment["namespace"], "wait", "--for=delete", "pod",
             "-l", f"app.kubernetes.io/name={name}", "--timeout=120s", check=False)
    _stop_forward(deployment, name)
    write(run_dir, deployment)


def start(run_dir, name):
    deployment = load(run_dir)
    _use(deployment)
    namespace = deployment["namespace"]
    # A pod in crash-loop back-off (for example after a failed start) is replaced at
    # once instead of after its back-off delay.
    _kubectl("-n", namespace, "delete", "pod", "-l", f"app.kubernetes.io/name={name}",
             "--wait=false", check=False)
    _kubectl("-n", namespace, "scale", f"deployment/{name}", "--replicas=1")
    try:
        _kubectl("-n", namespace, "rollout", "status", f"deployment/{name}", "--timeout=60s")
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"{name} did not become ready: {error.stdout or error.stderr}") from None
    _stop_forward(deployment, name)
    # A new pod: the port-forward to the old one is gone; open it again on the same port.
    _forward(deployment, name)
    write(run_dir, deployment)


def down(run_dir):
    deployment = load(run_dir)
    _use(deployment)
    for name in list(deployment.get("forwards", {})):
        _stop_forward(deployment, name)
    _kubectl("delete", "namespace", deployment["namespace"], "--wait=false", check=False)
    _wait_namespace_gone(deployment["namespace"])


def _namespace_exists(namespace):
    result = subprocess.run(["kubectl", "--kubeconfig", _KUBECONFIG or kubeconfig(), "get",
                             "namespace", namespace], capture_output=True, text=True)
    if result.returncode == 0:
        return True
    if "NotFound" in result.stderr:
        return False
    raise RuntimeError(f"kubectl cannot reach the cluster: {result.stderr.strip()[:200]}")


def _wait_namespace_gone(namespace, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _namespace_exists(namespace):
            return
        time.sleep(1)
    raise RuntimeError(f"namespace {namespace} still exists after {timeout}s")


def logs(run_dir):
    deployment = load(run_dir)
    _use(deployment)
    out = {}
    for name in deployment["services"]:
        out[name] = _kubectl("-n", deployment["namespace"], "logs", f"deployment/{name}",
                             "--all-containers", "--tail=-1", check=False) or ""
    return out
