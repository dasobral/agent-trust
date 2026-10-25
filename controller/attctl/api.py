"""HTTP clients for the testbed services (standard library only).

Every service answers JSON. Protocol outcomes arrive as ``{"ok": v}`` or
``{"error": "code: detail"}``; ``call`` returns ``v`` or raises ``ServiceError``.
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path


class ServiceError(Exception):
    """A protocol refusal (``{"error": ...}``) or a transport failure."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    @property
    def code(self):
        return self.message.split(":", 1)[0].strip() or "rejected"


class Service:
    def __init__(self, name, base_url, token=None, timeout=60, context=None):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        # Mutual TLS: the deployment CA and the attctl client certificate.
        self.context = context

    def raw(self, method, path, body=None, token=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        token = token if token is not None else self.token
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as error:
            try:
                return json.loads(error.read() or b"null")
            except ValueError:
                raise ServiceError(f"transport: HTTP {error.code} from {self.name}") from None
        except (urllib.error.URLError, OSError) as error:
            raise ServiceError(f"transport: {self.name}: {error}") from None

    def call(self, method, path, body=None, token=None):
        value = self.raw(method, path, body, token)
        if isinstance(value, dict) and "ok" in value:
            return value["ok"]
        if isinstance(value, dict) and "error" in value:
            raise ServiceError(str(value["error"]))
        raise ServiceError(f"transport: unexpected response from {self.name}: {value!r}")

    def healthy(self):
        try:
            self.call("GET", "/healthz")
            return True
        except ServiceError:
            return False

    def wait_healthy(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.healthy():
                return
            time.sleep(0.2)
        raise ServiceError(f"transport: {self.name} did not become healthy in {timeout}s")


class Agent(Service):
    """Control and application API of one agent sidecar."""

    def __init__(self, name, base_url, control_token, app_token, context=None):
        super().__init__(name, base_url, control_token, context=context)
        self.app_token = app_token

    def control(self, action, body=None, method="POST"):
        return self.call(method, f"/control/{action}", body if method == "POST" else None)

    def status(self):
        return self.call("GET", "/control/status")

    def send(self, **body):
        return self.call("POST", "/app/send", body, token=self.app_token)

    def inbox(self, after=0):
        return self.call("GET", f"/app/inbox?after={after}", token=self.app_token)


class Testbed:
    """Clients for every service of one deployment, from its ``deploy.json``."""

    def __init__(self, deployment):
        self.deployment = deployment
        tokens = deployment["tokens"]
        endpoints = deployment["endpoints"]
        self.group = deployment["group"]
        self.root = deployment["root"]
        context = tls_context(deployment.get("pki"))
        self.apf = Service("apf", endpoints["apf"], tokens["control"], context=context)
        self.relay = Service("relay", endpoints["relay"], tokens["control"], context=context)
        self.qrng = (Service("qrng", endpoints["qrng"], tokens["control"], context=context)
                     if "qrng" in endpoints else None)
        self.agents = {name: Agent(name, endpoints[name], tokens["control"], tokens["app"], context)
                       for name in deployment["agents"]}

    def services(self):
        return [s for s in [self.qrng, self.apf, self.relay, *self.agents.values()] if s]

    def agent(self, name):
        if name not in self.agents:
            raise ServiceError(f"malformed: unknown agent {name}")
        return self.agents[name]

    def wait_healthy(self, timeout=60):
        for service in self.services():
            service.wait_healthy(timeout)


# OpenSSL 3.5 is the first release that negotiates X25519MLKEM768 and verifies ML-DSA.
PQ_OPENSSL = (3, 5)


def control_chain():
    """``pq`` when this Python's OpenSSL can do post quantum TLS, else ``classical``.
    Services accept a classical certificate only for ``attctl`` and ``<agent>-app``
    (``crates/att-node/src/tls.rs``); this is the one link that falls back."""
    return "pq" if ssl.OPENSSL_VERSION_INFO[:2] >= PQ_OPENSSL else "classical"


def tls_context(pki, name="attctl"):
    """The control plane's mutual TLS context as ``name``, or None without TLS: the post
    quantum CA and certificate, or the classical ones (see ``control_chain``)."""
    if not pki:
        return None
    pki = Path(pki)
    if control_chain() == "pq":
        ca, stem = pki / "ca.crt", name
    else:
        ca, stem = pki / "classical-ca.crt", f"{name}.classical"
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(str(pki / f"{stem}.crt"), str(pki / f"{stem}.key"))
    return context
