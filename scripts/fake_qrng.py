#!/usr/bin/env python3
"""Development-only fake QRNG Open API server.

Serves ``GET /capabilities`` and ``POST /entropy`` like a QRNG Open API
endpoint so the laboratory can be exercised through its normal entropy
configuration without Entropy Core. Swapping to a real endpoint is then a
configuration change only.

THE BYTES ARE NOT RANDOM. They are a deterministic SHA-256 counter stream,
distinct per block so MLS key-uniqueness checks behave. Never use this server
for anything except development and tests.

Usage::

    python3 scripts/fake_qrng.py --port 8002

The first stdout line is the base URL (useful with ``--port 0``). ``GET
/_fake/stats`` returns request counters for tests; it is not part of the QRNG
Open API.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CAPABILITIES = {
    "entropy": {
        "min_block_size": 1,
        "max_block_size": 1024,
        "min_block_count": 1,
        "max_block_count": 1,
    }
}


class FakeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counter = 0
        self.entropy_posts = 0
        self.entropy_bytes = 0

    def block(self, size: int) -> bytes:
        with self.lock:
            out = bytearray()
            while len(out) < size:
                self.counter += 1
                out += hashlib.sha256(self.counter.to_bytes(8, "big")).digest()
            self.entropy_posts += 1
            self.entropy_bytes += size
            return bytes(out[:size])


def make_handler(state: FakeState):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: object) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path == "/capabilities":
                self._send(200, CAPABILITIES)
            elif self.path == "/_fake/stats":
                with state.lock:
                    stats = {
                        "entropy_posts": state.entropy_posts,
                        "entropy_bytes": state.entropy_bytes,
                    }
                self._send(200, stats)
            else:
                self._send(404, {"detail": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/entropy":
                self._send(404, {"detail": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                request = json.loads(self.rfile.read(length) or b"{}")
                size = int(request["block_size"])
                count = int(request.get("block_count", 1))
            except (ValueError, KeyError, TypeError):
                self._send(422, {"detail": "block_size required"})
                return
            if not 1 <= size <= 1024 or count != 1:
                self._send(422, {"detail": "unsupported block request"})
                return
            self._send(200, {"entropy": [base64.b64encode(state.block(size)).decode()]})

        def log_message(self, *_args) -> None:
            pass

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8002)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(FakeState()))
    host, port = server.server_address[:2]
    print(f"http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
