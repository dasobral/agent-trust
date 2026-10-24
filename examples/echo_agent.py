#!/usr/bin/env python3
"""A minimal application on top of an agent-trust sidecar.

This is the whole integration surface: two HTTP calls with a bearer token. The
application never touches keys, MLS state or the APF. Any agent framework, in any
language, integrates the same way: replace ``reply`` with the agent's logic.

    examples/echo_agent.py --sidecar http://127.0.0.1:PORT --token APP_TOKEN

With a running deployment, ``attctl`` prints the sidecar URL (``attctl up``) and the
token is ``tokens.app`` in ``runs/current/deploy.json``.
"""
import argparse
import json
import time
import urllib.request


def call(base, token, method, path, body=None):
    request = urllib.request.Request(base.rstrip("/") + path, method=method,
                                     data=None if body is None else json.dumps(body).encode())
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        answer = json.loads(response.read())
    if "error" in answer:
        raise RuntimeError(answer["error"])
    return answer["ok"]


def reply(message):
    """The application logic. Here: echo every text message once."""
    text = message.get("text") or ""
    if text.startswith("echo:"):
        return None  # never answer an echo, or two echo agents would loop forever
    return f"echo: {text}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--max-replies", type=int, default=0, help="stop after N replies (0: never)")
    args = parser.parse_args()
    seen, replies = 0, 0
    while True:
        for message in call(args.sidecar, args.token, "GET", f"/app/inbox?after={seen}"):
            seen += 1
            answer = reply(message)
            if answer is None:
                continue
            try:
                sent = call(args.sidecar, args.token, "POST", "/app/send", {"text": answer})
                print(f"replied to {message['op']} from {message['from']} as {sent['op']}", flush=True)
                replies += 1
            except RuntimeError as error:
                # A refusal is an authorization decision (for example read_fenced).
                print(f"not allowed to reply to {message['op']}: {error}", flush=True)
            if args.max_replies and replies >= args.max_replies:
                return
        time.sleep(0.2)


if __name__ == "__main__":
    main()
