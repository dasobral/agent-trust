"""The independent oracle and the broken controls.

The oracle is ``harness/oracle.py`` of the *same agent-trust revision* that the
services link. ``locate`` finds it through ``cargo metadata``, so the Cargo pin is
the single source of truth; ``ATT_ORACLE`` overrides the path. The oracle imports
no production code, and neither does this module.

``broken_controls`` derives deliberately invalid traces from a real exported trace.
Each must be rejected with a named violation; a control that the oracle accepts
means the check is blind and the run fails.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def locate():
    override = os.environ.get("ATT_ORACLE")
    if override:
        return Path(override)
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=REPO, check=True, capture_output=True, text=True).stdout)
    for package in metadata["packages"]:
        if package["name"] == "agent-trust":
            path = Path(package["manifest_path"]).parent / "harness" / "oracle.py"
            if path.is_file():
                return path
    raise FileNotFoundError("agent-trust harness/oracle.py not found through cargo metadata")


def load():
    path = locate()
    spec = importlib.util.spec_from_file_location("agent_trust_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def _grant(subject, right, generation):
    return {"subject": subject, "right": right, "generation": generation}


def replay(trace):
    """Frontier, roster, grants and policy revision after an accepted v2 trace."""
    state = {"policy_revision": 0, "epoch": None, "branch": None, "roster": [], "grants": {}}
    for event in trace:
        kind = event.get("type")
        if kind == "init":
            state["epoch"], state["branch"] = event["epoch"], event["branch"]
            state["roster"] = list(event["roster"])
            state["grants"] = {(g["subject"], g["right"]): [g["generation"], True]
                               for g in event["grants"]}
        elif kind == "allow":
            state["grants"][(event["subject"], event["right"])] = [event["generation"], True]
            state["policy_revision"] += 1
        elif kind == "deny":
            record = state["grants"].get((event["subject"], event["right"]))
            if record and record[1]:
                record[1] = False
                state["policy_revision"] += 1
        elif kind == "admit":
            state["roster"].append(event["subject"])
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
        elif kind == "repair_stage":
            state["roster"] = [m for m in state["roster"] if m not in event["removed"]]
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
        elif kind == "rekey":
            state["grants"][(event["subject"], event["right"])] = [event["generation"], True]
            state["policy_revision"] += 1
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
    return state


def forged_release(prefix, op, actor, tag):
    state = replay(prefix)
    writer = state["grants"].get((actor, "write"), [0, False])[0]
    cover = [[_grant(actor, "write", writer)]]
    cover += [[_grant(m, "read", state["grants"].get((m, "read"), [0, False])[0])]
              for m in state["roster"]]
    return [
        {"event_id": f"forged-allocate-{tag}", "type": "allocate", "op": op},
        {"event_id": f"forged-release-{tag}", "type": "release", "op": op, "actor": actor,
         "right": "write", "policy_revision": state["policy_revision"], "epoch": state["epoch"],
         "branch": state["branch"], "digest": f"forged-digest-{tag}", "cover": cover},
    ]


def _first(trace, predicate):
    return next((i for i, e in enumerate(trace) if predicate(e)), None)


def broken_controls(trace, revoked_reader, writer):
    """``{label: (events, index, expected_code)}`` built from a real trace.

    ``revoked_reader`` is the member whose read right was revoked and who was then
    removed by repair; ``writer`` is a member allowed to write at that point.
    Controls whose anchor event is absent from the trace are skipped and reported.
    """
    controls, skipped = {}, []
    deny_read = _first(trace, lambda e: e.get("type") == "deny" and e.get("subject") == revoked_reader
                       and e.get("right") == "read")
    stage = _first(trace, lambda e: e.get("type") == "repair_stage")
    opened = _first(trace, lambda e: e.get("type") == "repair_open")
    first_release = _first(trace, lambda e: e.get("type") == "release")
    first_persist = _first(trace, lambda e: e.get("type") == "persist")
    first_consume = _first(trace, lambda e: e.get("type") == "consume")

    if deny_read is not None:
        prefix = trace[:deny_read + 1]
        controls["release after the read denial"] = (
            prefix + forged_release(prefix, "op-forged", writer, "read"), len(prefix) + 1, "read_fenced")
    else:
        skipped.append("release after the read denial")
    if opened is not None:
        mutated = [e for e in trace[:opened + 1] if e.get("type") not in ("repair_stage", "confirm")]
        controls["fence opened by API only (no repair commit)"] = (mutated, len(mutated) - 1, "invalid_repair")
        mutated = [e for e in trace[:opened + 1] if e.get("type") != "confirm"]
        controls["fence opened without confirmation"] = (mutated, len(mutated) - 1, "unconfirmed")
    else:
        skipped += ["fence opened by API only (no repair commit)", "fence opened without confirmation"]
    if stage is not None:
        mutated = deepcopy(trace[:stage + 1])
        mutated[-1]["removed"] = []
        controls["repair that keeps the revoked reader"] = (mutated, len(mutated) - 1, "invalid_repair")
    else:
        skipped.append("repair that keeps the revoked reader")
    if first_release is not None:
        mutated = deepcopy(trace[:first_release + 1])
        release = mutated[-1]
        others = [s for s in release["cover"]
                  if s[0]["right"] == "read" and s[0]["subject"] != release["actor"]]
        if others:
            release["cover"].remove(others[0])
            controls["release cover that omits a reader"] = (mutated, len(mutated) - 1, "unsound_cover")
    if first_persist is not None:
        original = trace[first_persist]
        envelope = original["envelope"]
        changed = envelope[:-1] + ("1" if envelope[-1] != "1" else "0")
        second = dict(original, event_id=original["event_id"] + "-reencrypted", envelope=changed)
        controls["second envelope under one operation"] = (
            trace[:first_persist + 1] + [second], first_persist + 1, "binding_mismatch")
    if first_consume is not None:
        original = trace[first_consume]
        controls["replayed consumption"] = (
            trace[:first_consume + 1] + [dict(original, event_id=original["event_id"] + "-replay")],
            first_consume + 1, "replay")
    rekey = _first(trace, lambda e: e.get("type") == "rekey")
    if rekey is not None:
        subject = trace[rekey]["subject"]
        other = next((e["key"] for e in trace if e.get("type") == "admit" and e["subject"] != subject), None)
        if other is not None:
            mutated = deepcopy(trace[:rekey + 1])
            mutated[-1]["new_key"] = other
            controls["rekey that reuses another member's key"] = (mutated, rekey, "stale_key")
    else:
        skipped.append("rekey that reuses another member's key")
    return controls, skipped
