"""Independent deterministic oracle for the versioned trace contract.

This module deliberately contains no production-protocol imports.  It models only
fixture-visible authority, frontier, local readiness, and one-shot delivery state.
"""
from __future__ import annotations

from copy import deepcopy

RIGHTS = {"read", "write", "admin", "admit"}


def _string(value, nonempty=True):
    return isinstance(value, str) and (bool(value) if nonempty else True)


def _integer(value):
    return type(value) is int and value >= 0


def _boolean(value):
    return type(value) is bool


def _right(value):
    """Return whether value is a contract right without hashing arbitrary input."""
    return isinstance(value, str) and value in RIGHTS


def _grant(value):
    return (isinstance(value, dict) and set(value) == {"subject", "right", "generation"}
            and _string(value["subject"]) and _right(value["right"])
            and _integer(value["generation"]))


def _event_id(event):
    return isinstance(event, dict) and _string(event.get("event_id"))


def _active(state, subject, right):
    entry = state["grants"].get((subject, right))
    return entry if entry and entry["active"] else None


def _frontier_matches(state, event):
    return (event["revision"] == state["revision"] and event["epoch"] == state["epoch"]
            and event["branch"] == state["branch"])


def _valid_init(event):
    required = {"event_id", "type", "group", "revision", "epoch", "branch", "roster", "grants"}
    if not isinstance(event, dict) or set(event) != required:
        return False
    if (event["type"] != "init" or not _string(event["event_id"]) or not _string(event["group"])
            or not _integer(event["revision"]) or not _integer(event["epoch"])
            or event["revision"] != 0 or event["epoch"] != 0
            or not _string(event["branch"]) or not isinstance(event["roster"], list)
            or not isinstance(event["grants"], list)):
        return False
    if not all(_string(member) for member in event["roster"]) or len(set(event["roster"])) != len(event["roster"]):
        return False
    if not all(_grant(grant) for grant in event["grants"]):
        return False
    keys = [(g["subject"], g["right"]) for g in event["grants"]]
    if len(set(keys)) != len(keys):
        return False
    lookup = {(g["subject"], g["right"]): g for g in event["grants"]}
    return all((member, "read") in lookup for member in event["roster"])


def _initial_state(event):
    return {
        "revision": event["revision"], "epoch": event["epoch"], "branch": event["branch"],
        "roster": set(event["roster"]),
        "grants": {(g["subject"], g["right"]): {"generation": g["generation"], "active": True}
                   for g in event["grants"]},
        "ops": {}, "ready": {member: True for member in event["roster"]},
        "fenced": False, "pending": set(), "spent": set(),
    }


def _basic(event, fields):
    return isinstance(event, dict) and set(event) == {"event_id", "type", *fields} and _event_id(event)


def _cover_is_well_formed(cover):
    if not isinstance(cover, list):
        return False
    seen_supports = set()
    for support in cover:
        if not isinstance(support, list) or not support or not all(_grant(g) for g in support):
            return False
        rendered = tuple((g["subject"], g["right"], g["generation"]) for g in support)
        canonical = tuple(sorted(rendered))
        if canonical in seen_supports:
            return False
        seen_supports.add(canonical)
        if len(set(rendered)) != len(rendered):
            return False
    return True


def _cover_is_sound(state, event):
    cover = event["cover"]
    # Every supplied authority atom must be an active, exact generation.
    for support in cover:
        for grant in support:
            current = _active(state, grant["subject"], grant["right"])
            if current is None or current["generation"] != grant["generation"]:
                return False
    required = []
    if event["right"] == "read":
        required = [(member, "read", _active(state, member, "read")["generation"])
                    for member in state["roster"]]
    else:
        grant = _active(state, event["actor"], "write")
        if grant is None:
            return False
        required = [(event["actor"], "write", grant["generation"])]
    singleton = {tuple((g["subject"], g["right"], g["generation"]) for g in support)
                 for support in cover if len(support) == 1}
    return all((item,) in singleton for item in required)


def _release_schema(event):
    return (_basic(event, {"op", "actor", "right", "revision", "epoch", "branch", "digest", "cover"})
            and _string(event["op"]) and _string(event["actor"]) and event["right"] in ("read", "write")
            and _integer(event["revision"]) and _integer(event["epoch"]) and _string(event["branch"])
            and _string(event["digest"]) and _cover_is_well_formed(event["cover"]))


def check_trace(events):
    """Return ordered contract violations without trusting any production component."""
    violations = []
    if not isinstance(events, list):
        return [{"index": 0, "code": "not_initialized"}]
    state = None
    seen_ids = set()
    for index, event in enumerate(events):
        if not _event_id(event):
            violations.append({"index": index, "code": "malformed"})
            continue
        event_id = event["event_id"]
        if event_id in seen_ids:
            violations.append({"index": index, "code": "duplicate_event"})
            continue
        seen_ids.add(event_id)
        if state is None:
            if event.get("type") != "init":
                violations.append({"index": index, "code": "not_initialized"})
            elif not _valid_init(event):
                violations.append({"index": index, "code": "malformed"})
            else:
                state = _initial_state(event)
            continue
        if event.get("type") == "init":
            violations.append({"index": index, "code": "malformed"})
            continue
        candidate = deepcopy(state)
        code = _apply(candidate, event)
        if code:
            violations.append({"index": index, "code": code})
        else:
            state = candidate
    if state is None:
        violations.append({"index": len(events), "code": "not_initialized"})
    return violations


def _apply(state, event):
    kind = event.get("type") if isinstance(event, dict) else None
    if kind == "deny":
        if not (_basic(event, {"subject", "right"}) and _string(event["subject"]) and _right(event["right"])):
            return "malformed"
        active = _active(state, event["subject"], event["right"])
        if active is not None:
            active["active"] = False
            state["revision"] += 1
            if event["right"] == "read" and event["subject"] in state["roster"]:
                state["fenced"] = True
                state["pending"].add(event["subject"])
        return None
    if kind == "allow":
        if not (_basic(event, {"subject", "right", "generation", "fresh_keys"}) and _string(event["subject"])
                and _right(event["right"]) and _integer(event["generation"]) and _boolean(event["fresh_keys"])):
            return "malformed"
        previous = state["grants"].get((event["subject"], event["right"]))
        if event["fresh_keys"] is not True or previous is None or previous["active"] or event["generation"] <= previous["generation"]:
            return "invalid_generation"
        state["revision"] += 1
        state["grants"][(event["subject"], event["right"])] = {"generation": event["generation"], "active": True}
        return None
    if kind == "allocate":
        if not (_basic(event, {"op"}) and _string(event["op"])):
            return "malformed"
        if event["op"] in state["ops"]:
            return "duplicate_operation"
        state["ops"][event["op"]] = {"released": False, "persisted": None, "abandoned": False}
        return None
    if kind == "release":
        if not _release_schema(event):
            return "malformed"
        op = state["ops"].get(event["op"])
        if op is None or op["released"] or op["abandoned"]:
            return "invalid_transition"
        if state["fenced"]:
            return "read_fenced"
        if not _frontier_matches(state, event):
            return "stale_frontier"
        actor = _active(state, event["actor"], event["right"])
        if actor is None:
            return "unauthorized_release"
        if not _cover_is_sound(state, event):
            return "unsound_cover"
        op.update({"released": True, "digest": event["digest"], "epoch": event["epoch"], "branch": event["branch"],
                   "actor": event["actor"], "right": event["right"], "actor_generation": actor["generation"],
                   "reader_generations": {member: _active(state, member, "read")["generation"] for member in state["roster"]}})
        return None
    if kind == "persist":
        if not (_basic(event, {"op", "envelope", "digest"}) and _string(event["op"]) and _string(event["envelope"]) and _string(event["digest"])):
            return "malformed"
        op = state["ops"].get(event["op"])
        if op is None or not op["released"] or op["abandoned"]:
            return "invalid_transition"
        if event["digest"] != op["digest"] or (op["persisted"] is not None and op["persisted"] != event["envelope"]):
            return "binding_mismatch"
        op["persisted"] = event["envelope"]
        return None
    if kind == "emit":
        if not (_basic(event, {"op", "envelope"}) and _string(event["op"]) and _string(event["envelope"])):
            return "malformed"
        op = state["ops"].get(event["op"])
        if op is None or not op["released"]:
            return "read_fenced" if state["fenced"] else "not_persisted"
        if op["abandoned"]:
            return "invalid_transition"
        if op["epoch"] != state["epoch"] or op["branch"] != state["branch"]:
            return "stale_frontier"
        if op["persisted"] is None:
            return "not_persisted"
        return None if event["envelope"] == op["persisted"] else "binding_mismatch"
    if kind == "consume":
        if not (_basic(event, {"op", "recipient"}) and _string(event["op"]) and _string(event["recipient"])):
            return "malformed"
        if state["fenced"]:
            return "read_fenced"
        op = state["ops"].get(event["op"])
        if op is None or not op["released"] or op["abandoned"]:
            return "invalid_transition"
        if op["persisted"] is None:
            return "not_persisted"
        if op["epoch"] != state["epoch"] or op["branch"] != state["branch"]:
            return "stale_frontier"
        if not state["ready"].get(event["recipient"], False):
            return "not_ready"
        if op["right"] == "write":
            actor = _active(state, op["actor"], "write")
            if actor is None or actor["generation"] != op["actor_generation"]:
                return "unauthorized_release"
        required_generation = op["reader_generations"].get(event["recipient"])
        recipient = _active(state, event["recipient"], "read")
        if required_generation is None or recipient is None or recipient["generation"] != required_generation:
            return "unauthorized_release"
        pair = (event["op"], event["recipient"])
        if pair in state["spent"]:
            return "replay"
        state["spent"].add(pair)
        return None
    if kind == "crash":
        if not (_basic(event, {"client"}) and _string(event["client"])):
            return "malformed"
        state["ready"][event["client"]] = False
        return None
    if kind == "recover":
        if not (_basic(event, {"client", "epoch", "branch"}) and _string(event["client"])
                and _integer(event["epoch"]) and _string(event["branch"])):
            return "malformed"
        if event["epoch"] != state["epoch"] or event["branch"] != state["branch"]:
            return "stale_frontier"
        if event["client"] not in state["roster"]:
            return "not_ready"
        state["ready"][event["client"]] = True
        return None
    if kind == "abandon":
        if not (_basic(event, {"op"}) and _string(event["op"])):
            return "malformed"
        op = state["ops"].get(event["op"])
        if op is None or not op["released"]:
            return "invalid_transition"
        if op["persisted"] is not None:
            return "invalid_transition"
        op["abandoned"] = True
        return None
    if kind == "repair":
        fields = {"parent_branch", "new_branch", "epoch", "revision", "removed", "update_path", "confirmed", "durable"}
        if not (_basic(event, fields) and _string(event["parent_branch"]) and _string(event["new_branch"])
                and _integer(event["epoch"]) and _integer(event["revision"]) and isinstance(event["removed"], list)
                and all(_string(item) for item in event["removed"]) and len(set(event["removed"])) == len(event["removed"])
                and all(_boolean(event[name]) for name in ("update_path", "confirmed", "durable"))):
            return "malformed"
        if (not state["fenced"] or event["parent_branch"] != state["branch"] or event["new_branch"] == state["branch"]
                or event["epoch"] != state["epoch"] + 1 or event["revision"] != state["revision"]
                or set(event["removed"]) != state["pending"]
                or any(_active(state, subject, "read") is not None for subject in event["removed"])
                or not all(event[name] for name in ("update_path", "confirmed", "durable"))):
            return "invalid_repair"
        state["roster"].difference_update(event["removed"])
        state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
        state["fenced"], state["pending"] = False, set()
        state["ready"] = {member: False for member in state["roster"]}
        return None
    if kind == "admit":
        if not (_basic(event, {"subject", "generation", "fresh_keys"}) and _string(event["subject"])
                and _integer(event["generation"]) and _boolean(event["fresh_keys"])):
            return "malformed"
        read = _active(state, event["subject"], "read")
        if (event["fresh_keys"] is not True or read is None or read["generation"] != event["generation"]
                or event["subject"] in state["roster"] or state["fenced"] or state["pending"]):
            return "invalid_transition"
        state["roster"].add(event["subject"])
        state["ready"][event["subject"]] = False
        return None
    return "malformed"
