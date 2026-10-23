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
    apply = _apply
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
            elif "version" in event:
                # V2.1: the init event selects the version; only the integer 2 is valid.
                if not _valid_init_v2(event):
                    violations.append({"index": index, "code": "malformed"})
                else:
                    state, apply = _initial_state_v2(event), _apply_v2
            elif not _valid_init(event):
                violations.append({"index": index, "code": "malformed"})
            else:
                state = _initial_state(event)
            continue
        if event.get("type") == "init":
            violations.append({"index": index, "code": "malformed"})
            continue
        candidate = deepcopy(state)
        code = apply(candidate, event)
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


# ---------------------------------------------------------------------------
# Trace contract version 2 (R-5): docs/trace-contract.md, section "version 2".
# A separate state machine; the version 1 path above is unchanged.
# ---------------------------------------------------------------------------

REKEY_RIGHTS = ("write", "admin", "admit")
EVIDENCE_LABELS = ("pair", "single")


def _version_two(value):
    return type(value) is int and value == 2


def _distinct_strings(value):
    return (isinstance(value, list) and all(_string(item) for item in value)
            and len(set(value)) == len(value))


def _valid_init_v2(event):
    required = {"event_id", "type", "version", "group", "policy_revision", "epoch", "branch",
                "roster", "keys", "grants"}
    if not isinstance(event, dict) or set(event) != required:
        return False
    if (event["type"] != "init" or not _version_two(event["version"])
            or not _string(event["event_id"]) or not _string(event["group"])
            or not _integer(event["policy_revision"]) or event["policy_revision"] != 0
            or not _integer(event["epoch"]) or event["epoch"] != 0
            or not _string(event["branch"]) or not _distinct_strings(event["roster"])
            or not isinstance(event["keys"], dict) or not isinstance(event["grants"], list)):
        return False
    keys = event["keys"]
    if set(keys) != set(event["roster"]) or not all(_string(value) for value in keys.values()):
        return False
    if len(set(keys.values())) != len(keys):
        return False
    if not all(_grant(grant) for grant in event["grants"]):
        return False
    pairs = [(g["subject"], g["right"]) for g in event["grants"]]
    if len(set(pairs)) != len(pairs):
        return False
    return all((member, "read") in set(pairs) for member in event["roster"])


def _initial_state_v2(event):
    return {
        "policy_revision": 0, "epoch": 0, "branch": event["branch"],
        "seen_branches": {event["branch"]},
        "roster": set(event["roster"]),
        "grants": {(g["subject"], g["right"]): {"generation": g["generation"], "active": True}
                   for g in event["grants"]},
        "keys": dict(event["keys"]),
        "key_owner": {key: member for member, key in event["keys"].items()},
        "seen_key_packages": set(),
        "fenced": False, "fence_revision": None, "repair_pending": None,
        "ops": {}, "ready": {member: True for member in event["roster"]}, "spent": set(),
    }


def _required_removals(state):
    """V2.2: roster members whose read grant is not active."""
    return {member for member in state["roster"] if _active(state, member, "read") is None}


def _grant_rule_holds(state, subject, right, generation):
    """V2.2 grant rule: absent → 0, inactive → old + 1, active → never."""
    record = state["grants"].get((subject, right))
    if record is None:
        return generation == 0
    if record["active"]:
        return False
    return generation == record["generation"] + 1


def _commit_frontier_is_current(state, event):
    return event["parent_branch"] == state["branch"] and event["epoch"] == state["epoch"] + 1


def _new_branch_is_fresh(state, event):
    return event["new_branch"] != event["parent_branch"] and event["new_branch"] not in state["seen_branches"]


def _advance_frontier(state, event):
    """V2.2 frontier advance: new epoch and branch; every client becomes locally unready."""
    state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
    state["seen_branches"].add(event["new_branch"])
    state["ready"] = {}


def _v2_schema(event):
    """Return whether a non-init version 2 event has its exact field set and types."""
    kind = event.get("type")
    if kind == "deny":
        return _basic(event, {"subject", "right"}) and _string(event["subject"]) and _right(event["right"])
    if kind == "allow":
        return (_basic(event, {"subject", "right", "generation"}) and _string(event["subject"])
                and _right(event["right"]) and _integer(event["generation"]))
    if kind in ("allocate", "abandon"):
        return _basic(event, {"op"}) and _string(event["op"])
    if kind == "persist":
        return (_basic(event, {"op", "envelope", "digest"}) and _string(event["op"])
                and _string(event["envelope"]) and _string(event["digest"]))
    if kind == "emit":
        return _basic(event, {"op", "envelope"}) and _string(event["op"]) and _string(event["envelope"])
    if kind == "consume":
        return _basic(event, {"op", "recipient"}) and _string(event["op"]) and _string(event["recipient"])
    if kind == "crash":
        return _basic(event, {"client"}) and _string(event["client"])
    if kind == "recover":
        return (_basic(event, {"client", "epoch", "branch"}) and _string(event["client"])
                and _integer(event["epoch"]) and _string(event["branch"]))
    if kind == "admit":
        fields = {"actor", "subject", "generation", "parent_branch", "new_branch", "epoch", "key", "key_package"}
        return (_basic(event, fields) and _integer(event["generation"]) and _integer(event["epoch"])
                and all(_string(event[name]) for name in fields - {"generation", "epoch"}))
    if kind == "release":
        return (_basic(event, {"op", "actor", "right", "policy_revision", "epoch", "branch", "digest", "cover"})
                and _string(event["op"]) and _string(event["actor"])
                and isinstance(event["right"], str) and event["right"] in ("read", "write")
                and _integer(event["policy_revision"]) and _integer(event["epoch"])
                and _string(event["branch"]) and _string(event["digest"])
                and _cover_is_well_formed(event["cover"]))
    if kind == "repair_stage":
        return (_basic(event, {"actor", "parent_branch", "new_branch", "epoch", "policy_revision", "removed"})
                and _string(event["actor"]) and _string(event["parent_branch"]) and _string(event["new_branch"])
                and _integer(event["epoch"]) and _integer(event["policy_revision"])
                and _distinct_strings(event["removed"]))
    if kind == "confirm":
        return (_basic(event, {"actor", "branch", "hash"}) and _string(event["actor"])
                and _string(event["branch"]) and _string(event["hash"]))
    if kind == "repair_open":
        return (_basic(event, {"branch", "evidence"}) and _string(event["branch"])
                and isinstance(event["evidence"], str) and event["evidence"] in EVIDENCE_LABELS)
    if kind == "rekey":
        fields = {"actor", "subject", "right", "generation", "parent_branch", "new_branch", "epoch", "new_key"}
        return (_basic(event, fields) and _integer(event["generation"]) and _integer(event["epoch"])
                and isinstance(event["right"], str) and event["right"] in REKEY_RIGHTS
                and all(_string(event[name]) for name in fields - {"right", "generation", "epoch"}))
    # Unknown types, including the version 1 boolean `repair`, are malformed.
    return False


def _cover_is_exact_v2(state, event, writer_generation):
    """V2.3 release check 5: exactly the writer singleton plus every roster reader singleton."""
    required = {((event["actor"], "write", writer_generation),)}
    for member in state["roster"]:
        required.add(((member, "read", _active(state, member, "read")["generation"]),))
    supplied = [tuple((g["subject"], g["right"], g["generation"]) for g in support)
                for support in event["cover"]]
    return all(len(support) == 1 for support in supplied) and set(supplied) == required


def _apply_v2(state, event):
    if not _v2_schema(event):
        return "malformed"
    kind = event["type"]
    handler = _V2_HANDLERS[kind]
    return handler(state, event)


def _v2_deny(state, event):
    active = _active(state, event["subject"], event["right"])
    if active is not None:
        active["active"] = False
        state["policy_revision"] += 1
        if event["right"] == "read" and event["subject"] in state["roster"]:
            state["fenced"] = True
            state["fence_revision"] = state["policy_revision"]
    return None


def _v2_allow(state, event):
    if event["subject"] in state["roster"]:
        return "invalid_transition"
    if not _grant_rule_holds(state, event["subject"], event["right"], event["generation"]):
        return "invalid_generation"
    state["grants"][(event["subject"], event["right"])] = {"generation": event["generation"], "active": True}
    state["policy_revision"] += 1
    return None


def _v2_admit(state, event):
    if state["fenced"] or state["repair_pending"] is not None or _required_removals(state):
        return "read_fenced"
    if event["actor"] not in state["roster"] or _active(state, event["actor"], "admin") is None:
        return "unauthorized"
    if event["subject"] in state["roster"]:
        return "invalid_transition"
    read = _active(state, event["subject"], "read")
    if read is None or read["generation"] != event["generation"]:
        return "invalid_generation"
    if _active(state, event["subject"], "admit") is None:
        return "unauthorized"
    if not _commit_frontier_is_current(state, event):
        return "stale_frontier"
    if not _new_branch_is_fresh(state, event):
        return "invalid_transition"
    owner = state["key_owner"].get(event["key"])
    if event["key_package"] in state["seen_key_packages"] or (owner is not None and owner != event["subject"]):
        return "stale_key"
    state["roster"].add(event["subject"])
    state["keys"][event["subject"]] = event["key"]
    state["key_owner"].setdefault(event["key"], event["subject"])
    state["seen_key_packages"].add(event["key_package"])
    _advance_frontier(state, event)
    return None


def _v2_allocate(state, event):
    if event["op"] in state["ops"]:
        return "duplicate_operation"
    state["ops"][event["op"]] = {"released": False, "persisted": None, "abandoned": False}
    return None


def _v2_release(state, event):
    op = state["ops"].get(event["op"])
    if op is None or op["released"] or op["abandoned"]:
        return "invalid_transition"
    if state["fenced"] or state["repair_pending"] is not None:
        return "read_fenced"
    if (event["policy_revision"] != state["policy_revision"] or event["epoch"] != state["epoch"]
            or event["branch"] != state["branch"]):
        return "stale_frontier"
    writer = _active(state, event["actor"], "write")
    if event["actor"] not in state["roster"] or writer is None:
        return "unauthorized_release"
    if not _cover_is_exact_v2(state, event, writer["generation"]):
        return "unsound_cover"
    op.update({"released": True, "digest": event["digest"], "epoch": event["epoch"], "branch": event["branch"],
               "actor": event["actor"], "right": event["right"], "actor_generation": writer["generation"],
               "reader_generations": {member: _active(state, member, "read")["generation"]
                                      for member in state["roster"]}})
    return None


def _v2_persist(state, event):
    op = state["ops"].get(event["op"])
    if op is None or not op["released"] or op["abandoned"]:
        return "invalid_transition"
    if event["digest"] != op["digest"] or (op["persisted"] is not None and op["persisted"] != event["envelope"]):
        return "binding_mismatch"
    op["persisted"] = event["envelope"]
    return None


def _v2_emit(state, event):
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


def _v2_consume(state, event):
    if state["fenced"] or state["repair_pending"] is not None:
        return "read_fenced"
    op = state["ops"].get(event["op"])
    if op is None or not op["released"] or op["abandoned"]:
        return "invalid_transition"
    if op["persisted"] is None:
        return "not_persisted"
    if op["epoch"] != state["epoch"] or op["branch"] != state["branch"]:
        return "stale_frontier"
    recipient_name = event["recipient"]
    if not state["ready"].get(recipient_name, False) or recipient_name not in state["roster"]:
        return "not_ready"
    # Both rights are sent by a writer, so the writer generation is frozen for both.
    writer = _active(state, op["actor"], "write")
    if writer is None or writer["generation"] != op["actor_generation"]:
        return "unauthorized_release"
    frozen = op["reader_generations"].get(recipient_name)
    recipient = _active(state, recipient_name, "read")
    if frozen is None or recipient is None or recipient["generation"] != frozen:
        return "unauthorized_release"
    pair = (event["op"], recipient_name)
    if pair in state["spent"]:
        return "replay"
    state["spent"].add(pair)
    return None


def _v2_crash(state, event):
    state["ready"][event["client"]] = False
    return None


def _v2_recover(state, event):
    if event["epoch"] != state["epoch"] or event["branch"] != state["branch"]:
        return "stale_frontier"
    if event["client"] not in state["roster"]:
        return "not_ready"
    state["ready"][event["client"]] = True
    return None


def _v2_abandon(state, event):
    op = state["ops"].get(event["op"])
    if op is None or not op["released"] or op["persisted"] is not None:
        return "invalid_transition"
    op["abandoned"] = True
    return None


def _v2_repair_stage(state, event):
    if not state["fenced"]:
        return "invalid_repair"
    if not _commit_frontier_is_current(state, event):
        return "stale_frontier"
    removals = _required_removals(state)
    if event["actor"] not in state["roster"] or event["actor"] in removals:
        return "invalid_repair"
    if (event["policy_revision"] != state["policy_revision"]
            or (state["fence_revision"] is not None and event["policy_revision"] < state["fence_revision"])):
        return "invalid_repair"
    if not removals or set(event["removed"]) != removals:
        return "invalid_repair"
    if not _new_branch_is_fresh(state, event):
        return "invalid_repair"
    for member in event["removed"]:
        state["roster"].discard(member)
        state["keys"].pop(member, None)   # key_owner keeps the binding
    _advance_frontier(state, event)
    # A stacked repair replaces the pending one: superseded confirmations never count.
    state["repair_pending"] = {"branch": event["new_branch"], "committer": event["actor"], "confirmations": {}}
    return None


def _v2_confirm(state, event):
    pending = state["repair_pending"]
    if pending is None or event["branch"] != pending["branch"] or event["actor"] not in state["roster"]:
        return "invalid_repair"
    confirmations = pending["confirmations"]
    stored = confirmations.get(event["actor"])
    committer_hash = confirmations.get(pending["committer"])
    if stored is not None and stored != event["hash"]:
        return "binding_mismatch"
    if event["actor"] != pending["committer"] and committer_hash is not None and committer_hash != event["hash"]:
        return "binding_mismatch"
    confirmations[event["actor"]] = event["hash"]
    return None


def _v2_repair_open(state, event):
    pending = state["repair_pending"]
    if pending is None or event["branch"] != pending["branch"]:
        return "invalid_repair"
    if _required_removals(state):
        return "invalid_repair"
    committer = pending["committer"]
    confirmations = pending["confirmations"]
    committer_hash = confirmations.get(committer)
    if event["evidence"] == "pair":
        confirmed = (len(state["roster"]) >= 2 and committer_hash is not None
                     and any(member != committer and confirmations.get(member) == committer_hash
                             for member in state["roster"]))
    else:
        confirmed = state["roster"] == {committer} and committer_hash is not None
    if not confirmed:
        return "unconfirmed"
    state["fenced"], state["fence_revision"], state["repair_pending"] = False, None, None
    return None


def _v2_rekey(state, event):
    if _active(state, event["actor"], "admin") is None:
        return "unauthorized"
    if not _grant_rule_holds(state, event["subject"], event["right"], event["generation"]):
        return "invalid_generation"
    if event["subject"] not in state["roster"]:
        return "invalid_transition"
    if state["fenced"] or state["repair_pending"] is not None:
        return "read_fenced"
    if not _commit_frontier_is_current(state, event):
        return "stale_frontier"
    if not _new_branch_is_fresh(state, event):
        return "invalid_transition"
    if event["new_key"] in state["key_owner"]:
        return "stale_key"
    state["grants"][(event["subject"], event["right"])] = {"generation": event["generation"], "active": True}
    state["policy_revision"] += 1
    state["keys"][event["subject"]] = event["new_key"]
    state["key_owner"][event["new_key"]] = event["subject"]
    _advance_frontier(state, event)
    return None


_V2_HANDLERS = {
    "deny": _v2_deny, "allow": _v2_allow, "admit": _v2_admit, "allocate": _v2_allocate,
    "release": _v2_release, "persist": _v2_persist, "emit": _v2_emit, "consume": _v2_consume,
    "crash": _v2_crash, "recover": _v2_recover, "abandon": _v2_abandon,
    "repair_stage": _v2_repair_stage, "confirm": _v2_confirm, "repair_open": _v2_repair_open,
    "rekey": _v2_rekey,
}
