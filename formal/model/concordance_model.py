#!/usr/bin/env python3
"""Exhaustive finite-state check of the concordance construction.

This is the executable companion of formal/paper/concordance.tex. It models the
ledger, a symbolic MLS group and a retained-key adversary, then enumerates
every reachable state within fixed resource bounds (not a depth bound).

The adversary is implicit and maximal: every party keeps every epoch key it
ever obtained, forever, and every party is treated as potentially corrupt.
Nothing in the transition relation consults the safety property. A party
that holds an epoch key can read every message protected under it, whatever
the ledger says.

Usage:
    python3 concordance_model.py            human-readable report
    python3 concordance_model.py --json     machine-readable report
"""

from __future__ import annotations

import json
import sys
from collections import deque
from typing import Iterable, NamedTuple

PARTIES = ("A", "B", "C")
RECEIVERS = ("A", "B")

# Ledger facts. Read: A and B hold root grants; C reads through a delegation
# from B, so C's justification is {rB, dBC}. Write: A and C hold root grants;
# iAC is an invocation that lets C act on behalf of A.
FACTS = ("rA", "rB", "dBC", "wA", "wC", "iAC")
READ_PATH = {"A": ("rA",), "B": ("rB",), "C": ("rB", "dBC")}
DIRECT_READ_FACT = {"A": "rA", "B": "rB", "C": "dBC"}
WRITE_PATHS = {
    ("A", "self"): ("wA",),
    ("C", "self"): ("wC",),
    ("C", "for-A"): ("wA", "wC", "iAC"),
}

# Resource bounds. Together they make the reachable state space finite, so
# the search below is exhaustive for these bounds rather than depth-limited.
MAX_POLICY_CHANGES = 3  # revocations plus reauthorizations
MAX_GEN = 1             # each fact can be reissued once
MAX_EPOCH = 3
MAX_READ_RELEASES = 2
MAX_WRITE_RELEASES = 2
MAX_ACCEPTS = 3

# Each mutant deletes exactly one rule of the construction (paper, Sec. 4).
MUTANTS = {
    "no_fence": "a read revocation does not close the fence (rule F)",
    "no_cascade": "the fence and the repair look only at a member's own direct fact, not its delegation chain (rule F)",
    "no_update_path": "the removal commit carries no fresh path secret, so removed members derive the new key (rule C)",
    "remove_without_commit": "the ledger drops members from the roster without a new epoch (rule C)",
    "stale_epoch": "a sender may protect a released message under an older epoch it still holds (rule R)",
    "confused_deputy": "an invocation release checks the executor's facts but not the origin's (rule R)",
    "no_one_shot": "a receiver may accept the same release twice (rule A)",
    "no_certificate": "a receiver accepts a write on MLS sender authentication alone (rule A)",
    "external_rejoin": "the sequencer accepts an external commit, so a removed party rejoins with its retained signature key (condition K2)",
}


class State(NamedTuple):
    facts: tuple[tuple[int, bool], ...]          # (generation, live) per FACTS entry
    changes: int                                 # policy changes so far
    revision: int                                # ledger revision
    fence_closed: bool
    epoch: int
    roster: frozenset                            # {(party, justification)}
    roster_history: tuple[frozenset, ...]        # parties of each epoch
    knows: tuple[frozenset, ...]                 # epochs whose key each party ever held
    read_releases: tuple                         # (epoch, revision, authorized readers)
    write_releases: tuple                        # (rid, actor, path, valid at cut)
    accepts: tuple                               # (rid or None, receiver, actor)


def fact_index(name: str) -> int:
    return FACTS.index(name)


def fact_id(state: State, name: str) -> tuple[str, int]:
    return (name, state.facts[fact_index(name)][0])


def live(state: State, fid: tuple[str, int]) -> bool:
    gen, is_live = state.facts[fact_index(fid[0])]
    return is_live and gen == fid[1]


def valid(state: State, justification: Iterable[tuple[str, int]]) -> bool:
    return all(live(state, fid) for fid in justification)


def read_justification(state: State, party: str) -> frozenset:
    return frozenset(fact_id(state, name) for name in READ_PATH[party])


def authorized_readers(state: State) -> frozenset:
    return frozenset(p for p in PARTIES if valid(state, read_justification(state, p)))


def entry_dead(state: State, entry, mutant: str | None) -> bool:
    party, justification = entry
    if mutant == "no_cascade":
        direct = DIRECT_READ_FACT[party]
        return not all(live(state, fid) for fid in justification if fid[0] == direct)
    return not valid(state, justification)


def initial_state() -> State:
    facts = tuple((0, True) for _ in FACTS)
    base = State(facts, 0, 0, False, 0, frozenset(), (), (), (), (), ())
    roster = frozenset((p, read_justification(base, p)) for p in PARTIES)
    return base._replace(
        roster=roster,
        roster_history=(frozenset(PARTIES),),
        knows=tuple(frozenset({0}) for _ in PARTIES),
    )


def set_fact(state: State, name: str, gen: int, is_live: bool) -> tuple:
    facts = list(state.facts)
    facts[fact_index(name)] = (gen, is_live)
    return tuple(facts)


def new_epoch(state: State, roster: frozenset, learners: frozenset) -> State:
    epoch = state.epoch + 1
    knows = tuple(
        k | {epoch} if p in learners else k for p, k in zip(PARTIES, state.knows)
    )
    parties = frozenset(p for p, _ in roster)
    return state._replace(
        epoch=epoch,
        roster=roster,
        roster_history=state.roster_history + (parties,),
        knows=knows,
    )


def successors(state: State, mutant: str | None = None) -> Iterable[tuple[str, State]]:
    roster_parties = frozenset(p for p, _ in state.roster)

    # Policy: revoke a live fact, or reissue a revoked one with a new generation.
    if state.changes < MAX_POLICY_CHANGES:
        for name in FACTS:
            gen, is_live = state.facts[fact_index(name)]
            if is_live:
                nxt = state._replace(
                    facts=set_fact(state, name, gen, False),
                    changes=state.changes + 1,
                    revision=state.revision + 1,
                )
                if mutant != "no_fence" and any(entry_dead(nxt, e, mutant) for e in nxt.roster):
                    nxt = nxt._replace(fence_closed=True)
                yield f"revoke({name})", nxt
            elif gen < MAX_GEN:
                nxt = state._replace(
                    facts=set_fact(state, name, gen + 1, True),
                    changes=state.changes + 1,
                    revision=state.revision + 1,
                )
                yield f"reissue({name})", nxt

    # Repair: a continuing member whose own entry is still valid commits the
    # removal of every dead entry, with a fresh path secret.
    if state.fence_closed:
        keep = frozenset(e for e in state.roster if not entry_dead(state, e, mutant))
        kept_parties = frozenset(p for p, _ in keep)
        if mutant == "remove_without_commit":
            if keep:
                nxt = state._replace(roster=keep, fence_closed=False)
                yield "drop_members_without_commit", nxt
        elif state.epoch < MAX_EPOCH:
            for committer in sorted(kept_parties):
                learners = kept_parties
                if mutant == "no_update_path":
                    learners = roster_parties
                nxt = new_epoch(state, keep, learners)._replace(fence_closed=False)
                yield f"repair_commit({committer})", nxt

    # Admission of a currently authorized reader into a new epoch.
    if not state.fence_closed and state.epoch < MAX_EPOCH:
        for p in PARTIES:
            justification = read_justification(state, p)
            if p not in roster_parties and valid(state, justification):
                roster = state.roster | {(p, justification)}
                parties = roster_parties | {p}
                yield f"admit({p})", new_epoch(state, roster, parties)

    # External commit (ETK, Sec. 5.2): a former member signs a commit with the
    # signature key it retained and adds itself to the next epoch. The ledger
    # is not consulted, so neither its record nor its fence changes.
    if mutant == "external_rejoin" and state.epoch < MAX_EPOCH:
        for p in PARTIES:
            if p not in roster_parties:
                roster = state.roster | {(p, read_justification(state, p))}
                yield f"external_commit({p})", new_epoch(state, roster, roster_parties | {p})

    # Read release: the ledger releases only with an open fence, at the
    # canonical epoch. The record stores the ground truth of who was
    # authorized at this revision; the rule itself never reads it.
    if len(state.read_releases) < MAX_READ_RELEASES:
        fence_ok = not state.fence_closed
        for sender in sorted(roster_parties):
            epochs = [state.epoch]
            if mutant == "stale_epoch":
                epochs = sorted(state.knows[PARTIES.index(sender)])
            if fence_ok:
                for e in epochs:
                    record = (e, state.revision, authorized_readers(state))
                    yield f"release_read({sender},epoch={e})", state._replace(
                        read_releases=state.read_releases + (record,)
                    )

    # Write release: the ledger checks the justification of the path.
    if len(state.write_releases) < MAX_WRITE_RELEASES:
        for (actor, path), names in sorted(WRITE_PATHS.items()):
            justification = frozenset(fact_id(state, n) for n in names)
            checked = justification
            if mutant == "confused_deputy" and path != "self":
                checked = frozenset(f for f in justification if f[0] != "wA")
            if valid(state, checked):
                rid = len(state.write_releases)
                record = (rid, actor, path, valid(state, justification))
                yield f"release_write({actor},{path})", state._replace(
                    write_releases=state.write_releases + (record,)
                )

    # Acceptance at an honest receiver.
    if len(state.accepts) < MAX_ACCEPTS:
        for rid, actor, _path, _ok in state.write_releases:
            for receiver in RECEIVERS:
                seen = any(a[0] == rid and a[1] == receiver for a in state.accepts)
                if not seen or mutant == "no_one_shot":
                    yield f"accept(w{rid},{receiver})", state._replace(
                        accepts=state.accepts + ((rid, receiver, actor),)
                    )
        if mutant == "no_certificate":
            # Any party that ever held an epoch key can still authenticate as a
            # group sender in that epoch with its retained signature key.
            for actor in PARTIES:
                for receiver in RECEIVERS:
                    if receiver != actor:
                        yield f"inject_write({actor}->{receiver})", state._replace(
                            accepts=state.accepts + ((None, receiver, actor),)
                        )


# --- Properties --------------------------------------------------------------

def read_concordance(state: State) -> bool:
    """Theorem 1: whoever can derive the key of a released message was authorized at its cut."""
    return all(
        p in authorized
        for epoch, _rev, authorized in state.read_releases
        for p, known in zip(PARTIES, state.knows)
        if epoch in known
    )


def write_concordance(state: State) -> bool:
    """Theorem 2: every acceptance traces to one release valid at its cut, once per receiver."""
    releases = {rid: ok for rid, _a, _p, ok in state.write_releases}
    pairs = [(rid, receiver) for rid, receiver, _ in state.accepts]
    return len(pairs) == len(set(pairs)) and all(
        rid is not None and releases.get(rid, False) for rid, _r, _a in state.accepts
    )


def fence_lemma(state: State) -> bool:
    """Lemma 1: an open fence implies every roster entry is valid now."""
    return state.fence_closed or all(valid(state, j) for _, j in state.roster)


def key_confinement(state: State) -> bool:
    """Hypothesis K (symbolic form): only members of epoch e ever hold its key."""
    return all(
        p in state.roster_history[e]
        for p, known in zip(PARTIES, state.knows)
        for e in known
    )


PROPERTIES = (
    ("read_concordance", read_concordance),
    ("write_concordance", write_concordance),
    ("fence_lemma", fence_lemma),
    ("key_confinement", key_confinement),
)
SAFETY = ("read_concordance", "write_concordance")


def failed(state: State) -> list[str]:
    return [name for name, check in PROPERTIES if not check(state)]


# --- Search ------------------------------------------------------------------

def explore(mutant: str | None = None, stop_on_safety: bool = False):
    start = initial_state()
    parent: dict[State, tuple[State | None, str | None]] = {start: (None, None)}
    queue = deque([start])
    transitions = 0
    violations: dict[str, State] = {}
    while queue:
        state = queue.popleft()
        for name in failed(state):
            violations.setdefault(name, state)
        if stop_on_safety and any(v in violations for v in SAFETY):
            break
        for label, nxt in successors(state, mutant):
            transitions += 1
            if nxt not in parent:
                parent[nxt] = (state, label)
                queue.append(nxt)
    return parent, transitions, violations


def trace_to(parent, state: State) -> list[str]:
    labels = []
    while parent[state][0] is not None:
        state, label = parent[state][0], parent[state][1]
        labels.append(label)
    return labels[::-1]


def witnesses(parent) -> dict[str, list[str]]:
    """Non-vacuity: the good model must reach each of these situations."""
    goals = {
        "read_release_after_repair": lambda s: any(e > 0 for e, _, _ in s.read_releases)
        and s.changes > 0,
        "cascade_repaired": lambda s: not s.facts[fact_index("rB")][1]
        and "C" not in {p for p, _ in s.roster}
        and not s.fence_closed,
        "readmitted_after_revocation": lambda s: any(
            p == "A" and ("rA", 1) in j for p, j in s.roster
        ),
        "invocation_write_accepted": lambda s: any(
            p == "for-A" and any(a[0] == rid for a in s.accepts)
            for rid, _a, p, _ok in s.write_releases
        ),
        "revoked_reader_holds_old_key": lambda s: any(
            0 in k and p not in authorized_readers(s) for p, k in zip(PARTIES, s.knows)
        )
        and s.epoch > 0,
    }
    found = {}
    for state in parent:  # dict preserves BFS order, so traces are shortest
        for goal, test in goals.items():
            if goal not in found and test(state):
                found[goal] = trace_to(parent, state)
    return {g: found.get(g) for g in goals}


def repair_always_possible(parent) -> bool:
    """Progress precondition: with a valid continuing member and epoch budget, repair is enabled."""
    for state in parent:
        if state.fence_closed and state.epoch < MAX_EPOCH:
            if any(valid(state, j) for _, j in state.roster):
                if not any(l.startswith("repair_commit") for l, _ in successors(state)):
                    return False
    return True


def run() -> dict:
    parent, transitions, violations = explore()
    report = {
        "bounds": {
            "parties": list(PARTIES),
            "facts": list(FACTS),
            "max_policy_changes": MAX_POLICY_CHANGES,
            "max_generation": MAX_GEN,
            "max_epoch": MAX_EPOCH,
            "max_read_releases": MAX_READ_RELEASES,
            "max_write_releases": MAX_WRITE_RELEASES,
            "max_accepts": MAX_ACCEPTS,
        },
        "good_model": {
            "reachable_states": len(parent),
            "transitions": transitions,
            "exhaustive": True,
            "states_with_read_release": sum(1 for s in parent if s.read_releases),
            "states_with_accept": sum(1 for s in parent if s.accepts),
            "violations": sorted(violations),
            "repair_always_possible": repair_always_possible(parent),
            "witnesses": witnesses(parent),
        },
        "mutants": {},
    }
    for mutant, description in MUTANTS.items():
        m_parent, _t, m_viol = explore(mutant, stop_on_safety=True)
        safety = [v for v in SAFETY if v in m_viol]
        entry = {"deleted_rule": description, "safety_violated": safety}
        if safety:
            entry["shortest_counterexample"] = trace_to(m_parent, m_viol[safety[0]])
            entry["also_failed"] = sorted(v for v in m_viol if v not in SAFETY)
        report["mutants"][mutant] = entry
    return report


def main() -> int:
    report = run()
    good = report["good_model"]
    ok = (
        not good["violations"]
        and good["repair_always_possible"]
        and all(good["witnesses"].values())
        and all(m["safety_violated"] for m in report["mutants"].values())
    )
    report["accepted"] = ok
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"good model: {good['reachable_states']} states, {good['transitions']} transitions, "
              f"exhaustive within bounds")
        print(f"  states with a read release: {good['states_with_read_release']}, "
              f"with an accepted write: {good['states_with_accept']}")
        print(f"  violations: {good['violations'] or 'none'}")
        print(f"  repair always possible: {good['repair_always_possible']}")
        for goal, trace in good["witnesses"].items():
            print(f"  witness {goal}: {' -> '.join(trace) if trace else 'NOT REACHED'}")
        for name, m in report["mutants"].items():
            verdict = ", ".join(m["safety_violated"]) or "NO COUNTEREXAMPLE"
            print(f"mutant {name}: {verdict}")
            if m.get("shortest_counterexample"):
                print(f"    {' -> '.join(m['shortest_counterexample'])}")
        print("ACCEPTED" if ok else "REJECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
