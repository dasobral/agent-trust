"""Trace constructors and a deliberately permissive test-only oracle stub."""

from __future__ import annotations


def init_event():
    return {
        "event_id": "e-init",
        "type": "init",
        "group": "group-1",
        "revision": 0,
        "epoch": 0,
        "branch": "main",
        "roster": ["alice#1", "bob#1"],
        "grants": [
            {"subject": "alice#1", "right": "read", "generation": 1},
            {"subject": "bob#1", "right": "read", "generation": 1},
            {"subject": "alice#1", "right": "write", "generation": 1},
            {"subject": "alice#1", "right": "admin", "generation": 1},
            {"subject": "carol#1", "right": "read", "generation": 1},
        ],
    }


def release_event(op="op-1", *, actor="alice#1", right="write", revision=0,
                  epoch=0, branch="main", digest="digest-1", cover=None,
                  event_id="e-release"):
    if cover is None:
        if right == "read":
            cover = [
                [{"subject": "alice#1", "right": "read", "generation": 1}],
                [{"subject": "bob#1", "right": "read", "generation": 1}],
            ]
        else:
            cover = [[{"subject": actor, "right": "write", "generation": 1}]]
    return {"event_id": event_id, "type": "release", "op": op,
            "actor": actor, "right": right, "revision": revision, "epoch": epoch,
            "branch": branch, "digest": digest, "cover": cover}


def permissive_check_trace(events):
    """Negative control only: intentionally accepts every trace."""
    return []
