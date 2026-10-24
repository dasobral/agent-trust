"""Experiment runner.

An experiment is a TOML file: metadata, the topology it needs, and an ordered list
of ``[[step]]`` tables. Each step is an *action* (it drives the testbed through the
control and application APIs) or a *check* (``do = "check.<name>"``, it observes and
asserts). Every action states the outcome it expects (``expect``, default ``"ok"``,
otherwise an error code). The runner stops at the first failed step, collects the
artifacts, and writes ``report.json`` and ``report.md``.

Nothing here knows how the testbed is deployed: it reads ``deploy.json`` only.
"""
from __future__ import annotations

from collections import Counter
import json
import statistics
import threading
import time
import tomllib
from pathlib import Path

from . import oracle as oracle_mod
from .api import ServiceError, Testbed


class StepFailure(Exception):
    pass


class Experiment:
    def __init__(self, path):
        self.path = Path(path)
        data = tomllib.loads(self.path.read_text())
        meta = data.get("experiment", {})
        self.id = meta["id"]
        self.title = meta.get("title", self.id)
        self.hypothesis = meta.get("hypothesis", "")
        topology = meta["topology"]
        self.topology_path = (self.path.parent / topology).resolve()
        self.steps = data.get("step", [])
        if not self.steps:
            raise ValueError(f"{path}: no [[step]] tables")


class Runner:
    def __init__(self, testbed: Testbed, run_dir, log=print, lifecycle=None):
        self.tb = testbed
        # (backend module, run_dir): stops and starts services for restart experiments.
        self.lifecycle = lifecycle
        self.run_dir = Path(run_dir)
        self.log = log
        self.sent = {}          # op -> {"from", "text", "payload_hex", "recipients"}
        self.labels = {}        # experiment label -> op id chosen by the sidecar
        self.metrics = {"send_ms": [], "admit_ms": []}
        self._lock = threading.Lock()
        self.artifacts = {}

    # ------------------------------------------------------------------
    # Driver
    # ------------------------------------------------------------------

    def run(self, experiment: Experiment):
        results = []
        started = time.time()
        failed = False
        for index, step in enumerate(experiment.steps):
            action = step.get("do", "")
            label = step.get("name", action)
            begin = time.monotonic()
            record = {"index": index, "do": action, "name": label}
            try:
                handler = getattr(self, "do_" + action.replace(".", "_").replace("-", "_"), None)
                if handler is None:
                    raise StepFailure(f"unknown step {action!r}")
                detail = handler(step)
                record.update(status="pass", detail=detail)
            except (StepFailure, ServiceError) as error:
                record.update(status="fail", error=str(error))
                failed = True
            record["seconds"] = round(time.monotonic() - begin, 3)
            results.append(record)
            mark = "PASS" if record["status"] == "pass" else "FAIL"
            self.log(f"[{mark}] {index:02d} {label}" + ("" if mark == "PASS" else f": {record['error']}"))
            if failed:
                break
        return {
            "experiment": experiment.id,
            "title": experiment.title,
            "hypothesis": experiment.hypothesis,
            "result": "fail" if failed else "pass",
            "started": started,
            "seconds": round(time.time() - started, 3),
            "steps": results,
            "skipped_steps": len(experiment.steps) - len(results),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _expect(self, step, call):
        """Runs ``call`` and compares its outcome with ``step["expect"]`` (default ok)."""
        expect = step.get("expect", "ok")
        try:
            value = call()
        except ServiceError as error:
            if expect == "ok":
                raise StepFailure(f"expected ok, got {error.message}") from None
            if error.code != expect:
                raise StepFailure(f"expected {expect}, got {error.message}") from None
            return {"refused": error.code, "error": error.message}
        if expect != "ok":
            raise StepFailure(f"expected {expect}, but the step succeeded: {value}")
        return value

    def _wait(self, predicate, what, timeout=30, interval=0.1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(interval)
        raise StepFailure(f"timeout after {timeout}s waiting for {what}")

    def _statuses(self):
        """Status of every reachable agent; a stopped agent is left out."""
        out = {}
        for name, agent in self.tb.agents.items():
            try:
                out[name] = agent.status()
            except ServiceError as error:
                if not error.message.startswith("transport"):
                    raise
        return out

    def _inboxes(self):
        out = {}
        for name, agent in self.tb.agents.items():
            try:
                out[name] = agent.inbox()
            except ServiceError as error:
                if not error.message.startswith("transport"):
                    raise
        return out

    def _members(self):
        return [name for name, s in self._statuses().items()
                if s["membership"] == "member" and not s["retain"]]

    def _sync_members(self):
        for name in self._members():
            self.tb.agent(name).control("sync")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def do_genesis(self, step):
        return self._expect(step, lambda: self.tb.agent(step["agent"]).control("genesis"))

    def do_delegate(self, step):
        subject_key = self.tb.agent(step["subject"]).status()["public_key"]
        body = {"subject": step["subject"], "subject_key": subject_key, "rights": step["rights"]}
        for key in ("resources", "ttl_secs", "depth"):
            if key in step:
                body[key] = step[key]
        return self._expect(step, lambda: self.tb.agent(step["by"]).control("delegate", body))

    def do_admit(self, step):
        subject, by = step["subject"], step["by"]

        def admit():
            self.tb.agent(subject).control("join")
            added = self.tb.agent(by).control("add", {"subject": subject})
            self._wait(lambda: self.tb.agent(subject).status()["membership"] == "member",
                       f"{subject} to join from its Welcome")
            self._sync_members()
            return added
        return self._expect(step, admit)

    def do_join(self, step):
        """The candidate prepares, certifies and publishes its KeyPackage."""
        return self._expect(step, lambda: self.tb.agent(step["agent"]).control("join"))

    def do_add(self, step):
        """An admin adds a published KeyPackage; waits for the Welcome and syncs."""
        subject, by = step["subject"], step["by"]

        def add():
            added = self.tb.agent(by).control("add", {"subject": subject})
            self._wait(lambda: self.tb.agent(subject).status()["membership"] == "member",
                       f"{subject} to join from its Welcome")
            self._sync_members()
            return added
        return self._expect(step, add)

    def do_send(self, step):
        agent = self.tb.agent(step["agent"])
        body = {k: step[k] for k in ("text", "payload_hex", "op", "content_type") if k in step}
        begin = time.monotonic()
        result = self._expect(step, lambda: agent.send(**body))
        elapsed = (time.monotonic() - begin) * 1000
        with self._lock:
            return self._record_send(step, result, elapsed)

    def _record_send(self, step, result, elapsed):
        if "op" in result:
            self.metrics["send_ms"].append(elapsed)
            self.sent[result["op"]] = {"from": step["agent"], "text": step.get("text"),
                                       "payload_hex": step.get("payload_hex"),
                                       "recipients": result["recipients"]}
            self.sent[result["op"]]["sent_ms"] = result.get("sent_ms")
            if "label" in step:
                self.labels[step["label"]] = result["op"]
        return result

    def do_burst(self, step):
        """``count`` messages from each of ``agents``, interleaved, labelled
        ``<label>-<agent>-<i>``. Every send must succeed."""
        prefix = step.get("label", "burst")
        agents = list(self.tb.agents) if step["agents"] == "*" else step["agents"]
        agents = [a for a in agents if a not in step.get("except", [])]

        def one(name, i):
            label = f"{prefix}-{name}-{i}"
            self.do_send({"agent": name, "label": label, "text": f"{label}: {step.get('text', 'burst message')}"})

        begin = time.monotonic()
        if step.get("parallel"):
            # One thread per agent; each agent sends its messages in order.
            errors = []

            def worker(name):
                try:
                    for i in range(1, step["count"] + 1):
                        one(name, i)
                except (StepFailure, ServiceError) as error:
                    errors.append(f"{name}: {error}")
            threads = [threading.Thread(target=worker, args=(name,)) for name in agents]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            if errors:
                raise StepFailure("; ".join(errors[:5]))
        else:
            for i in range(1, step["count"] + 1):
                for name in agents:
                    one(name, i)
        seconds = time.monotonic() - begin
        total = len(agents) * step["count"]
        return {"sent": total, "seconds": round(seconds, 3), "sends_per_second": round(total / seconds, 1)}

    def do_rounds(self, step):
        """``count`` rounds; in each, every agent (but ``except``) sends ``per_agent``
        messages in parallel, then the testbed drains. Records each round's duration and
        the APF's median request time against its kernel history length."""
        rounds = []
        for number in range(1, step["count"] + 1):
            before = len(self.tb.apf.call("GET", "/control/metrics")["samples"])
            begin = time.monotonic()
            self.do_burst({"agents": step.get("agents", "*"), "except": step.get("except", []),
                           "count": step.get("per_agent", 1), "parallel": True,
                           "label": f"{step.get('label', 'round')}{number}"})
            self.do_quiesce({"timeout": step.get("timeout", 300)})
            seconds = time.monotonic() - begin
            samples = self.tb.apf.call("GET", "/control/metrics")["samples"][before:]
            micros = sorted(s[1] for s in samples)
            rounds.append({
                "round": number,
                "seconds": round(seconds, 2),
                "apf_requests": len(samples),
                "history_from": samples[0][0] if samples else None,
                "history_to": samples[-1][0] if samples else None,
                "apf_p50_ms": round(statistics.median(micros) / 1000, 1) if micros else None,
            })
        first, last = rounds[0], rounds[-1]
        growth = (round(last["apf_p50_ms"] / first["apf_p50_ms"], 1)
                  if first["apf_p50_ms"] and last["apf_p50_ms"] else None)
        if "max_round_seconds" in step and last["seconds"] > step["max_round_seconds"]:
            raise StepFailure(f"the last round took {last['seconds']} s")
        return {"rounds": rounds, "apf_p50_growth": growth}

    def do_admit_all(self, step):
        """Delegates ``rights`` to every agent but ``by`` and admits them one by one;
        records each admission's duration against the group size."""
        by = step["by"]
        timings = []
        for name in self.tb.agents:
            if name == by:
                continue
            self.do_delegate({"by": by, "subject": name, "rights": step["rights"]})
            begin = time.monotonic()
            self.do_admit({"by": by, "subject": name})
            elapsed = (time.monotonic() - begin) * 1000
            self.metrics["admit_ms"].append(elapsed)
            timings.append({"member": name, "group_size": len(timings) + 2, "ms": round(elapsed, 1)})
        return {"admitted": len(timings), "admissions": timings}

    def do_quiesce(self, step):
        """Waits until the relay has nothing pending, every reachable agent finished two
        poll rounds after that, and (unless ``allow_waiting``) no agent still holds a
        retried consumption or a future-epoch envelope."""
        timeout = step.get("timeout", 30)
        allow_waiting = step.get("allow_waiting", False)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            before = self.tb.relay.call("GET", "/control/stats")
            if before["pending"] == 0:
                polls = {n: s["polls"] for n, s in self._statuses().items()}
                self._wait(lambda: all(s["polls"] >= polls.get(n, 0) + 2
                                       for n, s in self._statuses().items()),
                           "agents to finish their poll rounds", timeout=10, interval=0.05)
                after = self.tb.relay.call("GET", "/control/stats")
                statuses = self._statuses()
                settled = allow_waiting or all(not s["waiting"] and not s["future"]
                                               for s in statuses.values())
                if after["pending"] == 0 and after["fetched"] == before["fetched"] and settled:
                    return {k: after[k] for k in ("posted", "fetched", "dropped", "duplicated",
                                                  "tapped", "queued", "held")}
            time.sleep(0.1)
        raise StepFailure(f"the testbed did not settle within {timeout}s")

    def do_faults(self, step):
        body = {k: step[k] for k in ("drop", "duplicate", "reorder", "seed") if k in step}
        return self.tb.relay.call("POST", "/control/faults", body)

    def do_hold(self, step):
        return self.tb.relay.call("POST", "/control/hold",
                                  {"mailbox": step["mailbox"], "held": step.get("held", True)})

    def do_tap(self, step):
        return self.tb.relay.call("POST", "/control/tap", {
            "victim": step["victim"], "observer": step["observer"],
            "enabled": step.get("enabled", True)})

    def do_revoke(self, step):
        body = {"command": "revoke", "subject": step["subject"], "right": step["right"]}
        return self._expect(step, lambda: self.tb.agent(step["by"]).control("request", {"body": body}))

    def do_grant(self, step):
        body = {"command": "grant", "subject": step["subject"], "right": step["right"],
                "generation": step["generation"], "fresh_keys": True}
        result = self._expect(step, lambda: self.tb.agent(step["by"]).control("request", {"body": body}))
        if "expect_result" in step and result != step["expect_result"]:
            raise StepFailure(f"expected result {step['expect_result']}, got {result}")
        return result

    def do_request(self, step):
        return self._expect(step, lambda: self.tb.agent(step["agent"]).control(
            "request", {"body": step["body"]}))

    def do_repair(self, step):
        result = self._expect(step, lambda: self.tb.agent(step["by"]).control("repair"))
        if "expect_removed" in step and sorted(result.get("removed", [])) != sorted(step["expect_removed"]):
            raise StepFailure(f"expected removed {step['expect_removed']}, got {result.get('removed')}")
        if step.get("expect", "ok") == "ok":
            # The other continuing members confirm as they apply the commit (C-23).
            self._sync_members()
            state = self._wait(lambda: (lambda s: s if not s["read_fenced"] else None)(
                self.tb.apf.call("GET", "/v1/state")), "the APF to reopen the fence")
            result["read_fenced_after"] = state["read_fenced"]
            evidence = self._evidence()
            result["evidence"] = evidence
            if "expect_evidence" in step and evidence != step["expect_evidence"]:
                raise StepFailure(f"expected evidence {step['expect_evidence']}, got {evidence}")
        return result

    def _evidence(self):
        for status in self._statuses().values():
            for record in reversed(status["confirmations"]):
                response = record.get("response") or {}
                if response.get("opened"):
                    return response.get("evidence")
        return None

    def do_rekey(self, step):
        def rekey():
            result = self.tb.agent(step["agent"]).control(
                "rekey", {"right": step["right"], "generation": step["generation"]})
            self._sync_members()
            return result
        return self._expect(step, rekey)

    def do_adversary(self, step):
        return self.tb.agent(step["agent"]).control("adversary", {"retain": step.get("retain", True)})

    def _service(self, name):
        services = {s.name: s for s in self.tb.services()}
        if name not in services:
            raise StepFailure(f"unknown service {name!r}")
        return services[name]

    def do_stop(self, step):
        if self.lifecycle is None:
            raise StepFailure("this runner has no lifecycle control")
        module, run_dir = self.lifecycle
        module.stop(run_dir, step["service"])
        if self._service(step["service"]).healthy():
            raise StepFailure(f"{step['service']} still answers after stop")
        return {"stopped": step["service"]}

    def do_start(self, step):
        """Starts a stopped service. With ``expect = "fails"`` the service must not come
        up (for example because its entropy source is down)."""
        if self.lifecycle is None:
            raise StepFailure("this runner has no lifecycle control")
        module, run_dir = self.lifecycle
        service = self._service(step["service"])
        expect = step.get("expect", "ok")
        timeout = step.get("timeout", 30 if expect == "ok" else 8)
        try:
            module.start(run_dir, step["service"])
            up = self._wait(service.healthy, f"{step['service']} to answer", timeout=timeout)
        except (RuntimeError, StepFailure, Exception) as error:  # noqa: BLE001 - backend errors vary
            if expect == "fails":
                return {"service": step["service"], "started": False, "reason": str(error)[:200]}
            raise StepFailure(f"{step['service']} did not start: {error}") from None
        if expect == "fails":
            raise StepFailure(f"{step['service']} started although it was expected to fail")
        return {"service": step["service"], "started": bool(up)}

    def do_restart(self, step):
        stopped = self.do_stop(step)
        started = self.do_start({"service": step["service"]})
        return {**stopped, **started}

    def do_entropy_outage(self, step):
        if self.tb.qrng is None:
            raise StepFailure("this deployment has no qrng service")
        return self.tb.qrng.call("POST", "/control/outage", {"available": step["available"]})

    def do_handshake(self, step):
        body = {k: v for k, v in step.items() if k not in ("do", "name")}
        body.setdefault("group", self.tb.group)
        return self.tb.relay.call("POST", "/control/handshake", body)

    def do_sync(self, step):
        self._sync_members()
        return {"synced": self._members()}

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _ops(self, step):
        return [self._resolve(op) for op in step["ops"]]

    def _resolve(self, label):
        op = self.labels.get(label, label)
        if op not in self.sent:
            raise StepFailure(f"no sent message is labelled {label!r}")
        return op

    def do_check_delivered(self, step):
        name = step["agent"]
        inbox = self.tb.agent(name).inbox()
        counts = Counter(item["op"] for item in inbox)
        ops = self._ops(step)
        problems = []
        for op in ops:
            if counts[op] != 1:
                problems.append(f"{op} delivered {counts[op]} times")
                continue
            item = next(i for i in inbox if i["op"] == op)
            sent = self.sent[op]
            if item["from"] != sent["from"]:
                problems.append(f"{op} from {item['from']}, sent by {sent['from']}")
            if sent["text"] is not None and item.get("text") != sent["text"]:
                problems.append(f"{op} payload differs from what was sent")
        if step.get("exact", True):
            extra = sorted(set(counts) - set(ops))
            if extra:
                problems.append(f"unexpected deliveries {extra}")
        if problems:
            raise StepFailure(f"{name}: " + "; ".join(problems))
        return {"agent": name, "delivered": sorted(ops)}

    def do_check_complete(self, step):
        """Every message sent so far reached every recipient named by its release
        certificate exactly once, with the sent payload. ``exclude`` lists
        ``"agent:label"`` pairs that are expected to be missing."""
        excluded = {(e.split(":")[0], self._resolve(e.split(":")[1])) for e in step.get("exclude", [])}
        # Optional pairs may be missing (crash windows, B4 and B5) but never duplicated;
        # check.at_most_once covers them.
        optional = set()
        for spec in step.get("exclude_prefix", []):
            agent, prefix = spec.split(":")
            optional |= {(agent, op) for label, op in self.labels.items() if label.startswith(prefix)
                         and agent in self.sent[op]["recipients"]}
        inboxes = self._inboxes()
        problems, checked = [], 0
        for op, sent in self.sent.items():
            for to in sent["recipients"]:
                if (to, op) in excluded or (to, op) in optional:
                    continue
                items = [i for i in inboxes.get(to, []) if i["op"] == op]
                checked += 1
                if len(items) != 1:
                    problems.append(f"{op}->{to} delivered {len(items)} times")
                elif sent["text"] is not None and items[0].get("text") != sent["text"]:
                    problems.append(f"{op}->{to} payload differs")
        for to, op in excluded:
            if any(i["op"] == op for i in inboxes.get(to, [])):
                problems.append(f"{op}->{to} was delivered but is excluded")
        if problems:
            raise StepFailure("; ".join(problems[:20]))
        return {"pairs": checked, "excluded": sorted(f"{a}:{o}" for a, o in excluded),
                "optional": len(optional)}

    def do_check_rejections_are_duplicates(self, step):
        """C-39: an honest member may reject only a copy of a message it already
        delivered (the relay's duplicates), never a first copy."""
        report = {}
        names = list(self.tb.agents) if step["agents"] == "*" else step["agents"]
        for name in names:
            agent = self.tb.agent(name)
            delivered = {i["op"] for i in agent.inbox()}
            rejections = agent.status()["rejections"]
            bad = [r for r in rejections if r["op"] not in delivered]
            if bad:
                raise StepFailure(f"{name} rejected messages it never delivered: {bad}")
            report[name] = Counter(r["code"] for r in rejections)
        return report

    def do_check_at_most_once(self, step):
        """Messages labelled with ``prefix`` reached ``agent`` at most once each. Reports
        how many arrived and how many were lost (allowed: at-most-once, B4 and B5)."""
        name, prefix = step["agent"], step["prefix"]
        ops = [op for label, op in self.labels.items() if label.startswith(prefix)
               and name in self.sent[op]["recipients"]]
        if not ops:
            raise StepFailure(f"no message labelled {prefix}* was sent to {name}")
        counts = Counter(item["op"] for item in self.tb.agent(name).inbox())
        twice = [op for op in ops if counts[op] > 1]
        if twice:
            raise StepFailure(f"{name} received {twice} more than once")
        arrived = sum(1 for op in ops if counts[op] == 1)
        if arrived < step.get("min_delivered", 0):
            raise StepFailure(f"only {arrived} of {len(ops)} arrived")
        return {"agent": name, "sent": len(ops), "delivered": arrived, "lost": len(ops) - arrived}

    def do_check_not_delivered(self, step):
        name = step["agent"]
        delivered = {item["op"] for item in self.tb.agent(name).inbox()}
        leaked = sorted(set(self._ops(step)) & delivered)
        if leaked:
            raise StepFailure(f"{name} received {leaked}")
        return {"agent": name, "not_delivered": self._ops(step)}

    def do_check_rejected(self, step):
        """The first copy of ``op`` that reached ``agent`` was refused with one of
        ``codes``. Later copies are relay duplicates: the MLS ratchet already moved,
        so they may only be refused as ``duplicate_codes``."""
        name, op = step["agent"], self._resolve(step["op"])
        codes = set(step["codes"])
        duplicate_codes = set(step.get("duplicate_codes", ["undecryptable", "replay"]))
        rejections = [r for r in self.tb.agent(name).status()["rejections"] if r["op"] == op]
        if not rejections:
            raise StepFailure(f"{name} has no rejection of {op}")
        first, later = rejections[0], rejections[1:]
        if first["code"] not in codes:
            raise StepFailure(f"{name} refused the first copy of {op} with {first}, expected {sorted(codes)}")
        unexpected = [r for r in later if r["code"] not in duplicate_codes]
        if unexpected:
            raise StepFailure(f"{name} refused later copies of {op} with unexpected codes: {unexpected}")
        return {"agent": name, "op": op, "first": first["code"], "duplicates": [r["code"] for r in later]}

    def do_check_adversary(self, step):
        name = step["agent"]
        attempts = self.tb.agent(name).status()["adversary"]
        report = []
        for op in self._ops(step):
            mine = [a for a in attempts if a["op"] == op]
            if not mine:
                raise StepFailure(f"{name} made no attempt on {op} (the tap did not deliver it)")
            for attempt in mine:
                if attempt["decrypted"]:
                    raise StepFailure(f"{name} DECRYPTED {op} with retained keys: {attempt}")
                if attempt["consume"] == "ok":
                    raise StepFailure(f"the APF let {name} consume {op}: {attempt}")
            report.extend(mine)
        return {"agent": name, "attempts": report}

    def do_check_agent(self, step):
        """Fields of one agent's status: ``membership``, ``restarts``, ``retain``,
        ``on_frontier`` (its epoch and branch equal the APF's) and ``min_skipped``."""
        name = step["agent"]
        status = self.tb.agent(name).status()
        problems = []
        for key in ("membership", "restarts", "retain"):
            if key in step and status[key] != step[key]:
                problems.append(f"{key} is {status[key]}, expected {step[key]}")
        if "on_frontier" in step:
            state = self.tb.apf.call("GET", "/v1/state")
            on = (status["epoch"], status["branch"]) == (state["epoch"], state["branch"])
            if on != step["on_frontier"]:
                problems.append(f"on the APF frontier: {on} (agent epoch {status['epoch']}, APF {state['epoch']})")
        if "min_skipped" in step and status["skipped_entries"] < step["min_skipped"]:
            problems.append(f"skipped {status['skipped_entries']} entries, expected at least {step['min_skipped']}")
        if problems:
            raise StepFailure(f"{name}: " + "; ".join(problems))
        return {k: status[k] for k in ("membership", "epoch", "restarts", "skipped_entries", "future", "waiting")}

    def do_check_apf(self, step):
        state = self.tb.apf.call("GET", "/v1/state")
        problems = []
        for key in ("roster", "read_fenced", "repair_pending", "epoch"):
            if key in step:
                actual = sorted(state[key]) if key == "roster" else state[key]
                expected = sorted(step[key]) if key == "roster" else step[key]
                if actual != expected:
                    problems.append(f"{key} is {actual}, expected {expected}")
        if problems:
            raise StepFailure("; ".join(problems))
        return {k: state[k] for k in ("roster", "epoch", "policy_revision", "read_fenced", "repair_pending")}

    def do_check_frontiers(self, step):
        state = self.tb.apf.call("GET", "/v1/state")
        names = step.get("agents") or self._members()
        bad = {}
        for name in names:
            status = self.tb.agent(name).status()
            if (status["epoch"], status["branch"]) != (state["epoch"], state["branch"]):
                bad[name] = status["epoch"]
        if bad:
            raise StepFailure(f"agents off the APF frontier (epoch {state['epoch']}): {bad}")
        return {"epoch": state["epoch"], "agents": names}

    def do_check_exactly_once(self, step):
        delivered = Counter()
        for name, inbox in self._inboxes().items():
            for item in inbox:
                delivered[(item["op"], name)] += 1
        duplicates = {f"{op}->{to}": n for (op, to), n in delivered.items() if n > 1}
        checkpoint = self.tb.apf.call("GET", "/control/checkpoint")
        history = checkpoint.get("history", [])
        snapshot = history[-1]["event"]["snapshot"] if history else {}
        consumed = {(c["op"], c["recipient"]) for c in snapshot.get("consumed", [])}
        without_consume = sorted(f"{op}->{to}" for (op, to) in delivered if (op, to) not in consumed)
        consumed_not_delivered = sorted(f"{op}->{to}" for (op, to) in consumed if (op, to) not in delivered)
        lost = len(consumed_not_delivered)
        if step.get("allow_lost"):
            # Barrier B5: a crash after consume and before the application delivery.
            consumed_not_delivered = []
        if duplicates or without_consume or consumed_not_delivered:
            raise StepFailure(f"duplicates={duplicates} delivered_without_consume={without_consume} "
                              f"consumed_not_delivered={consumed_not_delivered}")
        return {"deliveries": sum(delivered.values()), "consumed": len(consumed), "lost_after_consume": lost}

    def do_check_oracle(self, step):
        module, path = oracle_mod.load()
        trace = self.tb.apf.call("GET", "/control/trace")["trace"]
        self.artifacts["trace"] = trace
        (self.run_dir / "trace.json").write_text(json.dumps(trace, indent=1))
        violations = module.check_trace(trace)
        if violations:
            raise StepFailure(f"the oracle rejected the exported trace: {violations}")
        kinds = Counter(event.get("type") for event in trace)
        return {"oracle": str(Path(path).name), "events": len(trace), "kinds": dict(sorted(kinds.items()))}

    def do_check_broken_controls(self, step):
        module, _ = oracle_mod.load()
        trace = self.artifacts.get("trace") or self.tb.apf.call("GET", "/control/trace")["trace"]
        if module.check_trace(trace):
            raise StepFailure("precondition: the real trace is not accepted")
        controls, skipped = oracle_mod.broken_controls(trace, step["revoked_reader"], step["writer"])
        results, blind = {}, []
        for label, (events, index, code) in controls.items():
            violations = module.check_trace(events)
            results[label] = violations
            if violations != [{"index": index, "code": code}]:
                blind.append(f"{label}: expected {code} at {index}, got {violations}")
        minimum = step.get("minimum", len(controls))
        if blind or len(controls) < minimum:
            raise StepFailure("; ".join(blind) or f"only {len(controls)} controls, skipped {skipped}")
        return {"rejected": {k: v[0]["code"] for k, v in results.items()}, "skipped": skipped}

    def do_check_entropy(self, step):
        source = step["source"]
        reports = {"apf": self.tb.apf.call("GET", "/control/entropy")}
        for name, agent in self.tb.agents.items():
            reports[name] = agent.control("entropy", method="GET")
        problems = []
        # Nodes that must show refused draws (an outage experiment); all others none.
        must_fail = set(step.get("expect_failures", []))
        for name, report in reports.items():
            if report.get("source") != source:
                problems.append(f"{name} uses {report.get('source')}")
            if source == "os":
                continue
            if report.get("requests", 0) == 0:
                problems.append(f"{name} made no request: {report}")
            failed = report.get("failures", 0) > 0
            if failed != (name in must_fail):
                problems.append(f"{name} failures {report.get('failures')} (expected {'some' if name in must_fail else 'none'})")
        detail = {"nodes": reports}
        if self.tb.qrng is not None:
            stats = self.tb.qrng.call("GET", "/control/stats")
            detail["qrng_service"] = stats
            if (stats["refused"] != 0) != bool(must_fail) or stats["bytes"] == 0:
                problems.append(f"qrng service {stats}")
        if problems:
            raise StepFailure("; ".join(problems))
        return detail

    def do_check_metrics(self, step):
        """Latency and throughput of the run so far. Bounds (``max_*``) are loose sanity
        limits; the numbers are the result."""
        inboxes = self._inboxes()
        delivery = []
        for name, inbox in inboxes.items():
            for item in inbox:
                sent = self.sent.get(item["op"], {})
                if sent.get("sent_ms") and item.get("delivered_ms"):
                    delivery.append(item["delivered_ms"] - sent["sent_ms"])

        def summary(values):
            if not values:
                return None
            ordered = sorted(values)
            return {"n": len(ordered), "p50": round(statistics.median(ordered), 1),
                    "p95": round(ordered[max(0, int(len(ordered) * 0.95) - 1)], 1),
                    "max": round(ordered[-1], 1)}
        result = {"send_ms": summary(self.metrics["send_ms"]),
                  "delivery_ms": summary(delivery),
                  "admit_ms": summary(self.metrics["admit_ms"])}
        samples = self.tb.apf.call("GET", "/control/metrics")["samples"]
        if samples:
            # APF request time per tenth of the kernel history seen so far.
            top = max(s[0] for s in samples) or 1
            buckets = {}
            for history, micros, _ in samples:
                buckets.setdefault(min(9, history * 10 // (top + 1)), []).append(micros / 1000)
            result["apf_ms_by_history"] = [
                {"history_up_to": (b + 1) * (top + 1) // 10, "requests": len(v),
                 "p50": round(statistics.median(v), 2)} for b, v in sorted(buckets.items())]
        problems = []
        for key, bound in step.items():
            if key.startswith("max_") and key.endswith("_p95"):
                metric = result.get(key[4:-4] + "_ms")
                if metric is None or metric["p95"] > bound:
                    problems.append(f"{key[4:-4]} p95 {metric and metric['p95']} ms > {bound} ms")
        if problems:
            raise StepFailure("; ".join(problems))
        return result

    def do_check_errors_within(self, step):
        """Every error the agents logged is a handshake error on one of ``indices`` (the
        forged entries of an attack); there is no other error."""
        allowed = set(step["indices"])
        report, bad = {}, {}
        for name in step.get("agents") or list(self.tb.agents):
            errors = self.tb.agent(name).status()["errors"]
            report[name] = sorted({e.get("index") for e in errors})
            unexpected = [e for e in errors if e.get("stage") != "handshake" or e.get("index") not in allowed]
            if unexpected:
                bad[name] = unexpected
        if bad:
            raise StepFailure(f"unexpected errors: {bad}")
        return {"forged_indices_logged": report}

    def do_check_no_errors(self, step):
        names = step.get("agents") or list(self.tb.agents)
        errors = {n: self.tb.agent(n).status()["errors"] for n in names}
        errors = {n: e for n, e in errors.items() if e}
        if errors:
            raise StepFailure(f"agent errors: {errors}")
        return {"agents": names}

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def collect(self):
        """Final observations: statuses, relay and entropy stats, APF state."""
        out = {}
        for label, fetch in (
            ("apf_state", lambda: self.tb.apf.call("GET", "/v1/state")),
            ("relay_stats", lambda: self.tb.relay.call("GET", "/control/stats")),
            ("agents", self._statuses),
            ("qrng_stats", lambda: self.tb.qrng.call("GET", "/control/stats") if self.tb.qrng else None),
            ("adapter_trace", lambda: self.tb.apf.call("GET", "/control/adapter-trace")),
        ):
            try:
                out[label] = fetch()
            except ServiceError as error:
                out[label] = {"unavailable": error.message}
        return out


def render_markdown(report, deployment, observations):
    lines = [
        f"# {report['experiment']}: {report['title']}",
        "",
        f"- Result: **{report['result'].upper()}**",
        f"- Backend: `{deployment['backend']}`; topology `{deployment['name']}`; "
        f"entropy `{deployment['entropy'].get('source')}`",
        f"- Duration: {report['seconds']} s; steps run: {len(report['steps'])}; "
        f"steps not run: {report['skipped_steps']}",
        "",
        f"Hypothesis: {report['hypothesis']}",
        "",
        "| # | Step | Result | Seconds | Detail |",
        "|---|------|--------|---------|--------|",
    ]
    for step in report["steps"]:
        detail = step.get("error") or _short(step.get("detail"))
        lines.append(f"| {step['index']} | {step['name']} | {step['status']} | {step['seconds']} | "
                     f"{detail.replace('|', '/')} |")
    state = observations.get("apf_state", {})
    relay = observations.get("relay_stats", {})
    lines += [
        "",
        "## Final state",
        "",
        f"- APF roster: {state.get('roster')}; epoch {state.get('epoch')}; "
        f"policy revision {state.get('policy_revision')}; read fenced {state.get('read_fenced')}",
        f"- Relay: posted {relay.get('posted')}, fetched {relay.get('fetched')}, "
        f"dropped {relay.get('dropped')}, duplicated {relay.get('duplicated')}, tapped {relay.get('tapped')}",
        "",
    ]
    return "\n".join(lines)


def _short(value, limit=160):
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit - 3] + "..."
