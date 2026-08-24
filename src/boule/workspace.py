"""Local v0.3 operational ledger for an imported Boule problem manifest."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest_object
from .crypto import load_public_key, public_key_text, sign_object, verify_object
from .errors import ProtocolError
from .policy import build_case_policy, load_case_policy, policy_digest, validate_case_policy

PARTICIPANT_EVENTS = {
    "session_started",
    "work_claimed",
    "claim_heartbeat",
    "checkpoint_published",
    "message_posted",
    "claim_released",
    "handoff_published",
}


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtocolError("time must be an ISO-8601 UTC Z string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("invalid timestamp") from exc


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _text(value: Any, name: str, maximum: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProtocolError(f"{name} must be non-empty text up to {maximum} characters")
    return value


def _sha256(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ProtocolError(f"{name} must be a lowercase sha256 digest")
    return value


class Workspace:
    def __init__(
        self, problem_dir: str | Path, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.root = Path(problem_dir)
        self.control = self.root / ".boule"
        self.problem_path = self.root / "problem.json"
        self.policy_path = self.control / "policy.json"
        self.config_path = self.control / "config.json"
        if (
            not self.problem_path.exists()
            or not self.config_path.exists()
            or not self.policy_path.exists()
        ):
            raise ProtocolError(
                "workspace needs problem.json, .boule/policy.json, and .boule/config.json"
            )
        try:
            self.problem = json.loads(self.problem_path.read_text())
            self.config = json.loads(self.config_path.read_text())
        except json.JSONDecodeError as exc:
            raise ProtocolError("workspace JSON is invalid") from exc
        self.policy = load_case_policy(self.policy_path, self.problem)
        self._validate()
        self._clock = clock or (lambda: datetime.now(UTC))
        self.events_dir = self.control / "events"
        self.receipts_dir = self.control / "receipts"
        self.receipt_path = self.control / "maintainer-receipt.json"

    @classmethod
    def initialize(
        cls,
        problem_dir: str | Path,
        config: dict[str, Any],
        *,
        policy: dict[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> Workspace:
        root = Path(problem_dir)
        problem_path = root / "problem.json"
        if not problem_path.exists():
            raise ProtocolError("initialize requires an imported problem.json")
        try:
            problem = json.loads(problem_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("imported problem manifest is invalid JSON") from exc
        selected_policy = validate_case_policy(
            policy or build_case_policy(problem, "commitment_only"), problem
        )
        control = root / ".boule"
        control.mkdir(exist_ok=False)
        (control / "events").mkdir()
        (control / "receipts").mkdir()
        (control / "lock").touch(exist_ok=False)
        cls._write(control / "policy.json", selected_policy, True)
        complete_config = {**config, "policy_digest": policy_digest(selected_policy)}
        cls._write(control / "config.json", complete_config, True)
        os.chmod(control / "policy.json", 0o644)
        os.chmod(control / "config.json", 0o644)
        return cls(root, clock=clock)

    @staticmethod
    def _write(path: Path, value: Any, exclusive: bool = False) -> None:
        if exclusive:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as h:
                h.write(canonical_bytes(value) + b"\n")
                h.flush()
                os.fsync(h.fileno())
        else:
            fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as h:
                    h.write(canonical_bytes(value) + b"\n")
                    h.flush()
                    os.fsync(h.fileno())
                os.replace(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        d = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)

    def _validate(self) -> None:
        if not isinstance(self.problem, dict) or self.problem.get("schema") != "boule-problem/0.1":
            raise ProtocolError("imported problem.json has an unsupported schema")
        if not isinstance(self.problem.get("problem_id"), str):
            raise ProtocolError("imported problem.json must contain problem_id")
        task = self.problem.get("task")
        if not isinstance(task, dict) or not {
            "task_id",
            "task_commitment",
            "formal_repository_pin",
        } <= set(task):
            raise ProtocolError("imported problem.json has incomplete task identity")
        _text(self.problem["problem_id"], "problem_id", 128)
        _text(task["task_id"], "task.task_id", 128)
        _sha256(task["task_commitment"], "task.task_commitment")
        if (
            not isinstance(task["formal_repository_pin"], str)
            or len(task["formal_repository_pin"]) != 40
            or any(char not in "0123456789abcdef" for char in task["formal_repository_pin"])
        ):
            raise ProtocolError("task.formal_repository_pin must be a 40-hex commit")
        required = {
            "maintainer_key",
            "lease_seconds",
            "absolute_lease_seconds",
            "stale_seconds",
            "max_renewals",
            "policy_digest",
        }
        if not isinstance(self.config, dict) or set(self.config) != required:
            raise ProtocolError("workspace config has invalid fields")
        load_public_key(self.config["maintainer_key"])
        if self.config["policy_digest"] != policy_digest(self.policy):
            raise ProtocolError("workspace config does not match the frozen case policy")
        for k in required - {"maintainer_key", "policy_digest"}:
            if isinstance(self.config[k], bool) or not isinstance(self.config[k], int):
                raise ProtocolError(f"config.{k} must be an integer")
        if (
            not 60
            <= self.config["lease_seconds"]
            <= self.config["absolute_lease_seconds"]
            <= 604800
        ):
            raise ProtocolError("config lease bounds are invalid")
        if not 1 <= self.config["stale_seconds"] < self.config["lease_seconds"]:
            raise ProtocolError("config.stale_seconds is invalid")
        if not 0 <= self.config["max_renewals"] <= 32:
            raise ProtocolError("config.max_renewals is invalid")

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with (self.control / "lock").open("r+") as h:
            fcntl.flock(h, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(h, fcntl.LOCK_UN)

    def _verify_receipt(self, r: dict[str, Any]) -> None:
        fields = {"at", "head_event_hash", "event_count", "status_digest", "signature"}
        if not isinstance(r, dict) or set(r) != fields:
            raise ProtocolError("maintainer receipt has invalid fields")
        _time(r["at"])
        if (
            isinstance(r["event_count"], bool)
            or not isinstance(r["event_count"], int)
            or r["event_count"] < 0
        ):
            raise ProtocolError("maintainer receipt event count is invalid")
        if r["head_event_hash"] is not None:
            _sha256(f"sha256:{r['head_event_hash']}", "maintainer head event hash")
        _sha256(f"sha256:{r['status_digest']}", "maintainer status digest")
        verify_object(
            self.config["maintainer_key"], {k: r[k] for k in fields - {"signature"}}, r["signature"]
        )

    def _load_receipt(self, path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"maintainer receipt is invalid: {path.name}") from exc
        self._verify_receipt(value)
        return value

    def _guard_receipts(self, events: list[dict[str, Any]]) -> None:
        paths = sorted(self.receipts_dir.glob("*.json"))
        if self.receipt_path.exists():
            paths.append(self.receipt_path)
        for path in paths:
            receipt = self._load_receipt(path)
            count = receipt["event_count"]
            if count > len(events):
                raise ProtocolError("event log was truncated after a maintainer receipt")
            expected_head = events[count - 1]["event_hash"] if count else None
            if receipt["head_event_hash"] != expected_head:
                raise ProtocolError("maintainer receipt does not match its exact event prefix")
            if count and _time(receipt["at"]) < _time(events[count - 1]["received_at"]):
                raise ProtocolError("maintainer receipt predates its event prefix")

    def _events(self) -> list[dict[str, Any]]:
        events = []
        for p in sorted(self.events_dir.glob("*.json")):
            try:
                value = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise ProtocolError(f"invalid event file {p.name}") from exc
            if not isinstance(value, dict):
                raise ProtocolError(f"invalid event object {p.name}")
            events.append(value)
        previous = None
        for seq, e in enumerate(events):
            fields = {
                "seq",
                "event_id",
                "received_at",
                "kind",
                "actor",
                "payload",
                "prev_event_hash",
                "event_hash",
                "signature",
            }
            if (
                set(e) != fields
                or isinstance(e["seq"], bool)
                or not isinstance(e["seq"], int)
                or e["seq"] != seq
                or e["prev_event_hash"] != previous
            ):
                raise ProtocolError("event chain fields are invalid")
            if not isinstance(e["kind"], str) or e["kind"] not in PARTICIPANT_EVENTS:
                raise ProtocolError("unsupported workspace event")
            _time(e["received_at"])
            _text(e["event_id"], "event_id", 128)
            if not isinstance(e["payload"], dict):
                raise ProtocolError("event payload must be an object")
            identity_digest = digest_object([e["kind"], e["payload"], e["received_at"]])
            expected_id = f"{seq:08d}-{identity_digest[:16]}"
            if e["event_id"] != expected_id:
                raise ProtocolError("event id does not match its signed contents")
            load_public_key(e["actor"])
            unsigned = {k: e[k] for k in fields - {"event_hash", "signature"}}
            if e["event_hash"] != digest_object(unsigned):
                raise ProtocolError("event hash mismatch")
            verify_object(e["actor"], unsigned, e["signature"])
            if seq and _time(e["received_at"]) < _time(events[seq - 1]["received_at"]):
                raise ProtocolError("event receipt times must be monotonic")
            previous = e["event_hash"]
        validated: list[dict[str, Any]] = []
        for event in events:
            instant = _time(event["received_at"])
            state = self._state_from(validated, instant)
            self._authorize(event["kind"], event["payload"], event["actor"], state, instant)
            validated.append(event)
        self._guard_receipts(events)
        return events

    def append(self, kind: str, payload: dict[str, Any], private_key: Any) -> dict[str, Any]:
        if kind not in PARTICIPANT_EVENTS:
            raise ProtocolError("only participant events may be appended")
        observed = self._clock()
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise ProtocolError("workspace clock must return a timezone-aware datetime")
        now = observed.astimezone(UTC)
        received_at = _stamp(now)
        with self._lock():
            events = self._events()
            if events and now < _time(events[-1]["received_at"]):
                raise ProtocolError("event receipt times must be monotonic")
            state = self._state_from(events, now)
            actor = public_key_text(private_key)
            self._authorize(kind, payload, actor, state, now)
            u = {
                "seq": len(events),
                "event_id": f"{len(events):08d}-{digest_object([kind, payload, received_at])[:16]}",
                "received_at": received_at,
                "kind": kind,
                "actor": actor,
                "payload": payload,
                "prev_event_hash": events[-1]["event_hash"] if events else None,
            }
            event = {**u, "event_hash": digest_object(u), "signature": sign_object(private_key, u)}
            self._write(
                self.events_dir / f"{event['seq']:08d}-{event['event_id']}.json", event, True
            )
            return event

    def _authorize(
        self, kind: str, p: dict[str, Any], actor: str, s: dict[str, Any], now: datetime
    ) -> None:
        if not isinstance(p, dict) or p.get("problem_id") != self.problem["problem_id"]:
            raise ProtocolError("event belongs to another problem")
        if kind == "session_started":
            req = {
                "problem_id",
                "participant_id",
                "controller_id",
                "controller_key",
                "session_id",
                "session_key",
                "not_after",
                "policy_digest",
            }
            if set(p) - (req | {"label"}) or not req <= set(p):
                raise ProtocolError("invalid session_started payload")
            for key in ("participant_id", "controller_id", "session_id"):
                _text(p[key], key, 128)
            if actor != p["controller_key"] or p["session_key"] == p["controller_key"]:
                raise ProtocolError(
                    "session needs its controller signature and an independent session key"
                )
            if "label" in p:
                _text(p["label"], "session.label", 128)
            load_public_key(p["controller_key"])
            load_public_key(p["session_key"])
            if p["policy_digest"] != self.config["policy_digest"]:
                raise ProtocolError("session did not assent to the frozen case policy")
            if p["session_id"] in s["sessions"] or p["session_key"] in s["session_keys"]:
                raise ProtocolError("duplicate session")
            if _time(p["not_after"]) <= now:
                raise ProtocolError("session already expired")
            return
        session = s["session_keys"].get(actor)
        if session is None or _time(session["not_after"]) <= now:
            raise ProtocolError("actor is not an active session")
        if (
            p.get("session_id") != session["session_id"]
            or p.get("participant_id") != session["participant_id"]
        ):
            raise ProtocolError("participant/session identity mismatch")
        if kind == "message_posted":
            req = {"problem_id", "participant_id", "session_id", "claim_id", "topic", "body"}
            if set(p) != req or (p["claim_id"] is not None and not isinstance(p["claim_id"], str)):
                raise ProtocolError("invalid message payload")
            if p["claim_id"] is not None and p["claim_id"] not in s["claims"]:
                raise ProtocolError("message claim does not exist")
            _text(p["topic"], "message.topic", 128)
            _text(p["body"], "message.body", 1000)
            return
        if kind == "work_claimed":
            req = {
                "problem_id",
                "participant_id",
                "session_id",
                "claim_id",
                "route",
                "success_gate",
                "falsifier",
                "parallel",
            }
            if set(p) != req:
                raise ProtocolError("invalid work_claimed payload")
            for k in ("claim_id", "route", "success_gate", "falsifier"):
                _text(p[k], k, 1000)
            if session["active_claim"] is not None:
                raise ProtocolError("session already has an active claim")
            if p["claim_id"] in s["claims"]:
                raise ProtocolError("claim id is not unique")
            if not isinstance(p["parallel"], bool):
                raise ProtocolError("parallel must be boolean")
            return
        c = s["claims"].get(p.get("claim_id"))
        if c is None or c["session_id"] != session["session_id"]:
            raise ProtocolError("event does not own the claim")
        if c["status"] not in {"active", "stale"}:
            raise ProtocolError("claim is no longer open")
        if kind == "claim_heartbeat":
            if set(p) != {
                "problem_id",
                "participant_id",
                "session_id",
                "claim_id",
                "progress_digest",
            }:
                raise ProtocolError("invalid claim_heartbeat payload")
            _sha256(p["progress_digest"], "progress_digest")
            if c["renewals"] >= self.config["max_renewals"] or now >= c["absolute_deadline"]:
                raise ProtocolError("claim cannot be renewed")
        elif kind == "checkpoint_published":
            if set(p) != {
                "problem_id",
                "participant_id",
                "session_id",
                "claim_id",
                "summary",
                "next_action",
                "evidence",
            }:
                raise ProtocolError("invalid checkpoint payload")
            _text(p["summary"], "checkpoint.summary", 500)
            _text(p["next_action"], "checkpoint.next_action", 500)
            self._evidence(p["evidence"])
        elif kind == "claim_released":
            if set(p) != {"problem_id", "participant_id", "session_id", "claim_id", "reason"}:
                raise ProtocolError("invalid release payload")
            _text(p["reason"], "release.reason", 500)
        elif kind == "handoff_published":
            req = {
                "problem_id",
                "participant_id",
                "session_id",
                "claim_id",
                "handoff_id",
                "outcome",
                "summary",
                "next_action",
                "limitations",
                "reproduce",
                "evidence",
                "depends_on",
                "provenance",
                "citations",
            }
            if set(p) != req:
                raise ProtocolError("invalid handoff payload")
            for k in ("handoff_id", "summary", "next_action", "limitations", "reproduce"):
                _text(p[k], k, 2000)
            if p["handoff_id"] in s["handoff_ids"]:
                raise ProtocolError("handoff id is not unique")
            if not isinstance(p["outcome"], str) or p["outcome"] not in {
                "ADVANCE",
                "NEGATIVE",
                "BLOCKED",
                "NO_SIGNAL",
            }:
                raise ProtocolError("invalid handoff outcome")
            self._evidence(p["evidence"])
            if not isinstance(p["provenance"], str) or p["provenance"] not in {
                "original",
                "adapted",
                "reproduction",
                "unknown",
            }:
                raise ProtocolError("invalid handoff provenance")
            if (
                not isinstance(p["citations"], list)
                or len(p["citations"]) > 32
                or any(not isinstance(item, str) for item in p["citations"])
                or len(p["citations"]) != len(set(p["citations"]))
            ):
                raise ProtocolError("handoff citations are invalid")
            for citation in p["citations"]:
                _text(citation, "handoff citation", 1000)
            if (
                not isinstance(p["depends_on"], list)
                or any(not isinstance(item, str) for item in p["depends_on"])
                or len(p["depends_on"]) != len(set(p["depends_on"]))
            ):
                raise ProtocolError("handoff dependencies are invalid")
            if not set(p["depends_on"]) <= s["handoff_ids"]:
                raise ProtocolError("handoff dependency must refer to an earlier handoff")
            if p["outcome"] in {"ADVANCE", "NEGATIVE"} and not p["evidence"]:
                raise ProtocolError("ADVANCE and NEGATIVE handoffs require evidence")
            if (
                p["outcome"] == "BLOCKED"
                and not p["evidence"]
                and not p["depends_on"]
            ):
                raise ProtocolError("BLOCKED handoff needs evidence or an earlier dependency")
            if p["provenance"] == "original" and not p["evidence"]:
                raise ProtocolError("original provenance requires evidence")
        else:
            raise ProtocolError("unsupported participant event")

    @staticmethod
    def _evidence(value: Any) -> None:
        if not isinstance(value, list) or len(value) > 16:
            raise ProtocolError("evidence must be a list of at most 16 references")
        seen: set[tuple[str, str]] = set()
        for item in value:
            if not isinstance(item, dict) or set(item) != {"ref", "sha256"}:
                raise ProtocolError("evidence item has invalid fields")
            _text(item["ref"], "evidence.ref", 1000)
            digest = _sha256(item["sha256"], "evidence sha256")
            pair = (item["ref"], digest)
            if pair in seen:
                raise ProtocolError("evidence contains duplicate references")
            seen.add(pair)

    def _state_from(self, events: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
        s = {
            "sessions": {},
            "session_keys": {},
            "claims": {},
            "checkpoints": [],
            "messages": [],
            "handoffs": [],
            "handoff_ids": set(),
        }
        for e in events:
            p, k, at = e["payload"], e["kind"], _time(e["received_at"])
            if k == "session_started":
                s["sessions"][p["session_id"]] = {**p, "active_claim": None}
                s["session_keys"][p["session_key"]] = s["sessions"][p["session_id"]]
            elif k == "work_claimed":
                absolute = at + timedelta(seconds=self.config["absolute_lease_seconds"])
                c = {
                    **p,
                    "opened_at": at,
                    "last_activity": at,
                    "deadline": min(at + timedelta(seconds=self.config["lease_seconds"]), absolute),
                    "absolute_deadline": absolute,
                    "renewals": 0,
                    "status": "active",
                }
                s["claims"][p["claim_id"]] = c
                s["sessions"][p["session_id"]]["active_claim"] = p["claim_id"]
            elif k == "claim_heartbeat":
                c = s["claims"][p["claim_id"]]
                c["renewals"] += 1
                c["last_activity"] = at
                c["deadline"] = min(
                    at + timedelta(seconds=self.config["lease_seconds"]), c["absolute_deadline"]
                )
            elif k == "checkpoint_published":
                s["checkpoints"].append({"event_id": e["event_id"], **p})
            elif k == "message_posted":
                s["messages"].append({"event_id": e["event_id"], **p})
            elif k in {"claim_released", "handoff_published"}:
                c = s["claims"][p["claim_id"]]
                c["status"] = "released" if k == "claim_released" else "completed"
                s["sessions"][p["session_id"]]["active_claim"] = None
                if k == "handoff_published":
                    s["handoffs"].append(
                        {"event_id": e["event_id"], "status": "queued_for_review", **p}
                    )
                    s["handoff_ids"].add(p["handoff_id"])
        for c in s["claims"].values():
            if c["status"] == "active":
                if now >= c["deadline"]:
                    c["status"] = "expired"
                    session = s["sessions"][c["session_id"]]
                    if session["active_claim"] == c["claim_id"]:
                        session["active_claim"] = None
                elif now - c["last_activity"] >= timedelta(seconds=self.config["stale_seconds"]):
                    c["status"] = "stale"
        return s

    def _public(self, s: dict[str, Any], now: datetime) -> dict[str, Any]:
        claims = [
            {
                "claim_id": c["claim_id"],
                "session_id": c["session_id"],
                "route": c["route"],
                "status": c["status"],
                "deadline": _stamp(c["deadline"]),
                "absolute_deadline": _stamp(c["absolute_deadline"]),
                "renewals": c["renewals"],
                "parallel": c["parallel"],
            }
            for c in s["claims"].values()
        ]
        return {
            "problem_id": self.problem["problem_id"],
            "sessions": sorted(
                [
                    {
                        **item,
                        "status": "expired" if _time(item["not_after"]) <= now else "active",
                    }
                    for item in s["sessions"].values()
                ],
                key=lambda x: x["session_id"],
            ),
            "claims": sorted(claims, key=lambda x: x["claim_id"]),
            "checkpoints": s["checkpoints"],
            "messages": s["messages"],
            "handoffs": s["handoffs"],
        }

    def state(self, now: str) -> dict[str, Any]:
        with self._lock():
            instant = _time(now)
            events = self._events()
            if events and instant < _time(events[-1]["received_at"]):
                raise ProtocolError("state time precedes the latest received event")
            return self._public(self._state_from(events, instant), instant)

    def maintainer_tick(self, received_at: str, maintainer_private_key: Any) -> dict[str, Any]:
        now = _time(received_at)
        if public_key_text(maintainer_private_key) != self.config["maintainer_key"]:
            raise ProtocolError("wrong maintainer key")
        with self._lock():
            events = self._events()
            if events and now < _time(events[-1]["received_at"]):
                raise ProtocolError("maintainer time precedes the latest received event")
            s = self._state_from(events, now)
            public = self._public(s, now)
            active = [c for c in s["claims"].values() if c["status"] in {"active", "stale"}]
            warnings = []
            for i, left in enumerate(active):
                for right in active[i + 1 :]:
                    if left["route"] == right["route"] and not (
                        left["parallel"] and right["parallel"]
                    ):
                        warnings.append(
                            {
                                "kind": "overlap",
                                "claims": sorted([left["claim_id"], right["claim_id"]]),
                            }
                        )
            projected = {
                **public,
                "handoffs_queued": [x["handoff_id"] for x in s["handoffs"]],
                "warnings": warnings,
                "limitations": (
                    "Projection only: no mathematical validation, curation, credit review, "
                    "or payment."
                ),
            }
            status = {**projected, "at": received_at}
            unsigned = {
                "at": received_at,
                "head_event_hash": events[-1]["event_hash"] if events else None,
                "event_count": len(events),
                "status_digest": digest_object(projected),
            }
            receipt = {**unsigned, "signature": sign_object(maintainer_private_key, unsigned)}
            previous = None
            if self.receipt_path.exists():
                try:
                    previous = json.loads(self.receipt_path.read_text())
                except json.JSONDecodeError as exc:
                    raise ProtocolError("maintainer receipt JSON is invalid") from exc
            if (
                previous
                and previous["head_event_hash"] == unsigned["head_event_hash"]
                and previous["status_digest"] == unsigned["status_digest"]
            ):
                archived = [self._load_receipt(path) for path in self.receipts_dir.glob("*.json")]
                if previous not in archived:
                    receipt_name = f"{len(archived):08d}-{previous['status_digest'][:16]}.json"
                    self._write(self.receipts_dir / receipt_name, previous, True)
                return {"status": status, "receipt": previous}
            receipt_name = f"{len(list(self.receipts_dir.glob('*.json'))):08d}-"
            receipt_name += f"{receipt['status_digest'][:16]}.json"
            self._write(self.receipts_dir / receipt_name, receipt, True)
            self._write(self.control / "projection.json", status)
            self._write(self.receipt_path, receipt)
            return {"status": status, "receipt": receipt}
