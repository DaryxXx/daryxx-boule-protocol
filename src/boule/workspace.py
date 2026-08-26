"""Boule workspace ledger with local v0.4 and clerk-ordered v0.5 events."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_bytes, digest_object
from .crypto import load_public_key, public_key_text, sign_object, verify_object
from .errors import ProtocolError, RequestConflictError, StaleHeadError
from .policy import build_case_policy, load_case_policy, policy_digest, validate_case_policy
from .provider_contract import (
    decision_outcome,
    provider_contract_for_problem,
    provider_resolution,
    result_url,
    stage_contract,
    validate_submission_id,
)
from .remote_protocol import (
    ENVELOPE_SCHEMA,
    EVENT_SCHEMA,
    MAX_CHAIN_PROOF_LINKS,
    build_chain_proof,
    build_receipt,
    build_snapshot,
    envelope_digest,
    strict_json_bytes,
    verify_envelope,
    verify_receipt,
)

PARTICIPANT_EVENTS = {
    "session_started",
    "work_claimed",
    "claim_heartbeat",
    "checkpoint_published",
    "message_posted",
    "claim_released",
    "handoff_published",
    "submission_candidate_published",
}

MAINTAINER_EVENTS = {
    "external_submission_receipted",
    "candidate_feedback_recorded",
    "case_resolution_recorded",
}

WORKSPACE_EVENTS = PARTICIPANT_EVENTS | MAINTAINER_EVENTS
IDEMPOTENT_EVENTS = {
    "submission_candidate_published",
    "external_submission_receipted",
    "candidate_feedback_recorded",
    "case_resolution_recorded",
}

MAX_SESSION_LIFETIME = timedelta(hours=168)

LEGACY_EVENT_FIELDS = {
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
REMOTE_EVENT_FIELDS = {
    "schema",
    "seq",
    "event_id",
    "received_at",
    "kind",
    "actor",
    "payload",
    "prev_event_hash",
    "request_id",
    "base_event_hash",
    "envelope_digest",
    "envelope_signature",
    "event_hash",
    "clerk_receipt",
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
            self.problem = strict_json_bytes(self.problem_path.read_bytes())
            self.config = strict_json_bytes(self.config_path.read_bytes())
        except (OSError, ProtocolError) as exc:
            raise ProtocolError("workspace JSON is invalid") from exc
        self.policy = load_case_policy(self.policy_path, self.problem)
        self.provider_contract = provider_contract_for_problem(self.problem)
        self._validate()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._thread_lock = threading.RLock()
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
            problem = strict_json_bytes(problem_path.read_bytes())
        except (OSError, ProtocolError) as exc:
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
            fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as h:
                    h.write(canonical_bytes(value) + b"\n")
                    h.flush()
                    os.fsync(h.fileno())
                os.link(tmp, path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
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
        with self._thread_lock:
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
            value = strict_json_bytes(path.read_bytes())
        except (OSError, ProtocolError) as exc:
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
                value = strict_json_bytes(p.read_bytes())
            except (OSError, ProtocolError) as exc:
                raise ProtocolError(f"invalid event file {p.name}") from exc
            if not isinstance(value, dict):
                raise ProtocolError(f"invalid event object {p.name}")
            events.append(value)
        previous = None
        remote_request_ids: set[str] = set()
        for seq, e in enumerate(events):
            fields = frozenset(e)
            if fields not in {frozenset(LEGACY_EVENT_FIELDS), frozenset(REMOTE_EVENT_FIELDS)}:
                raise ProtocolError("event chain fields are invalid")
            if (
                isinstance(e.get("seq"), bool)
                or not isinstance(e.get("seq"), int)
                or e["seq"] != seq
                or e["prev_event_hash"] != previous
            ):
                raise ProtocolError("event chain fields are invalid")
            if not isinstance(e["kind"], str) or e["kind"] not in WORKSPACE_EVENTS:
                raise ProtocolError("unsupported workspace event")
            _time(e["received_at"])
            _text(e["event_id"], "event_id", 128)
            if not isinstance(e["payload"], dict):
                raise ProtocolError("event payload must be an object")
            if fields == LEGACY_EVENT_FIELDS:
                identity_digest = digest_object([e["kind"], e["payload"], e["received_at"]])
                expected_id = f"{seq:08d}-{identity_digest[:16]}"
                if e["event_id"] != expected_id:
                    raise ProtocolError("event id does not match its signed contents")
                load_public_key(e["actor"])
                unsigned = {k: e[k] for k in LEGACY_EVENT_FIELDS - {"event_hash", "signature"}}
                if e["event_hash"] != digest_object(unsigned):
                    raise ProtocolError("event hash mismatch")
                verify_object(e["actor"], unsigned, e["signature"])
            elif e.get("schema") == EVENT_SCHEMA:
                if e["kind"] not in PARTICIPANT_EVENTS:
                    raise ProtocolError("remote event kind is not a participant event")
                if e["base_event_hash"] != e["prev_event_hash"]:
                    raise ProtocolError("remote event base does not match its ordered predecessor")
                if e["request_id"] in remote_request_ids:
                    raise ProtocolError("remote request id is not unique")
                envelope = {
                    "schema": ENVELOPE_SCHEMA,
                    "request_id": e["request_id"],
                    "problem_id": self.problem["problem_id"],
                    "clerk_key": self.config["maintainer_key"],
                    "base_event_hash": e["base_event_hash"],
                    "kind": e["kind"],
                    "actor": e["actor"],
                    "payload": e["payload"],
                    "signature": e["envelope_signature"],
                }
                verify_envelope(
                    envelope,
                    problem_id=self.problem["problem_id"],
                    clerk_key=self.config["maintainer_key"],
                    allowed_kinds=PARTICIPANT_EVENTS,
                )
                if e["envelope_digest"] != envelope_digest(envelope):
                    raise ProtocolError("remote event envelope digest mismatch")
                expected_id = f"{seq:08d}-{digest_object(envelope)[:16]}"
                if e["event_id"] != expected_id:
                    raise ProtocolError("remote event id does not match its envelope")
                core = {
                    key: e[key] for key in REMOTE_EVENT_FIELDS - {"event_hash", "clerk_receipt"}
                }
                if e["event_hash"] != digest_object(core):
                    raise ProtocolError("remote event hash mismatch")
                receipt = verify_receipt(
                    e["clerk_receipt"],
                    problem_id=self.problem["problem_id"],
                    clerk_key=self.config["maintainer_key"],
                    request_id=e["request_id"],
                    envelope=envelope,
                )
                for key in (
                    "seq",
                    "event_id",
                    "received_at",
                    "prev_event_hash",
                    "event_hash",
                    "envelope_digest",
                ):
                    if receipt[key] != e[key]:
                        raise ProtocolError("remote clerk receipt does not match its event")
                remote_request_ids.add(e["request_id"])
            else:
                raise ProtocolError("remote event schema is unsupported")
            if seq and _time(e["received_at"]) < _time(events[seq - 1]["received_at"]):
                raise ProtocolError("event receipt times must be monotonic")
            previous = e["event_hash"]
        validated: list[dict[str, Any]] = []
        for event in events:
            instant = _time(event["received_at"])
            state = self._state_from(validated, instant)
            if event["kind"] in PARTICIPANT_EVENTS:
                self._authorize(
                    event["kind"],
                    event["payload"],
                    event["actor"],
                    state,
                    instant,
                    remote=event.get("schema") == EVENT_SCHEMA,
                )
            else:
                self._authorize_maintainer(
                    event["kind"], event["payload"], event["actor"], state, instant
                )
            validated.append(event)
        self._guard_receipts(events)
        return events

    def append(self, kind: str, payload: dict[str, Any], private_key: Any) -> dict[str, Any]:
        if kind not in PARTICIPANT_EVENTS:
            raise ProtocolError("only participant events may be appended")
        return self._append(kind, payload, private_key, maintainer=False)

    def append_maintainer(
        self, kind: str, payload: dict[str, Any], private_key: Any
    ) -> dict[str, Any]:
        if kind not in MAINTAINER_EVENTS:
            raise ProtocolError("only submission observation events may be appended by maintainer")
        return self._append(kind, payload, private_key, maintainer=True)

    def _append(
        self,
        kind: str,
        payload: dict[str, Any],
        private_key: Any,
        *,
        maintainer: bool,
    ) -> dict[str, Any]:
        observed = self._clock()
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise ProtocolError("workspace clock must return a timezone-aware datetime")
        now = observed.astimezone(UTC)
        received_at = _stamp(now)
        with self._lock():
            events = self._events()
            if events and now < _time(events[-1]["received_at"]):
                raise ProtocolError("event receipt times must be monotonic")
            actor = public_key_text(private_key)
            if kind in IDEMPOTENT_EVENTS:
                previous = next(
                    (
                        event
                        for event in reversed(events)
                        if event["kind"] == kind
                        and event["actor"] == actor
                        and event["payload"] == payload
                    ),
                    None,
                )
                if previous is not None:
                    return previous
            state = self._state_from(events, now)
            if maintainer:
                self._authorize_maintainer(kind, payload, actor, state, now)
            else:
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

    def append_envelope(
        self, envelope: dict[str, Any], maintainer_private_key: Any
    ) -> dict[str, Any]:
        """Order one participant-signed envelope and return its durable clerk receipt."""
        if public_key_text(maintainer_private_key) != self.config["maintainer_key"]:
            raise ProtocolError("wrong maintainer key")
        try:
            stable_envelope = json.loads(canonical_bytes(envelope))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProtocolError("remote envelope is not canonical JSON") from exc
        verify_envelope(
            stable_envelope,
            problem_id=self.problem["problem_id"],
            clerk_key=self.config["maintainer_key"],
            allowed_kinds=PARTICIPANT_EVENTS,
        )
        observed = self._clock()
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise ProtocolError("workspace clock must return a timezone-aware datetime")
        with self._lock():
            events = self._events()
            digest = envelope_digest(stable_envelope)
            previous_request = next(
                (
                    event
                    for event in events
                    if event.get("schema") == EVENT_SCHEMA
                    and event.get("request_id") == stable_envelope["request_id"]
                ),
                None,
            )
            if previous_request is not None:
                if previous_request["envelope_digest"] != digest:
                    raise RequestConflictError("remote request id was reused with another envelope")
                return {
                    "created": False,
                    "event": previous_request,
                    "receipt": previous_request["clerk_receipt"],
                }
            current_head = events[-1]["event_hash"] if events else None
            if stable_envelope["base_event_hash"] != current_head:
                raise StaleHeadError(current_head, len(events))
            now = observed.astimezone(UTC)
            if events:
                now = max(now, _time(events[-1]["received_at"]))
            received_at = _stamp(now)
            state = self._state_from(events, now)
            self._authorize(
                stable_envelope["kind"],
                stable_envelope["payload"],
                stable_envelope["actor"],
                state,
                now,
                remote=True,
            )
            core = {
                "schema": EVENT_SCHEMA,
                "seq": len(events),
                "event_id": f"{len(events):08d}-{digest_object(stable_envelope)[:16]}",
                "received_at": received_at,
                "kind": stable_envelope["kind"],
                "actor": stable_envelope["actor"],
                "payload": stable_envelope["payload"],
                "prev_event_hash": current_head,
                "request_id": stable_envelope["request_id"],
                "base_event_hash": stable_envelope["base_event_hash"],
                "envelope_digest": digest,
                "envelope_signature": stable_envelope["signature"],
            }
            event_without_receipt = {**core, "event_hash": digest_object(core)}
            receipt = build_receipt(
                event_without_receipt,
                problem_id=self.problem["problem_id"],
                clerk_private_key=maintainer_private_key,
            )
            event = {**event_without_receipt, "clerk_receipt": receipt}
            self._write(
                self.events_dir / f"{event['seq']:08d}-{event['event_id']}.json", event, True
            )
            return {"created": True, "event": event, "receipt": receipt}

    def remote_receipt(self, request_id: str, maintainer_private_key: Any) -> dict[str, Any] | None:
        if public_key_text(maintainer_private_key) != self.config["maintainer_key"]:
            raise ProtocolError("wrong maintainer key")
        with self._lock():
            events = self._events()
            event = next(
                (
                    item
                    for item in events
                    if item.get("schema") == EVENT_SCHEMA and item.get("request_id") == request_id
                ),
                None,
            )
            return event["clerk_receipt"] if event is not None else None

    def remote_snapshot(self, received_at: str, maintainer_private_key: Any) -> dict[str, Any]:
        if public_key_text(maintainer_private_key) != self.config["maintainer_key"]:
            raise ProtocolError("wrong maintainer key")
        requested = _time(received_at)
        with self._lock():
            events = self._events()
            now = max(requested, _time(events[-1]["received_at"])) if events else requested
            at = _stamp(now)
            state = self._public(self._state_from(events, now), now)
            snapshot = build_snapshot(
                problem_id=self.problem["problem_id"],
                at=at,
                event_count=len(events),
                head_event_hash=events[-1]["event_hash"] if events else None,
                state=state,
                clerk_private_key=maintainer_private_key,
            )
            return {"state": state, "snapshot": snapshot}

    def remote_chain_proof(
        self, from_count: int, to_count: int, maintainer_private_key: Any
    ) -> dict[str, Any]:
        if public_key_text(maintainer_private_key) != self.config["maintainer_key"]:
            raise ProtocolError("wrong maintainer key")
        if (
            isinstance(from_count, bool)
            or not isinstance(from_count, int)
            or isinstance(to_count, bool)
            or not isinstance(to_count, int)
            or not 0 <= from_count <= to_count
            or to_count - from_count > MAX_CHAIN_PROOF_LINKS
        ):
            raise ProtocolError("chain proof range is invalid")
        with self._lock():
            events = self._events()
            if to_count > len(events):
                raise ProtocolError("chain proof range exceeds the event log")
            start_head = events[from_count - 1]["event_hash"] if from_count else None
            return build_chain_proof(
                problem_id=self.problem["problem_id"],
                from_count=from_count,
                start_head=start_head,
                events=events[from_count:to_count],
                clerk_private_key=maintainer_private_key,
            )

    def _authorize(
        self,
        kind: str,
        p: dict[str, Any],
        actor: str,
        s: dict[str, Any],
        now: datetime,
        *,
        remote: bool = False,
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
            not_after = _time(p["not_after"])
            if not_after <= now:
                raise ProtocolError("session already expired")
            if remote and not_after > now + MAX_SESSION_LIFETIME:
                raise ProtocolError("session lifetime exceeds 168 hours")
            return
        session = s["session_keys"].get(actor)
        if session is None or _time(session["not_after"]) <= now:
            raise ProtocolError("actor is not an active session")
        if (
            p.get("session_id") != session["session_id"]
            or p.get("participant_id") != session["participant_id"]
        ):
            raise ProtocolError("participant/session identity mismatch")
        if kind == "submission_candidate_published":
            req = {
                "problem_id",
                "participant_id",
                "session_id",
                "candidate_id",
                "handoff_ids",
                "task_id",
                "task_commitment",
                "formal_repository_pin",
                "artifact",
                "summary",
                "reproduce",
                "limitations",
            }
            if set(p) != req:
                raise ProtocolError("invalid submission_candidate_published payload")
            if self._problem_status(s) == "SOLVED":
                raise ProtocolError("problem state does not accept another solution candidate")
            _text(p["candidate_id"], "candidate_id", 128)
            if p["candidate_id"] in s["candidates"]:
                raise ProtocolError("candidate id is not unique")
            self._task_binding(p)
            self._artifact(p["artifact"], "candidate artifact")
            if any(
                candidate["artifact"]["sha256"] == p["artifact"]["sha256"]
                for candidate in s["candidates"].values()
            ):
                raise ProtocolError("candidate artifact is already sealed")
            for key in ("summary", "reproduce", "limitations"):
                _text(p[key], f"candidate.{key}", 2000)
            handoff_ids = p["handoff_ids"]
            if (
                not isinstance(handoff_ids, list)
                or not handoff_ids
                or len(handoff_ids) > 32
                or any(not isinstance(item, str) for item in handoff_ids)
                or len(handoff_ids) != len(set(handoff_ids))
            ):
                raise ProtocolError("candidate handoff_ids must be 1 to 32 unique ids")
            linked = []
            for handoff_id in handoff_ids:
                handoff = s["handoffs_by_id"].get(handoff_id)
                if handoff is None or handoff["outcome"] != "ADVANCE":
                    raise ProtocolError("candidate dependencies must be earlier ADVANCE handoffs")
                linked.append(handoff)
            evidence = {
                (item["ref"], item["sha256"]) for handoff in linked for item in handoff["evidence"]
            }
            artifact = (p["artifact"]["ref"], p["artifact"]["sha256"])
            if artifact not in evidence:
                raise ProtocolError("candidate artifact must be evidence in a linked handoff")
            return
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
            if self._problem_status(s) == "SOLVED":
                raise ProtocolError("problem is not open for new work claims")
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
            if p["outcome"] == "BLOCKED" and not p["evidence"] and not p["depends_on"]:
                raise ProtocolError("BLOCKED handoff needs evidence or an earlier dependency")
            if p["provenance"] == "original" and not p["evidence"]:
                raise ProtocolError("original provenance requires evidence")
        else:
            raise ProtocolError("unsupported participant event")

    def _authorize_maintainer(
        self, kind: str, p: dict[str, Any], actor: str, s: dict[str, Any], now: datetime
    ) -> None:
        if actor != self.config["maintainer_key"]:
            raise ProtocolError("submission observations require the maintainer key")
        if not isinstance(p, dict) or p.get("problem_id") != self.problem["problem_id"]:
            raise ProtocolError("event belongs to another problem")
        common = {
            "problem_id",
            "candidate_id",
            "submission_id",
            "task_id",
            "task_commitment",
            "formal_repository_pin",
            "artifact_sha256",
            "public_result_url",
            "source",
        }
        if kind == "external_submission_receipted":
            req = common | {"submitted_at", "receipt"}
            if set(p) != req:
                raise ProtocolError("invalid external_submission_receipted payload")
            candidate = self._bound_candidate(p, s)
            if candidate["submission"] is not None:
                raise ProtocolError("candidate already has an external submission")
            if candidate["status"] != "CANDIDATE_READY":
                raise ProtocolError("candidate is not ready for external submission receipt")
            if self._problem_status(s) in {
                "VERIFICATION_PENDING",
                "REVIEW_PENDING",
                "ACCEPTANCE_RECORDED",
                "SOLVED",
            }:
                raise ProtocolError("another submission state currently blocks external receipt")
            submission_id = validate_submission_id(self.provider_contract, p["submission_id"])
            if submission_id in s["submission_ids"]:
                raise ProtocolError("external submission id is already bound")
            self._result_url(p["public_result_url"], submission_id)
            self._artifact(p["receipt"], "submission receipt")
            self._external_source(
                p["source"],
                self.provider_contract["submission"]["receipt_source"],
                p["receipt"],
                p["public_result_url"],
            )
            if _time(p["submitted_at"]) > now:
                raise ProtocolError("external submission time cannot be in the future")
            return
        if kind == "candidate_feedback_recorded":
            req = common | {
                "stage",
                "decision",
                "reason_code",
                "summary",
                "next_action",
                "report",
            }
            if set(p) != req:
                raise ProtocolError("invalid candidate_feedback_recorded payload")
            candidate = self._bound_candidate(p, s)
            submission = candidate["submission"]
            if submission is None or submission["submission_id"] != p["submission_id"]:
                raise ProtocolError("feedback is not bound to the candidate submission")
            self._result_url(p["public_result_url"], p["submission_id"])
            self._artifact(p["report"], "feedback report")
            stage = p["stage"]
            details = stage_contract(self.provider_contract, stage)
            expected_source = details["source"]
            self._external_source(
                p["source"],
                expected_source,
                p["report"],
                p["public_result_url"],
                allow_provider_observation=True,
            )
            for key in ("reason_code", "summary", "next_action"):
                _text(p[key], f"feedback.{key}", 2000)
            decision = p["decision"]
            outcome = decision_outcome(self.provider_contract, stage, decision)
            if outcome == "pending":
                raise ProtocolError("pending provider state is not terminal feedback")
            if stage == "verifier":
                if candidate["status"] != "VERIFICATION_PENDING":
                    raise ProtocolError("verifier feedback is not valid in the candidate state")
            elif stage == "review":
                if candidate["status"] != "REVIEW_PENDING":
                    raise ProtocolError("review feedback requires a Lean-verified candidate")
            elif stage == "reward":
                if candidate["status"] not in {"APPROVED", "REJECTED", "PARTIAL_AWARD"}:
                    raise ProtocolError("reward feedback requires a completed human review")
                if candidate["reward"] is not None:
                    raise ProtocolError("reward decision is already terminal")
            return
        if kind == "case_resolution_recorded":
            req = common | {"resolution", "review_event_id", "note"}
            if set(p) != req:
                raise ProtocolError("invalid case_resolution_recorded payload")
            candidate = self._bound_candidate(p, s)
            submission = candidate["submission"]
            review = candidate["review"]
            if submission is None or submission["submission_id"] != p["submission_id"]:
                raise ProtocolError("resolution is not bound to the candidate submission")
            self._result_url(p["public_result_url"], p["submission_id"])
            if p["source"] != self.provider_contract["resolution"]["source"]:
                raise ProtocolError("resolution source is invalid")
            review_success = self.provider_contract["stages"]["review"]["success"]
            if (
                candidate["status"] != "APPROVED"
                or review is None
                or review["event_id"] != p["review_event_id"]
                or review["decision"] not in review_success
                or p["resolution"] != self.provider_contract["resolution"]["success_status"]
            ):
                raise ProtocolError("case resolution requires the exact approved review event")
            if s["resolutions"]:
                raise ProtocolError("case already has a resolution")
            _text(p["note"], "resolution.note", 2000)
            return
        raise ProtocolError("unsupported maintainer event")

    def _task_binding(self, value: dict[str, Any]) -> None:
        task = self.problem["task"]
        for key in ("task_id", "task_commitment", "formal_repository_pin"):
            if value.get(key) != task[key]:
                raise ProtocolError("event task identity does not match the pinned problem")

    @staticmethod
    def _artifact(value: Any, name: str) -> None:
        if not isinstance(value, dict) or set(value) != {"ref", "sha256"}:
            raise ProtocolError(f"{name} has invalid fields")
        _text(value["ref"], f"{name}.ref", 1000)
        _sha256(value["sha256"], f"{name}.sha256")

    def _result_url(self, value: Any, submission_id: str) -> None:
        if value != result_url(self.provider_contract, submission_id):
            raise ProtocolError("public result URL must match the external submission id")

    @staticmethod
    def _external_source(
        source: Any,
        expected: str | None,
        evidence: dict[str, Any],
        result_url: str,
        *,
        allow_provider_observation: bool = False,
    ) -> None:
        if source != expected:
            raise ProtocolError("external observation source is invalid")
        if evidence["ref"] == result_url:
            return
        if not allow_provider_observation:
            raise ProtocolError("external evidence must digest the canonical public result URL")
        evidence_url = urlsplit(evidence["ref"])
        canonical_result = urlsplit(result_url)
        if (
            evidence_url.scheme != "https"
            or evidence_url.hostname != canonical_result.hostname
            or evidence_url.port != canonical_result.port
            or evidence_url.username
            or evidence_url.password
            or evidence_url.fragment
        ):
            raise ProtocolError(
                "external evidence must reference the result URL or a public same-provider URL"
            )

    def _bound_candidate(self, value: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        candidate = state["candidates"].get(value.get("candidate_id"))
        if candidate is None:
            raise ProtocolError("candidate does not exist")
        self._task_binding(value)
        if value.get("artifact_sha256") != candidate["artifact"]["sha256"]:
            raise ProtocolError("event artifact does not match the sealed candidate")
        return candidate

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
            "handoffs_by_id": {},
            "candidates": {},
            "submission_ids": {},
            "feedback": [],
            "resolutions": [],
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
                s["checkpoints"].append(
                    {"event_id": e["event_id"], "received_at": e["received_at"], **p}
                )
            elif k == "message_posted":
                s["messages"].append(
                    {"event_id": e["event_id"], "received_at": e["received_at"], **p}
                )
            elif k in {"claim_released", "handoff_published"}:
                c = s["claims"][p["claim_id"]]
                c["status"] = "released" if k == "claim_released" else "completed"
                s["sessions"][p["session_id"]]["active_claim"] = None
                if k == "handoff_published":
                    handoff = {
                        "event_id": e["event_id"],
                        "received_at": e["received_at"],
                        "status": "queued_for_review",
                        **p,
                    }
                    s["handoffs"].append(handoff)
                    s["handoff_ids"].add(p["handoff_id"])
                    s["handoffs_by_id"][p["handoff_id"]] = handoff
            elif k == "submission_candidate_published":
                s["candidates"][p["candidate_id"]] = {
                    "event_id": e["event_id"],
                    "received_at": e["received_at"],
                    "status": "CANDIDATE_READY",
                    "submission": None,
                    "verifier": None,
                    "review": None,
                    "reward": None,
                    "feedback": [],
                    **p,
                }
            elif k == "external_submission_receipted":
                candidate = s["candidates"][p["candidate_id"]]
                submission = {
                    "event_id": e["event_id"],
                    "received_at": e["received_at"],
                    **p,
                }
                candidate["submission"] = submission
                candidate["status"] = "VERIFICATION_PENDING"
                s["submission_ids"][p["submission_id"]] = p["candidate_id"]
            elif k == "candidate_feedback_recorded":
                candidate = s["candidates"][p["candidate_id"]]
                feedback = {
                    "event_id": e["event_id"],
                    "received_at": e["received_at"],
                    **p,
                }
                candidate["feedback"].append(feedback)
                s["feedback"].append(feedback)
                if p["stage"] == "verifier":
                    candidate["verifier"] = feedback
                    candidate["status"] = (
                        "REVIEW_PENDING"
                        if decision_outcome(self.provider_contract, "verifier", p["decision"])
                        == "success"
                        else "REJECTED"
                    )
                elif p["stage"] == "review":
                    candidate["review"] = feedback
                    outcome = decision_outcome(self.provider_contract, "review", p["decision"])
                    candidate["status"] = (
                        "APPROVED"
                        if outcome == "success"
                        else ("PARTIAL_AWARD" if p["decision"] == "PARTIAL_AWARD" else "REJECTED")
                    )
                else:
                    candidate["reward"] = feedback
            elif k == "case_resolution_recorded":
                s["resolutions"].append(
                    {"event_id": e["event_id"], "received_at": e["received_at"], **p}
                )
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

    @staticmethod
    def _problem_status(s: dict[str, Any]) -> str:
        if s["resolutions"]:
            return "SOLVED"
        statuses = {candidate["status"] for candidate in s["candidates"].values()}
        if "APPROVED" in statuses:
            return "ACCEPTANCE_RECORDED"
        if "REVIEW_PENDING" in statuses:
            return "REVIEW_PENDING"
        if "VERIFICATION_PENDING" in statuses:
            return "VERIFICATION_PENDING"
        if "CANDIDATE_READY" in statuses:
            return "CANDIDATE_READY"
        if statuses & {"REJECTED", "PARTIAL_AWARD"}:
            return "OPEN_AFTER_FEEDBACK"
        return "OPEN"

    def _research_resume(self, s: dict[str, Any]) -> dict[str, Any]:
        status = self._problem_status(s)
        if status == "OPEN":
            return {"action": "START_OR_RESUME_RESEARCH", "feedback": None}
        if status == "CANDIDATE_READY":
            ready = next(
                candidate
                for candidate in reversed(list(s["candidates"].values()))
                if candidate["status"] == "CANDIDATE_READY"
            )
            return {
                "action": "AWAIT_EXTERNAL_SUBMISSION",
                "candidate_id": ready["candidate_id"],
                "feedback": None,
            }
        if status in {"VERIFICATION_PENDING", "REVIEW_PENDING"}:
            pending_status = (
                "REVIEW_PENDING" if status == "REVIEW_PENDING" else "VERIFICATION_PENDING"
            )
            pending = next(
                candidate
                for candidate in reversed(list(s["candidates"].values()))
                if candidate["status"] == pending_status
            )
            return {
                "action": "AWAIT_OFFICIAL_FEEDBACK",
                "candidate_id": pending["candidate_id"],
                "submission_id": pending["submission"]["submission_id"],
                "feedback": pending["verifier"] if status == "REVIEW_PENDING" else None,
            }
        if status in {"ACCEPTANCE_RECORDED", "SOLVED"}:
            accepted = next(
                candidate
                for candidate in s["candidates"].values()
                if candidate["status"] == "APPROVED"
            )
            return {
                "action": (
                    "STOP_RESEARCH_PRESERVE_EVIDENCE"
                    if status == "SOLVED"
                    else "AWAIT_TRUSTED_CLERK_FINALIZATION"
                ),
                "candidate_id": accepted["candidate_id"],
                "submission_id": accepted["submission"]["submission_id"],
                "feedback": accepted["review"],
            }
        returned = next(
            candidate
            for candidate in reversed(list(s["candidates"].values()))
            if candidate["status"] in {"REJECTED", "PARTIAL_AWARD"}
        )
        terminal = returned["review"] or returned["verifier"]
        return {
            "action": "CONTINUE_RESEARCH_FROM_FEEDBACK",
            "candidate_id": returned["candidate_id"],
            "submission_id": returned["submission"]["submission_id"],
            "feedback": terminal,
        }

    def _public(self, s: dict[str, Any], now: datetime) -> dict[str, Any]:
        problem_status = self._problem_status(s)
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
            "problem_status": problem_status,
            "provider": {
                "id": self.provider_contract["provider_id"],
                "display_name": self.provider_contract["display_name"],
                "contract_schema": self.provider_contract["schema"],
                "definition_adapter": self.provider_contract["definition"]["adapter"],
            },
            "provider_resolution": provider_resolution(self.provider_contract, s, problem_status),
            "research_resume": self._research_resume(s),
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
            "candidates": list(s["candidates"].values()),
            "feedback": s["feedback"],
            "resolutions": s["resolutions"],
            "external_status_trust": {
                "mode": "trusted_clerk_observation",
                "authenticated_external_attestation": False,
            },
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
                    "Projection only. Maintainer signatures attest local recording, not external "
                    "reviewer authorship. No submission, mathematical validation, credit decision, "
                    "wallet action, or payment is performed by this projection."
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
                    previous = strict_json_bytes(self.receipt_path.read_bytes())
                except (OSError, ProtocolError) as exc:
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
