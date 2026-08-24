"""Durable, clerk-signed registry of Boule problems.

The registry deliberately contains only a small state machine.  It records
intake and maintainer decisions locally; the companion HTTP module exposes no
mutation routes.
"""

from __future__ import annotations

import fcntl
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, digest_object
from .crypto import load_public_key, public_key_text, sign_object, verify_object
from .errors import ProtocolError
from .model import CASE_ID_RE, parse_time
from .remote_protocol import strict_json_bytes

REGISTRY_SCHEMA = "boule-problem-registry/0.6"
SNAPSHOT_SCHEMA = "boule-problem-registry-snapshot/0.6"
CHAIN_PROOF_SCHEMA = "boule-problem-registry-chain-proof/0.6"
MAX_CHAIN_PROOF_ENTRIES = 256
ENTRY_FIELDS = {
    "schema",
    "seq",
    "received_at",
    "prev_hash",
    "event",
    "entry_hash",
    "clerk_signature",
}
EVENT_FIELDS = {"kind", "payload"}
PROPOSAL_FIELDS = {"case_id", "problem"}
STATES = frozenset({"PROPOSED", "ADMITTED", "PROVISIONING", "LIVE", "PROVISION_FAILED"})
MAX_RETRIES = 3
MAX_CASES = 10_000
MAX_REGISTRY_ENTRIES = 1_000_000
MAX_ERROR_LENGTH = 240
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _exact(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError(f"{name} has invalid fields")
    return value


def _text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProtocolError(f"{name} must be non-empty text up to {maximum} characters")
    return value


def _case_id(value: Any) -> str:
    value = _text(value, "case_id", 128)
    if CASE_ID_RE.fullmatch(value) is None:
        raise ProtocolError("case_id has an invalid format")
    return value


def _problem_summary(proposal: Any) -> tuple[str, dict[str, Any], str]:
    """Validate imported-problem data and retain the non-sensitive public subset."""
    proposal = _exact(proposal, PROPOSAL_FIELDS, "proposal")
    case_id = _case_id(proposal["case_id"])
    problem = proposal["problem"]
    if not isinstance(problem, dict):
        raise ProtocolError("proposal.problem must be an object")
    try:
        problem_id = _text(problem["problem_id"], "problem.problem_id", 256)
        title = _text(problem["problem"]["title"], "problem.problem.title", 240)
        source = problem["source"]
        task = problem["task"]
        if not isinstance(source, dict) or not isinstance(task, dict):
            raise TypeError
        provider = _text(source["provider"], "problem.source.provider", 80)
        source_url = _text(
            source["canonical_problem_url"], "problem.source.canonical_problem_url", 2_048
        )
        mode = _text(task["mode"], "problem.task.mode", 64)
        task_id = _text(task["task_id"], "problem.task.task_id", 256)
        commitment = task["task_commitment"]
        pin = _text(task["formal_repository_pin"], "problem.task.formal_repository_pin", 128)
        pinned_source = _text(task["pinned_source_url"], "problem.task.pinned_source_url", 2_048)
    except (KeyError, TypeError) as exc:
        raise ProtocolError("proposal.problem is missing registry fields") from exc
    if not isinstance(commitment, str) or SHA256_RE.fullmatch(commitment) is None:
        raise ProtocolError("problem.task.task_commitment must be a lowercase SHA-256 value")
    if mode not in {"formalized", "counterexample"}:
        raise ProtocolError("problem.task.mode is invalid")
    public = {
        "case_id": case_id,
        "problem_id": problem_id,
        "title": title,
        "source_name": provider,
        "source_url": source_url,
        "task_id": task_id,
        "task_commitment": commitment,
        "task_mode": mode,
        "formal_repository_pin": pin,
        "pinned_source_url": pinned_source,
    }
    return case_id, public, commitment


def _public_url(value: Any, name: str) -> str:
    value = _text(value, name, 2_048)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ProtocolError(f"{name} must be an HTTPS URL without credentials or a fragment")
    return value


def _case_evidence(head_event_hash: Any, event_count: Any) -> tuple[str | None, int]:
    if (
        isinstance(event_count, bool)
        or not isinstance(event_count, int)
        or not 0 <= event_count <= 10_000_000
    ):
        raise ProtocolError("event_count must be an integer between 0 and 10000000")
    if event_count == 0 and head_event_hash is None:
        return None, 0
    if (
        event_count == 0
        or not isinstance(head_event_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", head_event_hash) is None
    ):
        raise ProtocolError("a non-empty case needs a lowercase SHA-256 head digest")
    return head_event_hash, event_count


def _repository_identity(
    repository_id: Any, repository_node_id: Any
) -> tuple[int | str, str | None]:
    if isinstance(repository_id, bool):
        raise ProtocolError("repository identity is invalid")
    if isinstance(repository_id, int):
        if repository_id <= 0:
            raise ProtocolError("repository identity is invalid")
        node_id = _text(repository_node_id, "repository_node_id", 256)
        return repository_id, node_id
    if (
        isinstance(repository_id, str)
        and re.fullmatch(r"local:[0-9a-f]{32}", repository_id) is not None
        and repository_node_id is None
    ):
        return repository_id, None
    raise ProtocolError("repository identity is invalid")


def _entry_body(
    seq: int, received_at: str, prev_hash: str | None, event: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema": REGISTRY_SCHEMA,
        "seq": seq,
        "received_at": received_at,
        "prev_hash": prev_hash,
        "event": event,
    }


def _receipt_body(seq: int, prev_hash: str | None, entry_hash: str) -> dict[str, Any]:
    return {
        "domain": "boule-problem-registry-receipt/0.6",
        "seq": seq,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }


def verify_registry_snapshot(value: Any, *, clerk_key: str | None = None) -> dict[str, Any]:
    fields = {
        "schema",
        "generated_at",
        "clerk",
        "head",
        "count",
        "problems",
        "signature",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError("registry snapshot has invalid fields")
    if value["schema"] != SNAPSHOT_SCHEMA:
        raise ProtocolError("registry snapshot schema is unsupported")
    parse_time(value["generated_at"], "registry snapshot time")
    load_public_key(value["clerk"])
    if clerk_key is not None and value["clerk"] != clerk_key:
        raise ProtocolError("registry snapshot clerk key does not match the pin")
    if (
        not isinstance(value["head"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["head"]) is None
        or isinstance(value["count"], bool)
        or not isinstance(value["count"], int)
        or value["count"] < 1
        or value["count"] > MAX_REGISTRY_ENTRIES
        or not isinstance(value["problems"], list)
        or any(not isinstance(item, dict) for item in value["problems"])
    ):
        raise ProtocolError("registry snapshot content is invalid")
    unsigned = {key: value[key] for key in fields - {"signature"}}
    verify_object(
        value["clerk"],
        {"domain": "boule-problem-registry-snapshot/0.6", **unsigned},
        value["signature"],
    )
    return value


def _chain_proof_unsigned(proof: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": "boule-problem-registry-chain-proof/0.6",
        **{key: value for key, value in proof.items() if key != "signature"},
    }


def verify_registry_chain_proof(
    value: Any,
    *,
    clerk_key: str,
    from_count: int,
    from_head: str,
    to_count: int,
) -> dict[str, Any]:
    fields = {
        "schema",
        "clerk",
        "from_count",
        "from_head",
        "to_count",
        "to_head",
        "links",
        "signature",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError("registry chain proof has invalid fields")
    if (
        value["schema"] != CHAIN_PROOF_SCHEMA
        or value["clerk"] != clerk_key
        or value["from_count"] != from_count
        or value["from_head"] != from_head
        or value["to_count"] != to_count
        or isinstance(from_count, bool)
        or not isinstance(from_count, int)
        or isinstance(to_count, bool)
        or not isinstance(to_count, int)
        or not 1 <= from_count <= to_count
        or to_count > MAX_REGISTRY_ENTRIES
        or to_count - from_count > MAX_CHAIN_PROOF_ENTRIES
        or not isinstance(value["links"], list)
        or len(value["links"]) != to_count - from_count
        or re.fullmatch(r"[0-9a-f]{64}", from_head) is None
    ):
        raise ProtocolError("registry chain proof does not match the requested range")
    verify_object(clerk_key, _chain_proof_unsigned(value), value["signature"])
    previous_hash = from_head
    link_fields = {"seq", "prev_hash", "entry_hash", "clerk_signature"}
    for expected_seq, link in enumerate(value["links"], start=from_count):
        _exact(link, link_fields, f"registry chain link {expected_seq}")
        if (
            link["seq"] != expected_seq
            or link["prev_hash"] != previous_hash
            or not isinstance(link["entry_hash"], str)
            or re.fullmatch(r"[0-9a-f]{64}", link["entry_hash"]) is None
        ):
            raise ProtocolError("registry chain proof link is not a contiguous extension")
        verify_object(
            clerk_key,
            _receipt_body(expected_seq, previous_hash, link["entry_hash"]),
            link["clerk_signature"],
        )
        previous_hash = link["entry_hash"]
    if value["to_head"] != previous_hash:
        raise ProtocolError("registry chain proof does not reach its declared head")
    return value


@dataclass
class _Record:
    public: dict[str, Any]
    status: str = "PROPOSED"
    retries: int = 0
    repo_url: str | None = None
    clerk_url: str | None = None
    clerk_key: str | None = None
    marker_digest: str | None = None
    repository_commit: str | None = None
    repository_id: int | str | None = None
    repository_node_id: str | None = None
    head_event_hash: str | None = None
    event_count: int = 0
    updated_at: str | None = None


class Registry:
    """Append-only registry whose mutations are serialized through one clerk key."""

    def __init__(
        self,
        entries: list[dict[str, Any]],
        *,
        path: Path | None = None,
        clerk_private_key: Ed25519PrivateKey | None = None,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        if not 0 <= max_retries <= 32:
            raise ProtocolError("max_retries must be between 0 and 32")
        self._entries = list(entries)
        self._path = path
        self._clerk_private_key = clerk_private_key
        self._max_retries = max_retries
        self._thread_lock = threading.RLock()
        self.verify()
        if clerk_private_key is not None and public_key_text(clerk_private_key) != self.clerk_key:
            raise ProtocolError("wrong registry clerk key")

    @classmethod
    def create(
        cls,
        path: str | Path,
        clerk_private_key: Ed25519PrivateKey,
        received_at: str | None = None,
        *,
        max_retries: int = MAX_RETRIES,
    ) -> Registry:
        destination = Path(path)
        if destination.exists():
            raise FileExistsError(destination)
        event = {
            "kind": "registry_opened",
            "payload": {"clerk_key": public_key_text(clerk_private_key)},
        }
        body = _entry_body(0, received_at or _now(), None, event)
        entry_hash = digest_object(body)
        entry = {
            **body,
            "entry_hash": entry_hash,
            "clerk_signature": sign_object(clerk_private_key, _receipt_body(0, None, entry_hash)),
        }
        registry = cls(
            [entry], path=destination, clerk_private_key=clerk_private_key, max_retries=max_retries
        )
        registry._persist()
        return registry

    @classmethod
    def read(cls, path: str | Path, *, max_retries: int = MAX_RETRIES) -> Registry:
        source = Path(path)
        try:
            raw_lines = source.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ProtocolError(f"cannot read registry: {source}") from exc
        if not raw_lines or any(not line.strip() for line in raw_lines):
            raise ProtocolError("registry must contain non-empty JSONL records")
        entries: list[dict[str, Any]] = []
        for number, line in enumerate(raw_lines, start=1):
            try:
                value = strict_json_bytes(line.encode("utf-8"))
            except ProtocolError as exc:
                raise ProtocolError(f"registry line {number} is not valid strict JSON") from exc
            if not isinstance(value, dict):
                raise ProtocolError(f"registry line {number} is not an object")
            entries.append(value)
        return cls(entries, path=source, max_retries=max_retries)

    @classmethod
    def open(
        cls,
        path: str | Path,
        clerk_private_key: Ed25519PrivateKey,
        *,
        max_retries: int = MAX_RETRIES,
    ) -> Registry:
        registry = cls.read(path, max_retries=max_retries)
        if public_key_text(clerk_private_key) != registry.clerk_key:
            raise ProtocolError("wrong registry clerk key")
        registry._clerk_private_key = clerk_private_key
        return registry

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    @property
    def clerk_key(self) -> str:
        return self._entries[0]["event"]["payload"]["clerk_key"]

    @property
    def head(self) -> str:
        return self._entries[-1]["entry_hash"]

    @property
    def count(self) -> int:
        return len(self._entries)

    @property
    def path(self) -> Path | None:
        return self._path

    def refresh(self) -> None:
        """Load a newer atomically-published prefix without accepting rollback."""
        if self._path is None:
            return
        with self._thread_lock:
            latest = Registry.read(self._path, max_retries=self._max_retries)
            self._require_extension(latest)
            self._entries = list(latest.entries)

    def _require_extension(self, latest: Registry) -> None:
        """Require ``latest`` to contain this instance's exact observed prefix."""
        if latest.clerk_key != self.clerk_key:
            raise ProtocolError("registry clerk identity changed")
        if latest.count < self.count:
            raise ProtocolError("registry was truncated after observation")
        if latest.entries[self.count - 1]["entry_hash"] != self.head:
            raise ProtocolError("registry head conflicts at the observed length")

    @contextmanager
    def _write_lock(self):
        if self._path is None:
            raise ProtocolError("registry has no durable path")
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self._path.with_name(f".{self._path.name}.lock")
        with self._thread_lock, lock_path.open("a+") as handle:
            os.chmod(lock_path, 0o600)
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _replay(self) -> dict[str, _Record]:
        records: dict[str, _Record] = {}
        commitments: dict[str, str] = {}
        for entry in self._entries[1:]:
            event = entry["event"]
            kind = event["kind"]
            payload = event["payload"]
            if kind == "proposal_recorded":
                case_id, public, commitment = _problem_summary(payload)
                if case_id in records:
                    raise ProtocolError("duplicate case proposal")
                if commitment in commitments:
                    raise ProtocolError("task commitment is already registered")
                if len(records) >= MAX_CASES:
                    raise ProtocolError("registry case limit exceeded")
                records[case_id] = _Record(public, updated_at=entry["received_at"])
                commitments[commitment] = case_id
                continue
            if not isinstance(payload, dict) or set(payload) not in (
                {"case_id"},
                {"case_id", "error"},
                {"case_id", "retry"},
                {
                    "case_id",
                    "repo_url",
                    "clerk_key",
                    "marker_digest",
                    "repository_commit",
                    "repository_id",
                    "repository_node_id",
                },
                {
                    "case_id",
                    "clerk_url",
                    "head_event_hash",
                    "event_count",
                },
            ):
                raise ProtocolError("registry transition has invalid fields")
            case_id = _case_id(payload.get("case_id"))
            record = records.get(case_id)
            if record is None:
                raise ProtocolError("registry transition refers to an unknown case")
            if kind == "admitted" and record.status == "PROPOSED" and set(payload) == {"case_id"}:
                record.status = "ADMITTED"
                record.updated_at = entry["received_at"]
            elif (
                kind == "provisioning_started"
                and record.status == "ADMITTED"
                and set(payload) == {"case_id"}
            ):
                record.status = "PROVISIONING"
                record.updated_at = entry["received_at"]
            elif (
                kind == "repository_provisioned"
                and record.status == "PROVISIONING"
                and set(payload)
                == {
                    "case_id",
                    "repo_url",
                    "clerk_key",
                    "marker_digest",
                    "repository_commit",
                    "repository_id",
                    "repository_node_id",
                }
            ):
                if record.repo_url is not None:
                    raise ProtocolError("case repository is already provisioned")
                record.repo_url = _public_url(payload["repo_url"], "repo_url")
                load_public_key(payload["clerk_key"])
                record.clerk_key = payload["clerk_key"]
                marker = payload["marker_digest"]
                if not isinstance(marker, str) or re.fullmatch(r"[0-9a-f]{64}", marker) is None:
                    raise ProtocolError("repository marker digest is invalid")
                commit = payload["repository_commit"]
                if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
                    raise ProtocolError("repository commit is invalid")
                record.marker_digest = marker
                record.repository_commit = commit
                record.repository_id, record.repository_node_id = _repository_identity(
                    payload["repository_id"], payload["repository_node_id"]
                )
                record.updated_at = entry["received_at"]
            elif (
                kind == "live"
                and record.status == "PROVISIONING"
                and record.repo_url is not None
                and record.clerk_key is not None
                and set(payload)
                == {
                    "case_id",
                    "clerk_url",
                    "head_event_hash",
                    "event_count",
                }
            ):
                record.clerk_url = _public_url(payload["clerk_url"], "clerk_url")
                record.head_event_hash, record.event_count = _case_evidence(
                    payload["head_event_hash"], payload["event_count"]
                )
                record.status = "LIVE"
                record.updated_at = entry["received_at"]
            elif (
                kind == "provision_failed"
                and record.status == "PROVISIONING"
                and set(payload)
                == {
                    "case_id",
                    "error",
                }
            ):
                _text(payload["error"], "provision failure", MAX_ERROR_LENGTH)
                record.status = "PROVISION_FAILED"
                record.updated_at = entry["received_at"]
            elif (
                kind == "provisioning_retried"
                and record.status == "PROVISION_FAILED"
                and set(payload) == {"case_id", "retry"}
                and isinstance(payload["retry"], int)
                and not isinstance(payload["retry"], bool)
                and payload["retry"] == record.retries + 1
                and payload["retry"] <= self._max_retries
            ):
                record.retries += 1
                record.status = "PROVISIONING"
                record.updated_at = entry["received_at"]
            else:
                raise ProtocolError("invalid registry state transition")
        return records

    def verify(self) -> None:
        if not self._entries:
            raise ProtocolError("registry is empty")
        clerk_key: str | None = None
        previous_hash: str | None = None
        previous_time = None
        for expected_seq, entry in enumerate(self._entries):
            _exact(entry, ENTRY_FIELDS, f"registry entry {expected_seq}")
            if entry["schema"] != REGISTRY_SCHEMA or entry["seq"] != expected_seq:
                raise ProtocolError(f"registry sequence mismatch at {expected_seq}")
            received = parse_time(entry["received_at"], f"registry[{expected_seq}].received_at")
            if previous_time is not None and received < previous_time:
                raise ProtocolError(f"registry receipt time moved backwards at {expected_seq}")
            if entry["prev_hash"] != previous_hash:
                raise ProtocolError(f"registry previous hash mismatch at {expected_seq}")
            _exact(entry["event"], EVENT_FIELDS, f"registry event {expected_seq}")
            if expected_seq == 0:
                if entry["event"]["kind"] != "registry_opened":
                    raise ProtocolError("first registry event must open the registry")
                payload = _exact(entry["event"]["payload"], {"clerk_key"}, "registry genesis")
                clerk_key = payload["clerk_key"]
            elif not isinstance(entry["event"]["kind"], str) or not entry["event"]["kind"]:
                raise ProtocolError("registry event kind must be non-empty text")
            body = _entry_body(
                entry["seq"], entry["received_at"], entry["prev_hash"], entry["event"]
            )
            expected_hash = digest_object(body)
            if entry["entry_hash"] != expected_hash:
                raise ProtocolError(f"registry entry hash mismatch at {expected_seq}")
            if clerk_key is None:
                raise ProtocolError("registry clerk key is missing")
            verify_object(
                clerk_key,
                _receipt_body(expected_seq, entry["prev_hash"], expected_hash),
                entry["clerk_signature"],
            )
            previous_hash = expected_hash
            previous_time = received
        self._replay()

    def _append(self, kind: str, payload: dict[str, Any], received_at: str | None = None) -> None:
        if self._clerk_private_key is None or self._path is None:
            raise ProtocolError("registry is read-only")
        with self._write_lock():
            latest = Registry.read(self._path, max_retries=self._max_retries)
            if latest.clerk_key != public_key_text(self._clerk_private_key):
                raise ProtocolError("wrong registry clerk key")
            self._require_extension(latest)
            self._entries = list(latest.entries)
            timestamp = received_at or _now()
            observed = parse_time(timestamp, "registry.received_at")
            previous_time = parse_time(
                self._entries[-1]["received_at"], "previous registry.received_at"
            )
            if observed < previous_time:
                raise ProtocolError("registry receipt times must be monotonic")
            event = {"kind": kind, "payload": payload}
            body = _entry_body(self.count, timestamp, self.head, event)
            entry_hash = digest_object(body)
            entry = {
                **body,
                "entry_hash": entry_hash,
                "clerk_signature": sign_object(
                    self._clerk_private_key,
                    _receipt_body(self.count, self.head, entry_hash),
                ),
            }
            self._entries.append(entry)
            try:
                self.verify()
                self._persist()
            except BaseException:
                self._entries.pop()
                raise

    def record_proposal(
        self, proposal: dict[str, Any], received_at: str | None = None
    ) -> dict[str, Any]:
        _problem_summary(proposal)
        self._append("proposal_recorded", proposal, received_at)
        return self.problem(proposal["case_id"])

    def admit(self, case_id: str, received_at: str | None = None) -> dict[str, Any]:
        self._append("admitted", {"case_id": _case_id(case_id)}, received_at)
        return self.problem(case_id)

    def start_provisioning(self, case_id: str, received_at: str | None = None) -> dict[str, Any]:
        self._append("provisioning_started", {"case_id": _case_id(case_id)}, received_at)
        return self.problem(case_id)

    def mark_live(
        self,
        case_id: str,
        clerk_url: str,
        head_event_hash: str | None,
        event_count: int,
        received_at: str | None = None,
    ) -> dict[str, Any]:
        head_event_hash, event_count = _case_evidence(head_event_hash, event_count)
        self._append(
            "live",
            {
                "case_id": _case_id(case_id),
                "clerk_url": _public_url(clerk_url, "clerk_url"),
                "head_event_hash": head_event_hash,
                "event_count": event_count,
            },
            received_at,
        )
        return self.problem(case_id)

    def record_repository(
        self,
        case_id: str,
        repo_url: str,
        clerk_key: str,
        marker_digest: str,
        repository_commit: str,
        repository_id: int | str,
        repository_node_id: str | None,
        received_at: str | None = None,
    ) -> dict[str, Any]:
        load_public_key(clerk_key)
        repository_id, repository_node_id = _repository_identity(repository_id, repository_node_id)
        self._append(
            "repository_provisioned",
            {
                "case_id": _case_id(case_id),
                "repo_url": _public_url(repo_url, "repo_url"),
                "clerk_key": clerk_key,
                "marker_digest": marker_digest,
                "repository_commit": repository_commit,
                "repository_id": repository_id,
                "repository_node_id": repository_node_id,
            },
            received_at,
        )
        return self.problem(case_id)

    def mark_provision_failed(
        self, case_id: str, error: str, received_at: str | None = None
    ) -> dict[str, Any]:
        self._append(
            "provision_failed",
            {
                "case_id": _case_id(case_id),
                "error": _text(error, "provision failure", MAX_ERROR_LENGTH),
            },
            received_at,
        )
        return self.problem(case_id)

    def retry_provisioning(self, case_id: str, received_at: str | None = None) -> dict[str, Any]:
        case_id = _case_id(case_id)
        record = self._replay().get(case_id)
        if record is None:
            raise ProtocolError("registry transition refers to an unknown case")
        self._append(
            "provisioning_retried", {"case_id": case_id, "retry": record.retries + 1}, received_at
        )
        return self.problem(case_id)

    def _public(self, case_id: str, record: _Record) -> dict[str, Any]:
        return {
            **record.public,
            "repo_url": record.repo_url,
            "clerk_url": record.clerk_url,
            "clerk_key": record.clerk_key,
            "marker_digest": record.marker_digest,
            "repository_commit": record.repository_commit,
            "repository_id": record.repository_id,
            "repository_node_id": record.repository_node_id,
            "status": record.status,
            "head_event_hash": record.head_event_hash,
            "event_count": record.event_count,
            "updated_at": record.updated_at,
        }

    def problems(self, *, live_only: bool = False) -> list[dict[str, Any]]:
        records = self._replay()
        return [
            self._public(case_id, record)
            for case_id, record in sorted(records.items())
            if not live_only or record.status == "LIVE"
        ]

    def problem(self, case_id: str) -> dict[str, Any]:
        record = self._replay().get(_case_id(case_id))
        if record is None:
            raise ProtocolError("registry case does not exist")
        return self._public(case_id, record)

    def problem_by_commitment(self, commitment: str) -> dict[str, Any] | None:
        if not isinstance(commitment, str) or SHA256_RE.fullmatch(commitment) is None:
            raise ProtocolError("task commitment must be a lowercase SHA-256 value")
        return next(
            (
                self._public(case_id, record)
                for case_id, record in self._replay().items()
                if record.public["task_commitment"] == commitment
            ),
            None,
        )

    def signed_snapshot(
        self,
        records: list[dict[str, Any]] | None = None,
        generated_at: str | None = None,
        *,
        expected_head: str | None = None,
    ) -> dict[str, Any]:
        if self._clerk_private_key is None:
            raise ProtocolError("signed snapshots require the local clerk key")
        timestamp = generated_at or _now()
        parse_time(timestamp, "snapshot.generated_at")
        with self._thread_lock:
            if expected_head is not None and self.head != expected_head:
                raise ProtocolError("registry changed while snapshot was being prepared")
            body = {
                "schema": SNAPSHOT_SCHEMA,
                "generated_at": timestamp,
                "clerk": self.clerk_key,
                "head": self.head,
                "count": self.count,
                "problems": self.problems() if records is None else records,
            }
            return {
                **body,
                "signature": sign_object(
                    self._clerk_private_key,
                    {"domain": "boule-problem-registry-snapshot/0.6", **body},
                ),
            }

    def chain_proof(self, from_count: int, to_count: int) -> dict[str, Any]:
        if self._clerk_private_key is None:
            raise ProtocolError("registry chain proofs require the local clerk key")
        if (
            isinstance(from_count, bool)
            or not isinstance(from_count, int)
            or isinstance(to_count, bool)
            or not isinstance(to_count, int)
            or not 1 <= from_count <= to_count <= self.count
            or to_count > MAX_REGISTRY_ENTRIES
            or to_count - from_count > MAX_CHAIN_PROOF_ENTRIES
        ):
            raise ProtocolError("registry chain proof range is invalid")
        with self._thread_lock:
            from_head = self._entries[from_count - 1]["entry_hash"]
            entries = self._entries[from_count:to_count]
            to_head = entries[-1]["entry_hash"] if entries else from_head
            links = [
                {
                    "seq": entry["seq"],
                    "prev_hash": entry["prev_hash"],
                    "entry_hash": entry["entry_hash"],
                    "clerk_signature": entry["clerk_signature"],
                }
                for entry in entries
            ]
            body = {
                "schema": CHAIN_PROOF_SCHEMA,
                "clerk": self.clerk_key,
                "from_count": from_count,
                "from_head": from_head,
                "to_count": to_count,
                "to_head": to_head,
                "links": links,
            }
            return {
                **body,
                "signature": sign_object(self._clerk_private_key, _chain_proof_unsigned(body)),
            }

    def signed_error(
        self, code: str, message: str, generated_at: str | None = None
    ) -> dict[str, Any]:
        code = _text(code, "error code", 80)
        message = _text(message, "error message", 240)
        snapshot = self.signed_snapshot([], generated_at)
        return {**snapshot, "error": {"code": code, "message": message}}

    def _persist(self) -> None:
        if self._path is None:
            raise ProtocolError("registry has no durable path")
        destination = self._path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        body = b"".join(canonical_bytes(entry) + b"\n" for entry in self._entries)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
