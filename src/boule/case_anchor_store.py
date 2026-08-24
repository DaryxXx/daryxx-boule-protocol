"""Durable high-water anchors for verified case-clerk event chains.

The registry activation event is the baseline anchor.  Callers verify remote
snapshots and chain proofs before advancing this store; this module only
protects the locally persisted monotonic boundary.
"""

from __future__ import annotations

import fcntl
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from .canonical import canonical_bytes
from .crypto import load_public_key
from .errors import ProtocolError
from .model import CASE_ID_RE
from .remote_protocol import strict_json_bytes

CASE_ANCHOR_STORE_SCHEMA = "boule-case-anchor-store/0.1"
_STORE_FIELDS = {"schema", "anchors"}
_ANCHOR_FIELDS = {
    "case_id",
    "problem_id",
    "task_commitment",
    "clerk_key",
    "count",
    "head",
}
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVENT_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVENT_COUNT = 10_000_000
_MAX_STORE_BYTES = 16 * 1024 * 1024
_MAX_CASES = 10_000


def _text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProtocolError(f"case anchor {name} must be non-empty text up to {maximum} characters")
    return value


def _case_id(value: object) -> str:
    value = _text(value, "case_id", 128)
    if CASE_ID_RE.fullmatch(value) is None:
        raise ProtocolError("case anchor case_id has an invalid format")
    return value


def _identity(record: Mapping[str, object]) -> dict[str, str]:
    try:
        case_id = _case_id(record["case_id"])
        problem_id = _text(record["problem_id"], "problem_id", 256)
        task_commitment = record["task_commitment"]
        clerk_key = record["clerk_key"]
    except KeyError as exc:
        raise ProtocolError("registry record is missing case anchor identity") from exc
    if not isinstance(task_commitment, str) or _SHA256_RE.fullmatch(task_commitment) is None:
        raise ProtocolError("case anchor task_commitment must be a lowercase SHA-256 value")
    if not isinstance(clerk_key, str):
        raise ProtocolError("case anchor clerk_key must be text")
    load_public_key(clerk_key)
    return {
        "case_id": case_id,
        "problem_id": problem_id,
        "task_commitment": task_commitment,
        "clerk_key": clerk_key,
    }


def _anchor(count: object, head: object) -> tuple[int, str | None]:
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= _MAX_EVENT_COUNT:
        raise ProtocolError("case anchor count must be an integer between 0 and 10000000")
    if count == 0 and head is None:
        return count, None
    if count == 0 or not isinstance(head, str) or _EVENT_HASH_RE.fullmatch(head) is None:
        raise ProtocolError("a non-empty case anchor needs a lowercase SHA-256 head digest")
    return count, head


def _record_anchor(record: Mapping[str, object]) -> tuple[int, str | None]:
    try:
        return _anchor(record["event_count"], record["head_event_hash"])
    except KeyError as exc:
        raise ProtocolError("registry record is missing its activation anchor") from exc


def _secure_regular(path: Path, *, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ProtocolError(f"cannot inspect {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ProtocolError(f"{label} must be a regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ProtocolError(f"{label} permissions must be 0600")


def _protect_parent(parent: Path) -> None:
    try:
        created = not parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise ProtocolError("case-anchor-store parent must be a directory")
        if created:
            parent.chmod(0o700)
        elif stat.S_IMODE(parent.stat().st_mode) != 0o700:
            raise ProtocolError("case-anchor-store parent permissions must be 0700")
    except ProtocolError:
        raise
    except OSError as exc:
        raise ProtocolError(f"cannot protect case-anchor-store parent: {parent}") from exc


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ProtocolError(f"cannot open case-anchor-store lock: {lock_path}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProtocolError("case-anchor-store lock must be a regular file")
        _secure_regular(lock_path, label="case-anchor-store lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _stored_anchor(value: object, *, case_id: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
        raise ProtocolError("case anchor has invalid fields")
    identity = _identity(value)
    if identity["case_id"] != case_id:
        raise ProtocolError("case anchor key does not match its case_id")
    count, head = _anchor(value["count"], value["head"])
    return {**identity, "count": count, "head": head}


def _read(path: Path) -> dict[str, dict[str, object]]:
    try:
        _secure_regular(path, label="case-anchor store")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ProtocolError(f"cannot open case-anchor store: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ProtocolError("case-anchor store changed while opening")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(_MAX_STORE_BYTES + 1)
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(raw) > _MAX_STORE_BYTES:
        raise ProtocolError("case-anchor store exceeds its size limit")
    try:
        value = strict_json_bytes(raw)
    except ProtocolError as exc:
        raise ProtocolError("case-anchor store is not strict JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != _STORE_FIELDS
        or value.get("schema") != CASE_ANCHOR_STORE_SCHEMA
        or not isinstance(value.get("anchors"), dict)
        or len(value["anchors"]) > _MAX_CASES
    ):
        raise ProtocolError("case-anchor store has an unsupported schema")
    anchors = {
        _case_id(case_id): _stored_anchor(anchor, case_id=case_id)
        for case_id, anchor in value["anchors"].items()
    }
    if raw != canonical_bytes({"schema": CASE_ANCHOR_STORE_SCHEMA, "anchors": anchors}):
        raise ProtocolError("case-anchor store is not canonical JSON")
    return anchors


def _write(path: Path, anchors: dict[str, dict[str, object]]) -> None:
    payload = canonical_bytes({"schema": CASE_ANCHOR_STORE_SCHEMA, "anchors": anchors})
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _compatible(stored: Mapping[str, object], identity: Mapping[str, str]) -> None:
    for field, value in identity.items():
        if stored[field] != value:
            raise ProtocolError("case anchor identity changed for an existing case")


class CaseAnchorStore:
    """A process-safe persistent high-water store for one registry service."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def anchor_for(self, record: Mapping[str, object]) -> tuple[int, str | None]:
        """Return the persisted anchor, or the registry activation anchor.

        A store entry may only extend the immutable registry identity and its
        activation anchor.  Reading never writes, so a service can recover a
        missing store without inventing persistence before it has verified a
        snapshot.
        """
        identity = _identity(record)
        activation_count, activation_head = _record_anchor(record)
        _protect_parent(self.path.parent)
        with _locked(self.path):
            stored = _read(self.path).get(identity["case_id"])
            if stored is None:
                return activation_count, activation_head
            _compatible(stored, identity)
            stored_count, stored_head = _anchor(stored["count"], stored["head"])
            if stored_count < activation_count:
                return activation_count, activation_head
            if stored_count == activation_count and stored_head != activation_head:
                raise ProtocolError("case anchor forks at the registry activation anchor")
            return stored_count, stored_head

    def advance(self, record: Mapping[str, object], count: int, head: str | None) -> None:
        """Persist a caller-verified anchor without permitting a local rollback."""
        identity = _identity(record)
        activation_count, activation_head = _record_anchor(record)
        count, head = _anchor(count, head)
        if count < activation_count:
            raise ProtocolError("case anchor predates the registry activation anchor")
        if count == activation_count and head != activation_head:
            raise ProtocolError("case anchor forks at the registry activation anchor")
        _protect_parent(self.path.parent)
        with _locked(self.path):
            anchors = _read(self.path)
            stored = anchors.get(identity["case_id"])
            if stored is not None:
                _compatible(stored, identity)
                stored_count, stored_head = _anchor(stored["count"], stored["head"])
                if count < stored_count:
                    raise ProtocolError("case anchor rolled back below the stored high-water mark")
                if count == stored_count:
                    if head != stored_head:
                        raise ProtocolError("case anchor forks at the stored high-water mark")
                    return
            anchors[identity["case_id"]] = {**identity, "count": count, "head": head}
            _write(self.path, anchors)
