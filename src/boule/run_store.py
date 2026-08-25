"""Private durable state for locally supervised provider runs."""

from __future__ import annotations

import fcntl
import os
import re
import signal
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .errors import ProtocolError
from .remote_protocol import strict_json_bytes

RUN_ID = re.compile(r"run-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}\Z")
TERMINAL_STATES = frozenset(
    {
        "completed",
        "failed",
        "protocol_incomplete",
        "timed_out",
        "stopped",
        "interrupted",
    }
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def default_run_root() -> Path:
    configured = os.environ.get("BOULE_RUN_ROOT")
    if configured:
        return Path(configured).expanduser()
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "boule" / "runs"


def default_work_root() -> Path:
    configured = os.environ.get("BOULE_RUN_WORK_ROOT")
    if configured:
        return Path(configured).expanduser()
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "boule" / "runs"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _private_json(path: Path, value: dict[str, Any], *, exclusive: bool = False) -> None:
    _private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise ProtocolError(f"run record already exists: {path.name}") from exc
        else:
            os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_mode & 0o077:
            raise ProtocolError(f"run record permissions must be 0600: {path.name}")
        value = strict_json_bytes(path.read_bytes())
    except OSError as exc:
        raise ProtocolError(f"cannot read run record: {path}") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"run record is not an object: {path}")
    return value


def process_identity(pid: int) -> dict[str, int] | None:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        tail = raw[raw.rfind(")") + 2 :].split()
        return {
            "pid": pid,
            "pgid": int(tail[2]),
            "session_id": int(tail[3]),
            "start_ticks": int(tail[19]),
        }
    except (OSError, ValueError, IndexError):
        return None


def process_matches(identity: Any) -> bool:
    if not isinstance(identity, dict):
        return False
    current = process_identity(identity.get("pid"))
    return current is not None and all(
        current.get(key) == identity.get(key) for key in ("pid", "pgid", "start_ticks")
    )


def terminate_process_group(
    identity: dict[str, Any], *, grace: float = 8.0, force: bool = False
) -> bool:
    """Terminate only a process group whose recorded PID identity still matches."""

    if not process_matches(identity):
        return False
    pgid = identity.get("pgid")
    if not isinstance(pgid, int) or pgid <= 1 or pgid == os.getpgrp():
        raise ProtocolError("refusing to signal an unverified or current process group")
    os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, grace)
    while time.monotonic() < deadline:
        if not process_matches(identity):
            return True
        time.sleep(0.1)
    if force and process_matches(identity):
        os.killpg(pgid, signal.SIGKILL)
    return True


class RunStore:
    def __init__(self, root: str | Path | None = None, *, create: bool = True) -> None:
        path = Path(root) if root else default_run_root()
        if create:
            self.root = _private_dir(path)
            return
        try:
            metadata = path.stat()
        except OSError as exc:
            raise ProtocolError("local run store is unavailable") from exc
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ProtocolError("local run store must be a private directory")
        if metadata.st_mode & 0o077:
            raise ProtocolError("local run store permissions must be 0700")
        self.root = path

    @classmethod
    def open_existing(cls, root: str | Path | None = None) -> RunStore | None:
        """Open existing local run state without creating or changing anything."""

        path = Path(root) if root else default_run_root()
        if path.is_symlink():
            raise ProtocolError("local run store must not be a symlink")
        if not path.exists():
            return None
        return cls(path, create=False)

    def directory(self, run_id: str) -> Path:
        if RUN_ID.fullmatch(run_id) is None:
            raise ProtocolError("invalid run id")
        return self.root / run_id

    @contextmanager
    def _lock(self, run_id: str) -> Iterator[None]:
        directory = _private_dir(self.directory(run_id))
        path = directory / ".lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def create(self, run_id: str, config: dict[str, Any], status: dict[str, Any]) -> Path:
        directory = self.reserve(run_id, status)
        self.set_config(run_id, config)
        return directory

    def reserve(self, run_id: str, status: dict[str, Any]) -> Path:
        directory = self.directory(run_id)
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        directory.chmod(0o700)
        _private_json(
            directory / "status.json",
            {**status, "run_id": run_id, "created_at": utc_now(), "updated_at": utc_now()},
            exclusive=True,
        )
        (directory / "events.jsonl").touch(mode=0o600, exist_ok=False)
        (directory / "events.jsonl").chmod(0o600)
        return directory

    def set_config(self, run_id: str, config: dict[str, Any]) -> Path:
        path = self.directory(run_id) / "config.json"
        _private_json(path, config, exclusive=True)
        return path

    def config(self, run_id: str) -> dict[str, Any]:
        return _read_json(self.directory(run_id) / "config.json")

    def status(self, run_id: str) -> dict[str, Any]:
        value = _read_json(self.directory(run_id) / "status.json")
        if value.get("run_id") != run_id:
            raise ProtocolError("run status identity mismatch")
        return value

    def update(self, run_id: str, **changes: Any) -> dict[str, Any]:
        with self._lock(run_id):
            current = self.status(run_id)
            requested_state = changes.get("state")
            if (
                current.get("state") in TERMINAL_STATES
                and requested_state is not None
                and requested_state != current.get("state")
            ):
                raise ProtocolError("cannot regress a terminal run state")
            value = {**current, **changes, "updated_at": utc_now()}
            _private_json(self.directory(run_id) / "status.json", value)
            return value

    def transition(
        self,
        run_id: str,
        *,
        expected: set[str] | frozenset[str],
        state: str,
        **changes: Any,
    ) -> dict[str, Any]:
        with self._lock(run_id):
            current = self.status(run_id)
            if current.get("state") not in expected:
                raise ProtocolError(
                    f"run state changed concurrently: expected {sorted(expected)}, "
                    f"found {current.get('state')}"
                )
            value = {**current, **changes, "state": state, "updated_at": utc_now()}
            _private_json(self.directory(run_id) / "status.json", value)
            return value

    def acquire_worker_lease(self, run_id: str) -> int:
        path = self.directory(run_id) / ".worker.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(path, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise ProtocolError("this run already has an active worker") from exc
        return descriptor

    @staticmethod
    def release_worker_lease(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    def append_event(self, run_id: str, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock(run_id):
            status = self.status(run_id)
            sequence = int(status.get("event_count", 0)) + 1
            value = {"sequence": sequence, "observed_at": utc_now(), **event}
            path = self.directory(run_id) / "events.jsonl"
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                os.write(descriptor, canonical_bytes(value) + b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            status = {
                **status,
                "event_count": sequence,
                "latest_event": value,
                "updated_at": utc_now(),
            }
            _private_json(self.directory(run_id) / "status.json", status)
            return value

    def events_since(self, run_id: str, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        """Read only complete JSONL records appended after a byte offset."""

        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ProtocolError("run event offset must be a non-negative integer")
        path = self.directory(run_id) / "events.jsonl"
        try:
            with path.open("rb") as handle:
                size = os.fstat(handle.fileno()).st_size
                if offset > size:
                    raise ProtocolError("run event offset exceeds the event log size")
                handle.seek(offset)
                payload = handle.read()
        except OSError as exc:
            raise ProtocolError("cannot read run events") from exc

        newline = payload.rfind(b"\n")
        if newline < 0:
            return [], offset
        complete = payload[: newline + 1]
        values = []
        for line in complete.splitlines():
            value = strict_json_bytes(line)
            if isinstance(value, dict):
                values.append(value)
        return values, offset + newline + 1

    def events(self, run_id: str, after: int = 0) -> list[dict[str, Any]]:
        values, _offset = self.events_since(run_id)
        return [value for value in values if value.get("sequence", 0) > after]

    def list(self) -> list[dict[str, Any]]:
        values = []
        for path in sorted(self.root.glob("run-*"), reverse=True):
            if not path.is_dir() or RUN_ID.fullmatch(path.name) is None:
                continue
            try:
                values.append(self.status(path.name))
            except ProtocolError:
                continue
        return values
