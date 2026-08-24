"""Client-side signing, outbox recovery, and receipt verification for Boule v0.5."""

from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .canonical import canonical_bytes
from .errors import ProtocolError, RemoteTransportError, RequestConflictError, StaleHeadError
from .remote_protocol import (
    EVENT_SCHEMA,
    build_envelope,
    strict_json_bytes,
    verify_receipt,
    verify_snapshot,
)
from .workspace import Workspace

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
OUTBOX_SCHEMA = "boule-remote-outbox/0.5"
COMPLETED_SCHEMA = "boule-remote-completed/0.5"


class _PrivateRecordExists(ProtocolError):
    pass


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class _RemoteHTTPError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any]) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _server_origin(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError("remote clerk URL is required")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProtocolError("remote clerk URL must be an HTTP(S) origin without credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ProtocolError("remote clerk HTTP is allowed only on loopback; use HTTPS remotely")
    return value.rstrip("/")


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _write_private_json(path: Path, value: Any, *, exclusive: bool) -> None:
    _private_directory(path.parent)
    data = canonical_bytes(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise _PrivateRecordExists(
                    f"remote private record already exists: {path.name}"
                ) from exc
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


def _read_private_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_mode & 0o077:
            raise ProtocolError(f"remote private record permissions must be 0600: {path.name}")
        value = strict_json_bytes(path.read_bytes())
    except OSError as exc:
        raise ProtocolError(f"cannot load remote private record: {path.name}") from exc
    if not isinstance(value, dict):
        raise ProtocolError(f"remote private record is not an object: {path.name}")
    return value


class RemoteClient:
    def __init__(
        self,
        workspace: Workspace,
        server: str,
        *,
        timeout: float = 15.0,
    ) -> None:
        self.workspace = workspace
        self.server = _server_origin(server)
        if timeout <= 0:
            raise ProtocolError("remote timeout must be positive")
        self.timeout = timeout
        self.private = _private_directory(workspace.control / "private")
        self.outbox = _private_directory(self.private / "remote-outbox")
        self.completed = _private_directory(self.private / "remote-receipts")
        self.state_cache = _private_directory(self.private / "remote-state")
        self._state_thread_lock = threading.RLock()
        self._opener = build_opener(_NoRedirects())

    def _http(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any]]:
        data = canonical_bytes(body) if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.server + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RemoteTransportError("remote clerk response exceeds the client limit")
                try:
                    value = strict_json_bytes(raw)
                except ProtocolError as exc:
                    raise RemoteTransportError("remote clerk response is not strict JSON") from exc
                if not isinstance(value, dict):
                    raise RemoteTransportError("remote clerk response is not a JSON object")
                return response.status, value
        except HTTPError as exc:
            raw = exc.read(64 * 1024 + 1)
            try:
                value = strict_json_bytes(raw)
                error = value["error"]
                if not isinstance(error, dict):
                    raise KeyError("error")
                code = error["code"]
                message = error["message"]
                if not isinstance(code, str) or not isinstance(message, str):
                    raise KeyError("error fields")
            except (KeyError, ProtocolError, TypeError) as parse_error:
                raise RemoteTransportError(
                    f"remote clerk returned an unreadable HTTP {exc.code} error"
                ) from parse_error
            raise _RemoteHTTPError(exc.code, code, message, error) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise RemoteTransportError("remote clerk transport failed") from exc

    def _state_cache_path(self) -> Path:
        name = hashlib.sha256(self.server.encode("utf-8")).hexdigest()[:24]
        return self.state_cache / f"{name}.json"

    @contextmanager
    def _state_cache_lock(self) -> Iterator[None]:
        """Serialize rollback high-water updates across threads and processes."""
        lock_path = self.state_cache / ".lock"
        with self._state_thread_lock:
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                os.chmod(lock_path, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def fetch_state(self) -> dict[str, Any]:
        try:
            _, value = self._http("GET", "/v1/state")
        except _RemoteHTTPError as exc:
            raise RemoteTransportError(
                f"remote clerk state request failed: HTTP {exc.status} {exc.code}"
            ) from exc
        if set(value) != {"state", "snapshot"}:
            raise RemoteTransportError("remote clerk state response has invalid fields")
        snapshot = verify_snapshot(
            value["snapshot"],
            value["state"],
            problem_id=self.workspace.problem["problem_id"],
            clerk_key=self.workspace.config["maintainer_key"],
        )
        cache_path = self._state_cache_path()
        with self._state_cache_lock():
            # Re-read only after acquiring the cross-process lock. Otherwise a
            # slower client can overwrite a newer trusted head with an older one.
            if cache_path.exists():
                previous = _read_private_json(cache_path)
                if previous.get("server") != self.server or not isinstance(
                    previous.get("snapshot"), dict
                ):
                    raise ProtocolError("remote state cache has invalid fields")
                old = previous["snapshot"]
                if (
                    isinstance(old.get("event_count"), bool)
                    or not isinstance(old.get("event_count"), int)
                    or (
                        old.get("head_event_hash") is not None
                        and not isinstance(old.get("head_event_hash"), str)
                    )
                ):
                    raise ProtocolError("remote state cache snapshot is invalid")
                if snapshot["event_count"] < old.get("event_count", -1):
                    raise RemoteTransportError("remote clerk attempted to roll back event count")
                if snapshot["event_count"] == old.get("event_count") and snapshot[
                    "head_event_hash"
                ] != old.get("head_event_hash"):
                    raise RemoteTransportError("remote clerk returned a conflicting event head")
            _write_private_json(
                cache_path,
                {"server": self.server, "snapshot": snapshot},
                exclusive=False,
            )
        return value

    def _outbox_path(self, request_id: str) -> Path:
        return self.outbox / f"{request_id}.json"

    def _completed_path(self, request_id: str) -> Path:
        return self.completed / f"{request_id}.json"

    def _persist_outbox(self, envelope: dict[str, Any]) -> Path:
        path = self._outbox_path(envelope["request_id"])
        _write_private_json(
            path,
            {"schema": OUTBOX_SCHEMA, "server": self.server, "envelope": envelope},
            exclusive=True,
        )
        return path

    def _verify_result(self, value: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
        if set(value) != {"created", "event", "receipt"} or not isinstance(value["created"], bool):
            raise RemoteTransportError("remote append response has invalid fields")
        event = value["event"]
        expected_event_fields = {
            "schema",
            "seq",
            "event_id",
            "received_at",
            "kind",
            "actor",
            "request_id",
            "prev_event_hash",
            "event_hash",
        }
        if not isinstance(event, dict) or set(event) != expected_event_fields:
            raise RemoteTransportError("remote append event summary has invalid fields")
        if event["schema"] != EVENT_SCHEMA:
            raise RemoteTransportError("remote append event schema is unsupported")
        receipt = verify_receipt(
            value["receipt"],
            problem_id=self.workspace.problem["problem_id"],
            clerk_key=self.workspace.config["maintainer_key"],
            request_id=envelope["request_id"],
            envelope=envelope,
        )
        for key in (
            "seq",
            "event_id",
            "received_at",
            "prev_event_hash",
            "event_hash",
            "request_id",
        ):
            if event[key] != receipt[key]:
                raise RemoteTransportError("remote append event summary conflicts with its receipt")
        if event["kind"] != envelope["kind"] or event["actor"] != envelope["actor"]:
            raise RemoteTransportError("remote append event summary conflicts with its envelope")
        return value

    def _translate_error(self, exc: _RemoteHTTPError) -> NoReturn:
        if exc.status == 409 and exc.code == "stale_head":
            event_count = exc.details.get("event_count")
            current_head = exc.details.get("current_head")
            if isinstance(event_count, bool) or not isinstance(event_count, int):
                raise RemoteTransportError("remote stale-head response is malformed") from exc
            raise StaleHeadError(current_head, event_count) from exc
        if exc.status == 409 and exc.code == "request_id_conflict":
            raise RequestConflictError(exc.message) from exc
        if exc.status >= 500:
            raise RemoteTransportError(
                f"remote clerk failed ambiguously: HTTP {exc.status} {exc.code}"
            ) from exc
        raise ProtocolError(f"remote clerk rejected event: {exc.code}: {exc.message}") from exc

    def _submit_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        try:
            _, value = self._http("POST", "/v1/append", envelope)
        except _RemoteHTTPError as exc:
            self._translate_error(exc)
        return self._verify_result(value, envelope)

    def _receipt(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        request_id = envelope["request_id"]
        try:
            _, value = self._http("GET", f"/v1/receipts/{quote(request_id, safe='')}")
        except _RemoteHTTPError as exc:
            if exc.status == 404 and exc.code == "receipt_not_found":
                return None
            if exc.status >= 500:
                raise RemoteTransportError(
                    f"remote receipt lookup failed: HTTP {exc.status} {exc.code}"
                ) from exc
            raise ProtocolError(
                f"remote receipt lookup was rejected: {exc.code}: {exc.message}"
            ) from exc
        if set(value) != {"receipt"}:
            raise RemoteTransportError("remote receipt response has invalid fields")
        return verify_receipt(
            value["receipt"],
            problem_id=self.workspace.problem["problem_id"],
            clerk_key=self.workspace.config["maintainer_key"],
            request_id=request_id,
            envelope=envelope,
        )

    def _finalize(
        self,
        envelope: dict[str, Any],
        receipt: dict[str, Any],
        event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_id = envelope["request_id"]
        if event is None:
            event = {
                "schema": EVENT_SCHEMA,
                "seq": receipt["seq"],
                "event_id": receipt["event_id"],
                "received_at": receipt["received_at"],
                "kind": envelope["kind"],
                "actor": envelope["actor"],
                "request_id": request_id,
                "prev_event_hash": receipt["prev_event_hash"],
                "event_hash": receipt["event_hash"],
            }
        completed = {
            "schema": COMPLETED_SCHEMA,
            "server": self.server,
            "completed_at": _utc_now(),
            "envelope": envelope,
            "event": event,
            "receipt": receipt,
        }
        destination = self._completed_path(request_id)

        def validate_existing() -> None:
            previous = _read_private_json(destination)
            for key in ("server", "envelope", "event", "receipt"):
                if previous.get(key) != completed[key]:
                    raise ProtocolError("stored remote receipt conflicts with recovered receipt")

        if destination.exists():
            validate_existing()
        else:
            try:
                _write_private_json(destination, completed, exclusive=True)
            except _PrivateRecordExists:
                # Another recovery process atomically published the same request
                # after our existence check. Its exact bytes decide convergence.
                validate_existing()
        self._outbox_path(request_id).unlink(missing_ok=True)
        return {
            "created": False,
            "event": event,
            "receipt": receipt,
            "completed_path": str(destination),
        }

    def _finalize_or_preserve(
        self,
        envelope: dict[str, Any],
        receipt: dict[str, Any],
        event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            return self._finalize(envelope, receipt, event)
        except (OSError, ProtocolError) as exc:
            request_id = envelope["request_id"]
            raise RemoteTransportError(
                "remote event is confirmed but local receipt finalization failed; preserve "
                f"and recover request {request_id} from {self._outbox_path(request_id)}"
            ) from exc

    def recover(self, request_id: str) -> dict[str, Any]:
        try:
            canonical_id = str(uuid.UUID(request_id))
        except (ValueError, AttributeError) as exc:
            raise ProtocolError("request id must be a canonical UUID") from exc
        if canonical_id != request_id:
            raise ProtocolError("request id must be a canonical UUID")
        record = _read_private_json(self._outbox_path(request_id))
        if (
            set(record) != {"schema", "server", "envelope"}
            or record["schema"] != OUTBOX_SCHEMA
            or record["server"] != self.server
            or not isinstance(record["envelope"], dict)
        ):
            raise ProtocolError("remote outbox record has invalid fields")
        envelope = record["envelope"]
        receipt = self._receipt(envelope)
        if receipt is not None:
            return self._finalize_or_preserve(envelope, receipt)
        result = self._submit_envelope(envelope)
        finalized = self._finalize_or_preserve(envelope, result["receipt"], result["event"])
        return {**finalized, "created": result["created"]}

    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        private_key: Any,
        *,
        stale_retries: int = 3,
    ) -> dict[str, Any]:
        if stale_retries < 0 or stale_retries > 8:
            raise ProtocolError("remote stale retries must be between 0 and 8")
        for attempt in range(stale_retries + 1):
            snapshot = self.fetch_state()["snapshot"]
            request_id = str(uuid.uuid4())
            envelope = build_envelope(
                request_id=request_id,
                problem_id=self.workspace.problem["problem_id"],
                clerk_key=self.workspace.config["maintainer_key"],
                base_event_hash=snapshot["head_event_hash"],
                kind=kind,
                payload=payload,
                private_key=private_key,
            )
            self._persist_outbox(envelope)
            try:
                result = self._submit_envelope(envelope)
            except StaleHeadError:
                self._outbox_path(request_id).unlink(missing_ok=True)
                if attempt == stale_retries:
                    raise
            except (URLError, TimeoutError, OSError, RemoteTransportError):
                try:
                    return self.recover(request_id)
                except StaleHeadError:
                    self._outbox_path(request_id).unlink(missing_ok=True)
                    if attempt == stale_retries:
                        raise
                except (URLError, TimeoutError, OSError, RemoteTransportError) as recovery_error:
                    raise RemoteTransportError(
                        "remote outcome is ambiguous; preserve and recover request "
                        f"{request_id} from {self._outbox_path(request_id)}"
                    ) from recovery_error
            except ProtocolError:
                self._outbox_path(request_id).unlink(missing_ok=True)
                raise
            else:
                finalized = self._finalize_or_preserve(envelope, result["receipt"], result["event"])
                return {**finalized, "created": result["created"]}
        raise AssertionError("remote append retry loop exhausted")
