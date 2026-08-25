"""Authenticated case-ledger service and its single-case HTTP adapter."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from .canonical import canonical_bytes
from .errors import (
    AuthenticationError,
    ProtocolError,
    RequestConflictError,
    StaleHeadError,
)
from .remote_protocol import strict_json_bytes
from .workspace import MAINTAINER_EVENTS, Workspace

MAX_REQUEST_BYTES = 64 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _request_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError("request id must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ProtocolError("request id must be a canonical UUID")
    return value


def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": event["schema"],
        "seq": event["seq"],
        "event_id": event["event_id"],
        "received_at": event["received_at"],
        "kind": event["kind"],
        "actor": event["actor"],
        "request_id": event["request_id"],
        "prev_event_hash": event["prev_event_hash"],
        "event_hash": event["event_hash"],
    }


class ClerkService:
    """Transport-neutral operations for one case ledger.

    A service owns one ``Workspace`` instance so its in-process lock is shared by
    every request.  The unified Boule API can host many of these services while
    retaining one independently signed ledger and key per case.
    """

    def __init__(
        self,
        workspace: Workspace,
        maintainer_private_key: Any,
        *,
        max_workers: int = 8,
    ) -> None:
        if max_workers < 1:
            raise ProtocolError("case worker limit must be positive")
        self.workspace = workspace
        self.maintainer_private_key = maintainer_private_key
        self._request_slots = threading.BoundedSemaphore(max_workers)
        # Replay the full ledger and prove that the private key matches before a
        # server advertises the case.
        workspace.remote_snapshot(_now(), maintainer_private_key)

    def acquire_request(self) -> bool:
        return self._request_slots.acquire(blocking=False)

    def release_request(self) -> None:
        self._request_slots.release()

    @property
    def problem_id(self) -> str:
        return str(self.workspace.problem["problem_id"])

    @property
    def clerk_key(self) -> str:
        return str(self.workspace.config["maintainer_key"])

    @property
    def task_commitment(self) -> str:
        task = self.workspace.problem.get("task")
        if not isinstance(task, dict) or not isinstance(task.get("task_commitment"), str):
            raise ProtocolError("case service has no task commitment")
        return str(task["task_commitment"])

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "problem_id": self.problem_id,
            "service": "trusted-clerk-prototype",
        }

    def state(self) -> dict[str, Any]:
        return self.workspace.remote_snapshot(_now(), self.maintainer_private_key)

    def chain(self, from_count: int, to_count: int) -> dict[str, Any]:
        return self.workspace.remote_chain_proof(from_count, to_count, self.maintainer_private_key)

    def receipt(self, request_id: str) -> dict[str, Any] | None:
        return self.workspace.remote_receipt(request_id, self.maintainer_private_key)

    def append(self, envelope: Any) -> dict[str, Any]:
        if isinstance(envelope, dict) and envelope.get("kind") in MAINTAINER_EVENTS:
            raise ClerkHTTPError(
                HTTPStatus.FORBIDDEN,
                "maintainer_event_forbidden",
                "remote clients may append participant events only",
            )
        result = self.workspace.append_envelope(envelope, self.maintainer_private_key)
        return {
            "created": result["created"],
            "event": _public_event(result["event"]),
            "receipt": result["receipt"],
        }


def clerk_get(service: ClerkService, parts: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """Dispatch one normalized case GET route without coupling it to a server."""
    route = tuple(parts)
    if route == ("healthz",):
        return service.health()
    if route == ("v1", "state"):
        return service.state()
    if len(route) == 4 and route[:2] == ("v1", "chain"):
        try:
            from_count = int(route[2])
            to_count = int(route[3])
        except ValueError as exc:
            raise ProtocolError("chain proof counts must be integers") from exc
        return service.chain(from_count, to_count)
    if len(route) == 3 and route[:2] == ("v1", "receipts"):
        request_id = _request_id(route[2])
        receipt = service.receipt(request_id)
        if receipt is None:
            raise ClerkHTTPError(
                HTTPStatus.NOT_FOUND,
                "receipt_not_found",
                "no durable receipt exists for this request id",
            )
        return {"receipt": receipt}
    raise ClerkHTTPError(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")


def read_json_body(
    handler: BaseHTTPRequestHandler, *, max_request_bytes: int = MAX_REQUEST_BYTES
) -> Any:
    """Read one strict, bounded JSON request body from an HTTP handler."""
    if handler.headers.get_all("Transfer-Encoding", failobj=[]):
        raise ClerkHTTPError(
            HTTPStatus.BAD_REQUEST,
            "transfer_encoding_unsupported",
            "Transfer-Encoding is not supported",
        )
    encodings = handler.headers.get_all("Content-Encoding", failobj=[])
    if encodings and any(value.lower().strip() != "identity" for value in encodings):
        raise ClerkHTTPError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "content_encoding_unsupported",
            "compressed request bodies are not supported",
        )
    media = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise ClerkHTTPError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "content_type_required",
            "Content-Type must be application/json",
        )
    lengths = handler.headers.get_all("Content-Length", failobj=[])
    if len(lengths) != 1 or not lengths[0].isdigit():
        raise ClerkHTTPError(
            HTTPStatus.LENGTH_REQUIRED,
            "content_length_required",
            "one decimal Content-Length header is required",
        )
    length = int(lengths[0])
    if length <= 0:
        raise ClerkHTTPError(HTTPStatus.BAD_REQUEST, "empty_body", "request body must not be empty")
    if length > max_request_bytes:
        raise ClerkHTTPError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "body_too_large",
            f"request body exceeds {max_request_bytes} bytes",
        )
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise ClerkHTTPError(HTTPStatus.BAD_REQUEST, "incomplete_body", "request body ended early")
    try:
        return strict_json_bytes(raw)
    except ProtocolError as exc:
        raise ClerkHTTPError(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc)) from exc


class ClerkHTTPServer(ThreadingHTTPServer):
    """One-process prototype server; durable ordering lives in ``Workspace``."""

    daemon_threads = True
    request_queue_size = 32

    def __init__(
        self,
        address: tuple[str, int],
        workspace: Workspace,
        maintainer_private_key: Any,
        *,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        max_workers: int = 16,
        request_timeout: float = 10.0,
    ) -> None:
        if max_workers < 1 or request_timeout <= 0:
            raise ProtocolError("clerk worker and timeout limits must be positive")
        self.workspace = workspace
        self.maintainer_private_key = maintainer_private_key
        self.service = ClerkService(workspace, maintainer_private_key, max_workers=max_workers)
        self.max_request_bytes = max_request_bytes
        self.request_timeout = request_timeout
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(address, ClerkRequestHandler)

    def get_request(self):  # noqa: ANN201
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, client_address

    def process_request(self, request, client_address):  # noqa: ANN001, ANN201
        if not self._worker_slots.acquire(blocking=False):
            body = (
                canonical_bytes(
                    {"error": {"code": "clerk_busy", "message": "trusted clerk is busy"}}
                )
                + b"\n"
            )
            response = (
                b"HTTP/1.0 503 Service Unavailable\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
                + body
            )
            try:
                request.sendall(response)
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):  # noqa: ANN001, ANN201
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class ClerkRequestHandler(BaseHTTPRequestHandler):
    """HTTP transport only; participant and clerk signatures carry protocol identity."""

    server: ClerkHTTPServer
    server_version = "BouleClerk/0.5"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # The default line contains only request metadata; never add bodies or signatures here.
        super().log_message(format, *args)

    def _send(self, status: int, value: dict[str, Any]) -> None:
        body = canonical_bytes(value) + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str, **details: Any) -> None:
        self._send(status, {"error": {"code": code, "message": message, **details}})

    def _route(self) -> tuple[str, list[str]] | None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            return None
        path = unquote(parsed.path)
        return path, [part for part in path.split("/") if part]

    def do_GET(self) -> None:  # noqa: N802
        route = self._route()
        if route is None:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "query strings are not supported")
            return
        _path, parts = route
        try:
            self._send(HTTPStatus.OK, clerk_get(self.server.service, parts))
        except ClerkHTTPError as exc:
            self._error(exc.status, exc.code, exc.message)
        except ProtocolError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc))
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "trusted clerk could not complete the request",
            )

    def _read_json_body(self) -> Any:
        return read_json_body(self, max_request_bytes=self.server.max_request_bytes)

    def do_POST(self) -> None:  # noqa: N802
        route = self._route()
        if route is None or route[0] != "/v1/append":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
            return
        try:
            envelope = self._read_json_body()
            result = self.server.service.append(envelope)
            self._send(
                HTTPStatus.CREATED if result["created"] else HTTPStatus.OK,
                result,
            )
        except ClerkHTTPError as exc:
            self._error(exc.status, exc.code, exc.message)
        except AuthenticationError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, "signature_invalid", str(exc))
        except StaleHeadError as exc:
            self._error(
                HTTPStatus.CONFLICT,
                "stale_head",
                str(exc),
                current_head=exc.current_head,
                event_count=exc.event_count,
            )
        except RequestConflictError as exc:
            self._error(HTTPStatus.CONFLICT, "request_id_conflict", str(exc))
        except ProtocolError as exc:
            self._error(HTTPStatus.UNPROCESSABLE_ENTITY, "event_rejected", str(exc))
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "trusted clerk could not complete the request",
            )


class ClerkHTTPError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def build_server(
    workspace: Workspace,
    maintainer_private_key: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    max_request_bytes: int = MAX_REQUEST_BYTES,
    max_workers: int = 16,
    request_timeout: float = 10.0,
) -> ClerkHTTPServer:
    return ClerkHTTPServer(
        (host, port),
        workspace,
        maintainer_private_key,
        max_request_bytes=max_request_bytes,
        max_workers=max_workers,
        request_timeout=request_timeout,
    )
