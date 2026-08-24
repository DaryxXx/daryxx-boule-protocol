"""Minimal authenticated append API for one trusted-clerk Boule workspace."""

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
        path, parts = route
        try:
            if path == "/healthz":
                self._send(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "problem_id": self.server.workspace.problem["problem_id"],
                        "service": "trusted-clerk-prototype",
                    },
                )
                return
            if path == "/v1/state":
                self._send(
                    HTTPStatus.OK,
                    self.server.workspace.remote_snapshot(
                        _now(), self.server.maintainer_private_key
                    ),
                )
                return
            if len(parts) == 3 and parts[:2] == ["v1", "receipts"]:
                request_id = _request_id(parts[2])
                receipt = self.server.workspace.remote_receipt(
                    request_id, self.server.maintainer_private_key
                )
                if receipt is None:
                    self._error(
                        HTTPStatus.NOT_FOUND,
                        "receipt_not_found",
                        "no durable receipt exists for this request id",
                    )
                    return
                self._send(HTTPStatus.OK, {"receipt": receipt})
                return
            self._error(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        except ProtocolError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc))
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "trusted clerk could not complete the request",
            )

    def _read_json_body(self) -> Any:
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            raise _HTTPFailure(
                HTTPStatus.BAD_REQUEST,
                "transfer_encoding_unsupported",
                "Transfer-Encoding is not supported",
            )
        encodings = self.headers.get_all("Content-Encoding", failobj=[])
        if encodings and any(value.lower().strip() != "identity" for value in encodings):
            raise _HTTPFailure(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_encoding_unsupported",
                "compressed request bodies are not supported",
            )
        media = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media != "application/json":
            raise _HTTPFailure(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "content_type_required",
                "Content-Type must be application/json",
            )
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise _HTTPFailure(
                HTTPStatus.LENGTH_REQUIRED,
                "content_length_required",
                "one decimal Content-Length header is required",
            )
        length = int(lengths[0])
        if length <= 0:
            raise _HTTPFailure(
                HTTPStatus.BAD_REQUEST, "empty_body", "request body must not be empty"
            )
        if length > self.server.max_request_bytes:
            raise _HTTPFailure(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                f"request body exceeds {self.server.max_request_bytes} bytes",
            )
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise _HTTPFailure(
                HTTPStatus.BAD_REQUEST, "incomplete_body", "request body ended early"
            )
        try:
            return strict_json_bytes(raw)
        except ProtocolError as exc:
            raise _HTTPFailure(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc)) from exc

    def do_POST(self) -> None:  # noqa: N802
        route = self._route()
        if route is None or route[0] != "/v1/append":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
            return
        try:
            envelope = self._read_json_body()
            if isinstance(envelope, dict) and envelope.get("kind") in MAINTAINER_EVENTS:
                self._error(
                    HTTPStatus.FORBIDDEN,
                    "maintainer_event_forbidden",
                    "remote clients may append participant events only",
                )
                return
            result = self.server.workspace.append_envelope(
                envelope, self.server.maintainer_private_key
            )
            self._send(
                HTTPStatus.CREATED if result["created"] else HTTPStatus.OK,
                {
                    "created": result["created"],
                    "event": _public_event(result["event"]),
                    "receipt": result["receipt"],
                },
            )
        except _HTTPFailure as exc:
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


class _HTTPFailure(Exception):
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
    # Replay and verify the complete ledger before the listening socket exists.
    workspace.remote_snapshot(_now(), maintainer_private_key)
    return ClerkHTTPServer(
        (host, port),
        workspace,
        maintainer_private_key,
        max_request_bytes=max_request_bytes,
        max_workers=max_workers,
        request_timeout=request_timeout,
    )
