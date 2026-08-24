"""Read-only registry API, verified live projection, and static observatory."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .canonical import canonical_bytes
from .case_anchor_store import CaseAnchorStore
from .errors import ProtocolError
from .model import CASE_ID_RE, parse_time
from .registry import MAX_CHAIN_PROOF_ENTRIES, Registry
from .remote_protocol import (
    MAX_CHAIN_PROOF_LINKS,
    strict_json_bytes,
    verify_chain_proof,
    verify_snapshot,
)

MAX_PATH_BYTES = 2_048
MAX_CASE_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_WATCHER_STATUS_BYTES = 64 * 1024
MAX_SNAPSHOT_AGE = timedelta(minutes=5)
MAX_SNAPSHOT_FUTURE_SKEW = timedelta(minutes=1)
DEFAULT_WATCHER_STALE_SECONDS = 120
MAX_WATCH_INTERVAL_SECONDS = 300
WEB_ROOT = Path(__file__).with_name("web")
STATIC_FILES = {
    (): ("index.html", "text/html; charset=utf-8"),
    ("index.html",): ("index.html", "text/html; charset=utf-8"),
    ("styles.css",): ("styles.css", "text/css; charset=utf-8"),
    ("app.js",): ("app.js", "text/javascript; charset=utf-8"),
    ("favicon.svg",): ("favicon.svg", "image/svg+xml"),
    ("docs.html",): ("docs.html", "text/html; charset=utf-8"),
    ("llms.txt",): ("llms.txt", "text/plain; charset=utf-8"),
}

CaseFetcher = Callable[[dict[str, Any]], dict[str, Any]]
CaseCheckpoint = Callable[[int, str | None], None]


def maintainer_runtime_status(
    path: Path | None, *, observed_at: datetime | None = None
) -> dict[str, Any]:
    """Project one local watcher heartbeat without treating it as signed protocol state."""
    now = observed_at or datetime.now(UTC)
    base: dict[str, Any] = {
        "schema": "boule-maintainer-runtime/0.1",
        "status": "unknown",
        "basis": "unsigned_local_watcher_heartbeat",
        "observed_at": now.isoformat().replace("+00:00", "Z"),
        "last_tick_at": None,
        "heartbeat_age_seconds": None,
        "fresh_for_seconds": None,
        "cycle": None,
        "automatic_admission": None,
        "automatic_provisioning": None,
        "error_case_count": None,
    }
    if path is None:
        return base
    try:
        raw = path.read_bytes()
    except OSError:
        return base
    if len(raw) > MAX_WATCHER_STATUS_BYTES:
        return base
    try:
        value = strict_json_bytes(raw)
        if not isinstance(value, dict):
            return base
        last_tick_at = value.get("last_tick_at")
        heartbeat = parse_time(last_tick_at, "maintainer watcher heartbeat")
    except ProtocolError:
        return base
    interval = value.get("interval_seconds")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or not 0 <= interval <= MAX_WATCH_INTERVAL_SECONDS
    ):
        interval = None
    fresh_for = (
        max(15, min(900, int(interval * 3)))
        if interval is not None
        else DEFAULT_WATCHER_STALE_SECONDS
    )
    age = (now - heartbeat).total_seconds()
    if age < -MAX_SNAPSHOT_FUTURE_SKEW.total_seconds():
        return base
    errors = value.get("error_cases")
    error_count = len(errors) if isinstance(errors, list) else None
    cycle = value.get("cycle")
    if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 1:
        cycle = None
    automatic_admission = value.get("automatic_admission")
    if not isinstance(automatic_admission, bool):
        automatic_admission = None
    automatic_provisioning = value.get("automatic_provisioning")
    if not isinstance(automatic_provisioning, bool):
        automatic_provisioning = None
    return {
        **base,
        "status": "running" if age <= fresh_for else "stale",
        "last_tick_at": last_tick_at,
        "heartbeat_age_seconds": max(0, int(age)),
        "fresh_for_seconds": fresh_for,
        "cycle": cycle,
        "automatic_admission": automatic_admission,
        "automatic_provisioning": automatic_provisioning,
        "error_case_count": error_count,
    }


def _fetch_json(endpoint: str, timeout: float, maximum: int) -> Any:
    request = Request(endpoint, headers={"Accept": "application/json", "User-Agent": "Boule/0.6"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(maximum + 1)
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            final_url = response.geturl()
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ProtocolError("case clerk is unavailable") from exc
    if (
        status != 200
        or final_url != endpoint
        or len(body) > maximum
        or content_type.split(";", 1)[0].strip().lower() != "application/json"
    ):
        raise ProtocolError("case clerk returned an invalid response")
    return strict_json_bytes(body)


def fetch_case_state(
    record: dict[str, Any],
    timeout: float = 4.0,
    *,
    checkpoint: CaseCheckpoint | None = None,
) -> dict[str, Any]:
    """Fetch one case snapshot and prove extension from the registry-pinned head."""
    clerk_url = record.get("clerk_url")
    if not isinstance(clerk_url, str):
        raise ProtocolError("live case has no clerk URL")
    parsed = urlsplit(clerk_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolError("case clerk URL is not a safe HTTPS origin")
    if timeout <= 0:
        raise ProtocolError("case clerk timeout must be positive")
    deadline = time.monotonic() + timeout

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise ProtocolError("case clerk verification timed out")
        return value

    origin = clerk_url.rstrip("/")
    value = _fetch_json(origin + "/v1/state", remaining(), MAX_CASE_RESPONSE_BYTES)
    if not isinstance(value, dict) or set(value) != {"state", "snapshot"}:
        raise ProtocolError("case clerk response shape is invalid")
    snapshot = verify_snapshot(
        value["snapshot"],
        value["state"],
        problem_id=record["problem_id"],
        clerk_key=record["clerk_key"],
    )
    recorded_count = record.get("event_count")
    recorded_head = record.get("head_event_hash")
    if (
        isinstance(recorded_count, bool)
        or not isinstance(recorded_count, int)
        or recorded_count < 0
    ):
        raise ProtocolError("registry case event anchor is invalid")
    observed_at = datetime.now(UTC)
    snapshot_at = parse_time(snapshot["at"], "case snapshot time")
    if snapshot_at < observed_at - MAX_SNAPSHOT_AGE:
        raise ProtocolError("case clerk snapshot is too old")
    if snapshot_at > observed_at + MAX_SNAPSHOT_FUTURE_SKEW:
        raise ProtocolError("case clerk snapshot time is too far in the future")
    if snapshot["event_count"] < recorded_count:
        raise ProtocolError("case clerk snapshot predates registry admission")
    if snapshot["event_count"] == recorded_count and snapshot["head_event_hash"] != recorded_head:
        raise ProtocolError("case clerk snapshot conflicts with registry admission")
    current_count = recorded_count
    current_head = recorded_head
    while current_count < snapshot["event_count"]:
        to_count = min(current_count + MAX_CHAIN_PROOF_LINKS, snapshot["event_count"])
        proof = _fetch_json(
            f"{origin}/v1/chain/{current_count}/{to_count}",
            remaining(),
            MAX_CASE_RESPONSE_BYTES,
        )
        verified = verify_chain_proof(
            proof,
            problem_id=record["problem_id"],
            clerk_key=record["clerk_key"],
            from_count=current_count,
            from_head=current_head,
            to_count=to_count,
        )
        current_count = to_count
        current_head = verified["to_head"]
        if checkpoint is not None:
            checkpoint(current_count, current_head)
    if current_head != snapshot["head_event_hash"]:
        raise ProtocolError("case chain proof does not reach the signed snapshot")
    return value


def _activity(state: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    specs = (
        ("checkpoints", "checkpoint", "summary"),
        ("messages", "chat", "body"),
        ("handoffs", "handoff", "summary"),
        ("feedback", "feedback", "summary"),
        ("resolutions", "resolution", "note"),
    )
    for collection, kind, summary_field in specs:
        values = state.get(collection)
        if not isinstance(values, list):
            continue
        for item in values[-40:]:
            if not isinstance(item, dict):
                continue
            entry_kind = kind
            if kind == "feedback":
                stage = item.get("stage")
                entry_kind = (
                    f"{stage}_feedback" if stage in {"verifier", "review", "reward"} else kind
                )
            entry = {
                "kind": entry_kind,
                "id": item.get("handoff_id") or item.get("event_id"),
                "summary": item.get(summary_field) or item.get("topic") or entry_kind,
                "participant": item.get("participant_id"),
                "session_id": item.get("session_id"),
                "received_at": item.get("received_at"),
            }
            if entry_kind == "handoff":
                entry["handoff_id"] = item.get("handoff_id")
                entry["depends_on"] = item.get("depends_on", [])
                entry["outcome"] = item.get("outcome")
            result.append({key: value for key, value in entry.items() if value is not None})

    def sort_key(item: dict[str, Any]) -> tuple[float, int]:
        try:
            timestamp = parse_time(item.get("received_at"), "activity time").timestamp()
        except ProtocolError:
            timestamp = float("-inf")
        identifier = item.get("id")
        sequence = (
            int(identifier[:8]) if isinstance(identifier, str) and identifier[:8].isdigit() else -1
        )
        return timestamp, sequence

    result.sort(key=sort_key, reverse=True)
    return result[:40]


def project_case(record: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    state = bundle["state"]
    snapshot = bundle["snapshot"]
    sessions = state.get("sessions", [])
    claims = state.get("claims", [])
    active_session_ids = {
        item.get("session_id")
        for item in claims
        if isinstance(item, dict) and item.get("status") in {"active", "stale"}
    }
    active_agents = [
        {
            key: item[key]
            for key in ("participant_id", "session_id", "label", "status")
            if key in item
        }
        for item in sessions
        if (
            isinstance(item, dict)
            and item.get("status") == "active"
            and item.get("session_id") in active_session_ids
        )
    ]
    active_claims = [
        {
            key: item[key]
            for key in ("claim_id", "session_id", "route", "status", "deadline", "parallel")
            if key in item
        }
        for item in claims
        if isinstance(item, dict) and item.get("status") in {"active", "stale"}
    ]
    external_trust = state.get("external_status_trust")
    if (
        not isinstance(external_trust, dict)
        or set(external_trust) != {"mode", "authenticated_external_attestation"}
        or not isinstance(external_trust["mode"], str)
        or not isinstance(external_trust["authenticated_external_attestation"], bool)
    ):
        external_trust = {
            "mode": "unknown",
            "authenticated_external_attestation": False,
        }
    return {
        **record,
        "registry_status": record["status"],
        "status": state.get("problem_status", record["status"]),
        "active_agents": active_agents,
        "active_claims": active_claims,
        "recent_activity": _activity(state),
        "external_status_trust": external_trust,
        "status_source": "case_clerk_projection",
        "updated_at": snapshot["at"],
        "head_event_hash": snapshot["head_event_hash"],
        "event_count": snapshot["event_count"],
        "live_stale": False,
    }


class LiveProjector:
    """Short cache with bounded, parallel case-clerk fanout."""

    def __init__(
        self,
        fetcher: CaseFetcher | None = None,
        *,
        ttl_seconds: float = 15.0,
        clock: Callable[[], float] = time.monotonic,
        max_live_cases: int = 64,
        max_workers: int = 8,
        refresh_timeout: float = 5.0,
        anchor_store: CaseAnchorStore | None = None,
    ) -> None:
        if ttl_seconds < 0 or max_live_cases < 1 or max_workers < 1 or refresh_timeout <= 0:
            raise ProtocolError("live projection bounds are invalid")
        self.fetcher = fetcher or fetch_case_state
        self._fetcher_supports_checkpoints = fetcher is None or fetcher is fetch_case_state
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.max_live_cases = max_live_cases
        self.max_workers = max_workers
        self.refresh_timeout = refresh_timeout
        self._lock = threading.Lock()
        self._cached_head: str | None = None
        self._cached_until = 0.0
        self._cached: list[dict[str, Any]] = []
        self._refreshing = False
        self._anchors: dict[str, tuple[str, str, int, str | None]] = {}
        self._closed = False
        self._anchor_store = anchor_store
        self._fetch_slots = threading.BoundedSemaphore(self.max_workers)
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="boule-live",
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def _stale(record: dict[str, Any], message: str) -> dict[str, Any]:
        return {
            **record,
            "active_agents": [],
            "active_claims": [],
            "recent_activity": [],
            "external_status_trust": {
                "mode": "unknown",
                "authenticated_external_attestation": False,
            },
            "status_source": "registry_only",
            "live_stale": True,
            "live_error": message,
        }

    def problems(self, registry: Registry) -> list[dict[str, Any]]:
        now = self.clock()
        with self._lock:
            if self._closed:
                raise ProtocolError("live projector is closed")
            if self._cached_head == registry.head and now < self._cached_until:
                return list(self._cached)
            if self._refreshing:
                if self._cached:
                    return [{**item, "projection_cache_stale": True} for item in self._cached]
                return [
                    self._stale(record, "live projection refresh is already in progress")
                    for record in registry.problems(live_only=True)
                ]
            self._refreshing = True
        try:
            return self._refresh(registry)
        finally:
            with self._lock:
                self._refreshing = False

    def _refresh(self, registry: Registry) -> list[dict[str, Any]]:
        requested_head = registry.head
        records = registry.problems(live_only=True)
        selected = records[: self.max_live_cases]
        projected: list[dict[str, Any] | None] = [None] * len(selected)
        fetch_records: list[dict[str, Any]] = []
        with self._lock:
            anchors = dict(self._anchors)
        for record in selected:
            fetch_record = dict(record)
            anchor = anchors.get(record["case_id"])
            if self._anchor_store is not None:
                persisted_count, persisted_head = self._anchor_store.anchor_for(record)
                persisted = (
                    record["task_commitment"],
                    record["clerk_key"],
                    persisted_count,
                    persisted_head,
                )
                if (
                    anchor is not None
                    and persisted_count == anchor[2]
                    and persisted_head != anchor[3]
                ):
                    raise ProtocolError("persisted case anchor conflicts with the live high-water")
                if anchor is None or persisted_count > anchor[2]:
                    anchor = persisted
            if anchor is not None:
                commitment, clerk_key, count, head = anchor
                recorded_count = record["event_count"]
                recorded_head = record["head_event_hash"]
                same_identity = (
                    commitment == record["task_commitment"] and clerk_key == record["clerk_key"]
                )
                compatible = count > recorded_count or (
                    count == recorded_count and head == recorded_head
                )
                if same_identity and compatible:
                    fetch_record["event_count"] = count
                    fetch_record["head_event_hash"] = head
            fetch_records.append(fetch_record)

        futures: dict[Future[dict[str, Any]], int] = {}
        next_index = 0
        deadline = time.monotonic() + self.refresh_timeout
        capacity_blocked = False

        def fill_available_slots() -> None:
            nonlocal capacity_blocked, next_index
            capacity_blocked = False
            while next_index < len(fetch_records) and len(futures) < self.max_workers:
                if not self._fetch_slots.acquire(blocking=False):
                    capacity_blocked = True
                    return
                index = next_index
                next_index += 1
                try:
                    future = self._executor.submit(
                        self._fetch_case,
                        fetch_records[index],
                        selected[index],
                    )
                except BaseException:
                    self._fetch_slots.release()
                    raise
                future.add_done_callback(self._release_cancelled_fetch_slot)
                futures[future] = index

        fill_available_slots()
        while futures:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, _pending = wait(
                futures,
                timeout=remaining,
                return_when=FIRST_COMPLETED,
            )
            if not done:
                break
            for future in done:
                index = futures.pop(future)
                try:
                    bundle = future.result()
                    projected[index] = project_case(selected[index], bundle)
                    snapshot = bundle["snapshot"]
                    self._checkpoint(
                        selected[index], snapshot["event_count"], snapshot["head_event_hash"]
                    )
                except Exception:
                    projected[index] = self._stale(
                        selected[index], "case clerk unavailable or unverifiable"
                    )
            time.sleep(0)
            fill_available_slots()

        for future, index in futures.items():
            future.cancel()
            projected[index] = self._stale(selected[index], "case clerk projection timed out")
        unsubmitted_error = (
            "case clerk projection capacity is exhausted"
            if capacity_blocked
            else "case clerk projection refresh deadline reached"
        )
        for index in range(next_index, len(fetch_records)):
            projected[index] = self._stale(selected[index], unsubmitted_error)
        result = [item for item in projected if item is not None]
        result.extend(
            self._stale(record, "live projection case limit reached")
            for record in records[self.max_live_cases :]
        )
        with self._lock:
            self._cached_head = requested_head
            self._cached_until = self.clock() + self.ttl_seconds
            self._cached = result
            return list(result)

    def _release_cancelled_fetch_slot(self, future: Future[dict[str, Any]]) -> None:
        if future.cancelled():
            self._fetch_slots.release()

    def _checkpoint(self, record: dict[str, Any], count: int, head: str | None) -> None:
        if self._anchor_store is not None:
            self._anchor_store.advance(record, count, head)
        anchor = (
            record["task_commitment"],
            record["clerk_key"],
            count,
            head,
        )
        with self._lock:
            previous = self._anchors.get(record["case_id"])
            if previous is None or count > previous[2] or anchor == previous:
                self._anchors[record["case_id"]] = anchor

    def _fetch_case(
        self, fetch_record: dict[str, Any], registry_record: dict[str, Any]
    ) -> dict[str, Any]:
        try:

            def checkpoint(count: int, head: str | None) -> None:
                self._checkpoint(registry_record, count, head)

            if self._fetcher_supports_checkpoints:
                return self.fetcher(fetch_record, checkpoint=checkpoint)  # type: ignore[call-arg]
            return self.fetcher(fetch_record)
        finally:
            self._fetch_slots.release()


class RegistryHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(
        self,
        address: tuple[str, int],
        registry: Registry,
        *,
        live_projector: LiveProjector | None = None,
        anchor_store_path: Path | None = None,
        maintainer_status_path: Path | None = None,
        web_root: Path = WEB_ROOT,
        max_workers: int = 32,
        request_timeout: float = 10.0,
    ) -> None:
        if max_workers < 1 or request_timeout <= 0:
            raise ProtocolError("registry worker and timeout limits must be positive")
        self.registry = registry
        if live_projector is None:
            if anchor_store_path is None and registry.path is not None:
                anchor_store_path = registry.path.parent / ".boule" / "case-anchors.json"
            anchor_store = (
                CaseAnchorStore(anchor_store_path) if anchor_store_path is not None else None
            )
            live_projector = LiveProjector(anchor_store=anchor_store)
        self.live_projector = live_projector
        if maintainer_status_path is None and registry.path is not None:
            maintainer_status_path = registry.path.parent / ".boule" / "watcher.json"
        self.maintainer_status_path = maintainer_status_path
        self.web_root = web_root
        self.request_timeout = request_timeout
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(address, RegistryRequestHandler)

    def get_request(self):  # noqa: ANN201
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, client_address

    def process_request(self, request, client_address):  # noqa: ANN001, ANN201
        if not self._worker_slots.acquire(blocking=False):
            body = (
                canonical_bytes({"error": {"code": "registry_busy", "message": "registry is busy"}})
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

    def server_close(self) -> None:
        self.live_projector.close()
        super().server_close()


class RegistryRequestHandler(BaseHTTPRequestHandler):
    server: RegistryHTTPServer
    server_version = "BouleRegistry/0.6"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        super().log_message(format, *args)

    def _headers(self, content_type: str, length: int, *, static: bool = False) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-cache" if static else "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if static:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; "
                "style-src 'self' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
        else:
            self.send_header("Content-Security-Policy", "default-src 'none'")

    def _send_json(self, status: int, value: dict[str, Any]) -> None:
        body = canonical_bytes(value) + b"\n"
        self.send_response(status)
        self._headers("application/json; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, name: str, content_type: str) -> None:
        try:
            body = (self.server.web_root / name).read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "static asset does not exist")
            return
        self.send_response(HTTPStatus.OK)
        self._headers(content_type, len(body), static=True)
        self.end_headers()
        self.wfile.write(body)

    def _consistent_snapshot(
        self, records: Callable[[], list[dict[str, Any]]], *, attempts: int = 3
    ) -> dict[str, Any]:
        for _attempt in range(attempts):
            self.server.registry.refresh()
            expected_head = self.server.registry.head
            values = records()
            self.server.registry.refresh()
            try:
                return self.server.registry.signed_snapshot(values, expected_head=expected_head)
            except ProtocolError as exc:
                if str(exc) != "registry changed while snapshot was being prepared":
                    raise
        raise ProtocolError("registry changed repeatedly while snapshot was being prepared")

    def _error(self, status: int, code: str, message: str) -> None:
        try:
            self._send_json(status, self.server.registry.signed_error(code, message))
        except Exception:
            self._send_json(
                status, {"error": {"code": "clerk_unavailable", "message": "clerk unavailable"}}
            )

    def _route(self) -> tuple[str, ...] | None:
        if len(self.path.encode("utf-8", "ignore")) > MAX_PATH_BYTES:
            return None
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment or "%" in parsed.path:
            return None
        return tuple(part for part in parsed.path.split("/") if part)

    def do_GET(self) -> None:  # noqa: N802
        parts = self._route()
        if parts is None:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_path", "invalid request path")
            return
        if parts in STATIC_FILES:
            name, content_type = STATIC_FILES[parts]
            self._send_static(name, content_type)
            return
        try:
            self.server.registry.refresh()
            if parts == ("healthz",):
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "service": "boule-problem-registry",
                        "snapshot": self.server.registry.signed_snapshot([]),
                    },
                )
            elif parts == ("v1", "problems"):
                self._send_json(
                    HTTPStatus.OK,
                    self._consistent_snapshot(self.server.registry.problems),
                )
            elif parts == ("v1", "live"):
                self._send_json(
                    HTTPStatus.OK,
                    self._consistent_snapshot(
                        lambda: self.server.live_projector.problems(self.server.registry)
                    ),
                )
            elif parts == ("v1", "maintainer"):
                self._send_json(
                    HTTPStatus.OK,
                    {"maintainer": maintainer_runtime_status(self.server.maintainer_status_path)},
                )
            elif len(parts) == 4 and parts[:2] == ("v1", "chain"):
                try:
                    from_count = int(parts[2])
                    to_count = int(parts[3])
                except ValueError as exc:
                    raise ProtocolError("registry chain proof range is invalid") from exc
                if to_count - from_count > MAX_CHAIN_PROOF_ENTRIES:
                    raise ProtocolError("registry chain proof range is invalid")
                self._send_json(
                    HTTPStatus.OK,
                    self.server.registry.chain_proof(from_count, to_count),
                )
            elif len(parts) == 3 and parts[:2] == ("v1", "problems"):
                case_id = parts[2]
                if CASE_ID_RE.fullmatch(case_id) is None:
                    self._error(
                        HTTPStatus.BAD_REQUEST, "invalid_case_id", "invalid case identifier"
                    )
                    return
                self._send_json(
                    HTTPStatus.OK,
                    self._consistent_snapshot(lambda: [self.server.registry.problem(case_id)]),
                )
            else:
                self._error(HTTPStatus.NOT_FOUND, "not_found", "endpoint does not exist")
        except ProtocolError as exc:
            if str(exc) == "registry case does not exist":
                self._error(HTTPStatus.NOT_FOUND, "case_not_found", "case does not exist")
            else:
                self._error(
                    HTTPStatus.BAD_REQUEST, "invalid_registry", "registry request is invalid"
                )
        except Exception:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "clerk_unavailable", "clerk unavailable")

    def do_POST(self) -> None:  # noqa: N802
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "read_only", "registry is read-only")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


def build_server(
    registry: Registry,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    live_projector: LiveProjector | None = None,
    anchor_store_path: Path | None = None,
    maintainer_status_path: Path | None = None,
    web_root: Path = WEB_ROOT,
    max_workers: int = 32,
    request_timeout: float = 10.0,
) -> RegistryHTTPServer:
    """Build a read-only server; callers own its lifecycle and TLS proxy."""
    return RegistryHTTPServer(
        (host, port),
        registry,
        live_projector=live_projector,
        anchor_store_path=anchor_store_path,
        maintainer_status_path=maintainer_status_path,
        web_root=web_root,
        max_workers=max_workers,
        request_timeout=request_timeout,
    )
