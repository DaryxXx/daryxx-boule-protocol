"""Verified client for the signed Boule problem registry."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .errors import ProtocolError
from .registry import MAX_CHAIN_PROOF_ENTRIES, verify_registry_snapshot
from .remote_protocol import strict_json_bytes
from .trust_store import read_registry_trust, trust_registry_snapshot
from .version import USER_AGENT

MAX_REGISTRY_RESPONSE_BYTES = 4 * 1024 * 1024


def registry_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolError("registry server must be an HTTP(S) origin without credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ProtocolError("remote registry HTTP is allowed only on loopback; use HTTPS remotely")
    return value.rstrip("/")


def _get_json(origin: str, path: str, timeout: float) -> bytes:
    request = Request(
        origin + path,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_REGISTRY_RESPONSE_BYTES + 1)
            if (
                response.status != 200
                or len(raw) > MAX_REGISTRY_RESPONSE_BYTES
                or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/json"
                or response.geturl() != origin + path
            ):
                raise ProtocolError("registry returned an invalid response")
            return raw
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ProtocolError("registry request failed") from exc


def fetch_registry_index(
    server: str,
    *,
    clerk_key: str | None = None,
    trust_store: str | Path | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Fetch, verify, and pin one signed registry snapshot."""

    if timeout <= 0:
        raise ProtocolError("registry request timeout must be positive")
    origin = registry_origin(server)
    store = Path(trust_store or Path.home() / ".config" / "boule" / "trusted-registries.json")
    snapshot = verify_registry_snapshot(
        strict_json_bytes(_get_json(origin, "/v1/problems", timeout)),
        clerk_key=clerk_key,
    )
    if clerk_key is not None:
        trust = "explicit_pin"
    else:
        trust: str | None = None
        for attempt in range(2):
            anchor = read_registry_trust(store, origin)
            proofs: list[dict[str, Any]] = []
            if (
                anchor is not None
                and anchor["key"] == snapshot["clerk"]
                and anchor["count"] < snapshot["count"]
            ):
                deadline = time.monotonic() + timeout
                current = anchor["count"]
                while current < snapshot["count"]:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProtocolError("registry chain verification timed out")
                    target = min(current + MAX_CHAIN_PROOF_ENTRIES, snapshot["count"])
                    proof_raw = _get_json(origin, f"/v1/chain/{current}/{target}", remaining)
                    proof = strict_json_bytes(proof_raw)
                    if not isinstance(proof, dict):
                        raise ProtocolError("registry chain response is invalid")
                    proofs.append(proof)
                    current = target
            try:
                trust_state = trust_registry_snapshot(
                    store,
                    origin,
                    snapshot["clerk"],
                    snapshot["count"],
                    snapshot["head"],
                    proofs,
                )
                trust = f"tofu_{trust_state}"
                break
            except ProtocolError as exc:
                if attempt == 0 and "does not match the requested range" in str(exc):
                    continue
                raise
        if trust is None:
            raise ProtocolError("registry trust anchor changed concurrently")
    return {
        "registry": origin,
        "registry_key": snapshot["clerk"],
        "registry_key_pinned": True,
        "registry_key_trust": trust,
        "registry_head": snapshot["head"],
        "problems": snapshot["problems"],
    }
