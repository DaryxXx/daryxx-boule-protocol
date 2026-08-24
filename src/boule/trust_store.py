"""Local trust-on-first-use pins for Boule registry origins."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .canonical import canonical_bytes
from .crypto import load_public_key
from .errors import ProtocolError
from .registry import (
    MAX_CHAIN_PROOF_ENTRIES,
    MAX_REGISTRY_ENTRIES,
    verify_registry_chain_proof,
)
from .remote_protocol import strict_json_bytes

TRUST_SCHEMA = "boule-registry-trust/0.2"
_STORE_FIELDS = {"schema", "origins"}
_ANCHOR_FIELDS = {"key", "count", "head"}
_MAX_STORE_BYTES = 4 * 1024 * 1024
_MAX_ORIGINS = 4_096


def _origin(value: str) -> str:
    """Accept only an HTTPS origin or a literal loopback HTTP origin."""
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise ProtocolError("registry origin must be non-empty text")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProtocolError("registry origin is invalid") from exc
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65_535
    ):
        raise ProtocolError("registry origin must be a canonical origin")
    if parsed.scheme == "http":
        if parsed.hostname == "localhost":
            pass
        else:
            try:
                if not ipaddress.ip_address(parsed.hostname).is_loopback:
                    raise ProtocolError("HTTP registry origin must use a loopback IP address")
            except ValueError as exc:
                raise ProtocolError("HTTP registry origin must use a loopback IP address") from exc
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != {"https": 443, "http": 80}[parsed.scheme]:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}"


def _key(value: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError("registry public key must be text")
    load_public_key(value)
    return value


def _secure_regular(path: Path, *, label: str) -> os.stat_result:
    try:
        result = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ProtocolError(f"cannot inspect {label}: {path}") from exc
    if stat.S_ISLNK(result.st_mode) or not stat.S_ISREG(result.st_mode):
        raise ProtocolError(f"{label} must be a regular file")
    if stat.S_IMODE(result.st_mode) != 0o600:
        raise ProtocolError(f"{label} permissions must be 0600")
    return result


def _protect_parent(parent: Path) -> None:
    try:
        created = not parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent.is_dir() or parent.is_symlink():
            raise ProtocolError("trust-store parent must be a directory")
        if created:
            parent.chmod(0o700)
        elif stat.S_IMODE(parent.stat().st_mode) != 0o700:
            raise ProtocolError("trust-store parent permissions must be 0700")
    except ProtocolError:
        raise
    except OSError as exc:
        raise ProtocolError(f"cannot protect trust-store parent: {parent}") from exc


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ProtocolError(f"cannot open trust-store lock: {lock_path}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProtocolError("trust-store lock must be a regular file")
        _secure_regular(lock_path, label="trust-store lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _anchor(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
        raise ProtocolError("registry trust anchor has invalid fields")
    key = _key(value["key"])
    count = value["count"]
    head = value["head"]
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 1 <= count <= MAX_REGISTRY_ENTRIES
        or not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{64}", head) is None
    ):
        raise ProtocolError("registry trust anchor is invalid")
    return {"key": key, "count": count, "head": head}


def _read(path: Path) -> dict[str, dict[str, object]]:
    try:
        _secure_regular(path, label="trust store")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ProtocolError(f"cannot open trust store: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ProtocolError("trust store changed while opening")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(_MAX_STORE_BYTES + 1)
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if len(raw) > _MAX_STORE_BYTES:
        raise ProtocolError("trust store exceeds its size limit")
    try:
        value = strict_json_bytes(raw)
    except ProtocolError as exc:
        raise ProtocolError("trust store is not strict JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != _STORE_FIELDS
        or value.get("schema") != TRUST_SCHEMA
    ):
        raise ProtocolError("trust store has an unsupported schema")
    origins = value.get("origins")
    if not isinstance(origins, dict):
        raise ProtocolError("trust store origins must be an object")
    if len(origins) > _MAX_ORIGINS:
        raise ProtocolError("trust store origin limit exceeded")
    checked = {_origin(origin): _anchor(anchor) for origin, anchor in origins.items()}
    if raw != canonical_bytes({"schema": TRUST_SCHEMA, "origins": checked}):
        raise ProtocolError("trust store is not canonical JSON")
    return checked


def _write(path: Path, origins: dict[str, dict[str, object]]) -> None:
    payload = canonical_bytes({"schema": TRUST_SCHEMA, "origins": origins})
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


def read_registry_trust(path: str | Path, origin: str) -> dict[str, object] | None:
    """Read the key and append-only high-water anchor for one registry origin."""
    destination = Path(path)
    trusted_origin = _origin(origin)
    _protect_parent(destination.parent)
    with _locked(destination):
        value = _read(destination).get(trusted_origin)
        return None if value is None else dict(value)


def trust_registry_snapshot(
    path: str | Path,
    origin: str,
    presented_key: str,
    count: int,
    head: str,
    proofs: list[dict[str, object]] | None = None,
) -> str:
    """Pin or advance a registry snapshot only across a verified hash-chain extension."""
    destination = Path(path)
    trusted_origin = _origin(origin)
    trusted_key = _key(presented_key)
    proposed = _anchor({"key": trusted_key, "count": count, "head": head})
    _protect_parent(destination.parent)
    with _locked(destination):
        origins = _read(destination)
        previous = origins.get(trusted_origin)
        if previous is None:
            origins[trusted_origin] = proposed
            _write(destination, origins)
            return "first_use"
        if previous["key"] != trusted_key:
            raise ProtocolError("registry key changed for a trusted origin")
        previous_count = previous["count"]
        previous_head = previous["head"]
        if count < previous_count:
            raise ProtocolError("registry snapshot rolled back below the trusted high-water mark")
        if count == previous_count:
            if head != previous_head:
                raise ProtocolError("registry snapshot forks at the trusted high-water mark")
            return "pinned"

        current_count = previous_count
        current_head = previous_head
        for proof in proofs or []:
            expected_to = min(current_count + MAX_CHAIN_PROOF_ENTRIES, count)
            verified = verify_registry_chain_proof(
                proof,
                clerk_key=trusted_key,
                from_count=current_count,
                from_head=current_head,
                to_count=expected_to,
            )
            current_count = expected_to
            current_head = verified["to_head"]
        if current_count != count or current_head != head:
            raise ProtocolError("registry snapshot has no complete proof from the trusted anchor")
        origins[trusted_origin] = proposed
        _write(destination, origins)
        return "advanced"
