"""Signed remote envelopes and trusted-clerk receipts for Boule v0.5."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from .canonical import digest_object
from .crypto import load_public_key, public_key_text, sign_object, verify_object
from .errors import AuthenticationError, ProtocolError

ENVELOPE_SCHEMA = "boule-workspace-envelope/0.5"
EVENT_SCHEMA = "boule-workspace-event/0.5"
RECEIPT_SCHEMA = "boule-workspace-clerk-receipt/0.5"
SNAPSHOT_SCHEMA = "boule-workspace-clerk-snapshot/0.5"
CHAIN_PROOF_SCHEMA = "boule-workspace-chain-proof/0.6"
MAX_CHAIN_PROOF_LINKS = 256

ENVELOPE_FIELDS = {
    "schema",
    "request_id",
    "problem_id",
    "clerk_key",
    "base_event_hash",
    "kind",
    "actor",
    "payload",
    "signature",
}


def strict_json_bytes(raw: bytes) -> Any:
    """Decode UTF-8 JSON while rejecting duplicate keys and non-finite numbers."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ProtocolError("JSON contains a duplicate object key")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ProtocolError(f"JSON constant {value} is not permitted")

    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ProtocolError("request is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError("request is not valid JSON") from exc
    except RecursionError as exc:
        raise ProtocolError("JSON nesting is too deep") from exc


def _canonical_uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"{name} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ProtocolError(f"{name} must be a canonical UUID")
    return value


def _event_hash(value: Any, name: str, *, nullable: bool = True) -> str | None:
    if value is None:
        if not nullable:
            raise ProtocolError(f"{name} must be a lowercase 64-hex event hash")
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ProtocolError(f"{name} must be a lowercase 64-hex event hash or null")
    return value


def _sha256_digest(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ProtocolError(f"{name} must be a lowercase sha256 digest")
    return value


def _utc_time(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtocolError(f"{name} must be an ISO-8601 UTC Z string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"{name} is invalid") from exc
    if parsed.utcoffset() is None:
        raise ProtocolError(f"{name} is invalid")
    return value


def envelope_unsigned(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": "boule-workspace-envelope-v0.5",
        **{key: envelope[key] for key in ENVELOPE_FIELDS - {"signature"}},
    }


def build_envelope(
    *,
    request_id: str,
    problem_id: str,
    clerk_key: str,
    base_event_hash: str | None,
    kind: str,
    payload: dict[str, Any],
    private_key: Any,
) -> dict[str, Any]:
    actor = public_key_text(private_key)
    envelope: dict[str, Any] = {
        "schema": ENVELOPE_SCHEMA,
        "request_id": _canonical_uuid(request_id, "request_id"),
        "problem_id": problem_id,
        "clerk_key": clerk_key,
        "base_event_hash": _event_hash(base_event_hash, "base_event_hash"),
        "kind": kind,
        "actor": actor,
        "payload": payload,
    }
    return {**envelope, "signature": sign_object(private_key, envelope_unsigned(envelope))}


def verify_envelope(
    envelope: Any,
    *,
    problem_id: str,
    clerk_key: str,
    allowed_kinds: set[str] | frozenset[str],
) -> dict[str, Any]:
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ProtocolError("remote envelope has invalid fields")
    if envelope["schema"] != ENVELOPE_SCHEMA:
        raise ProtocolError("remote envelope schema is unsupported")
    _canonical_uuid(envelope["request_id"], "request_id")
    if envelope["problem_id"] != problem_id or envelope["clerk_key"] != clerk_key:
        raise ProtocolError("remote envelope targets another problem or clerk")
    _event_hash(envelope["base_event_hash"], "base_event_hash")
    if not isinstance(envelope["kind"], str) or envelope["kind"] not in allowed_kinds:
        raise ProtocolError("remote envelope event kind is not admitted")
    if not isinstance(envelope["payload"], dict):
        raise ProtocolError("remote envelope payload must be an object")
    if envelope["payload"].get("problem_id") != problem_id:
        raise ProtocolError("remote envelope payload belongs to another problem")
    try:
        load_public_key(envelope["actor"])
        verify_object(envelope["actor"], envelope_unsigned(envelope), envelope["signature"])
    except ProtocolError as exc:
        raise AuthenticationError("remote envelope signature verification failed") from exc
    return envelope


def envelope_digest(envelope: dict[str, Any]) -> str:
    return f"sha256:{digest_object(envelope)}"


def receipt_unsigned(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": "boule-workspace-clerk-receipt-v0.5",
        **{key: value for key, value in receipt.items() if key != "signature"},
    }


def build_receipt(
    event: dict[str, Any], *, problem_id: str, clerk_private_key: Any
) -> dict[str, Any]:
    clerk_key = public_key_text(clerk_private_key)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "request_id": event["request_id"],
        "problem_id": problem_id,
        "clerk_key": clerk_key,
        "envelope_digest": event["envelope_digest"],
        "seq": event["seq"],
        "event_id": event["event_id"],
        "received_at": event["received_at"],
        "prev_event_hash": event["prev_event_hash"],
        "event_hash": event["event_hash"],
        "event_count": event["seq"] + 1,
    }
    return {**receipt, "signature": sign_object(clerk_private_key, receipt_unsigned(receipt))}


def verify_receipt(
    receipt: Any,
    *,
    problem_id: str,
    clerk_key: str,
    request_id: str | None = None,
    envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields = {
        "schema",
        "request_id",
        "problem_id",
        "clerk_key",
        "envelope_digest",
        "seq",
        "event_id",
        "received_at",
        "prev_event_hash",
        "event_hash",
        "event_count",
        "signature",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields:
        raise ProtocolError("remote clerk receipt has invalid fields")
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise ProtocolError("remote clerk receipt schema is unsupported")
    _canonical_uuid(receipt["request_id"], "receipt.request_id")
    if request_id is not None and receipt["request_id"] != request_id:
        raise ProtocolError("remote clerk receipt request id mismatch")
    if receipt["problem_id"] != problem_id or receipt["clerk_key"] != clerk_key:
        raise ProtocolError("remote clerk receipt targets another problem or clerk")
    if envelope is not None and receipt["envelope_digest"] != envelope_digest(envelope):
        raise ProtocolError("remote clerk receipt does not bind the signed envelope")
    if (
        isinstance(receipt["seq"], bool)
        or not isinstance(receipt["seq"], int)
        or receipt["seq"] < 0
        or isinstance(receipt["event_count"], bool)
        or not isinstance(receipt["event_count"], int)
        or receipt["event_count"] != receipt["seq"] + 1
    ):
        raise ProtocolError("remote clerk receipt sequence is invalid")
    _event_hash(receipt["prev_event_hash"], "receipt.prev_event_hash")
    _event_hash(receipt["event_hash"], "receipt.event_hash", nullable=False)
    if not isinstance(receipt["event_id"], str) or not receipt["event_id"]:
        raise ProtocolError("remote clerk receipt event id is invalid")
    _utc_time(receipt["received_at"], "receipt.received_at")
    _sha256_digest(receipt["envelope_digest"], "receipt.envelope_digest")
    verify_object(clerk_key, receipt_unsigned(receipt), receipt["signature"])
    return receipt


def snapshot_unsigned(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": "boule-workspace-clerk-snapshot-v0.5",
        **{key: value for key, value in snapshot.items() if key != "signature"},
    }


def build_snapshot(
    *,
    problem_id: str,
    at: str,
    event_count: int,
    head_event_hash: str | None,
    state: dict[str, Any],
    clerk_private_key: Any,
) -> dict[str, Any]:
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "problem_id": problem_id,
        "clerk_key": public_key_text(clerk_private_key),
        "at": at,
        "event_count": event_count,
        "head_event_hash": head_event_hash,
        "state_digest": f"sha256:{digest_object(state)}",
    }
    return {**snapshot, "signature": sign_object(clerk_private_key, snapshot_unsigned(snapshot))}


def verify_snapshot(
    snapshot: Any,
    state: Any,
    *,
    problem_id: str,
    clerk_key: str,
) -> dict[str, Any]:
    fields = {
        "schema",
        "problem_id",
        "clerk_key",
        "at",
        "event_count",
        "head_event_hash",
        "state_digest",
        "signature",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != fields or not isinstance(state, dict):
        raise ProtocolError("remote clerk snapshot has invalid fields")
    if snapshot["schema"] != SNAPSHOT_SCHEMA:
        raise ProtocolError("remote clerk snapshot schema is unsupported")
    if snapshot["problem_id"] != problem_id or snapshot["clerk_key"] != clerk_key:
        raise ProtocolError("remote clerk snapshot targets another problem or clerk")
    if state.get("problem_id") != problem_id:
        raise ProtocolError("remote clerk snapshot state belongs to another problem")
    if (
        isinstance(snapshot["event_count"], bool)
        or not isinstance(snapshot["event_count"], int)
        or snapshot["event_count"] < 0
    ):
        raise ProtocolError("remote clerk snapshot event count is invalid")
    _utc_time(snapshot["at"], "snapshot.at")
    _event_hash(snapshot["head_event_hash"], "snapshot.head_event_hash")
    _sha256_digest(snapshot["state_digest"], "snapshot.state_digest")
    expected = f"sha256:{digest_object(state)}"
    if snapshot["state_digest"] != expected:
        raise ProtocolError("remote clerk snapshot state digest mismatch")
    verify_object(clerk_key, snapshot_unsigned(snapshot), snapshot["signature"])
    return snapshot


def _chain_proof_unsigned(proof: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": "boule-workspace-chain-proof-v0.6",
        **{key: value for key, value in proof.items() if key != "signature"},
    }


def build_chain_proof(
    *,
    problem_id: str,
    from_count: int,
    start_head: str | None,
    events: list[dict[str, Any]],
    clerk_private_key: Any,
) -> dict[str, Any]:
    """Sign a bounded hash-link suffix without disclosing event payloads."""
    if (
        isinstance(from_count, bool)
        or not isinstance(from_count, int)
        or from_count < 0
        or len(events) > MAX_CHAIN_PROOF_LINKS
    ):
        raise ProtocolError("chain proof range is invalid")
    _event_hash(start_head, "chain proof start head")
    links: list[dict[str, Any]] = []
    previous = start_head
    for offset, event in enumerate(events):
        if (
            not isinstance(event, dict)
            or event.get("seq") != from_count + offset
            or event.get("prev_event_hash") != previous
        ):
            raise ProtocolError("chain proof events are not a contiguous suffix")
        event_hash = _event_hash(event.get("event_hash"), "chain proof event hash", nullable=False)
        links.append(
            {
                "seq": from_count + offset,
                "prev_event_hash": previous,
                "event_hash": event_hash,
            }
        )
        previous = event_hash
    proof = {
        "schema": CHAIN_PROOF_SCHEMA,
        "problem_id": problem_id,
        "clerk_key": public_key_text(clerk_private_key),
        "from_count": from_count,
        "from_head": start_head,
        "to_count": from_count + len(links),
        "to_head": previous,
        "links": links,
    }
    return {**proof, "signature": sign_object(clerk_private_key, _chain_proof_unsigned(proof))}


def verify_chain_proof(
    proof: Any,
    *,
    problem_id: str,
    clerk_key: str,
    from_count: int,
    from_head: str | None,
    to_count: int,
) -> dict[str, Any]:
    fields = {
        "schema",
        "problem_id",
        "clerk_key",
        "from_count",
        "from_head",
        "to_count",
        "to_head",
        "links",
        "signature",
    }
    if not isinstance(proof, dict) or set(proof) != fields:
        raise ProtocolError("case chain proof has invalid fields")
    if (
        proof["schema"] != CHAIN_PROOF_SCHEMA
        or proof["problem_id"] != problem_id
        or proof["clerk_key"] != clerk_key
        or proof["from_count"] != from_count
        or proof["from_head"] != from_head
        or proof["to_count"] != to_count
        or isinstance(from_count, bool)
        or not isinstance(from_count, int)
        or isinstance(to_count, bool)
        or not isinstance(to_count, int)
        or not from_count <= to_count
        or to_count - from_count > MAX_CHAIN_PROOF_LINKS
        or not isinstance(proof["links"], list)
        or len(proof["links"]) != to_count - from_count
    ):
        raise ProtocolError("case chain proof does not match the requested range")
    _event_hash(from_head, "case chain proof start head")
    previous = from_head
    for offset, link in enumerate(proof["links"]):
        if (
            not isinstance(link, dict)
            or set(link) != {"seq", "prev_event_hash", "event_hash"}
            or link["seq"] != from_count + offset
            or link["prev_event_hash"] != previous
        ):
            raise ProtocolError("case chain proof link is invalid")
        previous = _event_hash(link["event_hash"], "case chain proof event hash", nullable=False)
    if proof["to_head"] != previous:
        raise ProtocolError("case chain proof end head is invalid")
    verify_object(clerk_key, _chain_proof_unsigned(proof), proof["signature"])
    return proof
