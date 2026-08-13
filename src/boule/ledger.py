from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, digest_object
from .crypto import public_key_text, sign_object, verify_object
from .errors import ProtocolError
from .model import parse_time

EVENT_FIELDS = {"kind", "actor", "payload", "signature"}
ENTRY_FIELDS = {
    "seq",
    "received_at",
    "prev_hash",
    "event",
    "entry_hash",
    "clerk_signature",
}


def _event_body(kind: str, actor: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"domain": "boule-event-v1", "kind": kind, "actor": actor, "payload": payload}


def signed_event(
    kind: str, payload: dict[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    if not isinstance(kind, str) or not kind:
        raise ProtocolError("event kind must be non-empty text")
    if not isinstance(payload, dict):
        raise ProtocolError("event payload must be an object")
    actor = public_key_text(private_key)
    body = _event_body(kind, actor, payload)
    return {
        "kind": kind,
        "actor": actor,
        "payload": payload,
        "signature": sign_object(private_key, body),
    }


def verify_event(event: Any) -> None:
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        raise ProtocolError("signed event has invalid fields")
    if not isinstance(event["kind"], str) or not event["kind"]:
        raise ProtocolError("event kind must be non-empty text")
    if not isinstance(event["payload"], dict):
        raise ProtocolError("event payload must be an object")
    body = _event_body(event["kind"], event["actor"], event["payload"])
    verify_object(event["actor"], body, event["signature"])


def _entry_body(
    seq: int,
    received_at: str,
    prev_hash: str | None,
    event: dict[str, Any],
) -> dict[str, Any]:
    return {
        "seq": seq,
        "received_at": received_at,
        "prev_hash": prev_hash,
        "event": event,
    }


class Ledger:
    """In-memory append-only ledger with signed clerk receipts."""

    def __init__(self, entries: list[dict[str, Any]] | None = None) -> None:
        self._entries = list(entries or [])

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    @property
    def clerk_key(self) -> str:
        if not self._entries:
            raise ProtocolError("empty ledger has no clerk")
        payload = self._entries[0]["event"]["payload"]
        return payload["clerk_key"]

    @classmethod
    def create(
        cls,
        case: dict[str, Any],
        reviewers: list[dict[str, Any]],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> Ledger:
        clerk_key = public_key_text(clerk_private_key)
        event = signed_event(
            "case_opened",
            {"clerk_key": clerk_key, "case": case, "reviewers": reviewers},
            clerk_private_key,
        )
        ledger = cls()
        ledger._append_event(event, clerk_private_key, received_at)
        return ledger

    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        actor_private_key: Ed25519PrivateKey,
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        if public_key_text(clerk_private_key) != self.clerk_key:
            raise ProtocolError("wrong clerk key")
        event = signed_event(kind, payload, actor_private_key)
        return self._append_event(event, clerk_private_key, received_at)

    def _append_event(
        self,
        event: dict[str, Any],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        received = parse_time(received_at, "entry.received_at")
        if self._entries:
            previous_received = parse_time(
                self._entries[-1]["received_at"], "previous entry.received_at"
            )
            if received < previous_received:
                raise ProtocolError("ledger receipt times must be monotonic")
        seq = len(self._entries)
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else None
        body = _entry_body(seq, received_at, prev_hash, event)
        entry_hash = digest_object(body)
        receipt = {"domain": "boule-clerk-receipt-v1", "entry_hash": entry_hash}
        entry = {
            **body,
            "entry_hash": entry_hash,
            "clerk_signature": sign_object(clerk_private_key, receipt),
        }
        self._entries.append(entry)
        return entry

    def _rollback_last(self) -> None:
        if self._entries:
            self._entries.pop()

    def verify(self) -> None:
        if not self._entries:
            raise ProtocolError("ledger is empty")
        first = self._entries[0]
        if not isinstance(first, dict) or set(first) != ENTRY_FIELDS:
            raise ProtocolError("genesis entry has invalid fields")
        if first["event"].get("kind") != "case_opened":
            raise ProtocolError("first event must open the case")
        payload = first["event"].get("payload")
        if not isinstance(payload, dict) or set(payload) != {"clerk_key", "case", "reviewers"}:
            raise ProtocolError("case_opened payload has invalid fields")
        clerk_key = payload["clerk_key"]
        if first["event"].get("actor") != clerk_key:
            raise ProtocolError("genesis event must be signed by the clerk")

        previous: str | None = None
        previous_received_at = None
        for expected_seq, entry in enumerate(self._entries):
            if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
                raise ProtocolError(f"ledger entry {expected_seq} has invalid fields")
            if entry["seq"] != expected_seq:
                raise ProtocolError(f"ledger sequence mismatch at {expected_seq}")
            received_at = parse_time(entry["received_at"], f"entry[{expected_seq}].received_at")
            if previous_received_at is not None and received_at < previous_received_at:
                raise ProtocolError(f"ledger receipt time moved backwards at {expected_seq}")
            if entry["prev_hash"] != previous:
                raise ProtocolError(f"ledger previous hash mismatch at {expected_seq}")
            verify_event(entry["event"])
            body = _entry_body(
                entry["seq"], entry["received_at"], entry["prev_hash"], entry["event"]
            )
            expected_hash = digest_object(body)
            if entry["entry_hash"] != expected_hash:
                raise ProtocolError(f"ledger entry hash mismatch at {expected_seq}")
            receipt = {"domain": "boule-clerk-receipt-v1", "entry_hash": expected_hash}
            verify_object(clerk_key, receipt, entry["clerk_signature"])
            previous = expected_hash
            previous_received_at = received_at

    def write(self, path: str | Path) -> Path:
        self.verify()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            for entry in self._entries:
                handle.write(canonical_bytes(entry).decode("utf-8"))
                handle.write("\n")
        return destination

    @classmethod
    def read(cls, path: str | Path) -> Ledger:
        source = Path(path)
        raw_lines = source.read_text(encoding="utf-8").splitlines()
        if not raw_lines or any(not line.strip() for line in raw_lines):
            raise ProtocolError("ledger must contain non-empty JSONL records")
        entries: list[dict[str, Any]] = []
        for index, line in enumerate(raw_lines):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProtocolError(f"ledger line {index + 1} is not valid JSON") from exc
            if not isinstance(value, dict):
                raise ProtocolError(f"ledger line {index + 1} is not an object")
            entries.append(value)
        ledger = cls(entries)
        ledger.verify()
        return ledger
