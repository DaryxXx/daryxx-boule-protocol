from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, digest_object
from .crypto import load_public_key, public_key_text, sign_object, verify_object
from .errors import ProtocolError
from .ledger import signed_event, verify_event
from .model import HEX_64_RE, parse_time

COMMUNITY_PROTOCOL = "boule-community/0.2-mock"
OUTCOMES = {"ADVANCE", "NEGATIVE", "BLOCKED", "NO_SIGNAL"}
ROLES = {
    "explorer",
    "falsifier",
    "formalizer",
    "literature_scout",
    "tool_builder",
    "integrator",
    "verifier",
    "maintainer",
}
SCOPES = {"message", "claim", "handoff", "access", "result"}
VISIBILITIES = {"public", "committee", "hash_only"}
ENTRY_FIELDS = {
    "seq",
    "received_at",
    "prev_hash",
    "event",
    "entry_hash",
    "clerk_signature",
}


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{name} must be an object")
    return value


def _exact(value: dict[str, Any], fields: set[str], name: str) -> dict[str, Any]:
    if set(value) != fields:
        missing = sorted(fields - set(value))
        extra = sorted(set(value) - fields)
        raise ProtocolError(f"{name} fields differ: missing={missing}, extra={extra}")
    return value


def _text(value: Any, name: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProtocolError(f"{name} must be non-empty text up to {maximum} characters")
    return value


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ProtocolError(f"{name} must be an integer in [{low}, {high}]")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or HEX_64_RE.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _string_list(
    value: Any,
    name: str,
    *,
    nonempty: bool = False,
    allowed: set[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProtocolError(f"{name} must be a list of strings")
    if nonempty and not value:
        raise ProtocolError(f"{name} cannot be empty")
    if len(value) != len(set(value)):
        raise ProtocolError(f"{name} contains duplicates")
    if allowed is not None and any(item not in allowed for item in value):
        raise ProtocolError(f"{name} contains an unsupported value")
    return value


def _entry_body(
    seq: int, received_at: str, prev_hash: str | None, event: dict[str, Any]
) -> dict[str, Any]:
    return {
        "seq": seq,
        "received_at": received_at,
        "prev_hash": prev_hash,
        "event": event,
    }


def _receipt(entry_hash: str) -> dict[str, str]:
    return {"domain": "boule-community-clerk-receipt-v1", "entry_hash": entry_hash}


class CommunityLedger:
    """Append-only signed hash chain for the opt-in community mock."""

    def __init__(self, entries: list[dict[str, Any]] | None = None) -> None:
        self._entries = list(entries or [])

    @property
    def entries(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._entries)

    @property
    def clerk_key(self) -> str:
        if not self._entries:
            raise ProtocolError("empty community ledger has no clerk")
        return self._entries[0]["event"]["payload"]["clerk_key"]

    @classmethod
    def create(
        cls,
        manifest: dict[str, Any],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> CommunityLedger:
        clerk_key = public_key_text(clerk_private_key)
        event = signed_event(
            "community_opened",
            {"clerk_key": clerk_key, "manifest": manifest},
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
            raise ProtocolError("wrong community clerk key")
        return self._append_event(
            signed_event(kind, payload, actor_private_key), clerk_private_key, received_at
        )

    def _append_event(
        self,
        event: dict[str, Any],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        received = parse_time(received_at, "entry.received_at")
        if self._entries:
            previous = parse_time(self._entries[-1]["received_at"], "previous entry.received_at")
            if received < previous:
                raise ProtocolError("community ledger receipt times must be monotonic")
        seq = len(self._entries)
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else None
        body = _entry_body(seq, received_at, prev_hash, event)
        entry_hash = digest_object(body)
        entry = {
            **body,
            "entry_hash": entry_hash,
            "clerk_signature": sign_object(clerk_private_key, _receipt(entry_hash)),
        }
        self._entries.append(entry)
        return entry

    def _rollback_last(self) -> None:
        if self._entries:
            self._entries.pop()

    def verify(self) -> None:
        if not self._entries:
            raise ProtocolError("community ledger is empty")
        first = self._entries[0]
        if not isinstance(first, dict) or set(first) != ENTRY_FIELDS:
            raise ProtocolError("community genesis entry has invalid fields")
        if first["event"].get("kind") != "community_opened":
            raise ProtocolError("first community event must open the case")
        payload = first["event"].get("payload")
        if not isinstance(payload, dict) or set(payload) != {"clerk_key", "manifest"}:
            raise ProtocolError("community_opened payload has invalid fields")
        clerk_key = payload["clerk_key"]
        if first["event"].get("actor") != clerk_key:
            raise ProtocolError("community genesis must be signed by its clerk")

        previous_hash: str | None = None
        previous_time = None
        for expected_seq, entry in enumerate(self._entries):
            if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
                raise ProtocolError(f"community ledger entry {expected_seq} has invalid fields")
            if entry["seq"] != expected_seq:
                raise ProtocolError(f"community ledger sequence mismatch at {expected_seq}")
            received = parse_time(entry["received_at"], f"entry[{expected_seq}].received_at")
            if previous_time is not None and received < previous_time:
                raise ProtocolError(
                    f"community ledger receipt time moved backwards at {expected_seq}"
                )
            if entry["prev_hash"] != previous_hash:
                raise ProtocolError(f"community previous hash mismatch at {expected_seq}")
            verify_event(entry["event"])
            expected_hash = digest_object(
                _entry_body(
                    entry["seq"],
                    entry["received_at"],
                    entry["prev_hash"],
                    entry["event"],
                )
            )
            if entry["entry_hash"] != expected_hash:
                raise ProtocolError(f"community entry hash mismatch at {expected_seq}")
            verify_object(clerk_key, _receipt(expected_hash), entry["clerk_signature"])
            previous_hash = expected_hash
            previous_time = received

    def write(self, path: str | Path) -> Path:
        self.verify()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            for entry in self._entries:
                handle.write(canonical_bytes(entry).decode("utf-8") + "\n")
        return destination

    @classmethod
    def read(cls, path: str | Path) -> CommunityLedger:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        if not lines or any(not line.strip() for line in lines):
            raise ProtocolError("community ledger must contain non-empty JSONL records")
        entries: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ProtocolError(f"community ledger line {index + 1} is not valid JSON") from exc
            if not isinstance(value, dict):
                raise ProtocolError(f"community ledger line {index + 1} is not an object")
            entries.append(value)
        ledger = cls(entries)
        ledger.verify()
        return ledger


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = _exact(
        _mapping(value, "community manifest"),
        {
            "protocol",
            "case_id",
            "title",
            "objective",
            "participants",
            "verifier_key",
            "reviewers",
            "policy",
            "economics",
            "disclosure",
            "initial_frontier",
            "simulation",
        },
        "community manifest",
    )
    if manifest["protocol"] != COMMUNITY_PROTOCOL:
        raise ProtocolError("unsupported community protocol")
    _text(manifest["case_id"], "manifest.case_id", maximum=128)
    _text(manifest["title"], "manifest.title", maximum=240)
    if manifest["simulation"] is not True:
        raise ProtocolError("community mock manifest must declare simulation=true")

    objective = _exact(
        _mapping(manifest["objective"], "manifest.objective"),
        {
            "statement",
            "base_commit",
            "environment_digest",
            "verifier",
            "task_id",
            "reward_target_id",
        },
        "manifest.objective",
    )
    for field in ("statement", "base_commit", "verifier", "task_id", "reward_target_id"):
        _text(objective[field], f"manifest.objective.{field}")
    _digest(objective["environment_digest"], "manifest.objective.environment_digest")

    participants = _mapping(manifest["participants"], "manifest.participants")
    if not 2 <= len(participants) <= 128:
        raise ProtocolError("community case must have between 2 and 128 participants")
    controller_keys: set[str] = set()
    controller_ids: set[str] = set()
    destinations: set[tuple[str, str]] = set()
    for participant_id, raw in participants.items():
        _text(participant_id, "participant id", maximum=64)
        participant = _exact(
            _mapping(raw, f"participant.{participant_id}"),
            {"controller_key", "controller_id", "display_name", "payout_destination"},
            f"participant.{participant_id}",
        )
        load_public_key(participant["controller_key"])
        if participant["controller_key"] in controller_keys:
            raise ProtocolError("participant controller keys must be unique")
        controller_keys.add(participant["controller_key"])
        controller_id = _text(
            participant["controller_id"], "participant.controller_id", maximum=128
        )
        if controller_id in controller_ids:
            raise ProtocolError("participant controller IDs must be unique")
        controller_ids.add(controller_id)
        _text(participant["display_name"], "participant.display_name", maximum=128)
        payout = _exact(
            _mapping(participant["payout_destination"], "participant.payout_destination"),
            {"coldkey", "hotkey"},
            "participant.payout_destination",
        )
        destination = (
            _text(payout["coldkey"], "payout.coldkey", maximum=128),
            _text(payout["hotkey"], "payout.hotkey", maximum=128),
        )
        if destination in destinations:
            raise ProtocolError("mock payout destinations must be unique")
        destinations.add(destination)

    load_public_key(manifest["verifier_key"])
    if manifest["verifier_key"] in controller_keys:
        raise ProtocolError("verifier key must be independent from participant controllers")
    reviewers = _mapping(manifest["reviewers"], "manifest.reviewers")
    if not 3 <= len(reviewers) <= 21:
        raise ProtocolError("community case must have between 3 and 21 reviewers")
    reviewer_keys: set[str] = set()
    reviewer_controllers: set[str] = set()
    participant_controllers = {
        participant["controller_id"] for participant in participants.values()
    }
    for reviewer_id, raw in reviewers.items():
        _text(reviewer_id, "reviewer id", maximum=64)
        reviewer = _exact(
            _mapping(raw, f"reviewer.{reviewer_id}"),
            {"reviewer_key", "controller_id"},
            f"reviewer.{reviewer_id}",
        )
        load_public_key(reviewer["reviewer_key"])
        controller = _text(reviewer["controller_id"], "reviewer.controller_id", maximum=128)
        if reviewer["reviewer_key"] in reviewer_keys:
            raise ProtocolError("reviewer keys must be unique")
        if (
            reviewer["reviewer_key"] in controller_keys
            or reviewer["reviewer_key"] == manifest["verifier_key"]
        ):
            raise ProtocolError("reviewer keys must be independent from case actors")
        if controller in reviewer_controllers or controller in participant_controllers:
            raise ProtocolError("reviewer controllers must be distinct and non-conflicted")
        reviewer_keys.add(reviewer["reviewer_key"])
        reviewer_controllers.add(controller)

    policy = _exact(
        _mapping(manifest["policy"], "manifest.policy"),
        {
            "lease_max_seconds",
            "allow_parallel",
            "review_quorum",
            "max_share_dispersion_bps",
        },
        "manifest.policy",
    )
    _integer(policy["lease_max_seconds"], "lease_max_seconds", 60, 604_800)
    if not isinstance(policy["allow_parallel"], bool):
        raise ProtocolError("allow_parallel must be boolean")
    _integer(policy["review_quorum"], "review_quorum", 3, len(reviewers))
    _integer(policy["max_share_dispersion_bps"], "max_share_dispersion_bps", 0, 10_000)

    economics = _exact(
        _mapping(manifest["economics"], "manifest.economics"),
        {"asset", "bounty_rao"},
        "manifest.economics",
    )
    if economics["asset"] != "mock-alpha-rao":
        raise ProtocolError("community mock asset must be mock-alpha-rao")
    _integer(economics["bounty_rao"], "economics.bounty_rao", 1, 10**30)
    _mapping(manifest["disclosure"], "manifest.disclosure")

    frontier = _exact(
        _mapping(manifest["initial_frontier"], "manifest.initial_frontier"),
        {"frontier_id", "summary", "open_obligations", "frontier_digest"},
        "manifest.initial_frontier",
    )
    _text(frontier["frontier_id"], "initial_frontier.frontier_id", maximum=128)
    _text(frontier["summary"], "initial_frontier.summary", maximum=4_000)
    _string_list(frontier["open_obligations"], "initial_frontier.open_obligations")
    expected = frontier_digest(
        manifest["case_id"],
        frontier["frontier_id"],
        None,
        frontier["summary"],
        frontier["open_obligations"],
        [],
    )
    if frontier["frontier_digest"] != expected:
        raise ProtocolError("initial frontier digest does not match its content")
    return manifest


def frontier_digest(
    case_id: str,
    frontier_id: str,
    parent_frontier_id: str | None,
    summary: str,
    open_obligations: list[str],
    accepted_handoffs: list[str],
) -> str:
    return digest_object(
        {
            "domain": "boule-community-frontier-v1",
            "case_id": case_id,
            "frontier_id": frontier_id,
            "parent_frontier_id": parent_frontier_id,
            "summary": summary,
            "open_obligations": open_obligations,
            "accepted_handoffs": accepted_handoffs,
        }
    )


def credit_ballot_commitment(ballot: dict[str, Any], salt: str) -> str:
    _digest(salt, "credit ballot salt")
    return digest_object(
        {"domain": "boule-community-credit-ballot-v1", "ballot": ballot, "salt": salt}
    )


def _normalize_bps(raw: dict[str, int]) -> dict[str, int]:
    total = sum(raw.values())
    if total <= 0:
        raise ProtocolError("cannot normalize an empty credit allocation")
    bases = {participant: 10_000 * value // total for participant, value in raw.items()}
    remainder = 10_000 - sum(bases.values())
    residues = sorted(
        raw,
        key=lambda participant: (
            -(10_000 * raw[participant] % total),
            participant,
        ),
    )
    for participant in residues[:remainder]:
        bases[participant] += 1
    return dict(sorted(bases.items()))


def _median(values: list[int]) -> int:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def payout_legs(manifest: dict[str, Any], allocation_bps: dict[str, int]) -> list[dict[str, Any]]:
    total = manifest["economics"]["bounty_rao"]
    participants = manifest["participants"]
    allocation = _mapping(allocation_bps, "allocation_bps")
    if set(allocation) != set(participants):
        raise ProtocolError("allocation must cover every participant exactly once")
    validated = {
        participant_id: _integer(
            allocation[participant_id], f"allocation_bps.{participant_id}", 0, 10_000
        )
        for participant_id in participants
    }
    if sum(validated.values()) != 10_000:
        raise ProtocolError("allocation must sum to 10000 bps")
    positive: list[tuple[str, str, str, int]] = []
    for participant_id, bps in validated.items():
        if bps <= 0:
            continue
        destination = participants[participant_id]["payout_destination"]
        positive.append((destination["coldkey"], destination["hotkey"], participant_id, bps))
    positive.sort()
    legs: list[dict[str, Any]] = []
    residues: dict[str, int] = {}
    for index, (coldkey, hotkey, participant_id, bps) in enumerate(positive):
        residues[participant_id] = total * bps % 10_000
        legs.append(
            {
                "leg_id": f"leg-{index + 1:03d}",
                "participant_id": participant_id,
                "destination_coldkey": coldkey,
                "destination_hotkey": hotkey,
                "bps": bps,
                "amount_rao": total * bps // 10_000,
            }
        )
    remainder = total - sum(leg["amount_rao"] for leg in legs)
    by_remainder = sorted(
        legs,
        key=lambda leg: (
            -residues[leg["participant_id"]],
            leg["destination_coldkey"],
            leg["destination_hotkey"],
            leg["participant_id"],
        ),
    )
    for leg in by_remainder[:remainder]:
        leg["amount_rao"] += 1
    return legs


@dataclass(frozen=True)
class SessionIdentity:
    session_id: str
    participant_id: str
    session_key: str
    scopes: tuple[str, ...]
    not_after: str
    revoked: bool = False


class CommunityState:
    def __init__(self) -> None:
        self.manifest: dict[str, Any] | None = None
        self.clerk_key: str | None = None
        self.phase = "new"
        self.sessions: dict[str, SessionIdentity] = {}
        self.session_by_key: dict[str, str] = {}
        self.claims: dict[str, dict[str, Any]] = {}
        self.commitments: dict[str, dict[str, Any]] = {}
        self.handoffs: dict[str, dict[str, Any]] = {}
        self.messages: dict[str, dict[str, Any]] = {}
        self.accesses: dict[str, dict[str, Any]] = {}
        self.frontiers: dict[str, dict[str, Any]] = {}
        self.current_frontier_id: str | None = None
        self.accepted_handoffs: set[str] = set()
        self.results: dict[str, dict[str, Any]] = {}
        self.technical_receipts: dict[str, dict[str, Any]] = {}
        self.sealed_result_id: str | None = None
        self.evidence_root: str | None = None
        self.review_commits: dict[str, str] = {}
        self.review_commits_closed = False
        self.ballots: dict[str, dict[str, Any]] = {}
        self.allocation: dict[str, Any] | None = None
        self.payout_plan: dict[str, Any] | None = None
        self.payout_submitted: dict[str, str] = {}
        self.payout_confirmed: set[str] = set()

    def _require_manifest(self) -> dict[str, Any]:
        if self.manifest is None:
            raise ProtocolError("community case is not open")
        return self.manifest

    @property
    def case_id(self) -> str:
        return self._require_manifest()["case_id"]

    @property
    def current_frontier(self) -> dict[str, Any]:
        if self.current_frontier_id is None:
            raise ProtocolError("community frontier is missing")
        return self.frontiers[self.current_frontier_id]

    def _case_payload(self, payload: Any, fields: set[str], name: str) -> dict[str, Any]:
        payload = _exact(_mapping(payload, name), fields | {"case_id"}, name)
        if payload["case_id"] != self.case_id:
            raise ProtocolError(f"{name} belongs to another case")
        return payload

    def _participant_for_controller(self, actor: str) -> str:
        manifest = self._require_manifest()
        matches = [
            participant_id
            for participant_id, participant in manifest["participants"].items()
            if participant["controller_key"] == actor
        ]
        if len(matches) != 1:
            raise ProtocolError("event signer is not a participant controller")
        return matches[0]

    def _session_actor(self, actor: str, received_at: str, scope: str) -> SessionIdentity:
        if self.phase != "active":
            raise ProtocolError("delegated sessions cannot mutate a sealed case")
        session_id = self.session_by_key.get(actor)
        if session_id is None:
            raise ProtocolError("event signer is not a delegated session")
        session = self.sessions[session_id]
        if session.revoked:
            raise ProtocolError("delegated session is revoked")
        if scope not in session.scopes:
            raise ProtocolError(f"delegated session lacks {scope} scope")
        if parse_time(received_at, "entry.received_at") >= parse_time(
            session.not_after, "session.not_after"
        ):
            raise ProtocolError("delegated session has expired")
        return session

    def _reviewer_id(self, actor: str) -> str:
        manifest = self._require_manifest()
        matches = [
            reviewer_id
            for reviewer_id, reviewer in manifest["reviewers"].items()
            if reviewer["reviewer_key"] == actor
        ]
        if len(matches) != 1:
            raise ProtocolError("event signer is not a frozen reviewer")
        return matches[0]

    def _claim_is_active(self, claim: dict[str, Any], received_at: str) -> bool:
        return claim["status"] == "active" and parse_time(
            received_at, "entry.received_at"
        ) < parse_time(claim["payload"]["expires_at"], "claim.expires_at")

    def _dependency_closure(self, roots: list[str]) -> set[str]:
        closure: set[str] = set()
        stack = list(roots)
        while stack:
            handoff_id = stack.pop()
            if handoff_id in closure:
                continue
            handoff = self.handoffs.get(handoff_id)
            if handoff is None:
                raise ProtocolError(f"unknown result dependency: {handoff_id}")
            if handoff["payload"]["outcome"] == "NO_SIGNAL":
                raise ProtocolError("NO_SIGNAL handoffs cannot support a result")
            closure.add(handoff_id)
            stack.extend(handoff["payload"]["depends_on"])
            stack.extend(handoff["payload"]["uses"])
        return closure

    def expected_evidence_root(self, result_id: str) -> str:
        result = self.results.get(result_id)
        receipt = self.technical_receipts.get(result_id)
        if result is None or receipt is None:
            raise ProtocolError("result or technical receipt is missing")
        return digest_object(
            {
                "domain": "boule-community-evidence-root-v1",
                "case_id": self.case_id,
                "frontier": self.current_frontier,
                "commitments": [
                    {"commitment_id": key, "entry_hash": value["entry_hash"]}
                    for key, value in sorted(self.commitments.items())
                ],
                "handoffs": [
                    {"handoff_id": key, "entry_hash": value["entry_hash"]}
                    for key, value in sorted(self.handoffs.items())
                ],
                "accesses": [
                    {"access_id": key, "entry_hash": value["entry_hash"]}
                    for key, value in sorted(self.accesses.items())
                ],
                "result": {"result_id": result_id, "entry_hash": result["entry_hash"]},
                "technical_receipt_entry_hash": receipt["entry_hash"],
            }
        )

    def apply(self, entry: dict[str, Any]) -> None:
        kind = entry["event"]["kind"]
        actor = entry["event"]["actor"]
        payload = entry["event"]["payload"]
        received_at = entry["received_at"]

        if kind == "community_opened":
            if self.phase != "new" or entry["seq"] != 0:
                raise ProtocolError("community case may be opened exactly once")
            payload = _exact(
                _mapping(payload, "community_opened"),
                {"clerk_key", "manifest"},
                "community_opened",
            )
            if actor != payload["clerk_key"]:
                raise ProtocolError("community case must be opened by its clerk")
            self.manifest = validate_manifest(payload["manifest"])
            self.clerk_key = actor
            actor_keys = {
                participant["controller_key"]
                for participant in self.manifest["participants"].values()
            }
            actor_keys.add(self.manifest["verifier_key"])
            actor_keys.update(
                reviewer["reviewer_key"] for reviewer in self.manifest["reviewers"].values()
            )
            if actor in actor_keys:
                raise ProtocolError("community clerk key must be independent from case actors")
            initial = deepcopy(self.manifest["initial_frontier"])
            initial["parent_frontier_id"] = None
            initial["accepted_handoffs"] = []
            self.frontiers[initial["frontier_id"]] = initial
            self.current_frontier_id = initial["frontier_id"]
            self.phase = "active"
            return

        manifest = self._require_manifest()

        if kind == "session_delegated":
            if self.phase != "active":
                raise ProtocolError("new sessions cannot join a sealed case")
            payload = self._case_payload(
                payload,
                {"participant_id", "session_id", "session_key", "role", "scopes", "not_after"},
                kind,
            )
            participant_id = self._participant_for_controller(actor)
            if payload["participant_id"] != participant_id:
                raise ProtocolError("controller cannot delegate another participant's session")
            session_id = _text(payload["session_id"], "session_id", maximum=128)
            session_key = payload["session_key"]
            load_public_key(session_key)
            if session_id in self.sessions or session_key in self.session_by_key:
                raise ProtocolError("duplicate delegated session id or key")
            reserved_keys = {self.clerk_key, manifest["verifier_key"]}
            reserved_keys.update(
                participant["controller_key"] for participant in manifest["participants"].values()
            )
            reserved_keys.update(
                reviewer["reviewer_key"] for reviewer in manifest["reviewers"].values()
            )
            if session_key in reserved_keys:
                raise ProtocolError("delegated session key must be independent from frozen actors")
            if payload["role"] not in ROLES:
                raise ProtocolError("unsupported community role")
            scopes = _string_list(
                payload["scopes"], "session.scopes", nonempty=True, allowed=SCOPES
            )
            not_after = parse_time(payload["not_after"], "session.not_after")
            if not_after <= parse_time(received_at, "entry.received_at"):
                raise ProtocolError("delegated session must expire in the future")
            identity = SessionIdentity(
                session_id=session_id,
                participant_id=participant_id,
                session_key=session_key,
                scopes=tuple(scopes),
                not_after=payload["not_after"],
            )
            self.sessions[session_id] = identity
            self.session_by_key[session_key] = session_id
            return

        if kind == "session_revoked":
            if self.phase != "active":
                raise ProtocolError("sessions cannot be revoked after evidence is sealed")
            payload = self._case_payload(payload, {"participant_id", "session_id", "reason"}, kind)
            participant_id = self._participant_for_controller(actor)
            if payload["participant_id"] != participant_id:
                raise ProtocolError("controller cannot revoke another participant's session")
            session_id = _text(payload["session_id"], "session_id", maximum=128)
            session = self.sessions.get(session_id)
            if session is None or session.participant_id != participant_id:
                raise ProtocolError("session revocation cites an unknown delegated session")
            if session.revoked:
                raise ProtocolError("delegated session was already revoked")
            _text(payload["reason"], "session_revoked.reason", maximum=1_000)
            self.sessions[session_id] = SessionIdentity(
                session_id=session.session_id,
                participant_id=session.participant_id,
                session_key=session.session_key,
                scopes=session.scopes,
                not_after=session.not_after,
                revoked=True,
            )
            for claim in self.claims.values():
                if claim["status"] == "active" and claim["payload"]["session_id"] == session_id:
                    claim["status"] = "released"
            return

        if kind == "message_posted":
            session = self._session_actor(actor, received_at, "message")
            payload = self._case_payload(
                payload, {"message_id", "session_id", "topic", "body", "references"}, kind
            )
            if payload["session_id"] != session.session_id:
                raise ProtocolError("message session id does not match signer")
            message_id = _text(payload["message_id"], "message_id", maximum=128)
            if message_id in self.messages:
                raise ProtocolError("duplicate message id")
            _text(payload["topic"], "message.topic", maximum=128)
            _text(payload["body"], "message.body", maximum=4_000)
            _string_list(payload["references"], "message.references")
            self.messages[message_id] = {"payload": payload, "entry_hash": entry["entry_hash"]}
            return

        if kind == "route_claimed":
            session = self._session_actor(actor, received_at, "claim")
            payload = self._case_payload(
                payload,
                {
                    "claim_id",
                    "route_id",
                    "participant_id",
                    "session_id",
                    "base_frontier_id",
                    "question",
                    "success_gate",
                    "falsifier",
                    "overlap",
                    "expires_at",
                },
                kind,
            )
            if (
                payload["participant_id"] != session.participant_id
                or payload["session_id"] != session.session_id
            ):
                raise ProtocolError("route claim identity does not match signer")
            claim_id = _text(payload["claim_id"], "claim_id", maximum=128)
            route_id = _text(payload["route_id"], "route_id", maximum=128)
            if claim_id in self.claims:
                raise ProtocolError("duplicate route claim id")
            if payload["base_frontier_id"] != self.current_frontier_id:
                raise ProtocolError("route claim is based on a stale frontier")
            for field in ("question", "success_gate", "falsifier"):
                _text(payload[field], f"route_claimed.{field}", maximum=2_000)
            if payload["overlap"] not in {"exclusive", "parallel"}:
                raise ProtocolError("route overlap policy is invalid")
            expiry = parse_time(payload["expires_at"], "route.expires_at")
            received = parse_time(received_at, "entry.received_at")
            seconds = (expiry - received).total_seconds()
            if seconds <= 0 or seconds > manifest["policy"]["lease_max_seconds"]:
                raise ProtocolError("route lease duration is outside the frozen policy")
            active_same_route = [
                claim
                for claim in self.claims.values()
                if claim["payload"]["route_id"] == route_id
                and self._claim_is_active(claim, received_at)
            ]
            parallel_allowed = (
                manifest["policy"]["allow_parallel"]
                and payload["overlap"] == "parallel"
                and all(claim["payload"]["overlap"] == "parallel" for claim in active_same_route)
            )
            if active_same_route and not parallel_allowed:
                raise ProtocolError("active route lease already exists")
            self.claims[claim_id] = {
                "payload": payload,
                "entry_hash": entry["entry_hash"],
                "status": "active",
            }
            return

        if kind == "contribution_committed":
            session = self._session_actor(actor, received_at, "handoff")
            payload = self._case_payload(
                payload,
                {
                    "commitment_id",
                    "claim_id",
                    "participant_id",
                    "session_id",
                    "artifact_digest",
                    "summary_digest",
                    "visibility",
                },
                kind,
            )
            if (
                payload["participant_id"] != session.participant_id
                or payload["session_id"] != session.session_id
            ):
                raise ProtocolError("contribution commitment identity does not match signer")
            commitment_id = _text(payload["commitment_id"], "commitment_id", maximum=128)
            if commitment_id in self.commitments:
                raise ProtocolError("duplicate contribution commitment")
            claim = self.claims.get(payload["claim_id"])
            if claim is None or claim["payload"]["session_id"] != session.session_id:
                raise ProtocolError("commitment does not belong to the session's route")
            if not self._claim_is_active(claim, received_at):
                raise ProtocolError("route lease is not active")
            _digest(payload["artifact_digest"], "commitment.artifact_digest")
            _digest(payload["summary_digest"], "commitment.summary_digest")
            if payload["visibility"] not in VISIBILITIES:
                raise ProtocolError("contribution visibility is invalid")
            self.commitments[commitment_id] = {
                "payload": payload,
                "entry_hash": entry["entry_hash"],
                "revealed_by": None,
            }
            return

        if kind == "handoff_published":
            session = self._session_actor(actor, received_at, "handoff")
            payload = self._case_payload(
                payload,
                {
                    "handoff_id",
                    "commitment_id",
                    "claim_id",
                    "participant_id",
                    "session_id",
                    "outcome",
                    "summary",
                    "artifact_digest",
                    "environment_digest",
                    "reproduce",
                    "depends_on",
                    "uses",
                    "refutes",
                    "limitations",
                    "next_test",
                    "base_commit",
                    "result_commit",
                    "originality",
                    "citations",
                },
                kind,
            )
            if (
                payload["participant_id"] != session.participant_id
                or payload["session_id"] != session.session_id
            ):
                raise ProtocolError("handoff identity does not match signer")
            handoff_id = _text(payload["handoff_id"], "handoff_id", maximum=128)
            if handoff_id in self.handoffs:
                raise ProtocolError("duplicate handoff id")
            claim = self.claims.get(payload["claim_id"])
            if claim is None or claim["payload"]["session_id"] != session.session_id:
                raise ProtocolError("handoff does not belong to the session's route")
            if not self._claim_is_active(claim, received_at):
                raise ProtocolError("route lease is not active")
            commitment = self.commitments.get(payload["commitment_id"])
            if commitment is None or commitment["payload"]["claim_id"] != payload["claim_id"]:
                raise ProtocolError("handoff has no matching contribution commitment")
            if commitment["revealed_by"] is not None:
                raise ProtocolError("contribution commitment was already revealed")
            if payload["artifact_digest"] != commitment["payload"]["artifact_digest"]:
                raise ProtocolError("handoff artifact does not match its commitment")
            if payload["outcome"] not in OUTCOMES:
                raise ProtocolError("handoff outcome is invalid")
            _text(payload["summary"], "handoff.summary", maximum=4_000)
            if digest_object(payload["summary"]) != commitment["payload"]["summary_digest"]:
                raise ProtocolError("handoff summary does not match its commitment")
            _digest(payload["artifact_digest"], "handoff.artifact_digest")
            if payload["environment_digest"] != manifest["objective"]["environment_digest"]:
                raise ProtocolError("handoff used the wrong frozen environment")
            _text(payload["reproduce"], "handoff.reproduce", maximum=2_000)
            edges: list[str] = []
            for field in ("depends_on", "uses", "refutes"):
                values = _string_list(payload[field], f"handoff.{field}")
                if handoff_id in values:
                    raise ProtocolError("handoff cannot depend on itself")
                edges.extend(values)
            if len(edges) != len(set(edges)):
                raise ProtocolError("handoff dependency roles overlap")
            missing = set(edges) - set(self.handoffs)
            if missing:
                raise ProtocolError(f"handoff has unknown dependencies: {sorted(missing)}")
            if any(self.handoffs[item]["payload"]["outcome"] == "NO_SIGNAL" for item in edges):
                raise ProtocolError("NO_SIGNAL handoffs cannot be dependencies")
            for field in ("limitations", "next_test", "base_commit"):
                _text(payload[field], f"handoff.{field}", maximum=2_000)
            if payload["result_commit"] is not None:
                _text(payload["result_commit"], "handoff.result_commit", maximum=256)
            if payload["originality"] not in {"original", "adapted", "replication", "fixture"}:
                raise ProtocolError("handoff originality declaration is invalid")
            _string_list(payload["citations"], "handoff.citations")
            self.handoffs[handoff_id] = {
                "payload": payload,
                "entry_hash": entry["entry_hash"],
            }
            commitment["revealed_by"] = handoff_id
            claim["status"] = "completed"
            return

        if kind == "frontier_accepted":
            if actor != self.clerk_key or self.phase != "active":
                raise ProtocolError("only the clerk can update an active frontier")
            payload = self._case_payload(
                payload,
                {
                    "frontier_id",
                    "parent_frontier_id",
                    "summary",
                    "open_obligations",
                    "accepted_handoffs",
                    "frontier_digest",
                },
                kind,
            )
            frontier_id = _text(payload["frontier_id"], "frontier_id", maximum=128)
            if frontier_id in self.frontiers:
                raise ProtocolError("duplicate frontier id")
            if payload["parent_frontier_id"] != self.current_frontier_id:
                raise ProtocolError("frontier update does not extend the current frontier")
            _text(payload["summary"], "frontier.summary", maximum=4_000)
            obligations = _string_list(payload["open_obligations"], "frontier.open_obligations")
            accepted = _string_list(
                payload["accepted_handoffs"], "frontier.accepted_handoffs", nonempty=True
            )
            missing = set(accepted) - set(self.handoffs)
            if missing:
                raise ProtocolError(f"frontier cites unknown handoffs: {sorted(missing)}")
            if any(self.handoffs[item]["payload"]["outcome"] == "NO_SIGNAL" for item in accepted):
                raise ProtocolError("NO_SIGNAL cannot advance the frontier")
            if any(
                self.commitments[self.handoffs[item]["payload"]["commitment_id"]]["payload"][
                    "visibility"
                ]
                == "hash_only"
                for item in accepted
            ):
                raise ProtocolError("hash-only handoffs are not inspectable frontier evidence")
            cumulative = self.accepted_handoffs | set(accepted)
            for handoff_id in accepted:
                dependencies = set(self.handoffs[handoff_id]["payload"]["depends_on"])
                dependencies |= set(self.handoffs[handoff_id]["payload"]["uses"])
                if not dependencies <= cumulative:
                    raise ProtocolError("frontier omitted an accepted handoff dependency")
            expected = frontier_digest(
                self.case_id,
                frontier_id,
                payload["parent_frontier_id"],
                payload["summary"],
                obligations,
                sorted(cumulative),
            )
            if payload["frontier_digest"] != expected:
                raise ProtocolError("frontier digest does not match its content")
            stored = deepcopy(payload)
            stored["accepted_handoffs"] = sorted(cumulative)
            self.frontiers[frontier_id] = stored
            self.current_frontier_id = frontier_id
            self.accepted_handoffs = cumulative
            return

        if kind == "knowledge_accessed":
            session = self._session_actor(actor, received_at, "access")
            payload = self._case_payload(
                payload,
                {
                    "access_id",
                    "contribution_id",
                    "artifact_digest",
                    "sender_participant_id",
                    "receiver_participant_id",
                    "session_id",
                    "purpose",
                    "license_digest",
                },
                kind,
            )
            if (
                payload["receiver_participant_id"] != session.participant_id
                or payload["session_id"] != session.session_id
            ):
                raise ProtocolError("knowledge receipt identity does not match signer")
            access_id = _text(payload["access_id"], "access_id", maximum=128)
            if access_id in self.accesses:
                raise ProtocolError("duplicate knowledge access receipt")
            contribution = self.handoffs.get(payload["contribution_id"])
            if contribution is None:
                raise ProtocolError("knowledge receipt cites an unknown contribution")
            if contribution["payload"]["participant_id"] != payload["sender_participant_id"]:
                raise ProtocolError("knowledge receipt names the wrong sender")
            if payload["sender_participant_id"] == payload["receiver_participant_id"]:
                raise ProtocolError("knowledge access must cross participant identities")
            if contribution["payload"]["artifact_digest"] != payload["artifact_digest"]:
                raise ProtocolError("knowledge receipt names the wrong artifact")
            _text(payload["purpose"], "knowledge_accessed.purpose", maximum=1_000)
            _digest(payload["license_digest"], "knowledge_accessed.license_digest")
            self.accesses[access_id] = {"payload": payload, "entry_hash": entry["entry_hash"]}
            return

        if kind == "result_proposed":
            session = self._session_actor(actor, received_at, "result")
            payload = self._case_payload(
                payload,
                {
                    "result_id",
                    "participant_id",
                    "session_id",
                    "artifact_digest",
                    "environment_digest",
                    "reproduce",
                    "direct_dependencies",
                    "claimed_transitive_dependencies",
                    "access_dispositions",
                    "summary",
                },
                kind,
            )
            if (
                payload["participant_id"] != session.participant_id
                or payload["session_id"] != session.session_id
            ):
                raise ProtocolError("result identity does not match signer")
            result_id = _text(payload["result_id"], "result_id", maximum=128)
            if result_id in self.results:
                raise ProtocolError("duplicate result id")
            _digest(payload["artifact_digest"], "result.artifact_digest")
            if payload["environment_digest"] != manifest["objective"]["environment_digest"]:
                raise ProtocolError("result used the wrong frozen environment")
            _text(payload["reproduce"], "result.reproduce", maximum=2_000)
            direct = _string_list(
                payload["direct_dependencies"], "result.direct_dependencies", nonempty=True
            )
            claimed = set(
                _string_list(
                    payload["claimed_transitive_dependencies"],
                    "result.claimed_transitive_dependencies",
                    nonempty=True,
                )
            )
            expected = self._dependency_closure(direct)
            if not expected <= self.accepted_handoffs:
                raise ProtocolError("result depends on a handoff not accepted on the frontier")
            dispositions = _mapping(payload["access_dispositions"], "result.access_dispositions")
            accessed = {
                access["payload"]["contribution_id"]
                for access in self.accesses.values()
                if access["payload"]["receiver_participant_id"] == session.participant_id
            }
            if set(dispositions) - accessed:
                raise ProtocolError("result disposition cites knowledge never received")
            if any(value not in {"used", "not_used"} for value in dispositions.values()):
                raise ProtocolError("result access disposition is invalid")
            used_but_absent = {
                contribution
                for contribution, disposition in dispositions.items()
                if disposition == "used" and contribution not in claimed
            }
            unaccounted = accessed - set(dispositions)
            omitted = (expected - claimed) | used_but_absent
            extraneous = claimed - expected
            unattributed_accesses = {
                contribution
                for contribution, disposition in dispositions.items()
                if disposition == "not_used" and contribution not in expected
            }
            _text(payload["summary"], "result.summary", maximum=4_000)
            self.results[result_id] = {
                "payload": payload,
                "entry_hash": entry["entry_hash"],
                "expected_dependencies": sorted(expected),
                "omitted_dependencies": sorted(omitted),
                "extraneous_dependencies": sorted(extraneous),
                "unaccounted_accesses": sorted(unaccounted),
                "unattributed_accesses": sorted(unattributed_accesses),
                "attribution_status": (
                    "complete"
                    if not omitted and not extraneous and not unaccounted
                    else "incomplete"
                ),
            }
            return

        if kind == "technical_receipt_recorded":
            if self.phase != "active":
                raise ProtocolError("technical receipts cannot mutate a sealed case")
            if actor != manifest["verifier_key"]:
                raise ProtocolError("technical receipt signer is not the frozen verifier")
            payload = self._case_payload(
                payload,
                {
                    "result_id",
                    "artifact_digest",
                    "environment_digest",
                    "report_digest",
                    "status",
                    "mode",
                    "summary",
                },
                kind,
            )
            result_id = payload["result_id"]
            result = self.results.get(result_id)
            if result is None:
                raise ProtocolError("technical receipt cites an unknown result")
            if result_id in self.technical_receipts:
                raise ProtocolError("duplicate technical receipt for result")
            if payload["artifact_digest"] != result["payload"]["artifact_digest"]:
                raise ProtocolError("technical receipt cites the wrong result artifact")
            if payload["environment_digest"] != manifest["objective"]["environment_digest"]:
                raise ProtocolError("technical receipt used the wrong environment")
            _digest(payload["report_digest"], "technical_receipt.report_digest")
            if payload["status"] not in {"pass", "fail"}:
                raise ProtocolError("technical receipt status is invalid")
            _text(payload["mode"], "technical_receipt.mode", maximum=128)
            _text(payload["summary"], "technical_receipt.summary", maximum=1_000)
            self.technical_receipts[result_id] = {
                "payload": payload,
                "entry_hash": entry["entry_hash"],
            }
            return

        if kind == "community_evidence_sealed":
            if actor != self.clerk_key or self.phase != "active":
                raise ProtocolError("only the clerk can seal active community evidence")
            payload = self._case_payload(
                payload, {"result_id", "evidence_root", "attributed_handoffs"}, kind
            )
            result = self.results.get(payload["result_id"])
            receipt = self.technical_receipts.get(payload["result_id"])
            if result is None or receipt is None:
                raise ProtocolError("cannot seal without result and technical receipt")
            if receipt["payload"]["status"] != "pass":
                raise ProtocolError("cannot seal a technically failing result")
            if result["attribution_status"] != "complete":
                raise ProtocolError("cannot seal a result with incomplete attribution")
            if payload["attributed_handoffs"] != result["expected_dependencies"]:
                raise ProtocolError("evidence seal does not contain the exact causal closure")
            expected = self.expected_evidence_root(payload["result_id"])
            if payload["evidence_root"] != expected:
                raise ProtocolError("community evidence root does not match the transcript")
            self.sealed_result_id = payload["result_id"]
            self.evidence_root = expected
            self.phase = "reviewing"
            return

        if kind == "credit_ballot_committed":
            if self.phase != "reviewing" or self.review_commits_closed:
                raise ProtocolError("credit ballot commit phase is closed")
            reviewer_id = self._reviewer_id(actor)
            payload = self._case_payload(
                payload, {"evidence_root", "reviewer_id", "commitment"}, kind
            )
            if (
                payload["reviewer_id"] != reviewer_id
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("credit commitment is bound to the wrong reviewer or evidence")
            if reviewer_id in self.review_commits:
                raise ProtocolError("reviewer already committed a credit ballot")
            _digest(payload["commitment"], "credit commitment")
            self.review_commits[reviewer_id] = payload["commitment"]
            return

        if kind == "credit_commits_closed":
            if actor != self.clerk_key or self.phase != "reviewing" or self.review_commits_closed:
                raise ProtocolError("credit commit closure is out of phase")
            payload = self._case_payload(payload, {"evidence_root", "committed_reviewers"}, kind)
            if payload["evidence_root"] != self.evidence_root:
                raise ProtocolError("credit commit closure cites the wrong evidence")
            committed = _string_list(
                payload["committed_reviewers"], "committed_reviewers", nonempty=True
            )
            if committed != sorted(self.review_commits):
                raise ProtocolError("credit commit closure does not match recorded commitments")
            if len(committed) < manifest["policy"]["review_quorum"]:
                raise ProtocolError("credit review quorum has not committed")
            self.review_commits_closed = True
            return

        if kind == "credit_ballot_revealed":
            if self.phase != "reviewing" or not self.review_commits_closed:
                raise ProtocolError("credit ballot reveal is premature")
            reviewer_id = self._reviewer_id(actor)
            payload = self._case_payload(
                payload, {"evidence_root", "reviewer_id", "ballot", "salt"}, kind
            )
            if (
                payload["reviewer_id"] != reviewer_id
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("credit reveal is bound to the wrong reviewer or evidence")
            if reviewer_id in self.ballots:
                raise ProtocolError("reviewer already revealed a credit ballot")
            ballot = self._validate_credit_ballot(payload["ballot"], reviewer_id)
            expected = credit_ballot_commitment(ballot, payload["salt"])
            if self.review_commits.get(reviewer_id) != expected:
                raise ProtocolError("credit ballot reveal does not match its commitment")
            self.ballots[reviewer_id] = ballot
            return

        if kind == "allocation_finalized":
            if actor != self.clerk_key or self.phase != "reviewing" or self.allocation is not None:
                raise ProtocolError("allocation finalization is out of phase")
            if set(self.ballots) != set(self.review_commits):
                raise ProtocolError("every committed reviewer must reveal before allocation")
            expected = self.aggregate_credit_ballots()
            if payload != expected:
                raise ProtocolError("allocation does not match deterministic aggregation")
            self.allocation = expected
            self.phase = "allocated" if expected["status"] == "decided" else "inconclusive"
            return

        if kind == "mock_payout_plan_created":
            if actor != self.clerk_key or self.phase != "allocated" or self.payout_plan is not None:
                raise ProtocolError("mock payout plan is duplicate or out of phase")
            payload = self._case_payload(
                payload,
                {
                    "plan_id",
                    "simulation",
                    "appeal_status",
                    "allocation_digest",
                    "total_alpha_rao",
                    "legs",
                },
                kind,
            )
            if payload["simulation"] is not True or payload["appeal_status"] != "final_mock":
                raise ProtocolError("mock payout plan must be final_mock simulation")
            _text(payload["plan_id"], "mock payout plan id", maximum=128)
            allocation = self.allocation["allocation_bps"]
            if payload["allocation_digest"] != digest_object(allocation):
                raise ProtocolError("mock payout plan cites the wrong allocation")
            if payload["total_alpha_rao"] != manifest["economics"]["bounty_rao"]:
                raise ProtocolError("mock payout plan uses the wrong frozen bounty")
            expected_legs = payout_legs(manifest, allocation)
            if payload["legs"] != expected_legs:
                raise ProtocolError("mock payout legs do not match deterministic allocation")
            if sum(leg["amount_rao"] for leg in expected_legs) != payload["total_alpha_rao"]:
                raise ProtocolError("mock payout plan does not conserve Alpha-rao")
            self.payout_plan = payload
            self.phase = "mock_paying"
            return

        if kind == "mock_payout_leg_submitted":
            if actor != self.clerk_key or self.phase != "mock_paying":
                raise ProtocolError("mock payout submission is out of phase")
            payload = self._case_payload(
                payload, {"plan_id", "leg_id", "mock_reference", "chain_observed"}, kind
            )
            leg = self._payout_leg(payload)
            if leg["amount_rao"] == 0:
                raise ProtocolError("zero-amount mock payout legs have no payment event")
            if payload["chain_observed"] is not True:
                raise ProtocolError("submitted mock payout must be observed on the mock best chain")
            if payload["leg_id"] in self.payout_submitted:
                raise ProtocolError("mock payout leg was already submitted")
            expected_reference = f"mock:{payload['plan_id']}:{leg['leg_id']}"
            if payload["mock_reference"] != expected_reference:
                raise ProtocolError("mock payout reference is not deterministic")
            self.payout_submitted[payload["leg_id"]] = payload["mock_reference"]
            return

        if kind == "mock_payout_leg_confirmed":
            if actor != self.clerk_key or self.phase != "mock_paying":
                raise ProtocolError("mock payout confirmation is out of phase")
            payload = self._case_payload(
                payload,
                {"plan_id", "leg_id", "mock_reference", "finalized", "finalized_block"},
                kind,
            )
            self._payout_leg(payload)
            if self.payout_submitted.get(payload["leg_id"]) != payload["mock_reference"]:
                raise ProtocolError("mock payout confirmation has no matching submission")
            if payload["finalized"] is not True:
                raise ProtocolError("mock payout confirmation must declare finalized=true")
            _integer(payload["finalized_block"], "mock finalized block", 1, 10**18)
            if payload["leg_id"] in self.payout_confirmed:
                raise ProtocolError("mock payout leg was already confirmed")
            self.payout_confirmed.add(payload["leg_id"])
            expected_ids = {
                leg["leg_id"] for leg in self.payout_plan["legs"] if leg["amount_rao"] > 0
            }
            if self.payout_confirmed == expected_ids:
                self.phase = "mock_paid"
            return

        raise ProtocolError(f"unsupported community event kind: {kind}")

    def _payout_leg(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.payout_plan is None or payload["plan_id"] != self.payout_plan["plan_id"]:
            raise ProtocolError("mock payout event cites the wrong plan")
        matches = [leg for leg in self.payout_plan["legs"] if leg["leg_id"] == payload["leg_id"]]
        if len(matches) != 1:
            raise ProtocolError("mock payout event cites an unknown leg")
        return matches[0]

    def _validate_credit_ballot(self, value: Any, reviewer_id: str) -> dict[str, Any]:
        ballot = _exact(
            _mapping(value, "credit ballot"),
            {
                "case_id",
                "evidence_root",
                "reviewer_id",
                "decision",
                "shares_bps",
                "evidence_refs",
                "note",
            },
            "credit ballot",
        )
        if ballot["case_id"] != self.case_id or ballot["evidence_root"] != self.evidence_root:
            raise ProtocolError("credit ballot is bound to the wrong case")
        if ballot["reviewer_id"] != reviewer_id:
            raise ProtocolError("credit ballot reviewer does not match signer")
        if ballot["decision"] not in {"decided", "inconclusive"}:
            raise ProtocolError("credit ballot decision is invalid")
        participants = set(self._require_manifest()["participants"])
        shares = _mapping(ballot["shares_bps"], "credit ballot shares")
        refs = _mapping(ballot["evidence_refs"], "credit ballot evidence refs")
        if set(shares) != participants or set(refs) != participants:
            raise ProtocolError("credit ballot must cover every participant exactly once")
        total = 0
        result_closure = set(self.results[self.sealed_result_id]["expected_dependencies"])
        for participant_id in sorted(participants):
            share = _integer(shares[participant_id], f"shares_bps.{participant_id}", 0, 10_000)
            total += share
            evidence = _string_list(refs[participant_id], f"evidence_refs.{participant_id}")
            if any(item not in result_closure for item in evidence):
                raise ProtocolError("credit ballot cites evidence outside the sealed result")
            if any(
                self.handoffs[item]["payload"]["participant_id"] != participant_id
                for item in evidence
            ):
                raise ProtocolError("credit ballot assigns another participant's evidence")
            if share > 0 and not evidence:
                raise ProtocolError("every nonzero credit share needs causal evidence")
        if ballot["decision"] == "decided" and total != 10_000:
            raise ProtocolError("decided credit ballot shares must sum to 10000 bps")
        if ballot["decision"] == "inconclusive" and total != 0:
            raise ProtocolError("inconclusive credit ballot must allocate zero bps")
        _text(ballot["note"], "credit ballot note", maximum=2_000)
        return ballot

    def aggregate_credit_ballots(self) -> dict[str, Any]:
        manifest = self._require_manifest()
        decided = [ballot for ballot in self.ballots.values() if ballot["decision"] == "decided"]
        quorum = manifest["policy"]["review_quorum"]
        reason: str | None = None
        if len(self.ballots) < quorum or len(decided) < quorum:
            reason = "review_quorum_not_met"
        participants = sorted(manifest["participants"])
        per_participant = {
            participant: [ballot["shares_bps"][participant] for ballot in decided]
            for participant in participants
        }
        dispersion = max(
            (max(values) - min(values) for values in per_participant.values() if values),
            default=None,
        )
        if (
            reason is None
            and dispersion is not None
            and dispersion > manifest["policy"]["max_share_dispersion_bps"]
        ):
            reason = "reviewer_dispersion_exceeded"
        if reason is not None:
            return {
                "case_id": self.case_id,
                "evidence_root": self.evidence_root,
                "status": "inconclusive",
                "allocation_bps": None,
                "reveals": len(self.ballots),
                "decided_ballots": len(decided),
                "dispersion_bps": dispersion,
                "reason": reason,
            }
        medians = {participant: _median(values) for participant, values in per_participant.items()}
        return {
            "case_id": self.case_id,
            "evidence_root": self.evidence_root,
            "status": "decided",
            "allocation_bps": _normalize_bps(medians),
            "reveals": len(self.ballots),
            "decided_ballots": len(decided),
            "dispersion_bps": dispersion,
            "reason": None,
        }

    def join_brief(self, received_at: str | None = None) -> dict[str, Any]:
        manifest = self._require_manifest()
        now = parse_time(received_at, "join received_at") if received_at else None
        active_claims = []
        for claim_id, claim in sorted(self.claims.items()):
            active = claim["status"] == "active"
            if now is not None:
                active = active and now < parse_time(
                    claim["payload"]["expires_at"], "claim.expires_at"
                )
            if active:
                active_claims.append(
                    {
                        "claim_id": claim_id,
                        "route_id": claim["payload"]["route_id"],
                        "participant_id": claim["payload"]["participant_id"],
                        "expires_at": claim["payload"]["expires_at"],
                        "overlap": claim["payload"]["overlap"],
                    }
                )
        return {
            "protocol": manifest["protocol"],
            "simulation": True,
            "case_id": self.case_id,
            "objective": manifest["objective"],
            "frontier": self.current_frontier,
            "active_claims": active_claims,
            "open_obligations": self.current_frontier["open_obligations"],
            "instruction": (
                "Verify this case, choose one useful open route, work within its lease, "
                "and publish a reproducible handoff. Do not submit or move value."
            ),
        }

    def summary(self) -> dict[str, Any]:
        latest_results = {
            result_id: {
                "attribution_status": result["attribution_status"],
                "omitted_dependencies": result["omitted_dependencies"],
                "extraneous_dependencies": result["extraneous_dependencies"],
                "unaccounted_accesses": result["unaccounted_accesses"],
                "unattributed_accesses": result["unattributed_accesses"],
                "technical_status": (
                    self.technical_receipts[result_id]["payload"]["status"]
                    if result_id in self.technical_receipts
                    else None
                ),
            }
            for result_id, result in sorted(self.results.items())
        }
        payout_status = None
        if self.payout_plan is not None:
            leg_statuses = []
            for leg in self.payout_plan["legs"]:
                if leg["amount_rao"] == 0:
                    status = "zero_amount"
                elif leg["leg_id"] in self.payout_confirmed:
                    status = "simulated_finalized"
                elif leg["leg_id"] in self.payout_submitted:
                    status = "simulated_submitted"
                else:
                    status = "pending"
                leg_statuses.append(
                    {
                        "leg_id": leg["leg_id"],
                        "participant_id": leg["participant_id"],
                        "amount_rao": leg["amount_rao"],
                        "status": status,
                    }
                )
            payout_status = {
                "plan_id": self.payout_plan["plan_id"],
                "legs": len(self.payout_plan["legs"]),
                "payable_legs": sum(leg["amount_rao"] > 0 for leg in self.payout_plan["legs"]),
                "leg_statuses": leg_statuses,
                "submitted": len(self.payout_submitted),
                "confirmed": len(self.payout_confirmed),
                "total_alpha_rao": self.payout_plan["total_alpha_rao"],
                "status": ("simulated_paid" if self.phase == "mock_paid" else "simulated_pending"),
                "simulation": True,
            }
        return {
            "protocol": self._require_manifest()["protocol"],
            "simulation": True,
            "case_id": self.case_id,
            "phase": self.phase,
            "sessions": len(self.sessions),
            "messages": len(self.messages),
            "route_claims": len(self.claims),
            "handoffs": len(self.handoffs),
            "accepted_handoffs": sorted(self.accepted_handoffs),
            "frontier_id": self.current_frontier_id,
            "frontier_digest": self.current_frontier["frontier_digest"],
            "results": latest_results,
            "sealed_result_id": self.sealed_result_id,
            "evidence_root": self.evidence_root,
            "review_commits": len(self.review_commits),
            "review_reveals": len(self.ballots),
            "allocation": self.allocation,
            "payout": payout_status,
            "claim_ceiling": (
                "Protocol mechanics and mock payout conservation only; no mathematical solve, "
                "Conjectures.io submission, Alpha transfer, or chain finality occurred."
            ),
        }


class CommunitySession:
    def __init__(
        self,
        ledger: CommunityLedger,
        state: CommunityState,
        clerk_private_key: Ed25519PrivateKey,
    ) -> None:
        if public_key_text(clerk_private_key) != ledger.clerk_key:
            raise ProtocolError("community session clerk key does not match ledger")
        self.ledger = ledger
        self.state = state
        self._clerk_private_key = clerk_private_key

    @classmethod
    def open(
        cls,
        manifest: dict[str, Any],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> CommunitySession:
        ledger = CommunityLedger.create(manifest, clerk_private_key, received_at)
        state = CommunityState()
        state.apply(ledger.entries[0])
        return cls(ledger, state, clerk_private_key)

    @classmethod
    def resume(
        cls, ledger: CommunityLedger, clerk_private_key: Ed25519PrivateKey
    ) -> CommunitySession:
        return cls(ledger, replay_community_ledger(ledger), clerk_private_key)

    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        actor_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        entry = self.ledger.append(
            kind,
            payload,
            actor_private_key,
            self._clerk_private_key,
            received_at,
        )
        try:
            self.state.apply(entry)
        except Exception:
            self.ledger._rollback_last()
            raise
        return entry

    def seal(self, result_id: str, received_at: str) -> str:
        result = self.state.results[result_id]
        root = self.state.expected_evidence_root(result_id)
        self.append(
            "community_evidence_sealed",
            {
                "case_id": self.state.case_id,
                "result_id": result_id,
                "evidence_root": root,
                "attributed_handoffs": result["expected_dependencies"],
            },
            self._clerk_private_key,
            received_at,
        )
        return root

    def close_credit_commits(self, received_at: str) -> None:
        self.append(
            "credit_commits_closed",
            {
                "case_id": self.state.case_id,
                "evidence_root": self.state.evidence_root,
                "committed_reviewers": sorted(self.state.review_commits),
            },
            self._clerk_private_key,
            received_at,
        )

    def finalize_allocation(self, received_at: str) -> dict[str, Any]:
        allocation = self.state.aggregate_credit_ballots()
        self.append(
            "allocation_finalized",
            allocation,
            self._clerk_private_key,
            received_at,
        )
        return allocation

    def create_mock_payout_plan(self, plan_id: str, received_at: str) -> dict[str, Any]:
        allocation = self.state.allocation
        if allocation is None or allocation["status"] != "decided":
            raise ProtocolError("decided allocation is required for a mock payout plan")
        manifest = self.state._require_manifest()
        payload = {
            "case_id": self.state.case_id,
            "plan_id": plan_id,
            "simulation": True,
            "appeal_status": "final_mock",
            "allocation_digest": digest_object(allocation["allocation_bps"]),
            "total_alpha_rao": manifest["economics"]["bounty_rao"],
            "legs": payout_legs(manifest, allocation["allocation_bps"]),
        }
        self.append(
            "mock_payout_plan_created",
            payload,
            self._clerk_private_key,
            received_at,
        )
        return payload


def replay_community_ledger(ledger: CommunityLedger) -> CommunityState:
    ledger.verify()
    state = CommunityState()
    for entry in ledger.entries:
        state.apply(entry)
    return state
