from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import digest_object
from .crypto import public_key_text
from .errors import ProtocolError
from .ledger import Ledger
from .model import (
    HEX_64_RE,
    parse_time,
    roster_digest,
    validate_ballot,
    validate_case,
    validate_contribution,
    validate_reviewer,
    validate_technical_receipt,
)
from .moderation import aggregate_ballots, ballot_commitment, select_reviewers


def _exact_payload(payload: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ProtocolError(f"{name} payload has invalid fields")
    return payload


class ProtocolState:
    def __init__(self) -> None:
        self.case: dict[str, Any] | None = None
        self.clerk_key: str | None = None
        self.roster: list[dict[str, Any]] = []
        self.phase = "new"
        self.contributions: dict[str, dict[str, Any]] = {}
        self.technical_receipt: dict[str, Any] | None = None
        self.technical_entry_hash: str | None = None
        self.evidence_root: str | None = None
        self.assigned_reviewers: tuple[str, ...] = ()
        self.review_commits: dict[str, str] = {}
        self.commits_closed = False
        self.ballots: dict[str, dict[str, Any]] = {}
        self.decision: dict[str, Any] | None = None

    def _require_case(self) -> dict[str, Any]:
        if self.case is None:
            raise ProtocolError("case is not open")
        return self.case

    def _deadline(self, name: str):
        return parse_time(self._require_case()["deadlines"][name], f"deadline.{name}")

    def _before_or_at(self, received_at: str, deadline: str) -> None:
        if parse_time(received_at, "entry.received_at") > self._deadline(deadline):
            raise ProtocolError(f"event arrived after the {deadline} deadline")

    @property
    def contribution_ids(self) -> set[str]:
        return set(self.contributions)

    def expected_evidence_root(self) -> str:
        case = self._require_case()
        if self.technical_entry_hash is None:
            raise ProtocolError("technical receipt is missing")
        contribution_entries = [
            {"contribution_id": contribution_id, "entry_hash": record["entry_hash"]}
            for contribution_id, record in sorted(self.contributions.items())
        ]
        return digest_object(
            {
                "domain": "boule-evidence-root-v1",
                "case_id": case["case_id"],
                "contributions": contribution_entries,
                "technical_receipt_entry_hash": self.technical_entry_hash,
            }
        )

    def apply(self, entry: dict[str, Any]) -> None:
        kind = entry["event"]["kind"]
        actor = entry["event"]["actor"]
        payload = entry["event"]["payload"]
        received_at = entry["received_at"]

        if kind == "case_opened":
            if self.phase != "new" or entry["seq"] != 0:
                raise ProtocolError("case may be opened exactly once at genesis")
            payload = _exact_payload(payload, {"clerk_key", "case", "reviewers"}, kind)
            if actor != payload["clerk_key"]:
                raise ProtocolError("case must be opened by its clerk")
            case = validate_case(payload["case"])
            if not isinstance(payload["reviewers"], list):
                raise ProtocolError("reviewer roster must be a list")
            roster = [validate_reviewer(item) for item in payload["reviewers"]]
            if roster_digest(roster) != case["review_policy"]["roster_digest"]:
                raise ProtocolError("reviewer roster does not match the frozen digest")
            self.case = case
            self.clerk_key = actor
            self.roster = roster
            self.phase = "active"
            return

        case = self._require_case()
        if kind == "contribution_added":
            if self.phase != "active":
                raise ProtocolError("contributions are closed")
            self._before_or_at(received_at, "submission")
            contribution = validate_contribution(payload, case)
            expected_actor = case["agents"][contribution["agent_id"]]
            if actor != expected_actor:
                raise ProtocolError("contribution signer does not match its agent")
            contribution_id = contribution["contribution_id"]
            if contribution_id in self.contributions:
                raise ProtocolError("duplicate contribution ID")
            missing = set(contribution["depends_on"]) - self.contribution_ids
            if missing:
                raise ProtocolError(f"contribution has unknown dependencies: {sorted(missing)}")
            self.contributions[contribution_id] = {
                "payload": contribution,
                "entry_hash": entry["entry_hash"],
            }
            return

        if kind == "technical_receipt_recorded":
            if self.phase != "active" or self.technical_receipt is not None:
                raise ProtocolError("technical receipt is duplicate or out of phase")
            self._before_or_at(received_at, "review_commit")
            if actor != case["verifier_key"]:
                raise ProtocolError("technical receipt signer is not the frozen verifier")
            self.technical_receipt = validate_technical_receipt(payload, case)
            self.technical_entry_hash = entry["entry_hash"]
            return

        if kind == "evidence_sealed":
            if self.phase != "active" or self.evidence_root is not None:
                raise ProtocolError("evidence is duplicate or out of phase")
            self._before_or_at(received_at, "review_commit")
            if actor != self.clerk_key:
                raise ProtocolError("only the clerk can seal evidence")
            payload = _exact_payload(
                payload,
                {
                    "case_id",
                    "evidence_root",
                    "contribution_ids",
                    "technical_report_digest",
                    "artifact_digest",
                },
                kind,
            )
            if payload["case_id"] != case["case_id"]:
                raise ProtocolError("evidence seal belongs to another case")
            if self.technical_receipt is None or self.technical_receipt["status"] != "pass":
                raise ProtocolError("evidence cannot be sealed without a passing technical receipt")
            contributing_agents = {
                record["payload"]["agent_id"] for record in self.contributions.values()
            }
            if contributing_agents != set(case["agents"]):
                raise ProtocolError("both agents need at least one admissible contribution")
            if payload["contribution_ids"] != sorted(self.contribution_ids):
                raise ProtocolError("evidence seal must list every contribution exactly once")
            if payload["technical_report_digest"] != self.technical_receipt["report_digest"]:
                raise ProtocolError("evidence seal cites the wrong technical report")
            if payload["artifact_digest"] != self.technical_receipt["artifact_digest"]:
                raise ProtocolError("evidence seal cites the wrong final artifact")
            expected_root = self.expected_evidence_root()
            if payload["evidence_root"] != expected_root:
                raise ProtocolError("evidence root does not match the signed transcript")
            self.evidence_root = expected_root
            self.phase = "sealed"
            return

        if kind == "reviewers_assigned":
            if self.phase != "sealed":
                raise ProtocolError("reviewer assignment is out of phase")
            self._before_or_at(received_at, "review_commit")
            if actor != self.clerk_key:
                raise ProtocolError("only the clerk can publish reviewer assignment")
            payload = _exact_payload(
                payload, {"case_id", "evidence_root", "seed", "reviewers"}, kind
            )
            if (
                payload["case_id"] != case["case_id"]
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("reviewer assignment is bound to the wrong evidence")
            expected = select_reviewers(case, self.roster, payload["seed"], self.evidence_root)
            if payload["reviewers"] != list(expected):
                raise ProtocolError("reviewer assignment is not the deterministic result")
            self.assigned_reviewers = expected
            self.phase = "reviewing"
            return

        if kind == "review_committed":
            if self.phase != "reviewing" or self.commits_closed:
                raise ProtocolError("review commit phase is closed")
            self._before_or_at(received_at, "review_commit")
            payload = _exact_payload(payload, {"case_id", "evidence_root", "commitment"}, kind)
            if actor not in self.assigned_reviewers:
                raise ProtocolError("reviewer was not assigned")
            if actor in self.review_commits:
                raise ProtocolError("reviewer already committed")
            if (
                payload["case_id"] != case["case_id"]
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("review commitment is bound to the wrong case")
            if (
                not isinstance(payload["commitment"], str)
                or HEX_64_RE.fullmatch(payload["commitment"]) is None
            ):
                raise ProtocolError("review commitment must be a SHA-256 digest")
            self.review_commits[actor] = payload["commitment"]
            return

        if kind == "review_commit_phase_closed":
            if self.phase != "reviewing" or self.commits_closed:
                raise ProtocolError("review commit close is duplicate or out of phase")
            self._before_or_at(received_at, "review_commit")
            if actor != self.clerk_key:
                raise ProtocolError("only the clerk can close review commits")
            payload = _exact_payload(
                payload, {"case_id", "evidence_root", "committed_reviewers"}, kind
            )
            if (
                payload["case_id"] != case["case_id"]
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("review close is bound to the wrong case")
            if payload["committed_reviewers"] != sorted(self.review_commits):
                raise ProtocolError("review close does not match recorded commitments")
            if set(self.review_commits) != set(self.assigned_reviewers):
                raise ProtocolError("every assigned reviewer must commit before reveal")
            self.commits_closed = True
            return

        if kind == "review_revealed":
            if self.phase != "reviewing" or not self.commits_closed:
                raise ProtocolError("review reveal is premature or out of phase")
            self._before_or_at(received_at, "review_reveal")
            payload = _exact_payload(payload, {"case_id", "evidence_root", "ballot", "salt"}, kind)
            if actor not in self.assigned_reviewers or actor not in self.review_commits:
                raise ProtocolError("reviewer has no valid assignment and commitment")
            if actor in self.ballots:
                raise ProtocolError("reviewer already revealed")
            if (
                payload["case_id"] != case["case_id"]
                or payload["evidence_root"] != self.evidence_root
            ):
                raise ProtocolError("review reveal is bound to the wrong case")
            ballot = validate_ballot(
                payload["ballot"], case, self.evidence_root, actor, self.contribution_ids
            )
            if ballot_commitment(ballot, payload["salt"]) != self.review_commits[actor]:
                raise ProtocolError("review reveal does not match its commitment")
            self.ballots[actor] = ballot
            return

        if kind == "provisional_decision_recorded":
            if self.phase != "reviewing" or not self.commits_closed or self.decision is not None:
                raise ProtocolError("provisional decision is duplicate or out of phase")
            if actor != self.clerk_key:
                raise ProtocolError("only the clerk can record the deterministic decision")
            reveal_deadline = self._deadline("review_reveal")
            received = parse_time(received_at, "entry.received_at")
            if len(self.ballots) < len(self.assigned_reviewers) and received < reveal_deadline:
                raise ProtocolError("cannot finalize while valid reveal time remains")
            if received > self._deadline("appeal"):
                raise ProtocolError("cannot record a decision after the appeal deadline")
            expected = aggregate_ballots(
                case, self.evidence_root, list(self.ballots.values()), self.contribution_ids
            )
            if payload != expected:
                raise ProtocolError("provisional decision does not match deterministic aggregation")
            self.decision = expected
            self.phase = "provisional"
            return

        raise ProtocolError(f"unsupported event kind: {kind}")

    def summary(self) -> dict[str, Any]:
        case = self._require_case()
        return {
            "protocol": case["protocol"],
            "case_id": case["case_id"],
            "phase": self.phase,
            "transcript_status": (
                "provisional_decision_recorded" if self.decision is not None else "partial"
            ),
            "contributions": len(self.contributions),
            "technical_status": self.technical_receipt["status"]
            if self.technical_receipt
            else None,
            "evidence_root": self.evidence_root,
            "assigned_reviewers": list(self.assigned_reviewers),
            "review_commits": len(self.review_commits),
            "review_reveals": len(self.ballots),
            "decision": self.decision,
        }


class ProtocolSession:
    def __init__(
        self,
        ledger: Ledger,
        state: ProtocolState,
        clerk_private_key: Ed25519PrivateKey,
    ) -> None:
        if public_key_text(clerk_private_key) != ledger.clerk_key:
            raise ProtocolError("session clerk key does not match ledger")
        self.ledger = ledger
        self.state = state
        self._clerk_private_key = clerk_private_key

    @classmethod
    def open(
        cls,
        case: dict[str, Any],
        reviewers: list[dict[str, Any]],
        clerk_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> ProtocolSession:
        ledger = Ledger.create(case, reviewers, clerk_private_key, received_at)
        state = ProtocolState()
        state.apply(ledger.entries[0])
        return cls(ledger, state, clerk_private_key)

    def _append(
        self,
        kind: str,
        payload: dict[str, Any],
        actor_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        entry = self.ledger.append(
            kind, payload, actor_private_key, self._clerk_private_key, received_at
        )
        try:
            self.state.apply(entry)
        except Exception:
            self.ledger._rollback_last()
            raise
        return entry

    def add_contribution(
        self,
        contribution: dict[str, Any],
        agent_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        return self._append("contribution_added", contribution, agent_private_key, received_at)

    def record_technical_receipt(
        self,
        receipt: dict[str, Any],
        verifier_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> dict[str, Any]:
        return self._append(
            "technical_receipt_recorded", receipt, verifier_private_key, received_at
        )

    def seal_evidence(self, received_at: str) -> str:
        if self.state.technical_receipt is None:
            raise ProtocolError("technical receipt is missing")
        root = self.state.expected_evidence_root()
        receipt = self.state.technical_receipt
        payload = {
            "case_id": self.state.case["case_id"],
            "evidence_root": root,
            "contribution_ids": sorted(self.state.contribution_ids),
            "technical_report_digest": receipt["report_digest"],
            "artifact_digest": receipt["artifact_digest"],
        }
        self._append("evidence_sealed", payload, self._clerk_private_key, received_at)
        return root

    def assign_reviewers(self, seed: str, received_at: str) -> tuple[str, ...]:
        case = self.state._require_case()
        if self.state.evidence_root is None:
            raise ProtocolError("evidence is not sealed")
        assigned = select_reviewers(case, self.state.roster, seed, self.state.evidence_root)
        payload = {
            "case_id": case["case_id"],
            "evidence_root": self.state.evidence_root,
            "seed": seed,
            "reviewers": list(assigned),
        }
        self._append("reviewers_assigned", payload, self._clerk_private_key, received_at)
        return assigned

    def commit_review(
        self,
        ballot: dict[str, Any],
        salt: str,
        reviewer_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> str:
        case = self.state._require_case()
        reviewer_id = public_key_text(reviewer_private_key)
        validate_ballot(
            ballot,
            case,
            self.state.evidence_root,
            reviewer_id,
            self.state.contribution_ids,
        )
        commitment = ballot_commitment(ballot, salt)
        payload = {
            "case_id": case["case_id"],
            "evidence_root": self.state.evidence_root,
            "commitment": commitment,
        }
        self._append("review_committed", payload, reviewer_private_key, received_at)
        return commitment

    def close_review_commits(self, received_at: str) -> None:
        case = self.state._require_case()
        payload = {
            "case_id": case["case_id"],
            "evidence_root": self.state.evidence_root,
            "committed_reviewers": sorted(self.state.review_commits),
        }
        self._append("review_commit_phase_closed", payload, self._clerk_private_key, received_at)

    def reveal_review(
        self,
        ballot: dict[str, Any],
        salt: str,
        reviewer_private_key: Ed25519PrivateKey,
        received_at: str,
    ) -> None:
        case = self.state._require_case()
        payload = {
            "case_id": case["case_id"],
            "evidence_root": self.state.evidence_root,
            "ballot": ballot,
            "salt": salt,
        }
        self._append("review_revealed", payload, reviewer_private_key, received_at)

    def finalize(self, received_at: str) -> dict[str, Any]:
        case = self.state._require_case()
        decision = aggregate_ballots(
            case,
            self.state.evidence_root,
            list(self.state.ballots.values()),
            self.state.contribution_ids,
        )
        self._append(
            "provisional_decision_recorded",
            decision,
            self._clerk_private_key,
            received_at,
        )
        return decision


def replay_ledger(ledger: Ledger) -> ProtocolState:
    ledger.verify()
    state = ProtocolState()
    for entry in ledger.entries:
        state.apply(entry)
    return state
