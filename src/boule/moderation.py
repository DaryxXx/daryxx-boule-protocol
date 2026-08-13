from __future__ import annotations

from typing import Any

from .canonical import digest_object
from .errors import ProtocolError
from .model import HEX_64_RE, validate_ballot, validate_reviewer


def seed_commitment(seed: str) -> str:
    if not isinstance(seed, str) or HEX_64_RE.fullmatch(seed) is None:
        raise ProtocolError("review seed must be 32 bytes encoded as lowercase hex")
    return digest_object({"domain": "boule-review-seed-v1", "seed": seed})


def select_reviewers(
    case: dict[str, Any],
    roster: list[dict[str, Any]],
    seed: str,
    evidence_root: str,
) -> tuple[str, ...]:
    policy = case["review_policy"]
    if seed_commitment(seed) != policy["seed_commitment"]:
        raise ProtocolError("review seed does not match the case commitment")
    if not isinstance(evidence_root, str) or HEX_64_RE.fullmatch(evidence_root) is None:
        raise ProtocolError("evidence root must be a SHA-256 digest")

    excluded_controllers = set(case["agent_controllers"].values())
    candidates: list[tuple[str, dict[str, Any]]] = []
    for raw_profile in roster:
        profile = validate_reviewer(raw_profile)
        eligible = (
            profile["status"] == "active"
            and profile["calibration_total"] >= policy["min_calibration_total"]
            and profile["calibration_passes"] >= policy["min_calibration_passes"]
            and profile["reveal_rate_bps"] >= policy["min_reveal_rate_bps"]
            and case["case_id"] not in profile["conflicts"]
            and profile["controller_id"] not in excluded_controllers
        )
        if not eligible:
            continue
        score = digest_object(
            {
                "domain": "boule-review-assignment-v1",
                "seed": seed,
                "case_id": case["case_id"],
                "evidence_root": evidence_root,
                "reviewer_id": profile["reviewer_id"],
            }
        )
        candidates.append((score, profile))

    selected: list[str] = []
    selected_controllers: set[str] = set()
    for _, profile in sorted(candidates, key=lambda item: (item[0], item[1]["reviewer_id"])):
        if profile["controller_id"] in selected_controllers:
            continue
        selected.append(profile["reviewer_id"])
        selected_controllers.add(profile["controller_id"])
        if len(selected) == policy["panel_size"]:
            return tuple(selected)
    raise ProtocolError("eligible independent reviewer pool cannot fill the frozen panel")


def ballot_commitment(ballot: dict[str, Any], salt: str) -> str:
    if not isinstance(salt, str) or HEX_64_RE.fullmatch(salt) is None:
        raise ProtocolError("ballot salt must be 32 bytes encoded as lowercase hex")
    return digest_object({"domain": "boule-ballot-commit-v1", "ballot": ballot, "salt": salt})


def ballot_causal_share_bps(ballot: dict[str, Any], case: dict[str, Any]) -> int | None:
    if ballot["decision"] != "decided":
        return None
    agent_a, agent_b = sorted(case["agents"])
    weighted_a = 0
    weighted_b = 0
    for criterion, weight in case["criteria_weights_bps"].items():
        weighted_a += weight * ballot["scores"][criterion][agent_a]
        weighted_b += weight * ballot["scores"][criterion][agent_b]
    denominator = weighted_a + weighted_b
    if denominator == 0:
        return None
    return (10_000 * weighted_a + denominator // 2) // denominator


def _median_int(values: list[int]) -> int:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) // 2


def aggregate_ballots(
    case: dict[str, Any],
    evidence_root: str,
    ballots: list[dict[str, Any]],
    contribution_ids: set[str],
) -> dict[str, Any]:
    seen: set[str] = set()
    shares: list[int] = []
    confidences: list[int] = []
    for ballot in ballots:
        reviewer_id = ballot.get("reviewer_id") if isinstance(ballot, dict) else ""
        validate_ballot(ballot, case, evidence_root, reviewer_id, contribution_ids)
        if reviewer_id in seen:
            raise ProtocolError("duplicate reviewer ballot")
        seen.add(reviewer_id)
        share = ballot_causal_share_bps(ballot, case)
        if share is not None:
            shares.append(share)
            confidences.append(ballot["confidence_bps"])

    policy = case["review_policy"]
    reason: str | None = None
    if len(ballots) < policy["quorum"]:
        reason = "review_quorum_not_met"
    elif len(shares) < 2:
        reason = "insufficient_decided_ballots"

    dispersion = max(shares) - min(shares) if shares else None
    if reason is None and dispersion is not None and dispersion > policy["max_dispersion_bps"]:
        reason = "reviewer_dispersion_exceeded"

    if reason is not None:
        return {
            "case_id": case["case_id"],
            "evidence_root": evidence_root,
            "status": "inconclusive",
            "allocation_bps": None,
            "median_causal_share_bps": _median_int(shares) if shares else None,
            "dispersion_bps": dispersion,
            "reveals": len(ballots),
            "decided_ballots": len(shares),
            "confidence_bps": _median_int(confidences) if confidences else None,
            "reason": reason,
        }

    median_share = _median_int(shares)
    floor = case["collaboration_floor_bps"]
    distributable = 10_000 - 2 * floor
    agent_a, agent_b = sorted(case["agents"])
    allocation_a = floor + (distributable * median_share + 5_000) // 10_000
    allocation_b = 10_000 - allocation_a
    return {
        "case_id": case["case_id"],
        "evidence_root": evidence_root,
        "status": "decided",
        "allocation_bps": {agent_a: allocation_a, agent_b: allocation_b},
        "median_causal_share_bps": median_share,
        "dispersion_bps": dispersion,
        "reveals": len(ballots),
        "decided_ballots": len(shares),
        "confidence_bps": _median_int(confidences),
        "reason": None,
    }
