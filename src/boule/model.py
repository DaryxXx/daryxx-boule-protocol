from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

from .canonical import digest_object
from .crypto import load_public_key
from .errors import ProtocolError

PROTOCOL = "boule/0.1"
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
CONTRIBUTION_KINDS = {
    "idea",
    "lemma",
    "counterexample",
    "experiment",
    "source",
    "patch",
    "debugging",
    "integration",
    "verification",
    "dead_end",
}
VISIBILITIES = {"public", "committee", "hash_only"}


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{name} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProtocolError(f"{name} fields differ: missing={missing}, extra={extra}")


def _text(value: Any, name: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ProtocolError(f"{name} must be non-empty text up to {max_length} characters")
    return value


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ProtocolError(f"{name} must be an integer in [{low}, {high}]")
    return value


def _hex_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or HEX_64_RE.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def parse_time(value: Any, name: str) -> datetime:
    text = _text(value, name, max_length=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProtocolError(f"{name} must include a timezone")
    return parsed


def validate_case(case: Any) -> dict[str, Any]:
    case = _mapping(case, "case")
    expected = {
        "protocol",
        "case_id",
        "title",
        "objective",
        "agents",
        "agent_controllers",
        "verifier_key",
        "criteria_weights_bps",
        "collaboration_floor_bps",
        "disclosure",
        "economics",
        "review_policy",
        "deadlines",
    }
    _exact_keys(case, expected, "case")
    if case["protocol"] != PROTOCOL:
        raise ProtocolError(f"unsupported protocol: {case['protocol']!r}")
    case_id = _text(case["case_id"], "case.case_id", max_length=128)
    if CASE_ID_RE.fullmatch(case_id) is None:
        raise ProtocolError("case.case_id has an invalid format")
    _text(case["title"], "case.title", max_length=240)

    objective = _mapping(case["objective"], "case.objective")
    for required in ("type", "statement", "base_commit", "environment_digest", "verifier"):
        if required not in objective:
            raise ProtocolError(f"case.objective is missing {required}")
        _text(objective[required], f"case.objective.{required}")

    agents = _mapping(case["agents"], "case.agents")
    if len(agents) != 2:
        raise ProtocolError("case.agents must contain exactly two agents")
    for agent_id, key in agents.items():
        _text(agent_id, "agent id", max_length=64)
        load_public_key(key)

    controllers = _mapping(case["agent_controllers"], "case.agent_controllers")
    if set(controllers) != set(agents):
        raise ProtocolError("agent controller IDs must match agent IDs")
    for controller in controllers.values():
        _text(controller, "agent controller", max_length=128)
    if len(set(controllers.values())) != len(controllers):
        raise ProtocolError("the two agents must declare distinct controllers")

    load_public_key(case["verifier_key"])

    criteria = _mapping(case["criteria_weights_bps"], "case.criteria_weights_bps")
    if not 2 <= len(criteria) <= 12:
        raise ProtocolError("case must define between 2 and 12 criteria")
    total_weight = 0
    for name, weight in criteria.items():
        _text(name, "criterion name", max_length=64)
        total_weight += _integer(weight, f"weight for {name}", 1, 10_000)
    if total_weight != 10_000:
        raise ProtocolError("criterion weights must sum to 10000 basis points")

    _integer(case["collaboration_floor_bps"], "collaboration_floor_bps", 0, 4_999)
    _mapping(case["disclosure"], "case.disclosure")
    _mapping(case["economics"], "case.economics")

    policy = _mapping(case["review_policy"], "case.review_policy")
    _exact_keys(
        policy,
        {
            "panel_size",
            "quorum",
            "max_dispersion_bps",
            "min_calibration_passes",
            "min_calibration_total",
            "min_reveal_rate_bps",
            "seed_commitment",
            "roster_digest",
        },
        "case.review_policy",
    )
    panel_size = _integer(policy["panel_size"], "panel_size", 3, 21)
    if panel_size % 2 == 0:
        raise ProtocolError("panel_size must be odd")
    quorum = _integer(policy["quorum"], "quorum", 3, panel_size)
    if quorum > panel_size:
        raise ProtocolError("quorum cannot exceed panel_size")
    minimum_total = _integer(policy["min_calibration_total"], "min_calibration_total", 1, 100)
    minimum_passes = _integer(
        policy["min_calibration_passes"], "min_calibration_passes", 1, minimum_total
    )
    if minimum_passes > minimum_total:
        raise ProtocolError("minimum calibration passes cannot exceed total")
    _integer(policy["min_reveal_rate_bps"], "min_reveal_rate_bps", 0, 10_000)
    _integer(policy["max_dispersion_bps"], "max_dispersion_bps", 0, 10_000)
    _hex_digest(policy["seed_commitment"], "seed_commitment")
    _hex_digest(policy["roster_digest"], "roster_digest")

    deadlines = _mapping(case["deadlines"], "case.deadlines")
    _exact_keys(
        deadlines,
        {"submission", "review_commit", "review_reveal", "appeal"},
        "case.deadlines",
    )
    times = [
        parse_time(deadlines[name], f"deadline.{name}")
        for name in ("submission", "review_commit", "review_reveal", "appeal")
    ]
    if times != sorted(times) or len(set(times)) != len(times):
        raise ProtocolError("deadlines must be strictly increasing")
    return case


def validate_reviewer(profile: Any) -> dict[str, Any]:
    profile = _mapping(profile, "reviewer")
    _exact_keys(
        profile,
        {
            "reviewer_id",
            "controller_id",
            "status",
            "calibration_passes",
            "calibration_total",
            "reveal_rate_bps",
            "conflicts",
        },
        "reviewer",
    )
    load_public_key(profile["reviewer_id"])
    _text(profile["controller_id"], "reviewer.controller_id", max_length=128)
    if profile["status"] not in {"probation", "active", "suspended"}:
        raise ProtocolError("reviewer.status is invalid")
    total = _integer(profile["calibration_total"], "calibration_total", 0, 100_000)
    passes = _integer(profile["calibration_passes"], "calibration_passes", 0, total)
    if passes > total:
        raise ProtocolError("calibration passes cannot exceed total")
    _integer(profile["reveal_rate_bps"], "reveal_rate_bps", 0, 10_000)
    conflicts = profile["conflicts"]
    if not isinstance(conflicts, list) or any(not isinstance(item, str) for item in conflicts):
        raise ProtocolError("reviewer.conflicts must be a list of case IDs")
    if len(conflicts) != len(set(conflicts)):
        raise ProtocolError("reviewer.conflicts contains duplicates")
    return profile


def roster_digest(roster: list[dict[str, Any]]) -> str:
    validated = [validate_reviewer(dict(item)) for item in roster]
    ids = [item["reviewer_id"] for item in validated]
    if len(ids) != len(set(ids)):
        raise ProtocolError("reviewer roster contains duplicate keys")
    return digest_object(sorted(validated, key=lambda item: item["reviewer_id"]))


def validate_contribution(value: Any, case: dict[str, Any]) -> dict[str, Any]:
    value = _mapping(value, "contribution")
    _exact_keys(
        value,
        {
            "case_id",
            "contribution_id",
            "agent_id",
            "kind",
            "summary",
            "artifact_digest",
            "depends_on",
            "visibility",
        },
        "contribution",
    )
    if value["case_id"] != case["case_id"]:
        raise ProtocolError("contribution belongs to another case")
    _text(value["contribution_id"], "contribution_id", max_length=128)
    if value["agent_id"] not in case["agents"]:
        raise ProtocolError("contribution agent is not a case participant")
    if value["kind"] not in CONTRIBUTION_KINDS:
        raise ProtocolError("contribution kind is invalid")
    _text(value["summary"], "contribution.summary", max_length=2_000)
    _hex_digest(value["artifact_digest"], "contribution.artifact_digest")
    dependencies = value["depends_on"]
    if not isinstance(dependencies, list) or any(
        not isinstance(item, str) for item in dependencies
    ):
        raise ProtocolError("contribution.depends_on must be a list of IDs")
    if len(dependencies) != len(set(dependencies)):
        raise ProtocolError("contribution.depends_on contains duplicates")
    if value["contribution_id"] in dependencies:
        raise ProtocolError("a contribution cannot depend on itself")
    if value["visibility"] not in VISIBILITIES:
        raise ProtocolError("contribution visibility is invalid")
    return value


def validate_technical_receipt(value: Any, case: dict[str, Any]) -> dict[str, Any]:
    value = _mapping(value, "technical receipt")
    _exact_keys(
        value,
        {
            "case_id",
            "artifact_digest",
            "environment_digest",
            "report_digest",
            "status",
            "mode",
            "summary",
        },
        "technical receipt",
    )
    if value["case_id"] != case["case_id"]:
        raise ProtocolError("technical receipt belongs to another case")
    for field in ("artifact_digest", "environment_digest", "report_digest"):
        _hex_digest(value[field], f"technical_receipt.{field}")
    if value["environment_digest"] != case["objective"]["environment_digest"]:
        raise ProtocolError("technical receipt used the wrong frozen environment")
    if value["environment_digest"] != case["objective"]["environment_digest"]:
        raise ProtocolError("technical receipt used the wrong frozen environment")
    if value["status"] not in {"pass", "fail"}:
        raise ProtocolError("technical receipt status is invalid")
    _text(value["mode"], "technical_receipt.mode", max_length=64)
    _text(value["summary"], "technical_receipt.summary", max_length=1_000)
    return value


def validate_ballot(
    value: Any,
    case: dict[str, Any],
    evidence_root: str,
    reviewer_id: str,
    contribution_ids: set[str],
) -> dict[str, Any]:
    value = _mapping(value, "ballot")
    _exact_keys(
        value,
        {
            "case_id",
            "evidence_root",
            "reviewer_id",
            "decision",
            "confidence_bps",
            "scores",
            "findings",
        },
        "ballot",
    )
    if value["case_id"] != case["case_id"] or value["evidence_root"] != evidence_root:
        raise ProtocolError("ballot is not bound to this sealed case")
    if value["reviewer_id"] != reviewer_id:
        raise ProtocolError("ballot reviewer does not match signer")
    if value["decision"] not in {"decided", "inconclusive"}:
        raise ProtocolError("ballot decision is invalid")
    _integer(value["confidence_bps"], "ballot.confidence_bps", 0, 10_000)

    criteria = set(case["criteria_weights_bps"])
    agents = set(case["agents"])
    scores = _mapping(value["scores"], "ballot.scores")
    findings = _mapping(value["findings"], "ballot.findings")
    if set(scores) != criteria or set(findings) != criteria:
        raise ProtocolError("ballot must score and explain every frozen criterion")
    for criterion in criteria:
        criterion_scores = _mapping(scores[criterion], f"scores.{criterion}")
        if set(criterion_scores) != agents:
            raise ProtocolError(f"scores.{criterion} must contain exactly both agents")
        for agent, score in criterion_scores.items():
            _integer(score, f"scores.{criterion}.{agent}", 0, 4)
        finding = _mapping(findings[criterion], f"findings.{criterion}")
        _exact_keys(finding, {"evidence_refs", "note"}, f"findings.{criterion}")
        refs = finding["evidence_refs"]
        if not isinstance(refs, list) or not refs:
            raise ProtocolError(f"findings.{criterion}.evidence_refs cannot be empty")
        if any(ref not in contribution_ids for ref in refs):
            raise ProtocolError(f"findings.{criterion} cites unsealed evidence")
        if len(refs) != len(set(refs)):
            raise ProtocolError(f"findings.{criterion} contains duplicate evidence")
        _text(finding["note"], f"findings.{criterion}.note", max_length=1_000)
    return value


def validate_finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProtocolError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ProtocolError(f"{name} must be finite")
    return result
