"""Frozen disclosure and permitted-use notice bound to every Boule session."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import digest_object
from .errors import ProtocolError

POLICY_SCHEMA = "boule-case-policy/0.1"
DISCLOSURE_MODES = frozenset({"public", "commitment_only", "committee"})


def build_case_policy(problem: dict[str, Any], disclosure: str) -> dict[str, Any]:
    if disclosure not in DISCLOSURE_MODES:
        raise ProtocolError("disclosure must be public, commitment_only, or committee")
    try:
        problem_id = problem["problem_id"]
        task_commitment = problem["task"]["task_commitment"]
        base_revision = problem["task"]["formal_repository_pin"]
    except (KeyError, TypeError) as exc:
        raise ProtocolError("problem manifest cannot anchor a case policy") from exc
    return {
        "schema": POLICY_SCHEMA,
        "problem_id": problem_id,
        "task_commitment": task_commitment,
        "base_revision": base_revision,
        "participant_admission": "open_self_declared",
        "disclosure": disclosure,
        "event_visibility": "public_metadata",
        "permitted_use": "case_research_and_verification_only",
        "submission_authority": "maintainer_after_independent_verification",
        "attribution_rule": "declared_dependencies_then_causal_review",
        "settlement": "manual_after_appeal",
        "legal_status": "protocol_notice_requires_external_legal_terms",
    }


def validate_case_policy(policy: Any, problem: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise ProtocolError("case policy must be an object")
    expected = build_case_policy(problem, policy.get("disclosure"))
    if policy != expected:
        raise ProtocolError("case policy has invalid or conflicting fields")
    return policy


def load_case_policy(path: str | Path, problem: dict[str, Any]) -> dict[str, Any]:
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError("case policy is missing or invalid JSON") from exc
    return validate_case_policy(policy, problem)


def policy_digest(policy: dict[str, Any]) -> str:
    return f"sha256:{digest_object(policy)}"
