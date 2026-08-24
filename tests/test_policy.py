from __future__ import annotations

import pytest

from boule.errors import ProtocolError
from boule.policy import build_case_policy, policy_digest, validate_case_policy


def problem():
    return {
        "problem_id": "conjectures:task-1",
        "task": {"task_commitment": "sha256:" + "a" * 64, "formal_repository_pin": "b" * 40},
    }


def test_policy_is_frozen_to_problem_and_has_no_legal_overclaim():
    policy = build_case_policy(problem(), "commitment_only")
    assert policy_digest(policy).startswith("sha256:")
    assert policy["submission_authority"] == "maintainer_after_independent_verification"
    assert policy["legal_status"] == "protocol_notice_requires_external_legal_terms"
    assert validate_case_policy(policy, problem()) == policy


def test_policy_changes_fail_closed():
    policy = build_case_policy(problem(), "committee")
    policy["permitted_use"] = "anything"
    with pytest.raises(ProtocolError, match="conflicting"):
        validate_case_policy(policy, problem())
