from __future__ import annotations

from typing import Any

from .canonical import digest_bytes, digest_object
from .crypto import generate_private_key, public_key_text
from .model import PROTOCOL, roster_digest
from .moderation import seed_commitment
from .protocol import ProtocolSession


def _reviewer_profile(private_key, controller: str, *, conflict: str | None = None):
    return {
        "reviewer_id": public_key_text(private_key),
        "controller_id": controller,
        "status": "active",
        "calibration_passes": 3,
        "calibration_total": 3,
        "reveal_rate_bps": 10_000,
        "conflicts": [conflict] if conflict else [],
    }


def _ballot(
    case: dict[str, Any],
    evidence_root: str,
    reviewer_id: str,
    agent_a_scores: tuple[int, ...],
    agent_b_scores: tuple[int, ...],
    confidence_bps: int,
) -> dict[str, Any]:
    agent_a, agent_b = sorted(case["agents"])
    criteria = list(case["criteria_weights_bps"])
    scores = {
        criterion: {agent_a: agent_a_scores[index], agent_b: agent_b_scores[index]}
        for index, criterion in enumerate(criteria)
    }
    refs = {
        "mathematical_insight": ["a-idea-1", "b-counterexample-1", "a-lemma-2"],
        "proof_architecture": ["b-counterexample-1", "a-lemma-2"],
        "formalization": ["a-lemma-2", "b-formalization-2"],
        "debugging": ["b-formalization-2", "a-debugging-3"],
        "verification": ["b-verification-3", "a-debugging-3"],
    }
    findings = {
        criterion: {
            "evidence_refs": refs[criterion],
            "note": f"Fixture finding for {criterion}; inspect the cited signed nodes.",
        }
        for criterion in criteria
    }
    return {
        "case_id": case["case_id"],
        "evidence_root": evidence_root,
        "reviewer_id": reviewer_id,
        "decision": "decided",
        "confidence_bps": confidence_bps,
        "scores": scores,
        "findings": findings,
    }


def build_demo_session() -> ProtocolSession:
    """Build a complete synthetic transcript without performing external actions."""
    clerk = generate_private_key()
    verifier = generate_private_key()
    agent_a_key = generate_private_key()
    agent_b_key = generate_private_key()
    reviewer_keys = [generate_private_key() for _ in range(7)]
    case_id = "boule-demo-two-agent-lean"
    seed = "42" * 32

    reviewers = [
        _reviewer_profile(reviewer_keys[0], "review-controller-0"),
        _reviewer_profile(reviewer_keys[1], "review-controller-1"),
        _reviewer_profile(reviewer_keys[2], "review-controller-2"),
        _reviewer_profile(reviewer_keys[3], "review-controller-3"),
        _reviewer_profile(reviewer_keys[4], "review-controller-4"),
        _reviewer_profile(reviewer_keys[5], "agent-controller-a"),
        _reviewer_profile(reviewer_keys[6], "review-controller-0"),
    ]
    case = {
        "protocol": PROTOCOL,
        "case_id": case_id,
        "title": "Synthetic two-agent Lean collaboration",
        "objective": {
            "type": "lean_proof",
            "statement": "Demo.Target",
            "base_commit": "sha256:" + digest_bytes(b"demo base commit"),
            "environment_digest": digest_bytes(b"demo Lean environment"),
            "verifier": "synthetic fixture; no Lean process is executed",
        },
        "agents": {
            "agent_a": public_key_text(agent_a_key),
            "agent_b": public_key_text(agent_b_key),
        },
        "agent_controllers": {
            "agent_a": "agent-controller-a",
            "agent_b": "agent-controller-b",
        },
        "verifier_key": public_key_text(verifier),
        "criteria_weights_bps": {
            "mathematical_insight": 3_500,
            "proof_architecture": 2_500,
            "formalization": 2_000,
            "debugging": 1_000,
            "verification": 1_000,
        },
        "collaboration_floor_bps": 1_500,
        "disclosure": {
            "evidence_visibility": "public_fixture",
            "method_license": "not_transferred",
            "method_disclosure_bonus_units": 0,
        },
        "economics": {
            "result_bounty_units": 10_000,
            "settlement": "disabled_demo",
        },
        "review_policy": {
            "panel_size": 3,
            "quorum": 3,
            "max_dispersion_bps": 2_000,
            "min_calibration_passes": 2,
            "min_calibration_total": 3,
            "min_reveal_rate_bps": 7_000,
            "seed_commitment": seed_commitment(seed),
            "roster_digest": roster_digest(reviewers),
        },
        "deadlines": {
            "submission": "2030-01-01T01:00:00Z",
            "review_commit": "2030-01-01T02:00:00Z",
            "review_reveal": "2030-01-01T03:00:00Z",
            "appeal": "2030-01-03T03:00:00Z",
        },
    }

    session = ProtocolSession.open(case, reviewers, clerk, "2030-01-01T00:00:00Z")
    contributions = [
        (
            agent_a_key,
            {
                "case_id": case_id,
                "contribution_id": "a-idea-1",
                "agent_id": "agent_a",
                "kind": "idea",
                "summary": "Decompose the target into a finite combinatorial lemma.",
                "artifact_digest": digest_bytes(b"agent A idea note"),
                "depends_on": [],
                "visibility": "public",
            },
            "2030-01-01T00:10:00Z",
        ),
        (
            agent_b_key,
            {
                "case_id": case_id,
                "contribution_id": "b-counterexample-1",
                "agent_id": "agent_b",
                "kind": "counterexample",
                "summary": "Falsify the first decomposition and isolate its missing condition.",
                "artifact_digest": digest_bytes(b"agent B counterexample"),
                "depends_on": ["a-idea-1"],
                "visibility": "public",
            },
            "2030-01-01T00:20:00Z",
        ),
        (
            agent_a_key,
            {
                "case_id": case_id,
                "contribution_id": "a-lemma-2",
                "agent_id": "agent_a",
                "kind": "lemma",
                "summary": (
                    "Replace the invalid step with a stronger lemma using the new condition."
                ),
                "artifact_digest": digest_bytes(b"agent A corrected lemma"),
                "depends_on": ["b-counterexample-1"],
                "visibility": "public",
            },
            "2030-01-01T00:30:00Z",
        ),
        (
            agent_b_key,
            {
                "case_id": case_id,
                "contribution_id": "b-formalization-2",
                "agent_id": "agent_b",
                "kind": "integration",
                "summary": "Formalize the corrected lemma and connect it to the target.",
                "artifact_digest": digest_bytes(b"agent B Lean patch"),
                "depends_on": ["a-lemma-2"],
                "visibility": "public",
            },
            "2030-01-01T00:40:00Z",
        ),
        (
            agent_a_key,
            {
                "case_id": case_id,
                "contribution_id": "a-debugging-3",
                "agent_id": "agent_a",
                "kind": "debugging",
                "summary": "Repair a universe mismatch blocking the integrated proof.",
                "artifact_digest": digest_bytes(b"agent A Lean repair"),
                "depends_on": ["b-formalization-2"],
                "visibility": "public",
            },
            "2030-01-01T00:45:00Z",
        ),
        (
            agent_b_key,
            {
                "case_id": case_id,
                "contribution_id": "b-verification-3",
                "agent_id": "agent_b",
                "kind": "verification",
                "summary": "Re-run the clean fixture verifier and bind the final artifact digest.",
                "artifact_digest": digest_bytes(b"agent B verification note"),
                "depends_on": ["a-debugging-3"],
                "visibility": "public",
            },
            "2030-01-01T00:50:00Z",
        ),
    ]
    for private_key, contribution, received_at in contributions:
        session.add_contribution(contribution, private_key, received_at)

    final_artifact = digest_bytes(b"synthetic final Lean artifact")
    technical_receipt = {
        "case_id": case_id,
        "artifact_digest": final_artifact,
        "environment_digest": case["objective"]["environment_digest"],
        "report_digest": digest_bytes(b"synthetic verifier report"),
        "status": "pass",
        "mode": "synthetic_fixture",
        "summary": "Fixture PASS for protocol testing; no Lean process was executed.",
    }
    session.record_technical_receipt(technical_receipt, verifier, "2030-01-01T01:10:00Z")
    evidence_root = session.seal_evidence("2030-01-01T01:15:00Z")
    assigned = session.assign_reviewers(seed, "2030-01-01T01:20:00Z")

    private_by_public = {public_key_text(key): key for key in reviewer_keys}
    score_sets = [
        ((4, 4, 3, 4, 3), (1, 1, 3, 1, 1), 8_800),
        ((4, 4, 3, 3, 3), (1, 1, 3, 2, 1), 8_200),
        ((4, 3, 4, 4, 3), (1, 2, 3, 1, 1), 8_500),
    ]
    sealed_ballots: list[tuple[Any, dict[str, Any], str]] = []
    for index, reviewer_id in enumerate(assigned):
        reviewer_private = private_by_public[reviewer_id]
        agent_a_scores, agent_b_scores, confidence = score_sets[index]
        ballot = _ballot(
            case,
            evidence_root,
            reviewer_id,
            agent_a_scores,
            agent_b_scores,
            confidence,
        )
        salt = digest_object({"fixture_salt_for": reviewer_id})
        session.commit_review(
            ballot,
            salt,
            reviewer_private,
            f"2030-01-01T01:{25 + index:02d}:00Z",
        )
        sealed_ballots.append((reviewer_private, ballot, salt))

    session.close_review_commits("2030-01-01T01:30:00Z")
    for index, (reviewer_private, ballot, salt) in enumerate(sealed_ballots):
        session.reveal_review(
            ballot,
            salt,
            reviewer_private,
            f"2030-01-01T02:{10 + index:02d}:00Z",
        )
    session.finalize("2030-01-01T02:30:00Z")
    return session
