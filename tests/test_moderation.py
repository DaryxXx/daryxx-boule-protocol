from __future__ import annotations

from copy import deepcopy

from boule.demo import build_demo_session
from boule.moderation import aggregate_ballots, ballot_commitment, select_reviewers


def test_assignment_is_deterministic_and_uses_distinct_non_agent_controllers() -> None:
    session = build_demo_session()
    case = session.state.case
    assert case is not None
    evidence_root = session.state.evidence_root
    assert evidence_root is not None

    first = select_reviewers(case, session.state.roster, "42" * 32, evidence_root)
    second = select_reviewers(case, list(reversed(session.state.roster)), "42" * 32, evidence_root)
    profiles = {profile["reviewer_id"]: profile for profile in session.state.roster}
    controllers = [profiles[reviewer]["controller_id"] for reviewer in first]

    assert first == second == session.state.assigned_reviewers
    assert len(set(controllers)) == len(controllers)
    assert set(controllers).isdisjoint(case["agent_controllers"].values())


def test_ballot_commitment_binds_the_salt_and_ballot() -> None:
    session = build_demo_session()
    ballot = next(iter(session.state.ballots.values()))

    original = ballot_commitment(ballot, "11" * 32)
    assert original != ballot_commitment(ballot, "22" * 32)

    changed = deepcopy(ballot)
    changed["confidence_bps"] -= 1
    assert original != ballot_commitment(changed, "11" * 32)


def test_large_reviewer_disagreement_fails_closed() -> None:
    session = build_demo_session()
    case = session.state.case
    evidence_root = session.state.evidence_root
    assert case is not None and evidence_root is not None
    ballots = deepcopy(list(session.state.ballots.values()))
    agent_a, agent_b = sorted(case["agents"])

    for criterion in case["criteria_weights_bps"]:
        ballots[0]["scores"][criterion] = {agent_a: 4, agent_b: 0}
        ballots[1]["scores"][criterion] = {agent_a: 0, agent_b: 4}

    decision = aggregate_ballots(
        case,
        evidence_root,
        ballots,
        session.state.contribution_ids,
    )

    assert decision["status"] == "inconclusive"
    assert decision["reason"] == "reviewer_dispersion_exceeded"
    assert decision["allocation_bps"] is None
