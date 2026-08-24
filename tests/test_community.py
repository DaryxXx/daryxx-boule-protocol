from __future__ import annotations

import json
from copy import deepcopy

import pytest

from boule.canonical import digest_object
from boule.cli import main
from boule.community import (
    CommunityLedger,
    CommunitySession,
    payout_legs,
    replay_community_ledger,
)
from boule.community_demo import (
    _accept_frontier,
    _claim,
    _commit_and_handoff,
    _delegate,
    _manifest,
    build_community_demo,
)
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError


def _open_kit():
    clerk = generate_private_key()
    verifier = generate_private_key()
    controllers = {name: generate_private_key() for name in ("agent_a", "agent_b", "agent_c")}
    sessions = {name: generate_private_key() for name in controllers}
    reviewers = {
        name: generate_private_key() for name in ("reviewer_1", "reviewer_2", "reviewer_3")
    }
    manifest = _manifest(
        public_key_text(clerk),
        public_key_text(verifier),
        {name: public_key_text(key) for name, key in controllers.items()},
        {name: public_key_text(key) for name, key in reviewers.items()},
    )
    community = CommunitySession.open(manifest, clerk, "2030-01-01T00:00:00Z")
    return community, clerk, verifier, controllers, sessions, reviewers


def test_complete_community_demo_replays_without_chat_history() -> None:
    demo = build_community_demo()
    live = demo.session.state.summary()
    replayed = replay_community_ledger(demo.session.ledger).summary()

    assert replayed == live
    assert demo.cold_resumes == 3
    assert demo.incomplete_attribution_blocked is True
    assert live["phase"] == "mock_paid"
    assert live["sessions"] == 3
    assert live["accepted_handoffs"] == [
        "handoff-a-intake",
        "handoff-b-even",
        "handoff-c-integration",
    ]
    assert live["results"]["result-omits-a"] == {
        "attribution_status": "incomplete",
        "omitted_dependencies": ["handoff-a-intake"],
        "extraneous_dependencies": [],
        "unaccounted_accesses": [],
        "unattributed_accesses": [],
        "technical_status": "pass",
    }
    assert live["results"]["result-complete"]["attribution_status"] == "complete"


def test_allocation_and_mock_payout_conserve_exact_integer_amount() -> None:
    state = build_community_demo().session.state

    assert state.allocation["allocation_bps"] == {
        "agent_a": 2_500,
        "agent_b": 3_000,
        "agent_c": 4_500,
    }
    assert sum(state.allocation["allocation_bps"].values()) == 10_000
    assert sum(leg["amount_rao"] for leg in state.payout_plan["legs"]) == 1_000_003
    assert state.phase == "mock_paid"
    assert len(state.payout_confirmed) == len(state.payout_plan["legs"])
    assert state.summary()["payout"]["status"] == "simulated_paid"


def test_payout_rounding_is_input_order_independent() -> None:
    state = build_community_demo().session.state
    manifest = state.manifest
    allocation_a = {"agent_a": 3_333, "agent_b": 3_333, "agent_c": 3_334}
    allocation_b = {"agent_c": 3_334, "agent_a": 3_333, "agent_b": 3_333}

    first = payout_legs(manifest, allocation_a)
    second = payout_legs(manifest, allocation_b)

    assert first == second
    assert sum(leg["amount_rao"] for leg in first) == manifest["economics"]["bounty_rao"]
    assert {leg["participant_id"]: leg["amount_rao"] for leg in first} == {
        "agent_a": 333_301,
        "agent_b": 333_301,
        "agent_c": 333_401,
    }


def test_payout_legs_validate_allocation_and_use_largest_remainder() -> None:
    state = build_community_demo().session.state
    manifest = deepcopy(state.manifest)
    manifest["economics"]["bounty_rao"] = 1

    legs = payout_legs(manifest, {"agent_a": 1, "agent_b": 1, "agent_c": 9_998})
    amounts = {leg["participant_id"]: leg["amount_rao"] for leg in legs}
    assert amounts == {"agent_a": 0, "agent_b": 0, "agent_c": 1}

    with pytest.raises(ProtocolError, match="every participant"):
        payout_legs(manifest, {"agent_a": 5_000, "agent_b": 5_000})
    with pytest.raises(ProtocolError, match="integer"):
        payout_legs(manifest, {"agent_a": -1, "agent_b": 1, "agent_c": 10_000})
    with pytest.raises(ProtocolError, match="sum to 10000"):
        payout_legs(manifest, {"agent_a": 1, "agent_b": 1, "agent_c": 1})


def test_zero_share_recipient_has_no_payout_leg() -> None:
    state = build_community_demo().session.state
    legs = payout_legs(
        state.manifest,
        {"agent_a": 0, "agent_b": 4_000, "agent_c": 6_000},
    )

    assert {leg["participant_id"] for leg in legs} == {"agent_b", "agent_c"}
    assert sum(leg["amount_rao"] for leg in legs) == state.manifest["economics"]["bounty_rao"]


def test_exclusive_parallel_and_expiry_route_rules() -> None:
    community, clerk, _, controllers, sessions, _ = _open_kit()
    for participant, minute in (("agent_a", 1), ("agent_b", 2)):
        _delegate(
            community,
            participant,
            controllers[participant],
            sessions[participant],
            "explorer",
            f"2030-01-01T00:0{minute}:00Z",
        )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-r",
        "Question A",
        "Success A",
        "Failure A",
        "2030-01-01T00:03:00Z",
        "2030-01-01T00:10:00Z",
    )
    before = len(community.ledger.entries)
    with pytest.raises(ProtocolError, match="active route lease"):
        _claim(
            community,
            "agent_b",
            sessions["agent_b"],
            "claim-b-collision",
            "route-r",
            "Question B",
            "Success B",
            "Failure B",
            "2030-01-01T00:04:00Z",
            "2030-01-01T00:09:00Z",
        )
    assert len(community.ledger.entries) == before
    assert "claim-b-collision" not in community.state.claims

    with pytest.raises(ProtocolError, match="active route lease"):
        community.append(
            "route_claimed",
            {
                "case_id": community.state.case_id,
                "claim_id": "claim-b-parallel-blocked",
                "route_id": "route-r",
                "participant_id": "agent_b",
                "session_id": "session-agent_b",
                "base_frontier_id": community.state.current_frontier_id,
                "question": "Question B",
                "success_gate": "Success B",
                "falsifier": "Failure B",
                "overlap": "parallel",
                "expires_at": "2030-01-01T00:09:00Z",
            },
            sessions["agent_b"],
            "2030-01-01T00:05:00Z",
        )
    _claim(
        community,
        "agent_b",
        sessions["agent_b"],
        "claim-b-after-expiry",
        "route-r",
        "Question after expiry",
        "Success after expiry",
        "Failure after expiry",
        "2030-01-01T00:10:00Z",
        "2030-01-01T00:20:00Z",
    )

    for participant, claim_id, received_at in (
        ("agent_a", "claim-a-parallel", "2030-01-01T00:11:00Z"),
        ("agent_b", "claim-b-parallel", "2030-01-01T00:12:00Z"),
    ):
        community.append(
            "route_claimed",
            {
                "case_id": community.state.case_id,
                "claim_id": claim_id,
                "route_id": "route-parallel",
                "participant_id": participant,
                "session_id": f"session-{participant}",
                "base_frontier_id": community.state.current_frontier_id,
                "question": f"Parallel question {participant}",
                "success_gate": "Independent replication",
                "falsifier": "Reproducible failure",
                "overlap": "parallel",
                "expires_at": "2030-01-01T00:20:00Z",
            },
            sessions[participant],
            received_at,
        )
    assert community.state.claims["claim-b-parallel"]["payload"]["overlap"] == "parallel"
    assert community.state.claims["claim-b-after-expiry"]["status"] == "active"
    assert public_key_text(clerk) == community.ledger.clerk_key


def test_unknown_dependency_is_rejected_without_mutating_state() -> None:
    community, _, _, controllers, sessions, _ = _open_kit()
    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        sessions["agent_a"],
        "explorer",
        "2030-01-01T00:01:00Z",
    )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-a",
        "Question",
        "Success",
        "Failure",
        "2030-01-01T00:02:00Z",
        "2030-01-01T01:00:00Z",
    )
    artifact = "a" * 64
    community.append(
        "contribution_committed",
        {
            "case_id": community.state.case_id,
            "commitment_id": "commit-a",
            "claim_id": "claim-a",
            "participant_id": "agent_a",
            "session_id": "session-agent_a",
            "artifact_digest": artifact,
            "summary_digest": digest_object("A claimed advance"),
            "visibility": "committee",
        },
        sessions["agent_a"],
        "2030-01-01T00:03:00Z",
    )
    before = len(community.ledger.entries)
    with pytest.raises(ProtocolError, match="unknown dependencies"):
        community.append(
            "handoff_published",
            {
                "case_id": community.state.case_id,
                "handoff_id": "handoff-a",
                "commitment_id": "commit-a",
                "claim_id": "claim-a",
                "participant_id": "agent_a",
                "session_id": "session-agent_a",
                "outcome": "ADVANCE",
                "summary": "A claimed advance",
                "artifact_digest": artifact,
                "environment_digest": community.state.manifest["objective"]["environment_digest"],
                "reproduce": "mock-replay",
                "depends_on": ["missing-handoff"],
                "uses": [],
                "refutes": [],
                "limitations": "Fixture",
                "next_test": "Next",
                "base_commit": "mock-base",
                "result_commit": "mock-result",
                "originality": "fixture",
                "citations": [],
            },
            sessions["agent_a"],
            "2030-01-01T00:04:00Z",
        )
    assert len(community.ledger.entries) == before
    assert "handoff-a" not in community.state.handoffs
    assert community.state.commitments["commit-a"]["revealed_by"] is None


def test_handoff_summary_must_match_commitment_and_rolls_back() -> None:
    community, _, _, controllers, sessions, _ = _open_kit()
    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        sessions["agent_a"],
        "explorer",
        "2030-01-01T00:01:00Z",
    )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-a",
        "Question",
        "Success",
        "Failure",
        "2030-01-01T00:02:00Z",
        "2030-01-01T01:00:00Z",
    )
    community.append(
        "contribution_committed",
        {
            "case_id": community.state.case_id,
            "commitment_id": "commit-a",
            "claim_id": "claim-a",
            "participant_id": "agent_a",
            "session_id": "session-agent_a",
            "artifact_digest": "a" * 64,
            "summary_digest": digest_object("summary A"),
            "visibility": "committee",
        },
        sessions["agent_a"],
        "2030-01-01T00:03:00Z",
    )
    before = len(community.ledger.entries)
    with pytest.raises(ProtocolError, match="summary does not match"):
        community.append(
            "handoff_published",
            {
                "case_id": community.state.case_id,
                "handoff_id": "handoff-a",
                "commitment_id": "commit-a",
                "claim_id": "claim-a",
                "participant_id": "agent_a",
                "session_id": "session-agent_a",
                "outcome": "ADVANCE",
                "summary": "summary B",
                "artifact_digest": "a" * 64,
                "environment_digest": community.state.manifest["objective"]["environment_digest"],
                "reproduce": "mock-replay",
                "depends_on": [],
                "uses": [],
                "refutes": [],
                "limitations": "Fixture",
                "next_test": "Next",
                "base_commit": "mock-base",
                "result_commit": "mock-result",
                "originality": "fixture",
                "citations": [],
            },
            sessions["agent_a"],
            "2030-01-01T00:04:00Z",
        )
    assert len(community.ledger.entries) == before
    assert community.state.commitments["commit-a"]["revealed_by"] is None


def test_hash_only_handoff_cannot_enter_frontier() -> None:
    community, clerk, _, controllers, sessions, _ = _open_kit()
    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        sessions["agent_a"],
        "explorer",
        "2030-01-01T00:01:00Z",
    )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-a",
        "Question",
        "Success",
        "Failure",
        "2030-01-01T00:02:00Z",
        "2030-01-01T01:00:00Z",
    )
    artifact = "a" * 64
    summary = "A timestamp claim with no inspectable evidence"
    community.append(
        "contribution_committed",
        {
            "case_id": community.state.case_id,
            "commitment_id": "commit-a",
            "claim_id": "claim-a",
            "participant_id": "agent_a",
            "session_id": "session-agent_a",
            "artifact_digest": artifact,
            "summary_digest": digest_object(summary),
            "visibility": "hash_only",
        },
        sessions["agent_a"],
        "2030-01-01T00:03:00Z",
    )
    _commit_payload = {
        "case_id": community.state.case_id,
        "handoff_id": "handoff-a",
        "commitment_id": "commit-a",
        "claim_id": "claim-a",
        "participant_id": "agent_a",
        "session_id": "session-agent_a",
        "outcome": "ADVANCE",
        "summary": summary,
        "artifact_digest": artifact,
        "environment_digest": community.state.manifest["objective"]["environment_digest"],
        "reproduce": "mock-replay",
        "depends_on": [],
        "uses": [],
        "refutes": [],
        "limitations": "Hash only",
        "next_test": "Reveal inspectable evidence",
        "base_commit": "mock-base",
        "result_commit": "mock-result",
        "originality": "fixture",
        "citations": [],
    }
    community.append(
        "handoff_published",
        _commit_payload,
        sessions["agent_a"],
        "2030-01-01T00:04:00Z",
    )
    before = len(community.ledger.entries)
    with pytest.raises(ProtocolError, match="hash-only"):
        _accept_frontier(
            community,
            clerk,
            "frontier-001",
            "Attempted hash-only frontier",
            ["reveal-evidence"],
            ["handoff-a"],
            "2030-01-01T00:05:00Z",
        )
    assert len(community.ledger.entries) == before
    assert "handoff-a" not in community.state.accepted_handoffs


def test_result_rejects_unaccepted_handoff() -> None:
    community, _, _, controllers, sessions, _ = _open_kit()
    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        sessions["agent_a"],
        "integrator",
        "2030-01-01T00:01:00Z",
    )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-a",
        "Question",
        "Success",
        "Failure",
        "2030-01-01T00:02:00Z",
        "2030-01-01T01:00:00Z",
    )
    _commit_and_handoff(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "handoff-a",
        "ADVANCE",
        "Inspectable but not curated",
        [],
        [],
        "2030-01-01T00:03:00Z",
        "2030-01-01T00:04:00Z",
    )
    before = len(community.ledger.entries)
    with pytest.raises(ProtocolError, match="not accepted"):
        community.append(
            "result_proposed",
            {
                "case_id": community.state.case_id,
                "result_id": "result-a",
                "participant_id": "agent_a",
                "session_id": "session-agent_a",
                "artifact_digest": "c" * 64,
                "environment_digest": community.state.manifest["objective"]["environment_digest"],
                "reproduce": "mock-verifier",
                "direct_dependencies": ["handoff-a"],
                "claimed_transitive_dependencies": ["handoff-a"],
                "access_dispositions": {},
                "summary": "Uncurated result",
            },
            sessions["agent_a"],
            "2030-01-01T00:05:00Z",
        )
    assert len(community.ledger.entries) == before
    assert "result-a" not in community.state.results


def test_controller_can_revoke_session_and_release_its_route() -> None:
    community, _, _, controllers, sessions, _ = _open_kit()
    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        sessions["agent_a"],
        "explorer",
        "2030-01-01T00:01:00Z",
    )
    _claim(
        community,
        "agent_a",
        sessions["agent_a"],
        "claim-a",
        "route-a",
        "Question",
        "Success",
        "Failure",
        "2030-01-01T00:02:00Z",
        "2030-01-01T01:00:00Z",
    )
    community.append(
        "session_revoked",
        {
            "case_id": community.state.case_id,
            "participant_id": "agent_a",
            "session_id": "session-agent_a",
            "reason": "Mock key compromise",
        },
        controllers["agent_a"],
        "2030-01-01T00:03:00Z",
    )
    assert community.state.sessions["session-agent_a"].revoked is True
    assert community.state.claims["claim-a"]["status"] == "released"
    with pytest.raises(ProtocolError, match="revoked"):
        community.append(
            "message_posted",
            {
                "case_id": community.state.case_id,
                "message_id": "after-revoke",
                "session_id": "session-agent_a",
                "topic": "invalid",
                "body": "This key is no longer authorized.",
                "references": [],
            },
            sessions["agent_a"],
            "2030-01-01T00:04:00Z",
        )


def test_credit_is_ballot_based_not_node_count() -> None:
    state = build_community_demo().session.state
    before = state.aggregate_credit_ballots()
    state.handoffs["decorative-extra-node"] = deepcopy(state.handoffs["handoff-a-intake"])

    after = state.aggregate_credit_ballots()

    assert after == before
    assert after["allocation_bps"]["agent_a"] == 2_500


def test_scientific_chat_is_signed_coordination_not_credit_evidence() -> None:
    state = build_community_demo().session.state

    assert len(state.messages) == 7
    assert list(state.messages) == [
        "message-a-1",
        "message-b-proposal",
        "message-a-critique",
        "message-b-response",
        "message-c-chair-question",
        "message-b-chair-answer",
        "message-c-verdict",
    ]
    assert [message["received_at"] for message in state.messages.values()] == sorted(
        message["received_at"] for message in state.messages.values()
    )
    assert {message["payload"]["topic"] for message in state.messages.values()} == {
        "chair-answer",
        "chair-question",
        "chair-verdict",
        "critique",
        "intake",
        "proposal",
        "response",
    }
    ballot_refs = {
        reference
        for ballot in state.ballots.values()
        for references in ballot["evidence_refs"].values()
        for reference in references
    }
    assert ballot_refs == {
        "handoff-a-intake",
        "handoff-b-even",
        "handoff-c-integration",
    }
    assert not ballot_refs.intersection(state.messages)


def test_tampered_community_ledger_is_rejected() -> None:
    entries = deepcopy(list(build_community_demo().session.ledger.entries))
    entries[3]["event"]["payload"]["question"] = "retrospectively rewritten"

    with pytest.raises(ProtocolError, match="signature verification failed"):
        CommunityLedger(entries).verify()


def test_cli_writes_replayable_artifacts_and_enforces_terminal_gate(tmp_path, capsys) -> None:
    output = tmp_path / "community-demo"
    assert main(["community-demo", "--output", str(output), "--json"]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["summary"]["phase"] == "mock_paid"
    assert created["mock_checks"]["incomplete_attribution_blocked"] is True
    assert {
        "agent-prompt.md",
        "case-manifest.json",
        "chat.jsonl",
        "frontier.md",
        "join-brief.md",
        "ledger.jsonl",
        "mock-checks.json",
        "mock-payout-plan.json",
        "summary.json",
    } <= {path.name for path in output.iterdir()}
    prompt = (output / "agent-prompt.md").read_text(encoding="utf-8")
    assert "one short-lived Boule Community mock session" in prompt
    assert "do not submit, spend, transfer value" in prompt
    chat = [
        json.loads(line)
        for line in (output / "chat.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [message["message_id"] for message in chat] == [
        "message-a-1",
        "message-b-proposal",
        "message-a-critique",
        "message-b-response",
        "message-c-chair-question",
        "message-b-chair-answer",
        "message-c-verdict",
    ]
    assert chat[1]["participant_id"] == "agent_b"
    assert chat[1]["received_at"] == "2030-01-01T00:10:20Z"

    assert main(["community-agent-prompt", str(output / "ledger.jsonl")]) == 0
    assert "Open obligations: none" in capsys.readouterr().out

    assert (
        main(
            [
                "verify-community-ledger",
                str(output / "ledger.jsonl"),
                "--require-allocation",
                "--require-mock-paid",
                "--json",
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified == created["summary"]

    lines = (output / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    partial = output / "partial-ledger.jsonl"
    partial.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert main(["verify-community-ledger", str(partial), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["phase"] == "mock_paying"
    assert main(["verify-community-ledger", str(partial), "--require-mock-paid"]) == 2
    assert "mock payout is not complete" in capsys.readouterr().err
