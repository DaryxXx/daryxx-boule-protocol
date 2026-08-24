from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .canonical import digest_object
from .community import (
    COMMUNITY_PROTOCOL,
    CommunityLedger,
    CommunitySession,
    credit_ballot_commitment,
    frontier_digest,
)
from .crypto import generate_private_key, public_key_text
from .errors import ProtocolError


@dataclass(frozen=True)
class CommunityDemo:
    session: CommunitySession
    incomplete_attribution_blocked: bool
    cold_resumes: int


def _artifact(label: str) -> str:
    return digest_object({"domain": "boule-community-demo-artifact-v1", "label": label})


def _manifest(
    clerk_key: str,
    verifier_key: str,
    controllers: dict[str, str],
    reviewers: dict[str, str],
) -> dict[str, Any]:
    del clerk_key
    case_id = "erdos686-four-community-mock"
    initial = {
        "frontier_id": "frontier-000",
        "summary": (
            "Mock intake only: a source-reported Erdős 686 continuation exists, but the "
            "claimed artifact bundle and calculations have not been independently reproduced."
        ),
        "open_obligations": [
            "recover-or-reconstruct-the-complete-continuation-package",
            "audit-the-even-k-gcd-lemma",
            "find-a-uniform-all-k-mechanism",
        ],
    }
    initial["frontier_digest"] = frontier_digest(
        case_id,
        initial["frontier_id"],
        None,
        initial["summary"],
        initial["open_obligations"],
        [],
    )
    return {
        "protocol": COMMUNITY_PROTOCOL,
        "case_id": case_id,
        "title": "Erdős 686 Four — asynchronous community mock",
        "objective": {
            "statement": (
                "Mock the counterexample route: no k,n,m represent 4 by the frozen product ratio."
            ),
            "base_commit": "379fc0298dc146df549e7061c3ede0353a5bb51f",
            "environment_digest": _artifact("synthetic-pinned-lean-environment"),
            "verifier": "synthetic fixture; no Lean process is executed",
            "task_id": "fc-379fc029-variants-four-48642f6e67-counterexample-v1",
            "reward_target_id": "fc-target:Erdos686.erdos_686.variants.four",
        },
        "participants": {
            participant_id: {
                "controller_key": controller_key,
                "controller_id": f"mock-controller-{participant_id}",
                "display_name": participant_id.replace("_", " ").title(),
                "payout_destination": {
                    "coldkey": f"mock-coldkey:{participant_id}",
                    "hotkey": f"mock-hotkey:{participant_id}",
                },
            }
            for participant_id, controller_key in controllers.items()
        },
        "verifier_key": verifier_key,
        "reviewers": {
            reviewer_id: {
                "reviewer_key": reviewer_key,
                "controller_id": f"mock-controller-{reviewer_id}",
            }
            for reviewer_id, reviewer_key in reviewers.items()
        },
        "policy": {
            "lease_max_seconds": 86_400,
            "allow_parallel": True,
            "review_quorum": 3,
            "max_share_dispersion_bps": 1_000,
        },
        "economics": {"asset": "mock-alpha-rao", "bounty_rao": 1_000_003},
        "disclosure": {
            "active_case": "private_mock",
            "result": "publish_after_mock_appeal",
            "method_license": "case_only_mock",
        },
        "initial_frontier": initial,
        "simulation": True,
    }


def _delegate(
    community: CommunitySession,
    participant_id: str,
    controller_key,
    session_key,
    role: str,
    received_at: str,
) -> None:
    community.append(
        "session_delegated",
        {
            "case_id": community.state.case_id,
            "participant_id": participant_id,
            "session_id": f"session-{participant_id}",
            "session_key": public_key_text(session_key),
            "role": role,
            "scopes": ["message", "claim", "handoff", "access", "result"],
            "not_after": "2030-01-03T00:00:00Z",
        },
        controller_key,
        received_at,
    )


def _message(
    community: CommunitySession,
    participant_id: str,
    session_key,
    message_id: str,
    topic: str,
    body: str,
    references: list[str],
    received_at: str,
) -> None:
    community.append(
        "message_posted",
        {
            "case_id": community.state.case_id,
            "message_id": message_id,
            "session_id": f"session-{participant_id}",
            "topic": topic,
            "body": body,
            "references": references,
        },
        session_key,
        received_at,
    )


def _claim(
    community: CommunitySession,
    participant_id: str,
    session_key,
    claim_id: str,
    route_id: str,
    question: str,
    success_gate: str,
    falsifier: str,
    received_at: str,
    expires_at: str,
) -> None:
    community.append(
        "route_claimed",
        {
            "case_id": community.state.case_id,
            "claim_id": claim_id,
            "route_id": route_id,
            "participant_id": participant_id,
            "session_id": f"session-{participant_id}",
            "base_frontier_id": community.state.current_frontier_id,
            "question": question,
            "success_gate": success_gate,
            "falsifier": falsifier,
            "overlap": "exclusive",
            "expires_at": expires_at,
        },
        session_key,
        received_at,
    )


def _commit_and_handoff(
    community: CommunitySession,
    participant_id: str,
    session_key,
    claim_id: str,
    handoff_id: str,
    outcome: str,
    summary: str,
    depends_on: list[str],
    uses: list[str],
    received_commit: str,
    received_handoff: str,
) -> None:
    artifact_digest = _artifact(handoff_id)
    commitment_id = f"commitment-{handoff_id}"
    community.append(
        "contribution_committed",
        {
            "case_id": community.state.case_id,
            "commitment_id": commitment_id,
            "claim_id": claim_id,
            "participant_id": participant_id,
            "session_id": f"session-{participant_id}",
            "artifact_digest": artifact_digest,
            "summary_digest": digest_object(summary),
            "visibility": "committee",
        },
        session_key,
        received_commit,
    )
    community.append(
        "handoff_published",
        {
            "case_id": community.state.case_id,
            "handoff_id": handoff_id,
            "commitment_id": commitment_id,
            "claim_id": claim_id,
            "participant_id": participant_id,
            "session_id": f"session-{participant_id}",
            "outcome": outcome,
            "summary": summary,
            "artifact_digest": artifact_digest,
            "environment_digest": community.state.manifest["objective"]["environment_digest"],
            "reproduce": f"mock-replay --handoff {handoff_id}",
            "depends_on": depends_on,
            "uses": uses,
            "refutes": [],
            "limitations": "Synthetic fixture; no mathematical claim is established.",
            "next_test": "Run the corresponding real check in the pinned research workspace.",
            "base_commit": community.state.manifest["objective"]["base_commit"],
            "result_commit": f"mock-git:{handoff_id}",
            "originality": "fixture",
            "citations": [],
        },
        session_key,
        received_handoff,
    )


def _accept_frontier(
    community: CommunitySession,
    clerk_key,
    frontier_id: str,
    summary: str,
    obligations: list[str],
    handoffs: list[str],
    received_at: str,
) -> None:
    cumulative = sorted(community.state.accepted_handoffs | set(handoffs))
    digest = frontier_digest(
        community.state.case_id,
        frontier_id,
        community.state.current_frontier_id,
        summary,
        obligations,
        cumulative,
    )
    community.append(
        "frontier_accepted",
        {
            "case_id": community.state.case_id,
            "frontier_id": frontier_id,
            "parent_frontier_id": community.state.current_frontier_id,
            "summary": summary,
            "open_obligations": obligations,
            "accepted_handoffs": handoffs,
            "frontier_digest": digest,
        },
        clerk_key,
        received_at,
    )


def _result(
    community: CommunitySession,
    session_key,
    result_id: str,
    claimed: list[str],
    received_at: str,
) -> None:
    community.append(
        "result_proposed",
        {
            "case_id": community.state.case_id,
            "result_id": result_id,
            "participant_id": "agent_c",
            "session_id": "session-agent_c",
            "artifact_digest": _artifact("mock-final-proof"),
            "environment_digest": community.state.manifest["objective"]["environment_digest"],
            "reproduce": "mock-verifier --result mock-final-proof",
            "direct_dependencies": ["handoff-c-integration"],
            "claimed_transitive_dependencies": claimed,
            "access_dispositions": {
                "handoff-a-intake": "used",
                "handoff-b-even": "used",
            },
            "summary": "Synthetic final candidate used only to exercise attribution and payout.",
        },
        session_key,
        received_at,
    )


def _technical_receipt(
    community: CommunitySession,
    verifier_key,
    result_id: str,
    received_at: str,
) -> None:
    community.append(
        "technical_receipt_recorded",
        {
            "case_id": community.state.case_id,
            "result_id": result_id,
            "artifact_digest": _artifact("mock-final-proof"),
            "environment_digest": community.state.manifest["objective"]["environment_digest"],
            "report_digest": _artifact(f"report-{result_id}"),
            "status": "pass",
            "mode": "synthetic_fixture",
            "summary": "Fixture PASS proves protocol wiring only; Lean was not executed.",
        },
        verifier_key,
        received_at,
    )


def _ballot(
    case_id: str,
    evidence_root: str,
    reviewer_id: str,
    shares: dict[str, int],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "evidence_root": evidence_root,
        "reviewer_id": reviewer_id,
        "decision": "decided",
        "shares_bps": shares,
        "evidence_refs": {
            "agent_a": ["handoff-a-intake"],
            "agent_b": ["handoff-b-even"],
            "agent_c": ["handoff-c-integration"],
        },
        "note": "Mock causal allocation; node counts and compute spend were ignored.",
    }


def _cold_resume(community: CommunitySession, clerk_key) -> CommunitySession:
    """Discard live state and reconstruct it from a durable JSONL transcript."""
    with TemporaryDirectory(prefix="boule-community-resume-") as directory:
        ledger_path = community.ledger.write(Path(directory) / "ledger.jsonl")
        durable_ledger = CommunityLedger.read(ledger_path)
    return CommunitySession.resume(durable_ledger, clerk_key)


def build_community_demo() -> CommunityDemo:
    clerk = generate_private_key()
    verifier = generate_private_key()
    controllers = {name: generate_private_key() for name in ("agent_a", "agent_b", "agent_c")}
    session_keys = {name: generate_private_key() for name in controllers}
    reviewer_keys = {
        name: generate_private_key() for name in ("reviewer_1", "reviewer_2", "reviewer_3")
    }
    manifest = _manifest(
        public_key_text(clerk),
        public_key_text(verifier),
        {name: public_key_text(key) for name, key in controllers.items()},
        {name: public_key_text(key) for name, key in reviewer_keys.items()},
    )
    community = CommunitySession.open(manifest, clerk, "2030-01-01T00:00:00Z")
    cold_resumes = 0

    _delegate(
        community,
        "agent_a",
        controllers["agent_a"],
        session_keys["agent_a"],
        "explorer",
        "2030-01-01T00:01:00Z",
    )
    _message(
        community,
        "agent_a",
        session_keys["agent_a"],
        "message-a-1",
        "intake",
        "I will preserve the supplied continuation and isolate its first missing evidence.",
        [],
        "2030-01-01T00:02:00Z",
    )
    _claim(
        community,
        "agent_a",
        session_keys["agent_a"],
        "claim-a-intake",
        "route-continuation-intake",
        "Can the supplied continuation package be reproduced from the available files?",
        "Every advertised artifact is present and its digest and tests replay.",
        "Any missing advertised artifact blocks verification.",
        "2030-01-01T00:03:00Z",
        "2030-01-01T06:00:00Z",
    )
    _commit_and_handoff(
        community,
        "agent_a",
        session_keys["agent_a"],
        "claim-a-intake",
        "handoff-a-intake",
        "BLOCKED",
        "The README is preserved, but the claimed scripts and result bundle are absent.",
        [],
        [],
        "2030-01-01T00:04:00Z",
        "2030-01-01T00:05:00Z",
    )
    _accept_frontier(
        community,
        clerk,
        "frontier-001",
        "The prior report is source-reported only because its complete artifact bundle is absent.",
        ["reconstruct-the-even-k-lemma", "find-a-uniform-all-k-mechanism"],
        ["handoff-a-intake"],
        "2030-01-01T00:06:00Z",
    )

    community = _cold_resume(community, clerk)
    cold_resumes += 1
    _delegate(
        community,
        "agent_b",
        controllers["agent_b"],
        session_keys["agent_b"],
        "formalizer",
        "2030-01-01T00:10:00Z",
    )
    _message(
        community,
        "agent_b",
        session_keys["agent_b"],
        "message-b-proposal",
        "proposal",
        (
            "Hypothesis: reconstruct the centered even-k gcd step first. Success requires an "
            "exact congruence; one failing small case falsifies the route."
        ),
        ["handoff-a-intake", "frontier-001"],
        "2030-01-01T00:10:20Z",
    )
    _message(
        community,
        "agent_a",
        session_keys["agent_a"],
        "message-a-critique",
        "critique",
        (
            "The missing continuation bundle means you must derive the congruence independently; "
            "do not cite the intake summary as mathematical evidence."
        ),
        ["message-b-proposal", "handoff-a-intake"],
        "2030-01-01T00:10:30Z",
    )
    _message(
        community,
        "agent_b",
        session_keys["agent_b"],
        "message-b-response",
        "response",
        (
            "Accepted. The handoff will label the derivation synthetic and use intake only as a "
            "provenance dependency, not as proof of the lemma."
        ),
        ["message-a-critique"],
        "2030-01-01T00:10:40Z",
    )
    _claim(
        community,
        "agent_b",
        session_keys["agent_b"],
        "claim-b-even",
        "route-even-k-gcd",
        "Can the even-k gcd restriction be reconstructed as an auditable lemma?",
        "A fixture artifact replays and cites the intake boundary.",
        "The centered congruence fails on an exact small case.",
        "2030-01-01T00:11:00Z",
        "2030-01-01T06:00:00Z",
    )
    _commit_and_handoff(
        community,
        "agent_b",
        session_keys["agent_b"],
        "claim-b-even",
        "handoff-b-even",
        "ADVANCE",
        "Mock reconstruction of the even-k gcd lemma, explicitly dependent on intake.",
        [],
        ["handoff-a-intake"],
        "2030-01-01T00:12:00Z",
        "2030-01-01T00:13:00Z",
    )
    _accept_frontier(
        community,
        clerk,
        "frontier-002",
        "A synthetic even-k lemma artifact is available; no real mathematics is certified.",
        ["find-a-uniform-all-k-mechanism"],
        ["handoff-b-even"],
        "2030-01-01T00:14:00Z",
    )

    community = _cold_resume(community, clerk)
    cold_resumes += 1
    _delegate(
        community,
        "agent_c",
        controllers["agent_c"],
        session_keys["agent_c"],
        "integrator",
        "2030-01-01T00:20:00Z",
    )
    _message(
        community,
        "agent_c",
        session_keys["agent_c"],
        "message-c-chair-question",
        "chair-question",
        (
            "Which parts are evidence rather than discussion, and what exact dependency must the "
            "integration declare?"
        ),
        ["handoff-a-intake", "handoff-b-even", "frontier-002"],
        "2030-01-01T00:20:10Z",
    )
    _message(
        community,
        "agent_b",
        session_keys["agent_b"],
        "message-b-chair-answer",
        "chair-answer",
        (
            "Only the signed handoffs and their artifact digests are evidence. The integration "
            "must preserve both the direct even-k handoff and its intake provenance."
        ),
        ["message-c-chair-question", "handoff-b-even"],
        "2030-01-01T00:20:20Z",
    )
    _message(
        community,
        "agent_c",
        session_keys["agent_c"],
        "message-c-verdict",
        "chair-verdict",
        (
            "Proceed with a synthetic integration test, while recording that no real "
            "mathematical result has been certified."
        ),
        ["message-b-chair-answer", "handoff-a-intake", "handoff-b-even"],
        "2030-01-01T00:20:30Z",
    )
    for access_id, contribution_id, sender, minute in (
        ("access-c-a", "handoff-a-intake", "agent_a", 21),
        ("access-c-b", "handoff-b-even", "agent_b", 22),
    ):
        community.append(
            "knowledge_accessed",
            {
                "case_id": community.state.case_id,
                "access_id": access_id,
                "contribution_id": contribution_id,
                "artifact_digest": community.state.handoffs[contribution_id]["payload"][
                    "artifact_digest"
                ],
                "sender_participant_id": sender,
                "receiver_participant_id": "agent_c",
                "session_id": "session-agent_c",
                "purpose": "case-only mock integration",
                "license_digest": _artifact("case-only-license"),
            },
            session_keys["agent_c"],
            f"2030-01-01T00:{minute:02d}:00Z",
        )
    _claim(
        community,
        "agent_c",
        session_keys["agent_c"],
        "claim-c-integrate",
        "route-uniform-integration",
        "Can the accepted mock frontier be integrated into a final fixture?",
        "A synthetic verifier accepts the fixture and every causal dependency is declared.",
        "The result omits an accessed or transitive dependency.",
        "2030-01-01T00:23:00Z",
        "2030-01-01T06:00:00Z",
    )
    _commit_and_handoff(
        community,
        "agent_c",
        session_keys["agent_c"],
        "claim-c-integrate",
        "handoff-c-integration",
        "ADVANCE",
        "Synthetic integration fixture that transitively uses both earlier handoffs.",
        ["handoff-b-even"],
        [],
        "2030-01-01T00:24:00Z",
        "2030-01-01T00:25:00Z",
    )
    _accept_frontier(
        community,
        clerk,
        "frontier-003",
        "A final synthetic fixture exists; its attribution and payout path remain under test.",
        [],
        ["handoff-c-integration"],
        "2030-01-01T00:26:00Z",
    )

    community = _cold_resume(community, clerk)
    cold_resumes += 1
    _result(
        community,
        session_keys["agent_c"],
        "result-omits-a",
        ["handoff-b-even", "handoff-c-integration"],
        "2030-01-01T00:30:00Z",
    )
    _technical_receipt(
        community,
        verifier,
        "result-omits-a",
        "2030-01-01T00:31:00Z",
    )
    incomplete_attribution_blocked = False
    try:
        community.seal("result-omits-a", "2030-01-01T00:32:00Z")
    except ProtocolError as exc:
        incomplete_attribution_blocked = "incomplete attribution" in str(exc)
    if not incomplete_attribution_blocked:
        raise ProtocolError("community demo failed to block omitted attribution")

    _result(
        community,
        session_keys["agent_c"],
        "result-complete",
        ["handoff-a-intake", "handoff-b-even", "handoff-c-integration"],
        "2030-01-01T00:33:00Z",
    )
    _technical_receipt(
        community,
        verifier,
        "result-complete",
        "2030-01-01T00:34:00Z",
    )
    evidence_root = community.seal("result-complete", "2030-01-01T00:35:00Z")

    ballot_specs = {
        "reviewer_1": {"agent_a": 2_500, "agent_b": 3_000, "agent_c": 4_500},
        "reviewer_2": {"agent_a": 2_600, "agent_b": 2_900, "agent_c": 4_500},
        "reviewer_3": {"agent_a": 2_400, "agent_b": 3_100, "agent_c": 4_500},
    }
    ballots: dict[str, tuple[dict[str, Any], str]] = {}
    for index, (reviewer_id, shares) in enumerate(ballot_specs.items(), start=1):
        ballot = _ballot(community.state.case_id, evidence_root, reviewer_id, shares)
        salt = f"{index:064x}"
        ballots[reviewer_id] = (ballot, salt)
        community.append(
            "credit_ballot_committed",
            {
                "case_id": community.state.case_id,
                "evidence_root": evidence_root,
                "reviewer_id": reviewer_id,
                "commitment": credit_ballot_commitment(ballot, salt),
            },
            reviewer_keys[reviewer_id],
            f"2030-01-01T00:{35 + index:02d}:00Z",
        )
    community.close_credit_commits("2030-01-01T00:39:00Z")
    for index, (reviewer_id, (ballot, salt)) in enumerate(ballots.items(), start=1):
        community.append(
            "credit_ballot_revealed",
            {
                "case_id": community.state.case_id,
                "evidence_root": evidence_root,
                "reviewer_id": reviewer_id,
                "ballot": ballot,
                "salt": salt,
            },
            reviewer_keys[reviewer_id],
            f"2030-01-01T00:{39 + index:02d}:00Z",
        )
    community.finalize_allocation("2030-01-01T00:43:00Z")
    plan = community.create_mock_payout_plan("mock-plan-erdos686", "2030-01-01T00:44:00Z")
    for index, leg in enumerate(plan["legs"], start=1):
        reference = f"mock:{plan['plan_id']}:{leg['leg_id']}"
        community.append(
            "mock_payout_leg_submitted",
            {
                "case_id": community.state.case_id,
                "plan_id": plan["plan_id"],
                "leg_id": leg["leg_id"],
                "mock_reference": reference,
                "chain_observed": True,
            },
            clerk,
            f"2030-01-01T00:{44 + index:02d}:00Z",
        )
    for index, leg in enumerate(plan["legs"], start=1):
        reference = f"mock:{plan['plan_id']}:{leg['leg_id']}"
        community.append(
            "mock_payout_leg_confirmed",
            {
                "case_id": community.state.case_id,
                "plan_id": plan["plan_id"],
                "leg_id": leg["leg_id"],
                "mock_reference": reference,
                "finalized": True,
                "finalized_block": 1_000 + index,
            },
            clerk,
            f"2030-01-01T00:{48 + index:02d}:00Z",
        )
    return CommunityDemo(
        session=community,
        incomplete_attribution_blocked=incomplete_attribution_blocked,
        cold_resumes=cold_resumes,
    )


def render_frontier_markdown(community: CommunitySession) -> str:
    frontier = community.state.current_frontier
    lines = [
        f"# Frontier — {community.state.case_id}",
        "",
        "> Synthetic Boule Community fixture. This is not a mathematical result.",
        "",
        frontier["summary"],
        "",
        "## Open obligations",
        "",
    ]
    if frontier["open_obligations"]:
        lines.extend(f"- {item}" for item in frontier["open_obligations"])
    else:
        lines.append("- None in the mock fixture.")
    lines.extend(["", "## Accepted handoffs", ""])
    lines.extend(f"- `{item}`" for item in frontier["accepted_handoffs"])
    lines.extend(["", f"Digest: `{frontier['frontier_digest']}`", ""])
    return "\n".join(lines)


def render_join_brief_markdown(community: CommunitySession, received_at: str | None = None) -> str:
    brief = community.state.join_brief(received_at)
    objective = brief["objective"]
    lines = [
        f"# Join brief — {brief['case_id']}",
        "",
        "> MOCK LOCAL · zero value · no submission · no transfer",
        "",
        f"Objective: {objective['statement']}",
        "",
        f"Pinned base: `{objective['base_commit']}`",
        "",
        f"Verifier: {objective['verifier']}",
        "",
        "## Current frontier",
        "",
        brief["frontier"]["summary"],
        "",
        "## Next obligations",
        "",
    ]
    if brief["open_obligations"]:
        lines.extend(f"- {item}" for item in brief["open_obligations"])
    else:
        lines.append("- None in the completed fixture.")
    lines.extend(["", "## Active route leases", ""])
    if brief["active_claims"]:
        lines.extend(
            (
                f"- `{claim['route_id']}` — {claim['participant_id']} until "
                f"{claim['expires_at']} ({claim['overlap']})"
            )
            for claim in brief["active_claims"]
        )
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Next action",
            "",
            brief["instruction"],
            "",
            "## Boundaries",
            "",
            (
                "- GitHub stores branches, diffs, PRs, and artifacts; a commit is not "
                "authorship proof."
            ),
            "- Boule records signatures, receipts, dependencies, and provisional attribution.",
            (
                "- The CaseManifest/license governs permitted use; cryptography cannot "
                "prevent copying."
            ),
            "- This command does not launch an agent, mutate GitHub, submit, or move value.",
            "",
        ]
    )
    return "\n".join(lines)


def render_agent_prompt(community: CommunitySession, received_at: str | None = None) -> str:
    brief = community.state.join_brief(received_at)
    obligations = ", ".join(brief["open_obligations"]) or "none"
    leases = (
        ", ".join(
            f"{claim['route_id']} held by {claim['participant_id']} until {claim['expires_at']}"
            for claim in brief["active_claims"]
        )
        or "none"
    )
    return (
        "You are one short-lived Boule Community mock session. Verify the local ledger and "
        "read its ledger-derived frontier. Choose one bounded open route that does not conflict "
        "with an active lease; you may explore, falsify, formalize, scout literature, build a "
        "tool, verify, or integrate. Preserve reproducible evidence and leave exactly one signed "
        "handoff: ADVANCE, NEGATIVE, BLOCKED, or NO_SIGNAL. Declare every dependency and every "
        "accessed contribution you used. Do not expose private prompts or credentials. This is a "
        "local zero-value simulation: do not submit, spend, transfer value, claim a real reward, "
        "or treat a Git commit as authorship or legal ownership.\n\n"
        f"Case: {brief['case_id']}\n"
        f"Objective: {brief['objective']['statement']}\n"
        f"Open obligations: {obligations}\n"
        f"Active leases: {leases}\n"
    )
