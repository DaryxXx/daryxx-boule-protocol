from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest

from boule.crypto import generate_private_key, public_key_text
from boule.errors import AuthenticationError, ProtocolError, RequestConflictError, StaleHeadError
from boule.remote_protocol import build_envelope, verify_receipt
from boule.workspace import EVENT_SCHEMA, Workspace


def set_time(workspace: Workspace, value: str) -> None:
    workspace._clock = lambda: datetime.fromisoformat(value.replace("Z", "+00:00"))


def kit(tmp_path, *, session_not_after: str = "2030-01-01T01:00:00Z"):
    maintainer, controller, session = (generate_private_key() for _ in range(3))
    root = tmp_path / "case"
    root.mkdir(parents=True)
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "p-remote",
                "task": {
                    "task_id": "task-remote",
                    "task_commitment": "sha256:" + "1" * 64,
                    "formal_repository_pin": "2" * 40,
                },
            }
        ),
        encoding="utf-8",
    )
    workspace = Workspace.initialize(
        root,
        {
            "maintainer_key": public_key_text(maintainer),
            "lease_seconds": 60,
            "absolute_lease_seconds": 120,
            "stale_seconds": 20,
            "max_renewals": 1,
        },
    )
    set_time(workspace, "2030-01-01T00:00:00Z")
    workspace.append(
        "session_started",
        {
            "problem_id": "p-remote",
            "participant_id": "agent-a",
            "controller_id": "controller-a",
            "controller_key": public_key_text(controller),
            "session_id": "session-a",
            "session_key": public_key_text(session),
            "not_after": session_not_after,
            "policy_digest": workspace.config["policy_digest"],
        },
        controller,
    )
    return workspace, maintainer, session, root


def test_legacy_v04_replay_keeps_long_session_compatibility(tmp_path):
    workspace, _, _, root = kit(tmp_path, session_not_after="2031-01-01T00:00:00Z")

    assert Workspace(root).state("2030-01-01T00:00:01Z")["sessions"][0]["status"] == "active"
    assert workspace._events()[0].get("schema") is None


def claim_payload() -> dict:
    return {
        "problem_id": "p-remote",
        "participant_id": "agent-a",
        "session_id": "session-a",
        "claim_id": "claim-remote",
        "route": "prove one bounded lemma",
        "success_gate": "reproducible certificate",
        "falsifier": "exact counterexample",
        "parallel": False,
    }


def envelope(workspace: Workspace, key, payload: dict, *, request_id: str | None = None):
    events = workspace._events()
    return build_envelope(
        request_id=request_id or str(uuid.uuid4()),
        problem_id=workspace.problem["problem_id"],
        clerk_key=workspace.config["maintainer_key"],
        base_event_hash=events[-1]["event_hash"] if events else None,
        kind="work_claimed",
        payload=payload,
        private_key=key,
    )


def test_v04_to_v05_replay_idempotence_conflict_and_restart(tmp_path):
    workspace, maintainer, session, root = kit(tmp_path)
    signed = envelope(workspace, session, claim_payload())
    set_time(workspace, "2030-01-01T00:00:01Z")
    accepted = workspace.append_envelope(signed, maintainer)

    assert accepted["created"] is True
    assert accepted["event"]["schema"] == EVENT_SCHEMA
    verify_receipt(
        accepted["receipt"],
        problem_id="p-remote",
        clerk_key=workspace.config["maintainer_key"],
        request_id=signed["request_id"],
        envelope=signed,
    )
    assert workspace.state("2030-01-01T00:00:02Z")["claims"][0]["status"] == "active"

    retried = workspace.append_envelope(signed, maintainer)
    assert retried["created"] is False
    assert retried["receipt"] == accepted["receipt"]
    assert len(workspace._events()) == 2

    conflicting = build_envelope(
        request_id=signed["request_id"],
        problem_id="p-remote",
        clerk_key=workspace.config["maintainer_key"],
        base_event_hash=signed["base_event_hash"],
        kind="work_claimed",
        payload={**claim_payload(), "route": "different route"},
        private_key=session,
    )
    with pytest.raises(RequestConflictError):
        workspace.append_envelope(conflicting, maintainer)

    reopened = Workspace(root)
    same = reopened.append_envelope(signed, maintainer)
    assert same["created"] is False
    assert same["receipt"] == accepted["receipt"]


def test_stale_head_tamper_and_clock_rollback_fail_safely(tmp_path):
    workspace, maintainer, session, _ = kit(tmp_path)
    stale = envelope(workspace, session, claim_payload())
    set_time(workspace, "2030-01-01T00:00:01Z")
    accepted = workspace.append_envelope(stale, maintainer)

    another = build_envelope(
        request_id=str(uuid.uuid4()),
        problem_id="p-remote",
        clerk_key=workspace.config["maintainer_key"],
        base_event_hash=stale["base_event_hash"],
        kind="message_posted",
        payload={
            "problem_id": "p-remote",
            "participant_id": "agent-a",
            "session_id": "session-a",
            "claim_id": "claim-remote",
            "topic": "coordination",
            "body": "check this route",
        },
        private_key=session,
    )
    with pytest.raises(StaleHeadError) as stale_error:
        workspace.append_envelope(another, maintainer)
    assert stale_error.value.current_head == accepted["event"]["event_hash"]

    current = build_envelope(
        request_id=str(uuid.uuid4()),
        problem_id="p-remote",
        clerk_key=workspace.config["maintainer_key"],
        base_event_hash=accepted["event"]["event_hash"],
        kind="message_posted",
        payload=another["payload"],
        private_key=session,
    )
    set_time(workspace, "2029-12-31T23:59:59Z")
    ordered = workspace.append_envelope(current, maintainer)
    assert ordered["event"]["received_at"] == accepted["event"]["received_at"]

    remote_path = sorted(workspace.events_dir.glob("*.json"))[-1]
    event = json.loads(remote_path.read_text(encoding="utf-8"))
    event["clerk_receipt"]["event_hash"] = "0" * 64
    remote_path.write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(ProtocolError, match="signature verification|does not match"):
        workspace.state("2030-01-01T00:00:02Z")


def test_signature_tamper_and_concurrent_exact_retry(tmp_path):
    workspace, maintainer, session, _ = kit(tmp_path)
    signed = envelope(workspace, session, claim_payload())
    tampered = json.loads(json.dumps(signed))
    tampered["payload"]["route"] = "stolen rewrite"
    with pytest.raises(AuthenticationError):
        workspace.append_envelope(tampered, maintainer)

    set_time(workspace, "2030-01-01T00:00:01Z")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: workspace.append_envelope(signed, maintainer), range(32)))
    assert sum(result["created"] for result in results) == 1
    assert len({result["receipt"]["signature"] for result in results}) == 1
    assert len(workspace._events()) == 2
