from __future__ import annotations

import json
from datetime import datetime

import pytest

from boule.canonical import digest_object
from boule.crypto import generate_private_key, public_key_text, sign_object
from boule.errors import ProtocolError
from boule.workspace import Workspace


def set_time(workspace, value):
    workspace._clock = lambda: datetime.fromisoformat(value.replace("Z", "+00:00"))


def kit(tmp_path):
    m, c, s, o = (generate_private_key() for _ in range(4))
    root = tmp_path / "imported"
    root.mkdir(parents=True)
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "p-1",
                "task": {
                    "task_id": "task-1",
                    "task_commitment": "sha256:" + "1" * 64,
                    "formal_repository_pin": "2" * 40,
                },
            }
        )
    )
    w = Workspace.initialize(
        root,
        {
            "maintainer_key": public_key_text(m),
            "lease_seconds": 60,
            "absolute_lease_seconds": 120,
            "stale_seconds": 20,
            "max_renewals": 1,
        },
    )
    set_time(w, "2030-01-01T00:00:00Z")
    w.append(
        "session_started",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "controller_id": "controller-a",
            "controller_key": public_key_text(c),
            "session_id": "s-a",
            "session_key": public_key_text(s),
            "not_after": "2030-01-01T01:00:00Z",
            "policy_digest": w.config["policy_digest"],
        },
        c,
    )
    return w, m, c, s, o, root


def claim(w, s, received_at="2030-01-01T00:00:01Z", cid="c-1"):
    set_time(w, received_at)
    w.append(
        "work_claimed",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": cid,
            "route": "lemma-x",
            "success_gate": "check",
            "falsifier": "counterexample",
            "parallel": False,
        },
        s,
    )


def heartbeat(w, s, received_at):
    set_time(w, received_at)
    w.append(
        "claim_heartbeat",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": "c-1",
            "progress_digest": "sha256:" + "a" * 64,
        },
        s,
    )


def test_import_chain_tamper_and_receipt_truncation(tmp_path):
    w, m, _, s, _, root = kit(tmp_path)
    original = (root / "problem.json").read_text()
    claim(w, s)
    w.maintainer_tick("2030-01-01T00:00:02Z", m)
    assert (root / "problem.json").read_text() == original
    p = next(w.events_dir.glob("*.json"))
    event = json.loads(p.read_text())
    event["payload"]["participant_id"] = "evil"
    p.write_text(json.dumps(event))
    with pytest.raises(ProtocolError, match="event (id|hash)"):
        w.state("2030-01-01T00:00:03Z")
    w, m, _, s, _, _ = kit(tmp_path / "second")
    claim(w, s)
    w.maintainer_tick("2030-01-01T00:00:02Z", m)
    for p in w.events_dir.glob("*.json"):
        p.unlink()
    w.receipt_path.unlink()
    with pytest.raises(ProtocolError, match="truncated"):
        w.state("2030-01-01T00:00:03Z")


def test_stale_heartbeat_expiry_releases_and_problem_chat(tmp_path):
    w, _, _, s, _, _ = kit(tmp_path)
    claim(w, s)
    assert w.state("2030-01-01T00:00:22Z")["claims"][0]["status"] == "stale"
    heartbeat(w, s, "2030-01-01T00:00:30Z")
    assert w.state("2030-01-01T00:00:31Z")["claims"][0]["status"] == "active"
    set_time(w, "2030-01-01T00:00:31Z")
    w.append(
        "message_posted",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": None,
            "topic": "problem",
            "body": "coordination only",
        },
        s,
    )
    assert w.state("2030-01-01T00:01:31Z")["claims"][0]["status"] == "expired"
    claim(w, s, "2030-01-01T00:01:32Z", "c-2")
    state = w.state("2030-01-01T00:01:33Z")
    assert len(state["messages"]) == 1
    assert state["sessions"][0]["active_claim"] == "c-2"


def test_checkpoint_handoff_dependencies_and_privileges(tmp_path):
    w, m, c, s, o, _ = kit(tmp_path)
    claim(w, s)
    set_time(w, "2030-01-01T00:00:02Z")
    w.append(
        "checkpoint_published",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": "c-1",
            "summary": "progress",
            "next_action": "continue",
            "evidence": [{"ref": "local", "sha256": "sha256:" + "b" * 64}],
        },
        s,
    )
    bad = {
        "problem_id": "p-1",
        "participant_id": "a",
        "session_id": "s-a",
        "claim_id": "c-1",
        "handoff_id": "h-1",
        "outcome": "BLOCKED",
        "summary": "x",
        "next_action": "continue",
        "limitations": "none",
        "reproduce": "pytest",
        "evidence": [{"ref": "report", "sha256": "sha256:" + "c" * 64}],
        "depends_on": ["missing"],
        "provenance": "unknown",
        "citations": [],
    }
    set_time(w, "2030-01-01T00:00:03Z")
    with pytest.raises(ProtocolError, match="earlier handoff"):
        w.append("handoff_published", bad, s)
    w.append("handoff_published", {**bad, "depends_on": []}, s)
    set_time(w, "2030-01-01T00:00:03.500000Z")
    with pytest.raises(ProtocolError, match="no longer open"):
        w.append("handoff_published", {**bad, "handoff_id": "h-2", "depends_on": []}, s)
    first_tick = w.maintainer_tick("2030-01-01T00:00:04Z", m)
    assert first_tick["status"]["handoffs_queued"] == ["h-1"]
    assert first_tick["status"]["at"] == "2030-01-01T00:00:04Z"
    later_tick = w.maintainer_tick("2030-01-01T00:00:05Z", m)
    assert later_tick["receipt"] == first_tick["receipt"]
    with pytest.raises(ProtocolError, match="only participant events"):
        w.append("frontier_accepted", {}, c)
    with pytest.raises(ProtocolError, match="wrong maintainer key"):
        w.maintainer_tick("2030-01-01T00:00:05Z", o)


def test_policy_assent_and_evidence_requirements_fail_closed(tmp_path):
    w, _, controller, session, _, _ = kit(tmp_path)
    other_session = generate_private_key()
    set_time(w, "2030-01-01T00:00:01Z")
    with pytest.raises(ProtocolError, match="assent"):
        w.append(
            "session_started",
            {
                "problem_id": "p-1",
                "participant_id": "b",
                "controller_id": "controller-a",
                "controller_key": public_key_text(controller),
                "session_id": "s-b",
                "session_key": public_key_text(other_session),
                "not_after": "2030-01-01T01:00:00Z",
                "policy_digest": "sha256:" + "0" * 64,
            },
            controller,
        )
    claim(w, session, "2030-01-01T00:00:02Z")
    set_time(w, "2030-01-01T00:00:03Z")
    with pytest.raises(ProtocolError, match="require evidence"):
        w.append(
            "handoff_published",
            {
                "problem_id": "p-1",
                "participant_id": "a",
                "session_id": "s-a",
                "claim_id": "c-1",
                "handoff_id": "h-empty",
                "outcome": "ADVANCE",
                "summary": "unsupported claim",
                "next_action": "review",
                "limitations": "none",
                "reproduce": "none",
                "evidence": [],
                "depends_on": [],
                "provenance": "original",
                "citations": [],
            },
            session,
        )


def test_replay_rejects_a_validly_signed_second_handoff_on_closed_claim(tmp_path):
    w, _, _, session, _, _ = kit(tmp_path)
    claim(w, session)
    payload = {
        "problem_id": "p-1",
        "participant_id": "a",
        "session_id": "s-a",
        "claim_id": "c-1",
        "handoff_id": "h-1",
        "outcome": "NEGATIVE",
        "summary": "closed route",
        "next_action": "stop",
        "limitations": "narrow only",
        "reproduce": "run check",
        "evidence": [{"ref": "check", "sha256": "sha256:" + "d" * 64}],
        "depends_on": [],
        "provenance": "original",
        "citations": [],
    }
    set_time(w, "2030-01-01T00:00:02Z")
    w.append("handoff_published", payload, session)
    events = w._events()
    second_payload = {**payload, "handoff_id": "h-2"}
    received_at = "2030-01-01T00:00:03Z"
    unsigned = {
        "seq": len(events),
        "event_id": (
            f"{len(events):08d}-"
            f"{digest_object(['handoff_published', second_payload, received_at])[:16]}"
        ),
        "received_at": received_at,
        "kind": "handoff_published",
        "actor": public_key_text(session),
        "payload": second_payload,
        "prev_event_hash": events[-1]["event_hash"],
    }
    forged = {
        **unsigned,
        "event_hash": digest_object(unsigned),
        "signature": sign_object(session, unsigned),
    }
    Workspace._write(
        w.events_dir / f"{forged['seq']:08d}-{forged['event_id']}.json", forged, True
    )
    with pytest.raises(ProtocolError, match="no longer open"):
        w.state("2030-01-01T00:00:04Z")
