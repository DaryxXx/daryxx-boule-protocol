from __future__ import annotations

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from boule.canonical import digest_object
from boule.cli import _sync_pending_provider_cases
from boule.crypto import generate_private_key, public_key_text, sign_object
from boule.errors import ProtocolError
from boule.provider_observer import ProviderObservation
from boule.provider_sync import sync_provider_candidate
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


ARTIFACT = {"ref": "Solution.lean", "sha256": "sha256:" + "e" * 64}
SUBMISSION_ID = "82ab85ee-5dfc-4775-b3e1-8abc16e213b9"


def advance(w, s, received_at="2030-01-01T00:00:02Z", handoff_id="h-solution"):
    set_time(w, received_at)
    return w.append(
        "handoff_published",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": "c-1",
            "handoff_id": handoff_id,
            "outcome": "ADVANCE",
            "summary": "exact candidate",
            "next_action": "seal the candidate",
            "limitations": "awaits external checks",
            "reproduce": "lake env lean Solution.lean",
            "evidence": [ARTIFACT],
            "depends_on": [],
            "provenance": "original",
            "citations": [],
        },
        s,
    )


def candidate_payload(candidate_id="candidate-1", handoff_id="h-solution"):
    return {
        "problem_id": "p-1",
        "participant_id": "a",
        "session_id": "s-a",
        "candidate_id": candidate_id,
        "handoff_ids": [handoff_id],
        "task_id": "task-1",
        "task_commitment": "sha256:" + "1" * 64,
        "formal_repository_pin": "2" * 40,
        "artifact": ARTIFACT,
        "summary": "solves the pinned task",
        "reproduce": "lake env lean Solution.lean",
        "limitations": "external review still required",
    }


def submission_payload(candidate_id="candidate-1", submission_id=SUBMISSION_ID):
    result_url = f"https://conjectures.io/results/{submission_id}"
    return {
        "problem_id": "p-1",
        "candidate_id": candidate_id,
        "submission_id": submission_id,
        "task_id": "task-1",
        "task_commitment": "sha256:" + "1" * 64,
        "formal_repository_pin": "2" * 40,
        "artifact_sha256": ARTIFACT["sha256"],
        "submitted_at": "2030-01-01T00:00:04Z",
        "public_result_url": result_url,
        "source": "trusted-clerk/conjectures.io-submission",
        "receipt": {"ref": result_url, "sha256": "sha256:" + "3" * 64},
    }


def feedback_payload(stage, decision, candidate_id="candidate-1", submission_id=SUBMISSION_ID):
    result_url = f"https://conjectures.io/results/{submission_id}"
    return {
        "problem_id": "p-1",
        "candidate_id": candidate_id,
        "submission_id": submission_id,
        "task_id": "task-1",
        "task_commitment": "sha256:" + "1" * 64,
        "formal_repository_pin": "2" * 40,
        "artifact_sha256": ARTIFACT["sha256"],
        "stage": stage,
        "decision": decision,
        "reason_code": f"TEST_{decision}",
        "summary": f"official {stage} state observed as {decision}",
        "next_action": "continue from the attached report",
        "public_result_url": result_url,
        "source": {
            "verifier": "trusted-clerk/conjectures.io-lean-verifier",
            "review": "trusted-clerk/conjectures.io-human-review",
            "reward": "trusted-clerk/conjectures.io-reward-eligibility",
        }[stage],
        "report": {"ref": result_url, "sha256": "sha256:" + "4" * 64},
    }


class StaticProviderObserver:
    provider_id = "conjectures.io"

    def __init__(self, observation: ProviderObservation):
        self.observation = observation
        self.calls = 0

    def observe(self, contract, submission_id, task_id):
        self.calls += 1
        assert contract["provider_id"] == self.provider_id
        assert submission_id == SUBMISSION_ID
        assert task_id == "task-1"
        return self.observation


def provider_observation(
    *,
    verification="VERIFIED",
    review="UNREVIEWED",
    reward="INELIGIBLE",
    reason=None,
    summary=None,
):
    return ProviderObservation(
        provider_id="conjectures.io",
        submission_id=SUBMISSION_ID,
        task_id="task-1",
        public_result_url=f"https://conjectures.io/results/{SUBMISSION_ID}",
        evidence_sha256="sha256:" + "8" * 64,
        evidence_source_url="https://conjectures.io/v1/results/submissions?limit=100",
        verification_status=verification,
        review_status=review,
        settlement_status=reward,
        failure_reason=reason if verification == "REJECTED" else None,
        review_reason_code=reason if review != "UNREVIEWED" else None,
        review_summary=summary if review != "UNREVIEWED" else None,
    )


def resolution_payload(review_event_id, candidate_id="candidate-1", submission_id=SUBMISSION_ID):
    return {
        "problem_id": "p-1",
        "candidate_id": candidate_id,
        "submission_id": submission_id,
        "task_id": "task-1",
        "task_commitment": "sha256:" + "1" * 64,
        "formal_repository_pin": "2" * 40,
        "artifact_sha256": ARTIFACT["sha256"],
        "public_result_url": f"https://conjectures.io/results/{submission_id}",
        "source": "trusted-clerk/conjectures.io-human-review",
        "resolution": "SOLVED",
        "review_event_id": review_event_id,
        "note": "trusted clerk finalized the approved result",
    }


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
    Workspace._write(w.events_dir / f"{forged['seq']:08d}-{forged['event_id']}.json", forged, True)
    with pytest.raises(ProtocolError, match="no longer open"):
        w.state("2030-01-01T00:00:04Z")


def test_candidate_submission_verification_review_and_reward_are_separate(tmp_path):
    w, maintainer, _, session, outsider, _ = kit(tmp_path)
    claim(w, session)
    advance(w, session)
    set_time(w, "2030-01-01T00:00:03Z")
    candidate_event = w.append("submission_candidate_published", candidate_payload(), session)
    state = w.state("2030-01-01T00:00:03Z")
    assert state["problem_status"] == "CANDIDATE_READY"
    assert state["provider_resolution"]["status"] == "OPEN"
    assert state["provider_resolution"]["research_open"] is True
    assert state["candidates"][0]["submission"] is None
    assert state["candidates"][0]["reward"] is None

    with pytest.raises(ProtocolError, match="only participant events"):
        w.append("external_submission_receipted", submission_payload(), session)
    with pytest.raises(ProtocolError, match="maintainer key"):
        w.append_maintainer("external_submission_receipted", submission_payload(), outsider)

    set_time(w, "2030-01-01T00:00:05Z")
    w.append_maintainer("external_submission_receipted", submission_payload(), maintainer)
    state = w.state("2030-01-01T00:00:05Z")
    assert state["problem_status"] == "VERIFICATION_PENDING"
    assert state["provider_resolution"]["status"] == "PENDING_VERIFICATION"
    assert state["provider_resolution"]["native_status"] == {
        "manual_review_status": "UNREVIEWED",
        "reward_status": "INELIGIBLE",
        "verification_status": "UNVERIFIED",
    }
    assert state["candidates"][0]["verifier"] is None
    claim(w, session, "2030-01-01T00:00:06Z", "c-during-review")
    set_time(w, "2030-01-01T00:00:06.500000Z")
    w.append(
        "claim_released",
        {
            "problem_id": "p-1",
            "participant_id": "a",
            "session_id": "s-a",
            "claim_id": "c-during-review",
            "reason": "review can remain pending without freezing independent research",
        },
        session,
    )

    set_time(w, "2030-01-01T00:00:07Z")
    w.append_maintainer(
        "candidate_feedback_recorded", feedback_payload("verifier", "VERIFIED"), maintainer
    )
    state = w.state("2030-01-01T00:00:07Z")
    assert state["problem_status"] == "REVIEW_PENDING"
    assert state["provider_resolution"]["status"] == "PENDING_VERIFICATION"
    assert state["provider_resolution"]["native_status"]["verification_status"] == "VERIFIED"
    assert state["candidates"][0]["review"] is None
    assert state["candidates"][0]["reward"] is None

    set_time(w, "2030-01-01T00:00:08Z")
    review_event = w.append_maintainer(
        "candidate_feedback_recorded", feedback_payload("review", "APPROVED"), maintainer
    )
    state = w.state("2030-01-01T00:00:08Z")
    assert state["problem_status"] == "ACCEPTANCE_RECORDED"
    assert state["provider_resolution"]["status"] == "PENDING_VERIFICATION"
    assert state["research_resume"]["action"] == "AWAIT_TRUSTED_CLERK_FINALIZATION"
    assert state["candidates"][0]["reward"] is None

    set_time(w, "2030-01-01T00:00:09Z")
    with pytest.raises(ProtocolError, match="exact approved review"):
        w.append_maintainer(
            "case_resolution_recorded", resolution_payload("invented-review"), maintainer
        )
    with pytest.raises(ProtocolError, match="task identity"):
        w.append_maintainer(
            "case_resolution_recorded",
            {
                **resolution_payload(review_event["event_id"]),
                "task_commitment": "sha256:" + "9" * 64,
            },
            maintainer,
        )
    with pytest.raises(ProtocolError, match="resolution source"):
        w.append_maintainer(
            "case_resolution_recorded",
            {**resolution_payload(review_event["event_id"]), "source": "participant-self-report"},
            maintainer,
        )
    w.append_maintainer(
        "case_resolution_recorded", resolution_payload(review_event["event_id"]), maintainer
    )
    state = w.state("2030-01-01T00:00:09Z")
    assert state["problem_status"] == "SOLVED"
    assert state["provider_resolution"]["status"] == "SOLVED"
    assert state["provider_resolution"]["terminal"] is True
    assert state["provider_resolution"]["bounty"] == {
        "managed_by_boule": False,
        "native_status": "INELIGIBLE",
        "status": "NOT_MANAGED",
    }
    assert state["research_resume"]["action"] == "STOP_RESEARCH_PRESERVE_EVIDENCE"
    assert state["external_status_trust"]["authenticated_external_attestation"] is False
    with pytest.raises(ProtocolError, match="not open"):
        claim(w, session, "2030-01-01T00:00:10Z", "c-after-solved")

    set_time(w, "2030-01-01T00:00:11Z")
    w.append_maintainer(
        "candidate_feedback_recorded", feedback_payload("reward", "ELIGIBLE"), maintainer
    )
    state = w.state("2030-01-01T00:00:11Z")
    assert state["problem_status"] == "SOLVED"
    assert state["candidates"][0]["reward"]["decision"] == "ELIGIBLE"
    assert candidate_event["actor"] == public_key_text(session)


def test_rejection_feedback_reopens_research_and_exact_retry_is_idempotent(tmp_path):
    w, maintainer, _, session, _, _ = kit(tmp_path)
    claim(w, session)
    advance(w, session)
    set_time(w, "2030-01-01T00:00:03Z")
    w.append("submission_candidate_published", candidate_payload(), session)
    with pytest.raises(ProtocolError, match="already sealed"):
        w.append(
            "submission_candidate_published",
            {**candidate_payload("candidate-copy"), "summary": "duplicate under a new id"},
            session,
        )
    set_time(w, "2030-01-01T00:00:05Z")
    w.append_maintainer("external_submission_receipted", submission_payload(), maintainer)
    rejected = feedback_payload("verifier", "REJECTED")
    set_time(w, "2030-01-01T00:00:06Z")
    first = w.append_maintainer("candidate_feedback_recorded", rejected, maintainer)
    count = len(w._events())
    set_time(w, "2030-01-01T00:00:07Z")
    retry = w.append_maintainer("candidate_feedback_recorded", rejected, maintainer)
    assert retry["event_id"] == first["event_id"]
    assert len(w._events()) == count

    state = w.state("2030-01-01T00:00:07Z")
    assert state["problem_status"] == "OPEN_AFTER_FEEDBACK"
    assert state["provider_resolution"]["status"] == "FAILED"
    assert state["provider_resolution"]["research_open"] is True
    assert state["provider_resolution"]["terminal"] is False
    assert state["provider_resolution"]["feedback"][-1]["decision"] == "REJECTED"
    assert state["research_resume"]["action"] == "CONTINUE_RESEARCH_FROM_FEEDBACK"
    assert state["research_resume"]["feedback"]["decision"] == "REJECTED"
    claim(w, session, "2030-01-01T00:00:08Z", "c-revision")
    assert w.state("2030-01-01T00:00:08Z")["claims"][-1]["status"] == "active"

    set_time(w, "2030-01-01T00:00:09Z")
    with pytest.raises(ProtocolError, match="candidate state"):
        w.append_maintainer(
            "candidate_feedback_recorded", feedback_payload("verifier", "VERIFIED"), maintainer
        )


def test_task_artifact_external_id_and_feedback_binding_fail_closed(tmp_path):
    w, maintainer, _, session, _, _ = kit(tmp_path)
    claim(w, session)
    advance(w, session)
    set_time(w, "2030-01-01T00:00:03Z")
    with pytest.raises(ProtocolError, match="task identity"):
        w.append(
            "submission_candidate_published",
            {**candidate_payload(), "formal_repository_pin": "9" * 40},
            session,
        )
    with pytest.raises(ProtocolError, match="evidence in a linked handoff"):
        w.append(
            "submission_candidate_published",
            {
                **candidate_payload(),
                "artifact": {"ref": "Other.lean", "sha256": "sha256:" + "f" * 64},
            },
            session,
        )
    w.append("submission_candidate_published", candidate_payload(), session)
    set_time(w, "2030-01-01T00:00:05Z")
    with pytest.raises(ProtocolError, match="sealed candidate"):
        w.append_maintainer(
            "external_submission_receipted",
            {**submission_payload(), "artifact_sha256": "sha256:" + "f" * 64},
            maintainer,
        )
    with pytest.raises(ProtocolError, match="result URL"):
        w.append_maintainer(
            "external_submission_receipted",
            {**submission_payload(), "public_result_url": "https://example.com/fake"},
            maintainer,
        )
    with pytest.raises(ProtocolError, match="source"):
        w.append_maintainer(
            "external_submission_receipted",
            {**submission_payload(), "source": "participant-self-report"},
            maintainer,
        )
    w.append_maintainer("external_submission_receipted", submission_payload(), maintainer)
    set_time(w, "2030-01-01T00:00:06Z")
    with pytest.raises(ProtocolError, match="result URL"):
        w.append_maintainer(
            "candidate_feedback_recorded",
            {
                **feedback_payload("verifier", "REJECTED"),
                "public_result_url": "https://conjectures.io/results/00000000-0000-0000-0000-000000000000",
            },
            maintainer,
        )


def test_partial_award_records_feedback_and_keeps_research_open(tmp_path):
    w, maintainer, _, session, _, _ = kit(tmp_path)
    claim(w, session)
    advance(w, session)
    set_time(w, "2030-01-01T00:00:03Z")
    w.append("submission_candidate_published", candidate_payload(), session)
    set_time(w, "2030-01-01T00:00:05Z")
    w.append_maintainer("external_submission_receipted", submission_payload(), maintainer)
    set_time(w, "2030-01-01T00:00:06Z")
    w.append_maintainer(
        "candidate_feedback_recorded", feedback_payload("verifier", "VERIFIED"), maintainer
    )
    set_time(w, "2030-01-01T00:00:07Z")
    partial = feedback_payload("review", "PARTIAL_AWARD")
    partial["reason_code"] = "FORMALIZATION_DEFECT_AWARD"
    partial["next_action"] = "import a corrected task manifest before more research"
    w.append_maintainer("candidate_feedback_recorded", partial, maintainer)
    state = w.state("2030-01-01T00:00:07Z")
    assert state["problem_status"] == "OPEN_AFTER_FEEDBACK"
    assert state["research_resume"]["action"] == "CONTINUE_RESEARCH_FROM_FEEDBACK"
    assert state["research_resume"]["feedback"]["decision"] == "PARTIAL_AWARD"
    claim(w, session, "2030-01-01T00:00:08Z", "c-after-partial")
    set_time(w, "2030-01-01T00:00:08Z")
    with pytest.raises(ProtocolError, match="invalid reward decision"):
        w.append_maintainer(
            "candidate_feedback_recorded", feedback_payload("reward", "PAID"), maintainer
        )
    w.append_maintainer(
        "candidate_feedback_recorded", feedback_payload("reward", "ELIGIBLE"), maintainer
    )
    assert w.state("2030-01-01T00:00:08Z")["problem_status"] == "OPEN_AFTER_FEEDBACK"


def _submitted_workspace(tmp_path):
    w, maintainer, _, session, _, _ = kit(tmp_path)
    claim(w, session)
    advance(w, session)
    set_time(w, "2030-01-01T00:00:03Z")
    w.append("submission_candidate_published", candidate_payload(), session)
    set_time(w, "2030-01-01T00:00:05Z")
    w.append_maintainer("external_submission_receipted", submission_payload(), maintainer)
    set_time(w, "2030-01-01T00:00:06Z")
    return w, maintainer


def test_provider_sync_records_approved_review_and_resolution_without_bounty_action(tmp_path):
    w, maintainer = _submitted_workspace(tmp_path)
    observer = StaticProviderObserver(
        provider_observation(
            review="APPROVED",
            reward="ELIGIBLE",
            reason="VALID_PROOF",
            summary="The pinned Lean artifact passed review.",
        )
    )
    result = sync_provider_candidate(
        w,
        "candidate-1",
        maintainer,
        observer=observer,
        now=lambda: "2030-01-01T00:00:06Z",
    )

    assert result["events_appended"] == [
        "candidate_feedback_recorded",
        "candidate_feedback_recorded",
        "case_resolution_recorded",
    ]
    assert result["problem_status"] == "SOLVED"
    assert result["provider_resolution"]["status"] == "SOLVED"
    assert result["observed"]["reward_status"] == "ELIGIBLE"
    assert result["bounty_action_performed"] is False
    state = w.state("2030-01-01T00:00:06Z")
    assert state["candidates"][0]["reward"] is None
    assert state["feedback"][-1]["reason_code"] == "VALID_PROOF"
    assert state["feedback"][-1]["report"]["ref"].startswith(
        "https://conjectures.io/v1/results/submissions"
    )

    event_count = len(w._events())
    replay = sync_provider_candidate(
        w,
        "candidate-1",
        maintainer,
        observer=observer,
        now=lambda: "2030-01-01T00:00:06Z",
    )
    assert replay["events_appended"] == []
    assert len(w._events()) == event_count
    assert observer.calls == 2


def test_provider_sync_retains_reviewer_rejection_and_reopens_research(tmp_path):
    w, maintainer = _submitted_workspace(tmp_path)
    result = sync_provider_candidate(
        w,
        "candidate-1",
        maintainer,
        observer=StaticProviderObserver(
            provider_observation(
                review="REJECTED",
                reason="MISSING_CASE",
                summary="One required case is not covered.",
            )
        ),
        now=lambda: "2030-01-01T00:00:06Z",
    )

    assert result["events_appended"] == [
        "candidate_feedback_recorded",
        "candidate_feedback_recorded",
    ]
    assert result["provider_resolution"]["status"] == "FAILED"
    assert result["provider_resolution"]["research_open"] is True
    assert result["provider_resolution"]["feedback"][-1]["summary"] == (
        "One required case is not covered."
    )


def test_provider_sync_retains_public_verifier_failure(tmp_path):
    w, maintainer = _submitted_workspace(tmp_path)
    result = sync_provider_candidate(
        w,
        "candidate-1",
        maintainer,
        observer=StaticProviderObserver(
            provider_observation(
                verification="REJECTED",
                reason="Lean compilation failed at the pinned task.",
            )
        ),
        now=lambda: "2030-01-01T00:00:06Z",
    )

    assert result["events_appended"] == ["candidate_feedback_recorded"]
    feedback = result["provider_resolution"]["feedback"][-1]
    assert result["provider_resolution"]["status"] == "FAILED"
    assert feedback["reason_code"] == "PROVIDER_REJECTED"
    assert feedback["summary"] == "Lean compilation failed at the pinned task."


def test_provider_sync_pending_state_is_read_only_and_identity_mismatch_fails(tmp_path):
    w, maintainer = _submitted_workspace(tmp_path)
    pending = sync_provider_candidate(
        w,
        "candidate-1",
        maintainer,
        observer=StaticProviderObserver(
            provider_observation(verification="UNVERIFIED", review="UNREVIEWED")
        ),
        now=lambda: "2030-01-01T00:00:06Z",
    )
    assert pending["events_appended"] == []
    assert pending["provider_resolution"]["status"] == "PENDING_VERIFICATION"

    mismatch = provider_observation()
    mismatch = ProviderObservation(**{**mismatch.__dict__, "task_id": "another-task"})
    with pytest.raises(ProtocolError, match="does not match the submitted candidate"):
        sync_provider_candidate(
            w,
            "candidate-1",
            maintainer,
            observer=StaticProviderObserver(mismatch),
            now=lambda: "2030-01-01T00:00:06Z",
        )


def test_registry_maintainer_discovers_and_syncs_pending_cases(monkeypatch, tmp_path):
    w, maintainer = _submitted_workspace(tmp_path)
    observer = StaticProviderObserver(
        provider_observation(
            review="REJECTED",
            reason="MISSING_CASE",
            summary="One required case is not covered.",
        )
    )

    class FakeRegistry:
        @staticmethod
        def problems(*, live_only):
            assert live_only is True
            return [{"case_id": "case-1"}]

    class FakeHub:
        registry = FakeRegistry()

        @staticmethod
        def case_workspace(case_id):
            assert case_id == "case-1"
            return w

    monkeypatch.setattr("boule.cli._now", lambda: "2030-01-01T00:00:06Z")
    monkeypatch.setattr("boule.cli.load_maintainer_key", lambda _workspace: maintainer)
    monkeypatch.setattr("boule.cli.observer_for_provider", lambda *_args, **_kwargs: observer)

    def fixed_sync(workspace, candidate_id, key, **kwargs):
        return sync_provider_candidate(
            workspace,
            candidate_id,
            key,
            **kwargs,
            now=lambda: "2030-01-01T00:00:06Z",
        )

    monkeypatch.setattr("boule.cli.sync_provider_candidate", fixed_sync)
    errors = {}
    results = _sync_pending_provider_cases(
        FakeHub(),
        SimpleNamespace(provider_sync=True, provider_timeout=4, provider_max_pages=2),
        errors,
    )

    assert errors == {}
    assert len(results) == 1
    assert results[0]["case_id"] == "case-1"
    assert results[0]["provider_resolution"]["status"] == "FAILED"
    assert results[0]["events_appended"] == [
        "candidate_feedback_recorded",
        "candidate_feedback_recorded",
    ]
