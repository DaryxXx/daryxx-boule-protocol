"""Evidence-backed synchronization from provider observations into one case ledger."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .errors import ProtocolError
from .provider_contract import decision_outcome, stage_contract
from .provider_observer import ProviderObservation, SubmissionObserver, observer_for_provider
from .workspace import Workspace


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _bounded(value: str | None, fallback: str, maximum: int = 2000) -> str:
    text = value.strip() if isinstance(value, str) else ""
    text = text or fallback
    if len(text) <= maximum:
        return text
    suffix = " [truncated; see the provider result]"
    return text[: maximum - len(suffix)].rstrip() + suffix


def _candidate(workspace: Workspace, candidate_id: str, at: str) -> dict[str, Any]:
    state = workspace.state(at)
    candidate = next(
        (item for item in state["candidates"] if item["candidate_id"] == candidate_id), None
    )
    if candidate is None:
        raise ProtocolError("candidate does not exist")
    if candidate.get("submission") is None:
        raise ProtocolError("candidate has no recorded provider submission")
    return candidate


def _feedback_payload(
    workspace: Workspace,
    candidate: dict[str, Any],
    observation: ProviderObservation,
    *,
    stage: str,
    decision: str,
) -> dict[str, Any]:
    outcome = decision_outcome(workspace.provider_contract, stage, decision)
    if stage == "verifier":
        fallback_summary = (
            f"{workspace.provider_contract['display_name']} public status reports "
            f"verification_status={decision}."
        )
        reason_code = f"PROVIDER_{decision}"
        summary = _bounded(
            observation.failure_reason if outcome == "failure" else None,
            fallback_summary,
        )
        next_action = (
            "Continue from the provider verifier report and seal a new artifact."
            if outcome == "failure"
            else "Await the provider review decision."
        )
    else:
        reason_code = _bounded(observation.review_reason_code, f"PROVIDER_{decision}", 256)
        summary = _bounded(
            observation.review_summary,
            (
                f"{workspace.provider_contract['display_name']} public status reports "
                f"manual_review_status={decision}."
            ),
        )
        next_action = (
            "Preserve the accepted evidence; Boule may record exact-case resolution."
            if outcome == "success"
            else "Address the published provider feedback and seal a new candidate."
        )
    task = workspace.problem["task"]
    details = stage_contract(workspace.provider_contract, stage)
    return {
        "problem_id": workspace.problem["problem_id"],
        "candidate_id": candidate["candidate_id"],
        "submission_id": observation.submission_id,
        "task_id": task["task_id"],
        "task_commitment": task["task_commitment"],
        "formal_repository_pin": task["formal_repository_pin"],
        "artifact_sha256": candidate["artifact"]["sha256"],
        "stage": stage,
        "decision": decision,
        "reason_code": reason_code,
        "summary": summary,
        "next_action": next_action,
        "public_result_url": observation.public_result_url,
        "source": details["source"],
        "report": {
            "ref": observation.evidence_source_url,
            "sha256": observation.evidence_sha256,
        },
    }


def sync_provider_candidate(
    workspace: Workspace,
    candidate_id: str,
    maintainer_private_key: Any,
    *,
    observer: SubmissionObserver | None = None,
    timeout: float = 10.0,
    max_pages: int = 3,
    now: Callable[[], str] = _now,
) -> dict[str, Any]:
    """Observe one external submission and append only newly reached provider decisions."""

    observed_at = now()
    candidate = _candidate(workspace, candidate_id, observed_at)
    submission = candidate["submission"]
    task = workspace.problem["task"]
    selected = observer or observer_for_provider(
        workspace.provider_contract["provider_id"], timeout=timeout, max_pages=max_pages
    )
    if selected is None:
        raise ProtocolError(
            f"no status observer is installed for {workspace.provider_contract['provider_id']}"
        )
    observation = selected.observe(
        workspace.provider_contract, submission["submission_id"], task["task_id"]
    )
    expected_result_url = submission["public_result_url"]
    if (
        observation.provider_id != workspace.provider_contract["provider_id"]
        or observation.submission_id != submission["submission_id"]
        or observation.task_id != task["task_id"]
        or observation.public_result_url != expected_result_url
    ):
        raise ProtocolError("provider observation does not match the submitted candidate")
    events: list[dict[str, Any]] = []

    verifier = workspace.provider_contract["stages"]["verifier"]
    if candidate.get("verifier") is None:
        if observation.verification_status in verifier["pending"]:
            state = workspace.state(now())
            return _result(observation, events, state)
        event = workspace.append_maintainer(
            "candidate_feedback_recorded",
            _feedback_payload(
                workspace,
                candidate,
                observation,
                stage="verifier",
                decision=observation.verification_status,
            ),
            maintainer_private_key,
        )
        events.append(event)
        candidate = _candidate(workspace, candidate_id, now())
    elif candidate["verifier"]["decision"] != observation.verification_status:
        raise ProtocolError("provider verification status conflicts with recorded feedback")

    if (
        decision_outcome(workspace.provider_contract, "verifier", observation.verification_status)
        == "failure"
    ):
        return _result(observation, events, workspace.state(now()))

    review = workspace.provider_contract["stages"]["review"]
    if candidate.get("review") is None:
        if observation.review_status in review["pending"]:
            return _result(observation, events, workspace.state(now()))
        event = workspace.append_maintainer(
            "candidate_feedback_recorded",
            _feedback_payload(
                workspace,
                candidate,
                observation,
                stage="review",
                decision=observation.review_status,
            ),
            maintainer_private_key,
        )
        events.append(event)
        candidate = _candidate(workspace, candidate_id, now())
    elif candidate["review"]["decision"] != observation.review_status:
        raise ProtocolError("provider review status conflicts with recorded feedback")

    if (
        decision_outcome(workspace.provider_contract, "review", observation.review_status)
        == "success"
    ):
        state = workspace.state(now())
        if not state["resolutions"]:
            review_event = candidate["review"]
            event = workspace.append_maintainer(
                "case_resolution_recorded",
                {
                    "problem_id": workspace.problem["problem_id"],
                    "candidate_id": candidate["candidate_id"],
                    "submission_id": observation.submission_id,
                    "task_id": task["task_id"],
                    "task_commitment": task["task_commitment"],
                    "formal_repository_pin": task["formal_repository_pin"],
                    "artifact_sha256": candidate["artifact"]["sha256"],
                    "public_result_url": observation.public_result_url,
                    "source": workspace.provider_contract["resolution"]["source"],
                    "resolution": workspace.provider_contract["resolution"]["success_status"],
                    "review_event_id": review_event["event_id"],
                    "note": (
                        "Trusted maintainer finalized the exact case from the provider's "
                        "public approved-review observation. Bounty handling was not performed."
                    ),
                },
                maintainer_private_key,
            )
            events.append(event)
    return _result(observation, events, workspace.state(now()))


def _result(
    observation: ProviderObservation,
    events: list[dict[str, Any]],
    state: dict[str, Any],
) -> dict[str, Any]:
    return {
        "provider_id": observation.provider_id,
        "submission_id": observation.submission_id,
        "observed": {
            "verification_status": observation.verification_status,
            "manual_review_status": observation.review_status,
            "reward_status": observation.settlement_status,
            "evidence_sha256": observation.evidence_sha256,
            "evidence_source_url": observation.evidence_source_url,
        },
        "events_appended": [event["kind"] for event in events],
        "problem_status": state["problem_status"],
        "provider_resolution": state["provider_resolution"],
        "bounty_action_performed": False,
    }
