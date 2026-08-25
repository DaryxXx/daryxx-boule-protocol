"""Causal labels for differences between bounded protocol projections."""

from __future__ import annotations

from typing import Any


def classify_protocol_change(previous: Any, projection: dict[str, Any]) -> str:
    """Describe a transition without treating repeated observations as new claims."""

    before = previous if isinstance(previous, dict) else {}
    old_handoff = before.get("handoff") if isinstance(before.get("handoff"), dict) else None
    new_handoff = projection.get("handoff") if isinstance(projection.get("handoff"), dict) else None
    if old_handoff != new_handoff:
        return "handoff.recorded" if old_handoff is None and new_handoff else "handoff.updated"

    old_claim = before.get("claim") if isinstance(before.get("claim"), dict) else None
    new_claim = projection.get("claim") if isinstance(projection.get("claim"), dict) else None
    if old_claim != new_claim:
        if old_claim is None and new_claim:
            return "claim.recorded"
        if new_claim is None:
            return "claim.cleared"
        if old_claim and old_claim.get("claim_id") == new_claim.get("claim_id"):
            old_without_deadline = {
                key: value for key, value in old_claim.items() if key != "deadline"
            }
            new_without_deadline = {
                key: value for key, value in new_claim.items() if key != "deadline"
            }
            if (
                old_claim.get("deadline") != new_claim.get("deadline")
                and old_without_deadline == new_without_deadline
            ):
                return "claim.renewed"
            if old_claim.get("status") != new_claim.get("status"):
                return "claim.status_changed"
        return "claim.updated"

    old_checkpoints = before.get("checkpoint_count")
    new_checkpoints = projection.get("checkpoint_count")
    old_checkpoint_count = (
        old_checkpoints
        if isinstance(old_checkpoints, int) and not isinstance(old_checkpoints, bool)
        else 0
    )
    if (
        isinstance(new_checkpoints, int)
        and not isinstance(new_checkpoints, bool)
        and new_checkpoints > old_checkpoint_count
    ):
        return "checkpoint.recorded"

    old_messages = before.get("message_count")
    new_messages = projection.get("message_count")
    old_message_count = (
        old_messages if isinstance(old_messages, int) and not isinstance(old_messages, bool) else 0
    )
    if (
        isinstance(new_messages, int)
        and not isinstance(new_messages, bool)
        and new_messages > old_message_count
    ):
        return "message.recorded"

    if before.get("collaborators") != projection.get("collaborators") or before.get(
        "collaborator_count"
    ) != projection.get("collaborator_count"):
        return "collaboration.updated"
    if before.get("network") != projection.get("network"):
        return "network.updated"
    return "signed_state.updated"
