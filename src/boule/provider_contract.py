"""Versioned contracts between Boule cases and external problem providers."""

from __future__ import annotations

import copy
import re
import uuid
from typing import Any
from urllib.parse import urlsplit

from .canonical import digest_object
from .errors import ProtocolError

PROVIDER_CONTRACT_SCHEMA = "boule-provider-contract/0.1"
SIMPLE_RESOLUTION_STATUSES = frozenset({"OPEN", "PENDING_VERIFICATION", "SOLVED", "FAILED"})
SAFE_EXTERNAL_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,127})\Z")
SAFE_PROVIDER_ID = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,127})\Z")
SAFE_DECISION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,63})\Z")

CONJECTURES_PROVIDER_CONTRACT: dict[str, Any] = {
    "schema": PROVIDER_CONTRACT_SCHEMA,
    "provider_id": "conjectures.io",
    "display_name": "Conjectures.io",
    "definition": {
        "adapter": "conjectures-html-v1",
        "source_kind": "pinned-lean-task",
    },
    "submission": {
        "id_format": "uuid",
        "public_result_url_template": "https://conjectures.io/results/{submission_id}",
        "receipt_source": "trusted-clerk/conjectures.io-submission",
    },
    "stages": {
        "verifier": {
            "native_field": "verification_status",
            "pending": ["UNVERIFIED"],
            "success": ["VERIFIED"],
            "failure": ["REJECTED"],
            "source": "trusted-clerk/conjectures.io-lean-verifier",
        },
        "review": {
            "native_field": "manual_review_status",
            "pending": ["UNREVIEWED"],
            "success": ["APPROVED"],
            "failure": ["REJECTED"],
            "source": "trusted-clerk/conjectures.io-human-review",
        },
    },
    "resolution": {
        "success_stage": "review",
        "success_status": "SOLVED",
        "failure_status": "FAILED",
        "source": "trusted-clerk/conjectures.io-human-review",
    },
    "feedback": {
        "evidence_required": True,
        "retained_after_failure": True,
    },
    "settlement": {
        "managed_by_boule": False,
        "native_field": "reward_status",
        "initial_status": "INELIGIBLE",
        "decisions": ["INELIGIBLE", "ELIGIBLE", "REWARDED", "FAILED"],
        "source": "trusted-clerk/conjectures.io-reward-eligibility",
    },
}


def _nonempty(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ProtocolError(f"{name} must be non-empty text up to {maximum} characters")
    return value


def _decision_list(value: Any, name: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > 16
        or any(not isinstance(item, str) or SAFE_DECISION.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        raise ProtocolError(f"{name} must be a bounded list of unique decision labels")
    return value


def validate_provider_contract(value: Any) -> dict[str, Any]:
    """Validate the immutable provider semantics embedded in a problem manifest."""

    required = {
        "schema",
        "provider_id",
        "display_name",
        "definition",
        "submission",
        "stages",
        "resolution",
        "feedback",
        "settlement",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ProtocolError("provider contract has invalid fields")
    if value["schema"] != PROVIDER_CONTRACT_SCHEMA:
        raise ProtocolError("provider contract has an unsupported schema")
    provider_id = _nonempty(value["provider_id"], "provider_contract.provider_id", 128)
    if SAFE_PROVIDER_ID.fullmatch(provider_id) is None:
        raise ProtocolError("provider contract id must be a lowercase safe identifier")
    _nonempty(value["display_name"], "provider_contract.display_name", 128)

    definition = value["definition"]
    if not isinstance(definition, dict) or set(definition) != {"adapter", "source_kind"}:
        raise ProtocolError("provider definition contract has invalid fields")
    _nonempty(definition["adapter"], "provider_contract.definition.adapter", 128)
    _nonempty(definition["source_kind"], "provider_contract.definition.source_kind", 128)

    submission = value["submission"]
    if not isinstance(submission, dict) or set(submission) != {
        "id_format",
        "public_result_url_template",
        "receipt_source",
    }:
        raise ProtocolError("provider submission contract has invalid fields")
    if submission["id_format"] not in {"uuid", "safe-id"}:
        raise ProtocolError("provider submission id format is unsupported")
    template = _nonempty(
        submission["public_result_url_template"],
        "provider_contract.submission.public_result_url_template",
        1000,
    )
    if template.count("{submission_id}") != 1:
        raise ProtocolError("provider result URL template needs one {submission_id} placeholder")
    sample = template.replace("{submission_id}", "sample")
    parts = urlsplit(sample)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise ProtocolError("provider result URL template must be a public HTTPS URL")
    _nonempty(submission["receipt_source"], "provider_contract.submission.receipt_source")

    stages = value["stages"]
    if not isinstance(stages, dict) or set(stages) != {"verifier", "review"}:
        raise ProtocolError("provider stages must define verifier and review")
    for stage_id, stage in stages.items():
        if not isinstance(stage, dict) or set(stage) != {
            "native_field",
            "pending",
            "success",
            "failure",
            "source",
        }:
            raise ProtocolError(f"provider {stage_id} stage has invalid fields")
        _nonempty(stage["native_field"], f"provider_contract.stages.{stage_id}.native_field")
        pending = _decision_list(stage["pending"], f"provider {stage_id} pending states")
        success = _decision_list(stage["success"], f"provider {stage_id} success states")
        failure = _decision_list(stage["failure"], f"provider {stage_id} failure states")
        if set(pending) & (set(success) | set(failure)) or set(success) & set(failure):
            raise ProtocolError(f"provider {stage_id} decisions must be disjoint")
        _nonempty(stage["source"], f"provider_contract.stages.{stage_id}.source")

    resolution = value["resolution"]
    if not isinstance(resolution, dict) or set(resolution) != {
        "success_stage",
        "success_status",
        "failure_status",
        "source",
    }:
        raise ProtocolError("provider resolution contract has invalid fields")
    if resolution["success_stage"] != "review":
        raise ProtocolError("provider resolution must be gated by the normalized review stage")
    if resolution["success_status"] != "SOLVED" or resolution["failure_status"] != "FAILED":
        raise ProtocolError("provider resolution must use Boule SOLVED and FAILED statuses")
    _nonempty(resolution["source"], "provider_contract.resolution.source")
    if resolution["source"] != stages[resolution["success_stage"]]["source"]:
        raise ProtocolError("provider resolution source must match its success stage")

    feedback = value["feedback"]
    if (
        not isinstance(feedback, dict)
        or set(feedback)
        != {
            "evidence_required",
            "retained_after_failure",
        }
        or not all(isinstance(feedback[key], bool) for key in feedback)
    ):
        raise ProtocolError("provider feedback contract has invalid fields")
    if not feedback["evidence_required"] or not feedback["retained_after_failure"]:
        raise ProtocolError("Boule provider feedback must be evidenced and retained")

    settlement = value["settlement"]
    if not isinstance(settlement, dict) or set(settlement) != {
        "managed_by_boule",
        "native_field",
        "initial_status",
        "decisions",
        "source",
    }:
        raise ProtocolError("provider settlement contract has invalid fields")
    if not isinstance(settlement["managed_by_boule"], bool):
        raise ProtocolError("provider settlement ownership must be boolean")
    if settlement["managed_by_boule"]:
        raise ProtocolError("Boule-managed settlement is not implemented in this contract version")
    _nonempty(settlement["native_field"], "provider_contract.settlement.native_field")
    decisions = _decision_list(settlement["decisions"], "provider settlement decisions")
    if settlement["initial_status"] not in decisions:
        raise ProtocolError("provider settlement initial status must be a declared decision")
    _nonempty(settlement["source"], "provider_contract.settlement.source")
    native_fields = [
        stages["verifier"]["native_field"],
        stages["review"]["native_field"],
        settlement["native_field"],
    ]
    if len(native_fields) != len(set(native_fields)):
        raise ProtocolError("provider native status fields must be distinct")
    evidence_sources = [
        submission["receipt_source"],
        stages["verifier"]["source"],
        stages["review"]["source"],
        settlement["source"],
    ]
    if len(evidence_sources) != len(set(evidence_sources)):
        raise ProtocolError("provider observation sources must be distinct")
    return copy.deepcopy(value)


def conjectures_provider_contract() -> dict[str, Any]:
    return validate_provider_contract(CONJECTURES_PROVIDER_CONTRACT)


def provider_contract_digest(contract: Any) -> str:
    return f"sha256:{digest_object(validate_provider_contract(contract))}"


def _legacy_conjectures_provider_contract() -> dict[str, Any]:
    """Replay semantics for pre-contract v0.1 manifests without rewriting history."""

    contract = copy.deepcopy(CONJECTURES_PROVIDER_CONTRACT)
    contract["stages"]["review"]["failure"].append("PARTIAL_AWARD")
    return validate_provider_contract(contract)


def provider_contract_for_problem(problem: dict[str, Any]) -> dict[str, Any]:
    embedded = problem.get("provider_contract")
    if embedded is not None:
        contract = validate_provider_contract(embedded)
        source = problem.get("source")
        if not isinstance(source, dict) or source.get("provider") != contract["provider_id"]:
            raise ProtocolError("problem source and provider contract identities differ")
        return contract
    source = problem.get("source")
    provider_id = source.get("provider") if isinstance(source, dict) else None
    if provider_id not in {None, "conjectures.io"}:
        raise ProtocolError("non-Conjectures problems require an embedded provider contract")
    # Backward-compatible replay for v0.1 case manifests created before contracts were embedded.
    return _legacy_conjectures_provider_contract()


def validate_submission_id(contract: dict[str, Any], value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("submission_id has the wrong provider format")
    if contract["submission"]["id_format"] == "uuid":
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise ProtocolError("submission_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ProtocolError("submission_id must be a canonical UUID")
    elif SAFE_EXTERNAL_ID.fullmatch(value) is None:
        raise ProtocolError("submission_id must be a 1-128 character safe identifier")
    return value


def result_url(contract: dict[str, Any], submission_id: Any) -> str:
    identifier = validate_submission_id(contract, submission_id)
    return str(contract["submission"]["public_result_url_template"]).replace(
        "{submission_id}", identifier
    )


def stage_contract(contract: dict[str, Any], stage: str) -> dict[str, Any]:
    if stage in {"verifier", "review"}:
        return contract["stages"][stage]
    if stage == "reward":
        settlement = contract["settlement"]
        return {
            "native_field": settlement["native_field"],
            "pending": [settlement["initial_status"]],
            "success": list(settlement["decisions"]),
            "failure": [],
            "source": settlement["source"],
        }
    raise ProtocolError("feedback stage must be verifier, review, or reward")


def decision_outcome(contract: dict[str, Any], stage: str, decision: Any) -> str:
    details = stage_contract(contract, stage)
    if decision in details["success"]:
        return "success"
    if decision in details["failure"]:
        return "failure"
    if decision in details["pending"]:
        return "pending"
    raise ProtocolError(f"invalid {stage} decision for provider {contract['provider_id']}")


def provider_resolution(
    contract: dict[str, Any], state: dict[str, Any], problem_status: str
) -> dict[str, Any]:
    """Project detailed ledger state into the simple provider lifecycle shown to users."""

    if state["resolutions"]:
        status = "SOLVED"
        research_open = False
        terminal = True
        next_action = "BOUNTY_MANAGEMENT_NOT_IMPLEMENTED"
    elif problem_status in {"VERIFICATION_PENDING", "REVIEW_PENDING", "ACCEPTANCE_RECORDED"}:
        status = "PENDING_VERIFICATION"
        research_open = True
        terminal = False
        next_action = "AWAIT_PROVIDER_RESOLUTION"
    elif problem_status == "OPEN_AFTER_FEEDBACK":
        status = "FAILED"
        research_open = True
        terminal = False
        next_action = "CONTINUE_FROM_PROVIDER_FEEDBACK"
    else:
        status = "OPEN"
        research_open = True
        terminal = False
        next_action = (
            "SUBMIT_SEALED_CANDIDATE" if problem_status == "CANDIDATE_READY" else "RESEARCH"
        )

    feedback = [
        {
            key: item[key]
            for key in (
                "event_id",
                "received_at",
                "candidate_id",
                "submission_id",
                "stage",
                "decision",
                "reason_code",
                "summary",
                "next_action",
                "public_result_url",
                "report",
            )
            if key in item
        }
        for item in state["feedback"]
    ]
    native: dict[str, str] = {}
    candidates = list(state["candidates"].values())
    wanted_status = {
        "CANDIDATE_READY": "CANDIDATE_READY",
        "VERIFICATION_PENDING": "VERIFICATION_PENDING",
        "REVIEW_PENDING": "REVIEW_PENDING",
        "ACCEPTANCE_RECORDED": "APPROVED",
        "OPEN_AFTER_FEEDBACK": ("REJECTED", "PARTIAL_AWARD"),
    }.get(problem_status)
    candidate = None
    if state["resolutions"]:
        resolved_id = state["resolutions"][-1]["candidate_id"]
        candidate = state["candidates"].get(resolved_id)
    elif wanted_status is not None:
        statuses = {wanted_status} if isinstance(wanted_status, str) else set(wanted_status)
        candidate = next(
            (item for item in reversed(candidates) if item["status"] in statuses), None
        )
    if candidate is None:
        candidate = candidates[-1] if candidates else None
    if candidate is not None and candidate.get("submission") is not None:
        verifier = contract["stages"]["verifier"]
        review = contract["stages"]["review"]
        settlement = contract["settlement"]
        native[verifier["native_field"]] = verifier["pending"][0]
        native[review["native_field"]] = review["pending"][0]
        native[settlement["native_field"]] = settlement["initial_status"]
        for item in candidate["feedback"]:
            details = stage_contract(contract, item["stage"])
            native[details["native_field"]] = item["decision"]

    result: dict[str, Any] = {
        "schema": "boule-provider-resolution/0.1",
        "provider_id": contract["provider_id"],
        "status": status,
        "detailed_status": problem_status,
        "research_open": research_open,
        "submitted_attempt_locked": status == "PENDING_VERIFICATION",
        "terminal": terminal,
        "next_action": next_action,
        "native_status": native,
        "feedback": feedback,
        "bounty": {
            "managed_by_boule": contract["settlement"]["managed_by_boule"],
            "status": (
                "NOT_MANAGED" if not contract["settlement"]["managed_by_boule"] else "PENDING"
            ),
            "native_status": native.get(contract["settlement"]["native_field"]),
        },
    }
    if candidate is not None:
        result["candidate_id"] = candidate["candidate_id"]
        submission = candidate.get("submission")
        if submission is not None:
            result["submission_id"] = submission["submission_id"]
            result["public_result_url"] = submission["public_result_url"]
    return result
