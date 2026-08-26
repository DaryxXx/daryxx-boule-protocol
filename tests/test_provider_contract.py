from __future__ import annotations

from copy import deepcopy

import pytest

from boule.errors import ProtocolError
from boule.provider_contract import (
    conjectures_provider_contract,
    decision_outcome,
    result_url,
    validate_provider_contract,
)


def test_conjectures_contract_keeps_verification_review_and_settlement_separate() -> None:
    contract = conjectures_provider_contract()

    assert decision_outcome(contract, "verifier", "VERIFIED") == "success"
    assert decision_outcome(contract, "verifier", "REJECTED") == "failure"
    assert decision_outcome(contract, "review", "APPROVED") == "success"
    assert contract["stages"]["verifier"]["native_field"] == "verification_status"
    assert contract["stages"]["review"]["native_field"] == "manual_review_status"
    assert contract["settlement"]["native_field"] == "reward_status"
    assert contract["settlement"]["managed_by_boule"] is False


def test_contract_can_define_another_providers_ids_urls_and_decisions() -> None:
    contract = deepcopy(conjectures_provider_contract())
    contract["provider_id"] = "proofs.example"
    contract["display_name"] = "Proofs Example"
    contract["definition"]["adapter"] = "proofs-json-v1"
    contract["submission"] = {
        "id_format": "safe-id",
        "public_result_url_template": "https://proofs.example/submissions/{submission_id}",
        "receipt_source": "trusted-clerk/proofs.example-submission",
    }
    contract["stages"]["verifier"] = {
        "native_field": "check_state",
        "pending": ["QUEUED"],
        "success": ["CHECKED"],
        "failure": ["INVALID"],
        "source": "trusted-clerk/proofs.example-checker",
    }
    contract["stages"]["review"] = {
        "native_field": "decision_state",
        "pending": ["WAITING"],
        "success": ["ACCEPTED"],
        "failure": ["DECLINED"],
        "source": "trusted-clerk/proofs.example-review",
    }
    contract["resolution"]["source"] = "trusted-clerk/proofs.example-review"
    contract["settlement"] = {
        "managed_by_boule": False,
        "native_field": "payout_state",
        "initial_status": "NOT_READY",
        "decisions": ["NOT_READY", "READY", "PAID", "FAILED"],
        "source": "trusted-clerk/proofs.example-payout",
    }

    validated = validate_provider_contract(contract)
    assert result_url(validated, "result-42") == ("https://proofs.example/submissions/result-42")
    assert decision_outcome(validated, "verifier", "CHECKED") == "success"
    assert decision_outcome(validated, "review", "DECLINED") == "failure"


def test_contract_rejects_ambiguous_decisions_and_non_https_results() -> None:
    overlap = conjectures_provider_contract()
    overlap["stages"]["verifier"]["failure"] = ["VERIFIED"]
    with pytest.raises(ProtocolError, match="disjoint"):
        validate_provider_contract(overlap)

    insecure = conjectures_provider_contract()
    insecure["submission"]["public_result_url_template"] = (
        "http://proofs.example/results/{submission_id}"
    )
    with pytest.raises(ProtocolError, match="public HTTPS"):
        validate_provider_contract(insecure)
