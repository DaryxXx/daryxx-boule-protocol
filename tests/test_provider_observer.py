from __future__ import annotations

import json

import pytest

from boule.canonical import digest_object
from boule.cli import build_parser
from boule.errors import ProtocolError
from boule.provider_contract import conjectures_provider_contract
from boule.provider_observer import (
    CONJECTURES_RESULTS_FEED,
    ConjecturesPublicObserver,
    ProviderHTTPResponse,
)

SUBMISSION_ID = "82ab85ee-5dfc-4775-b3e1-8abc16e213b9"
OTHER_ID = "2ac83d2a-b26f-4358-84f7-78e149c124ff"


def row(
    submission_id: str = SUBMISSION_ID,
    *,
    task_id: str = "task-1",
    verification: str = "UNVERIFIED",
    review_status: str = "UNREVIEWED",
    reward: str = "INELIGIBLE",
    review: dict[str, str | None] | None = None,
) -> dict[str, object]:
    return {
        "id": submission_id,
        "task_id": task_id,
        "verification_status": verification,
        "manual_review_status": review_status,
        "reward_status": reward,
        "review": review,
    }


def response(url: str, items: list[dict[str, object]], cursor: str | None = None):
    return ProviderHTTPResponse(
        body=json.dumps({"items": items, "next_cursor": cursor}).encode(),
        final_url=url,
    )


def test_conjectures_observer_reads_and_caches_canonical_public_rows() -> None:
    calls: list[str] = []
    pending = row()

    def fetch(url: str, timeout: float) -> ProviderHTTPResponse:
        calls.append(url)
        assert timeout == 4
        return response(url, [pending, row(OTHER_ID)])

    observer = ConjecturesPublicObserver(timeout=4, fetcher=fetch)
    contract = conjectures_provider_contract()
    observed = observer.observe(contract, SUBMISSION_ID, "task-1")

    assert observed.verification_status == "UNVERIFIED"
    assert observed.review_status == "UNREVIEWED"
    assert observed.settlement_status == "INELIGIBLE"
    assert observed.evidence_sha256 == f"sha256:{digest_object(pending)}"
    assert observed.evidence_source_url == f"{CONJECTURES_RESULTS_FEED}?limit=100"
    assert observed.public_result_url.endswith(SUBMISSION_ID)

    observer.observe(contract, OTHER_ID, "task-1")
    assert calls == [f"{CONJECTURES_RESULTS_FEED}?limit=100"]


def test_conjectures_observer_uses_bounded_pagination_and_retains_review_feedback() -> None:
    calls: list[str] = []
    accepted = row(
        verification="VERIFIED",
        review_status="APPROVED",
        reward="ELIGIBLE",
        review={
            "decision": "APPROVED",
            "reason_code": "VALID_PROOF",
            "notes_public": "The pinned Lean artifact passed review.",
        },
    )

    def fetch(url: str, _timeout: float) -> ProviderHTTPResponse:
        calls.append(url)
        if len(calls) == 1:
            return response(url, [row(OTHER_ID)], "next-page")
        return response(url, [accepted])

    observer = ConjecturesPublicObserver(max_pages=2, fetcher=fetch)
    observed = observer.observe(conjectures_provider_contract(), SUBMISSION_ID, "task-1")

    assert calls == [
        f"{CONJECTURES_RESULTS_FEED}?limit=100",
        f"{CONJECTURES_RESULTS_FEED}?limit=100&cursor=next-page",
    ]
    assert observed.verification_status == "VERIFIED"
    assert observed.review_status == "APPROVED"
    assert observed.review_reason_code == "VALID_PROOF"
    assert observed.review_summary == "The pinned Lean artifact passed review."


@pytest.mark.parametrize(
    ("bad_row", "message"),
    [
        (row(task_id="another-task"), "pinned task"),
        (
            row(
                verification="UNVERIFIED",
                review_status="APPROVED",
                review={"decision": "APPROVED"},
            ),
            "before verification succeeds",
        ),
        (
            row(
                verification="VERIFIED",
                review_status="REJECTED",
                review={"decision": "APPROVED"},
            ),
            "details do not match",
        ),
    ],
)
def test_conjectures_observer_rejects_mismatched_or_impossible_rows(
    bad_row: dict[str, object], message: str
) -> None:
    def fetch(url: str, _timeout: float) -> ProviderHTTPResponse:
        return response(url, [bad_row])

    observer = ConjecturesPublicObserver(fetcher=fetch)
    with pytest.raises(ProtocolError, match=message):
        observer.observe(conjectures_provider_contract(), SUBMISSION_ID, "task-1")


def test_conjectures_observer_fails_when_submission_is_outside_bounded_window() -> None:
    def fetch(url: str, _timeout: float) -> ProviderHTTPResponse:
        return response(url, [row(OTHER_ID)], "more")

    observer = ConjecturesPublicObserver(max_pages=1, fetcher=fetch)
    with pytest.raises(ProtocolError, match="bounded public provider feed"):
        observer.observe(conjectures_provider_contract(), SUBMISSION_ID, "task-1")


def test_provider_sync_cli_is_automatic_but_can_be_disabled() -> None:
    parser = build_parser()
    watch = parser.parse_args(["registry", "watch", "/tmp/registry"])
    assert watch.provider_sync is True
    assert watch.provider_max_pages == 3

    disabled = parser.parse_args(["registry", "watch", "/tmp/registry", "--no-provider-sync"])
    assert disabled.provider_sync is False

    manual = parser.parse_args(
        [
            "maintainer",
            "sync-provider",
            "/tmp/problem",
            "--candidate",
            "candidate-1",
        ]
    )
    assert manual.provider_timeout == 10
    assert manual.provider_max_pages == 3
