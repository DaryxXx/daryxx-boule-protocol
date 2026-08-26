"""Read-only adapters for observing external provider submission state."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .canonical import digest_object
from .errors import ProtocolError
from .provider_contract import result_url, validate_submission_id
from .remote_protocol import strict_json_bytes
from .version import USER_AGENT

MAX_PUBLIC_RESPONSE_BYTES = 4 * 1024 * 1024
CONJECTURES_RESULTS_FEED = "https://conjectures.io/v1/results/submissions"


@dataclass(frozen=True)
class ProviderHTTPResponse:
    body: bytes
    final_url: str
    status: int = 200
    content_type: str = "application/json"


@dataclass(frozen=True)
class ProviderObservation:
    provider_id: str
    submission_id: str
    task_id: str
    public_result_url: str
    evidence_sha256: str
    evidence_source_url: str
    verification_status: str
    review_status: str
    settlement_status: str
    failure_reason: str | None
    review_reason_code: str | None
    review_summary: str | None


class SubmissionObserver(Protocol):
    provider_id: str

    def observe(
        self, contract: dict[str, Any], submission_id: str, task_id: str
    ) -> ProviderObservation: ...


def fetch_public_json(url: str, timeout: float) -> ProviderHTTPResponse:
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": f"{USER_AGENT} provider-observer"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_PUBLIC_RESPONSE_BYTES + 1)
            result = ProviderHTTPResponse(
                body=body,
                final_url=response.geturl(),
                status=response.status,
                content_type=response.headers.get("Content-Type", ""),
            )
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ProtocolError(f"provider status fetch failed: {exc}") from exc
    return result


class ConjecturesPublicObserver:
    """Bounded reader for the credential-free Conjectures dashboard feed."""

    provider_id = "conjectures.io"

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_pages: int = 3,
        fetcher: Callable[[str, float], ProviderHTTPResponse] = fetch_public_json,
    ) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ProtocolError("provider observer timeout must be between 0 and 60 seconds")
        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or not 1 <= max_pages <= 100
        ):
            raise ProtocolError("provider observer pages must be between 1 and 100")
        self.timeout = timeout
        self.max_pages = max_pages
        self.fetcher = fetcher
        self._rows: dict[str, tuple[dict[str, Any], str]] = {}
        self._next_cursor: str | None = None
        self._started = False
        self._exhausted = False
        self._page_count = 0

    def _next_url(self) -> str:
        parameters = {"limit": "100"}
        if self._started and self._next_cursor is not None:
            parameters["cursor"] = self._next_cursor
        return f"{CONJECTURES_RESULTS_FEED}?{urlencode(parameters)}"

    def _fetch_page(self) -> None:
        if self._exhausted or self._page_count >= self.max_pages:
            return
        url = self._next_url()
        response = self.fetcher(url, self.timeout)
        if response.status != 200 or response.final_url != url:
            raise ProtocolError("provider status feed returned an unexpected response")
        if len(response.body) > MAX_PUBLIC_RESPONSE_BYTES:
            raise ProtocolError("provider status response exceeds the size limit")
        if response.content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ProtocolError("provider status feed is not JSON")
        value = strict_json_bytes(response.body)
        if not isinstance(value, dict) or set(value) != {"items", "next_cursor"}:
            raise ProtocolError("provider status feed has invalid fields")
        items = value["items"]
        next_cursor = value["next_cursor"]
        if (
            not isinstance(items, list)
            or len(items) > 100
            or (next_cursor is not None and not isinstance(next_cursor, str))
            or (isinstance(next_cursor, str) and (not next_cursor or len(next_cursor) > 4096))
        ):
            raise ProtocolError("provider status feed page is invalid")
        for item in items:
            if not isinstance(item, dict):
                raise ProtocolError("provider status feed item is invalid")
            identifier = item.get("id")
            if not isinstance(identifier, str):
                raise ProtocolError("provider status feed item has no submission id")
            if identifier in self._rows:
                raise ProtocolError("provider status feed repeats a submission id")
            self._rows[identifier] = (item, url)
        self._page_count += 1
        self._started = True
        self._next_cursor = next_cursor
        self._exhausted = next_cursor is None

    @staticmethod
    def _text_or_none(value: Any, name: str, maximum: int) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > maximum:
            raise ProtocolError(f"provider {name} is invalid")
        return value

    def observe(
        self, contract: dict[str, Any], submission_id: str, task_id: str
    ) -> ProviderObservation:
        if contract["provider_id"] != self.provider_id:
            raise ProtocolError("provider observer does not match the problem contract")
        submission_id = validate_submission_id(contract, submission_id)
        while submission_id not in self._rows and not self._exhausted:
            previous_pages = self._page_count
            self._fetch_page()
            if self._page_count == previous_pages:
                break
        found = self._rows.get(submission_id)
        if found is None:
            raise ProtocolError(
                "submission was not found in the bounded public provider feed; "
                "increase --provider-max-pages or record feedback manually"
            )
        row, source_url = found
        required = {
            "id",
            "task_id",
            "verification_status",
            "manual_review_status",
            "reward_status",
            "review",
        }
        if not required <= set(row) or row["task_id"] != task_id:
            raise ProtocolError("provider submission does not match the pinned task")
        verification = row["verification_status"]
        review_status = row["manual_review_status"]
        settlement = row["reward_status"]
        if (
            verification
            not in contract["stages"]["verifier"]["pending"]
            + contract["stages"]["verifier"]["success"]
            + contract["stages"]["verifier"]["failure"]
        ):
            raise ProtocolError("provider verification status is outside the contract")
        if (
            review_status
            not in contract["stages"]["review"]["pending"]
            + contract["stages"]["review"]["success"]
            + contract["stages"]["review"]["failure"]
        ):
            raise ProtocolError("provider review status is outside the contract")
        if settlement not in contract["settlement"]["decisions"]:
            raise ProtocolError("provider settlement status is outside the contract")

        verifier = contract["stages"]["verifier"]
        review_stage = contract["stages"]["review"]
        if review_status not in review_stage["pending"] and verification not in verifier["success"]:
            raise ProtocolError("provider review cannot finish before verification succeeds")

        review = row["review"]
        review_reason = None
        review_summary = None
        if (
            review_status
            in contract["stages"]["review"]["success"] + contract["stages"]["review"]["failure"]
        ):
            if not isinstance(review, dict) or review.get("decision") != review_status:
                raise ProtocolError("provider review details do not match its decision")
            review_reason = self._text_or_none(review.get("reason_code"), "review reason", 256)
            review_summary = self._text_or_none(review.get("notes_public"), "review notes", 50_000)
        elif review is not None:
            raise ProtocolError("pending provider review unexpectedly has a decision")

        return ProviderObservation(
            provider_id=self.provider_id,
            submission_id=submission_id,
            task_id=task_id,
            public_result_url=result_url(contract, submission_id),
            evidence_sha256=f"sha256:{digest_object(row)}",
            evidence_source_url=source_url,
            verification_status=verification,
            review_status=review_status,
            settlement_status=settlement,
            failure_reason=self._text_or_none(row.get("failure_reason"), "failure reason", 2000),
            review_reason_code=review_reason,
            review_summary=review_summary,
        )


def observer_for_provider(
    provider_id: str, *, timeout: float = 10.0, max_pages: int = 3
) -> SubmissionObserver | None:
    if provider_id == "conjectures.io":
        return ConjecturesPublicObserver(timeout=timeout, max_pages=max_pages)
    return None
