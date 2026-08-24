"""Optional, fail-closed Codex advice for a Boule maintainer projection.

This module deliberately has no access to the workspace event protocol.  It
only stores a local, non-authoritative suggestion beside a projection.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest_object
from .errors import ProtocolError

ALLOWED_MODELS = frozenset({"gpt-5.6-terra", "gpt-5.6-sol", "gpt-5.6"})
ALLOWED_REASONING = frozenset({"low"})
ALLOWED_ACTIONS = frozenset(
    {"NO_ACTION", "COORDINATE", "REQUEST_CHECKPOINT", "REQUEST_REPRODUCTION"}
)
Runner = Callable[[list[str], str, float], str]


def brief_from_tick(tick: dict[str, Any]) -> dict[str, Any]:
    """Return the small operational subset of a maintainer tick safe to share."""
    if not isinstance(tick, dict) or not isinstance(tick.get("status"), dict):
        raise ProtocolError("maintainer tick has no status")
    status = tick["status"]
    required = {
        "problem_id",
        "problem_status",
        "at",
        "claims",
        "handoffs_queued",
        "candidates",
        "warnings",
    }
    if not required <= set(status):
        raise ProtocolError("maintainer tick is missing operational fields")
    claims = status["claims"]
    handoffs = status["handoffs_queued"]
    candidates = status["candidates"]
    warnings = status["warnings"]
    if (
        not all(isinstance(item, dict) for item in claims)
        or not all(isinstance(item, str) for item in handoffs)
        or not all(isinstance(item, dict) for item in candidates)
        or not all(isinstance(item, dict) for item in warnings)
    ):
        raise ProtocolError("maintainer tick has invalid operational fields")
    # Do not pass participant prose, event payloads, signatures, or arbitrary
    # future fields to the model.
    return {
        "domain": "boule-maintainer-advisor-v0.4",
        "problem_id": status["problem_id"],
        "problem_status": status["problem_status"],
        "at": status["at"],
        "claims": [
            {
                key: claim[key]
                for key in ("claim_id", "session_id", "route", "status", "deadline", "parallel")
                if key in claim
            }
            for claim in claims
        ],
        "handoffs_queued": list(handoffs),
        "candidates": [
            {
                "candidate_id": candidate.get("candidate_id"),
                "status": candidate.get("status"),
                "submission_id": (
                    candidate["submission"].get("submission_id")
                    if isinstance(candidate.get("submission"), dict)
                    else None
                ),
            }
            for candidate in candidates
        ],
        "warnings": [
            {key: warning[key] for key in ("kind", "claims") if key in warning}
            for warning in warnings
        ],
    }


def state_digest(tick: dict[str, Any]) -> str:
    """Digest the operational state, deliberately excluding tick observation time."""
    brief = brief_from_tick(tick)
    return digest_object({key: value for key, value in brief.items() if key != "at"})


def _references(brief: dict[str, Any]) -> set[str]:
    return (
        {claim["claim_id"] for claim in brief["claims"] if isinstance(claim.get("claim_id"), str)}
        | set(brief["handoffs_queued"])
        | {
            candidate["candidate_id"]
            for candidate in brief["candidates"]
            if isinstance(candidate.get("candidate_id"), str)
        }
    )


def _prompt(brief: dict[str, Any], digest: str) -> str:
    return (
        "You are an optional operational advisor, never a protocol authority.\n"
        "Return one JSON object only, with exactly action, summary, and refs.\n"
        "action must be one of NO_ACTION, COORDINATE, REQUEST_CHECKPOINT, "
        "REQUEST_REPRODUCTION. summary must be brief operational text. refs must "
        "contain only IDs present in the supplied brief. Do not give review, credit, "
        "payment, submission, or protocol-state commands.\n"
        f"state_digest: {digest}\n"
        f"brief: {canonical_bytes(brief).decode('utf-8')}\n"
    )


def _codex_runner(argv: list[str], prompt: str, timeout: float) -> str:
    try:
        completed = subprocess.run(
            argv,
            input=prompt,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolError("maintainer advisor did not complete") from exc
    if completed.returncode != 0:
        raise ProtocolError("maintainer advisor failed")
    return completed.stdout


def _validate_response(raw: str, references: set[str]) -> dict[str, Any]:
    try:
        response = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProtocolError("maintainer advisor returned invalid JSON") from exc
    if not isinstance(response, dict) or set(response) != {"action", "summary", "refs"}:
        raise ProtocolError("maintainer advisor returned an invalid schema")
    if response["action"] not in ALLOWED_ACTIONS:
        raise ProtocolError("maintainer advisor returned an invalid action")
    summary = response["summary"]
    refs = response["refs"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 500:
        raise ProtocolError("maintainer advisor returned an invalid summary")
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        raise ProtocolError("maintainer advisor returned invalid refs")
    if len(refs) != len(set(refs)) or not set(refs) <= references:
        raise ProtocolError("maintainer advisor referenced unknown state")
    return response


def _validate_cached(
    value: Any, digest: str, brief: dict[str, Any], references: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "advisory_only",
        "state_digest",
        "brief",
        "advice",
    }:
        raise ProtocolError("stored maintainer advisory has an invalid wrapper")
    if value["advisory_only"] is not True or value["state_digest"] != digest:
        raise ProtocolError("stored maintainer advisory identity is invalid")
    stored_brief = value["brief"]
    if not isinstance(stored_brief, dict):
        raise ProtocolError("stored maintainer advisory brief is invalid")

    def without_time(item: dict[str, Any]) -> dict[str, Any]:
        return {key: content for key, content in item.items() if key != "at"}

    if without_time(stored_brief) != without_time(brief):
        raise ProtocolError("stored maintainer advisory does not match current state")
    if digest_object(without_time(stored_brief)) != digest:
        raise ProtocolError("stored maintainer advisory digest is invalid")
    validated = _validate_response(json.dumps(value["advice"]), references)
    return {**value, "advice": validated}


def _atomic_json(path: Path, value: Any) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["action", "summary", "refs"],
        "properties": {
            "action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
            "summary": {"type": "string", "minLength": 1, "maxLength": 500},
            # The Responses structured-output subset does not accept uniqueItems;
            # duplicate refs are rejected again by _validate_response.
            "refs": {"type": "array", "items": {"type": "string"}},
        },
    }


@contextmanager
def _advisory_lock(directory: Path) -> Iterator[None]:
    lock_path = directory / ".lock"
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def advise(
    workspace_root: str | Path,
    tick: dict[str, Any],
    *,
    model: str = "gpt-5.6-sol",
    reasoning: str = "low",
    timeout: float = 30.0,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Persist or return a digest-deduplicated, advisory-only model suggestion."""
    if model not in ALLOWED_MODELS or reasoning not in ALLOWED_REASONING:
        raise ProtocolError("maintainer advisor model configuration is not allowed")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ProtocolError("maintainer advisor timeout is invalid")
    brief = brief_from_tick(tick)
    digest = state_digest(tick)
    directory = Path(workspace_root) / ".boule" / "advisories"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.json"
    with _advisory_lock(directory):
        if path.exists():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ProtocolError("stored maintainer advisory is invalid") from exc
            refs = _references(brief)
            return _validate_cached(cached, digest, brief, refs)
        refs = _references(brief)
        fd, schema_name = tempfile.mkstemp(prefix=".maintainer-advisor-schema-", suffix=".json")
        schema_path = Path(schema_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_bytes(_output_schema()) + b"\n")
            argv = [
                "codex",
                "exec",
                "--ephemeral",
                "--sandbox",
                "read-only",
                "--cd",
                str(Path(workspace_root).resolve()),
                "--skip-git-repo-check",
                "--color",
                "never",
                "--model",
                model,
                "--config",
                f'model_reasoning_effort="{reasoning}"',
                "--output-schema",
                str(schema_path),
            ]
            response = _validate_response(
                (runner or _codex_runner)(argv, _prompt(brief, digest), timeout), refs
            )
        finally:
            schema_path.unlink(missing_ok=True)
        advisory = {
            "advisory_only": True,
            "state_digest": digest,
            "brief": brief,
            "advice": response,
        }
        _atomic_json(path, advisory)
        return advisory
