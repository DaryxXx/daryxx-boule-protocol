from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from boule.canonical import digest_object
from boule.errors import ProtocolError
from boule.research_router import (
    ROUTER_BRIEF_SCHEMA,
    _codex_runner,
    route_registry_problem,
)


def _record(
    case_id: str,
    *,
    mode: str = "counterexample",
    event_count: int = 0,
    repository_commit: str | None = None,
) -> dict:
    return {
        "status": "LIVE",
        "case_id": case_id,
        "problem_id": f"problem-{case_id}",
        "task_id": f"task-{case_id}",
        "title": f"Problem {case_id}",
        "task_mode": mode,
        "source_name": "Conjectures.io",
        "source_url": f"https://conjectures.io/problems/{case_id}",
        "repo_url": f"https://github.com/BouleProtocol/{case_id}",
        "repository_commit": repository_commit or "a" * 40,
        "clerk_url": f"https://{case_id}.example",
        "clerk_key": "ed25519:public-test-key",
        "event_count": event_count,
        "head_event_hash": "b" * 64 if event_count else None,
    }


def _bundle(
    record: dict,
    *,
    problem_status: str = "OPEN",
    claims: list[dict] | None = None,
    handoffs: list[dict] | None = None,
    checkpoints: list[dict] | None = None,
    resume_action: str | None = "START_OR_RESUME_RESEARCH",
) -> dict:
    return {
        "snapshot": {
            "event_count": record["event_count"],
            "head_event_hash": record["head_event_hash"],
        },
        "state": {
            "problem_status": problem_status,
            "research_resume": ({"action": resume_action} if resume_action is not None else None),
            "claims": claims or [],
            "handoffs": handoffs or [],
            "checkpoints": checkpoints or [],
            "candidates": [],
        },
    }


def _fixtures(records: list[dict], bundles: dict[str, dict]):
    index = {
        "registry": "https://registry.example",
        "registry_key": "ed25519:registry-key",
        "registry_key_trust": "explicit_pin",
        "registry_head": "c" * 64,
        "problems": records,
    }

    def fetch_registry(*args, **kwargs):
        assert args == ("https://registry.example",)
        assert kwargs["timeout"] > 0
        return index

    def fetch_case(record, timeout):
        assert 0 < timeout <= 5
        value = bundles[record["case_id"]]
        if isinstance(value, Exception):
            raise value
        return value

    return fetch_registry, fetch_case


def _route(records: list[dict], bundles: dict[str, dict], **kwargs):
    fetch_registry, fetch_case = _fixtures(records, bundles)
    return route_registry_problem(
        registry="https://registry.example",
        mode=kwargs.pop("mode", None),
        clerk_key="ed25519:registry-key",
        trust_store=None,
        router=kwargs.pop("router", "deterministic"),
        registry_fetcher=fetch_registry,
        case_fetcher=fetch_case,
        **kwargs,
    )


def test_deterministic_router_prefers_verified_reusable_compute_progress() -> None:
    fresh = _record("fresh")
    compute = _record("compute", event_count=42)
    bundles = {
        "fresh": _bundle(fresh),
        "compute": _bundle(
            compute,
            handoffs=[
                {
                    "handoff_id": "h-1",
                    "outcome": "ADVANCE",
                    "summary": "Reduced the problem to one explicit curve.",
                    "next_action": "Compute the Mordell-Weil rank, then run Chabauty and a sieve.",
                }
            ],
        ),
    }

    index, selected, decision = _route([fresh, compute], bundles)

    assert index["registry_head"] == "c" * 64
    assert selected["case_id"] == "compute"
    assert decision["selected_case_id"] == "compute"
    assert decision["method"] == "deterministic"
    assert decision["strategy"] == "COMPUTATION"
    assert decision["compute_ready"] is True
    assert decision["advisory_only"] is True
    assert decision["protocol_authority"] is False
    assert decision["eligible_case_ids"] == ["compute", "fresh"]
    assert decision["ranking"][0]["case_id"] == "compute"
    assert decision["ranking"][0]["score"] > decision["ranking"][1]["score"]
    assert "Mordell-Weil" in decision["suggested_focus"]
    assert decision["brief_digest"] == digest_object(
        {"schema": ROUTER_BRIEF_SCHEMA, "candidates": decision["candidate_briefs"]}
    )
    assert decision["advisor_case_ids"] == ["compute", "fresh"]


def test_router_excludes_busy_paused_closed_invalid_and_unverifiable_cases() -> None:
    idle = _record("idle", mode="formalized")
    busy = _record("busy")
    paused = _record("paused")
    closed = _record("closed")
    invalid = _record("invalid", repository_commit="not-a-commit")
    broken = _record("broken")
    malformed = _record("malformed")
    records = [busy, paused, closed, invalid, broken, malformed, idle]
    bundles = {
        "idle": _bundle(idle),
        "busy": _bundle(
            busy,
            claims=[{"claim_id": "c-1", "route": "route", "status": "active"}],
        ),
        "paused": _bundle(paused, resume_action="WAIT_FOR_REVIEW"),
        "closed": _bundle(closed, problem_status="RESOLVED"),
        "invalid": _bundle(invalid),
        "broken": ProtocolError("offline"),
        "malformed": {
            "snapshot": {"event_count": 0, "head_event_hash": None},
            "state": {"problem_status": "OPEN", "claims": None},
        },
    }

    def must_not_run(*args):
        raise AssertionError("one eligible case does not need a model turn")

    _index, selected, decision = _route(
        records,
        bundles,
        router="codex",
        runner=must_not_run,
    )

    assert selected["case_id"] == "idle"
    assert decision["method"] == "deterministic-single-candidate"
    assert decision["model"] is None
    assert {(item["case_id"], item["reason"]) for item in decision["excluded"]} == {
        ("broken", "UNAVAILABLE_OR_UNVERIFIABLE"),
        ("busy", "ACTIVE_CLAIM"),
        ("closed", "NOT_OPEN"),
        ("invalid", "INVALID_REPOSITORY_PIN"),
        ("malformed", "UNAVAILABLE_OR_UNVERIFIABLE"),
        ("paused", "RESEARCH_PAUSED"),
    }


def test_router_fails_clearly_when_every_case_is_unavailable() -> None:
    busy = _record("busy")
    closed = _record("closed")
    bundles = {
        "busy": _bundle(busy, claims=[{"status": "stale"}]),
        "closed": _bundle(closed, problem_status="RESOLVED"),
    }
    with pytest.raises(ProtocolError, match="no idle OPEN case"):
        _route([busy, closed], bundles)


def test_event_volume_never_increases_the_routing_score() -> None:
    noisy = _record("noisy", event_count=60)
    quiet = _record("quiet")
    bundles = {"noisy": _bundle(noisy), "quiet": _bundle(quiet)}

    _index, _selected, decision = _route([noisy, quiet], bundles)

    scores = {item["case_id"]: item["score"] for item in decision["ranking"]}
    assert scores == {"noisy": 0, "quiet": 0}


def test_codex_router_can_rank_only_the_bounded_eligible_shortlist() -> None:
    first = _record("first", event_count=20)
    second = _record("second", event_count=10)
    bundles = {
        "first": _bundle(
            first,
            handoffs=[{"outcome": "ADVANCE", "next_action": "Run the exact search."}],
        ),
        "second": _bundle(second),
    }

    def runner(argv, prompt, timeout):
        assert timeout == 30
        assert argv[:2] == ["codex", "exec"]
        for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules"):
            assert flag in argv
        assert argv[argv.index("--sandbox") + 1] == "read-only"
        assert argv[argv.index("--model") + 1] == "gpt-5.6-terra"
        assert "shell_tool" in argv
        assert "untrusted research data" in prompt
        assert '"case_id":"first"' in prompt
        assert '"case_id":"second"' in prompt
        return json.dumps(
            {
                "selected_case_id": "second",
                "confidence": "LOW",
                "strategy": "THEORY",
                "reason": "The empty case offers a clean bounded theory pass.",
                "suggested_focus": "Derive one exact reformulation before claiming work.",
            }
        )

    _index, selected, decision = _route(
        [first, second],
        bundles,
        router="codex",
        model="gpt-5.6-terra",
        timeout=30,
        runner=runner,
    )

    assert selected["case_id"] == "second"
    assert decision["method"] == "codex-advisor"
    assert decision["model"] == "gpt-5.6-terra"
    assert decision["reason"].startswith("The empty case")


def test_auto_router_falls_back_but_explicit_codex_is_fail_closed() -> None:
    first = _record("first", event_count=5)
    second = _record("second")
    bundles = {"first": _bundle(first), "second": _bundle(second)}

    def invalid_runner(*args):
        return '{"selected_case_id":"not-eligible"}'

    _index, selected, decision = _route(
        [first, second], bundles, router="auto", runner=invalid_runner
    )
    assert selected["case_id"] == "first"
    assert decision["method"] == "deterministic-fallback"
    assert decision["warning"]

    with pytest.raises(ProtocolError, match="invalid schema"):
        _route([first, second], bundles, router="codex", runner=invalid_runner)


def test_mode_filter_is_applied_before_case_state_is_fetched() -> None:
    formalized = _record("formal", mode="formalized")
    counterexample = _record("counter", mode="counterexample")
    bundles = {
        "formal": _bundle(formalized),
        "counter": AssertionError("filtered case must not be fetched"),
    }
    _index, selected, decision = _route([counterexample, formalized], bundles, mode="formalized")
    assert selected["case_id"] == "formal"
    assert decision["evaluated_case_count"] == 1


def test_unexpected_case_fetch_failure_excludes_only_that_case() -> None:
    broken = _record("broken")
    healthy = _record("healthy")
    _index, selected, decision = _route(
        [broken, healthy],
        {
            "broken": ValueError("malformed remote response"),
            "healthy": _bundle(healthy),
        },
    )
    assert selected["case_id"] == "healthy"
    assert {item["case_id"]: item["reason"] for item in decision["excluded"]} == {
        "broken": "UNAVAILABLE_OR_UNVERIFIABLE"
    }


def test_codex_router_process_does_not_inherit_provider_or_project_secrets(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-pass")
    monkeypatch.setenv("BOULE_SESSION", "must-not-pass")
    monkeypatch.setenv("PROJECT_SECRET", "must-not-pass")
    monkeypatch.setenv("CODEX_HOME", "/tmp/codex-auth-location")
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr("boule.research_router.subprocess.run", fake_run)
    assert _codex_runner(["codex", "exec"], "prompt", 10) == "{}"
    environment = captured["env"]
    assert environment["CODEX_HOME"] == "/tmp/codex-auth-location"
    assert environment["GIT_SSH_COMMAND"] == "/bin/false"
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "BOULE_SESSION", "PROJECT_SECRET"):
        assert key not in environment
