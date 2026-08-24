from __future__ import annotations

import json
from pathlib import Path

import pytest

from boule.errors import ProtocolError
from boule.maintainer_advisor import advise, brief_from_tick, state_digest


def _tick():
    return {
        "status": {
            "problem_id": "p-1",
            "problem_status": "REVIEW_PENDING",
            "at": "2030-01-01T00:00:00Z",
            "claims": [{"claim_id": "c-1", "status": "active", "deadline": "2030-01-01T00:01:00Z"}],
            "handoffs_queued": ["event-1"],
            "candidates": [
                {
                    "candidate_id": "candidate-1",
                    "status": "REVIEW_PENDING",
                    "submission": {"submission_id": "submission-1", "private": "redacted"},
                    "summary": "must not reach advisor",
                }
            ],
            "warnings": [{"kind": "overlap", "claims": ["c-1"]}],
            "limitations": "Projection only",
        },
        "receipt": {"private": "not supplied to advisor"},
    }


def test_deduplicates_digest_and_uses_locked_down_codex_argv(tmp_path):
    calls = []

    def runner(argv, prompt, timeout):
        schema_path = Path(argv[argv.index("--output-schema") + 1])
        calls.append((argv, prompt, timeout, json.loads(schema_path.read_text())))
        return json.dumps({"action": "COORDINATE", "summary": "Resolve overlap.", "refs": ["c-1"]})

    first = advise(tmp_path, _tick(), runner=runner, timeout=12)
    second = advise(tmp_path, _tick(), runner=runner, timeout=12)
    assert first == second
    assert len(calls) == 1
    argv, prompt, timeout, schema = calls[0]
    assert argv[:2] == ["codex", "exec"]
    assert "--ephemeral" in argv
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert argv[argv.index("--cd") + 1] == str(tmp_path.resolve())
    assert "--skip-git-repo-check" in argv
    assert argv[argv.index("--color") + 1] == "never"
    assert argv[argv.index("--model") + 1] == "gpt-5.6-sol"
    assert argv[argv.index("--config") + 1] == 'model_reasoning_effort="low"'
    schema_path = Path(argv[argv.index("--output-schema") + 1])
    assert schema["additionalProperties"] is False
    assert "uniqueItems" not in schema["properties"]["refs"]
    assert timeout == 12
    assert "private" not in prompt
    assert first["state_digest"] == state_digest(_tick())
    assert not schema_path.exists()


def test_deduplicates_ticks_with_only_a_different_observation_time(tmp_path):
    calls = []

    def runner(*_):
        calls.append(True)
        return json.dumps({"action": "NO_ACTION", "summary": "No action.", "refs": []})

    later = _tick()
    later["status"]["at"] = "2030-01-01T00:10:00Z"
    assert state_digest(_tick()) == state_digest(later)
    assert advise(tmp_path, _tick(), runner=runner) == advise(tmp_path, later, runner=runner)
    assert calls == [True]


@pytest.mark.parametrize(
    "output, message",
    [
        ("not json", "invalid JSON"),
        (
            json.dumps({"action": "NO_ACTION", "summary": "x", "refs": [], "extra": True}),
            "invalid schema",
        ),
        (
            json.dumps({"action": "COORDINATE", "summary": "x", "refs": ["invented"]}),
            "unknown state",
        ),
    ],
)
def test_invalid_or_fabricated_model_output_fails_closed(tmp_path, output, message):
    with pytest.raises(ProtocolError, match=message):
        advise(tmp_path, _tick(), runner=lambda *_: output)
    assert not list((tmp_path / ".boule" / "advisories").glob("*.json"))


def test_persists_atomically_without_mutating_protocol_state(tmp_path):
    events = tmp_path / "events"
    events.mkdir()
    before = list(tmp_path.rglob("*"))
    result = advise(
        tmp_path,
        _tick(),
        runner=lambda *_: json.dumps({"action": "NO_ACTION", "summary": "No action.", "refs": []}),
    )
    directory = tmp_path / ".boule" / "advisories"
    path = directory / f"{result['state_digest']}.json"
    assert json.loads(path.read_text()) == result
    assert not list(directory.glob(".*.json.*"))
    assert list(events.iterdir()) == []
    assert all(path.name != "events" for path in (tmp_path / ".boule").iterdir())
    assert events in before


def test_cached_advisory_tampering_fails_closed(tmp_path):
    result = advise(
        tmp_path,
        _tick(),
        runner=lambda *_: json.dumps({"action": "NO_ACTION", "summary": "No action.", "refs": []}),
    )
    path = tmp_path / ".boule" / "advisories" / f"{result['state_digest']}.json"
    value = json.loads(path.read_text())
    value["advisory_only"] = False
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ProtocolError, match="identity"):
        advise(tmp_path, _tick(), runner=lambda *_: pytest.fail("must use cache"))


def test_brief_redacts_unknown_tick_fields():
    brief = brief_from_tick(_tick())
    assert set(brief) == {
        "domain",
        "problem_id",
        "problem_status",
        "at",
        "claims",
        "handoffs_queued",
        "candidates",
        "warnings",
    }
    assert "limitations" not in brief
    assert brief["candidates"] == [
        {
            "candidate_id": "candidate-1",
            "status": "REVIEW_PENDING",
            "submission_id": "submission-1",
        }
    ]
