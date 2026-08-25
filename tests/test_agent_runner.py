from __future__ import annotations

import json
import os
import pty
import shutil
import stat
import subprocess
import termios
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from boule.agent_runner import (
    _git as runner_git,
)
from boule.agent_runner import _prompt as build_agent_prompt
from boule.agent_runner import (
    _shared_controller_key,
    launch_background,
    prepare_resume,
    prepare_run,
    resolve_registry_problem,
    run_worker,
)
from boule.clerk_api import build_server
from boule.cli import build_parser
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.protocol_change import classify_protocol_change
from boule.provider_runtime import (
    build_provider_command,
    normalize_provider_event,
    provider_environment,
    validate_provider_options,
)
from boule.run_store import RunStore, process_identity, process_matches
from boule.terminal_ui import (
    RunTerminal,
    _timeline_label,
    build_run_dashboard,
    format_runtime_line,
    print_run_dashboard,
    print_run_list,
    progress_report,
    runtime_phase,
    usage_report,
)
from boule.workspace import Workspace


def test_provider_commands_are_structured_and_never_bypass_sandbox(tmp_path) -> None:
    codex = build_provider_command(
        "codex",
        binary="/opt/codex",
        workspace=tmp_path,
        final_message=tmp_path / "final.md",
        agent_name="Daryxx1",
        model="gpt-test",
        effort="high",
    )
    assert codex[:2] == ["/opt/codex", "exec"]
    assert "--json" in codex
    assert "--approve-for-me" in codex
    assert "--sandbox" not in codex
    assert "--dangerously-bypass-approvals-and-sandbox" not in codex
    assert codex[-1] == "-"
    resumed = build_provider_command(
        "codex",
        binary="/opt/codex",
        workspace=tmp_path,
        final_message=tmp_path / "resume.md",
        agent_name="Daryxx1",
        model=None,
        effort="ultra",
        resume_session_id="thread-123",
    )
    assert resumed[:3] == ["/opt/codex", "exec", "resume"]
    assert "--approve-for-me" not in resumed
    assert resumed[-2:] == ["thread-123", "-"]

    claude = build_provider_command(
        "claude-code",
        binary="/opt/claude",
        workspace=tmp_path,
        final_message=tmp_path / "unused.md",
        agent_name="Daryxx2",
        model="opus",
        effort="max",
    )
    assert claude[:2] == ["/opt/claude", "--print"]
    assert "stream-json" in claude
    assert "--dangerously-skip-permissions" not in claude
    assert "Daryxx2" in claude

    with pytest.raises(ProtocolError, match="unsupported claude-code effort"):
        validate_provider_options("claude-code", "ultra")


def test_provider_projection_reports_usage_without_double_counting_cache() -> None:
    codex = normalize_provider_event(
        "codex",
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 247,
                "cached_input_tokens": 192,
                "output_tokens": 31,
                "reasoning_output_tokens": 12,
            },
        },
    )
    assert codex == {
        "provider": "codex",
        "raw_type": "turn.completed",
        "kind": "turn.completed",
        "usage": {
            "authoritative": True,
            "input_tokens": 247,
            "cache_read_tokens": 192,
            "output_tokens": 31,
            "reasoning_output_tokens": 12,
        },
    }
    claude = normalize_provider_event(
        "claude-code",
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "duration_ms": 12,
            "total_cost_usd": 0.01,
            "usage": {"input_tokens": 2, "output_tokens": 1},
            "result": "done",
        },
    )
    assert claude["kind"] == "turn.completed"
    assert claude["provider_reported_cost_usd"] == 0.01
    assert claude["provider_duration_ms"] == 12
    assert claude["usage"]["output_tokens"] == 1


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            {"claim": None},
            {"claim": {"claim_id": "c-1", "status": "active"}},
            "claim.recorded",
        ),
        (
            {"claim": {"claim_id": "c-1", "status": "active", "deadline": "first"}},
            {"claim": {"claim_id": "c-1", "status": "active", "deadline": "second"}},
            "claim.renewed",
        ),
        (
            {"claim": {"claim_id": "c-1"}, "checkpoint_count": 0},
            {"claim": {"claim_id": "c-1"}, "checkpoint_count": 1},
            "checkpoint.recorded",
        ),
        (
            {"claim": {"claim_id": "c-1"}, "handoff": None},
            {"claim": {"claim_id": "c-1"}, "handoff": {"handoff_id": "h-1"}},
            "handoff.recorded",
        ),
        (
            {"claim": {"claim_id": "c-1"}, "network": {"sessions": 1}},
            {"claim": {"claim_id": "c-1"}, "network": {"sessions": 2}},
            "network.updated",
        ),
    ],
)
def test_protocol_change_classifies_signed_state_transitions(before, after, expected) -> None:
    assert classify_protocol_change(before, after) == expected


def test_terminal_protocol_labels_are_precise_and_legacy_safe() -> None:
    assert _timeline_label(
        {
            "kind": "protocol.updated",
            "change": "claim.recorded",
            "claim": {"route": "k=5 curve"},
        }
    ) == ("Boule", "Signed claim recorded · k=5 curve")
    assert _timeline_label(
        {
            "kind": "protocol.updated",
            "change": "claim.renewed",
            "claim": {"deadline": "2026-08-25T13:37:00Z"},
        }
    ) == ("Boule", "Signed claim renewed · deadline 2026-08-25T13:37:00Z")
    assert _timeline_label({"kind": "protocol.updated", "claim": {"route": "legacy route"}}) == (
        "Boule",
        "Signed claim state observed",
    )


def test_legacy_protocol_timeline_infers_claim_record_and_renewal() -> None:
    status, config, _events = _terminal_fixture()
    claim = {
        "claim_id": "c-legacy",
        "route": "legacy k=5 route",
        "status": "active",
        "deadline": "2026-01-01T01:00:00Z",
    }
    events = [
        {
            "sequence": 1,
            "kind": "protocol.updated",
            "claim": None,
            "handoff": None,
            "collaborator_count": 0,
            "observed_at": "2026-01-01T00:00:01Z",
        },
        {
            "sequence": 2,
            "kind": "protocol.updated",
            "claim": claim,
            "handoff": None,
            "collaborator_count": 0,
            "observed_at": "2026-01-01T00:00:02Z",
        },
        {
            "sequence": 3,
            "kind": "protocol.updated",
            "claim": {**claim, "deadline": "2026-01-01T01:05:00Z"},
            "handoff": None,
            "collaborator_count": 0,
            "observed_at": "2026-01-01T00:00:03Z",
        },
    ]
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
        )
    )
    text = output.getvalue()
    assert "Signed claim recorded · legacy k=5 route" in text
    assert "Signed claim renewed · deadline 2026-01-01T01:05:00Z" in text


@pytest.mark.parametrize("cost", [True, -1, float("nan"), float("inf")])
def test_provider_projection_rejects_invalid_cost_and_duration(cost) -> None:
    claude = normalize_provider_event(
        "claude-code",
        {
            "type": "result",
            "subtype": "success",
            "total_cost_usd": cost,
            "duration_ms": cost,
        },
    )
    assert "provider_reported_cost_usd" not in claude
    assert "provider_duration_ms" not in claude


def test_provider_projection_redacts_credential_like_message_text() -> None:
    token = "sk" + "-" + "fixturevalue123456789"
    event = normalize_provider_event(
        "codex",
        {
            "type": "item.completed",
            "item": {
                "type": "agent_message",
                "text": "OPENAI_API_KEY=" + token + " continue with the lemma",
            },
        },
    )
    assert token not in event["summary"]
    assert "OPENAI_API_KEY=[redacted]" in event["summary"]


def test_provider_environment_removes_publish_credentials_without_serializing_auth(
    monkeypatch, tmp_path
) -> None:
    provider_value = "fixture-provider-value"
    monkeypatch.setenv("GH_TOKEN", "fixture-github-value")
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-github-value-2")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("OPENAI_API_KEY", provider_value)
    monkeypatch.setenv("UNRELATED_PRIVATE_TOKEN", "fixture-private-value")
    value = provider_environment("codex", "session-a", "https://clerk.example", tmp_path)
    assert "GH_TOKEN" not in value
    assert "GITHUB_TOKEN" not in value
    assert "SSH_AUTH_SOCK" not in value
    assert "UNRELATED_PRIVATE_TOKEN" not in value
    assert value["OPENAI_API_KEY"] == provider_value
    assert value["GIT_SSH_COMMAND"] == "/bin/false"


def test_case_clone_git_rejects_protocol_rewrites_and_injected_config(monkeypatch) -> None:
    captured = {}
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.ssh://attacker.invalid/.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="git version test\n", stderr="")

    monkeypatch.setattr("boule.agent_runner.subprocess.run", fake_run)
    assert runner_git(["git", "version"]) == "git version test"
    assert captured["command"][:5] == [
        "git",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
    ]
    environment = captured["env"]
    assert environment["GIT_ALLOW_PROTOCOL"] == "https"
    assert environment["GIT_PROTOCOL_FROM_USER"] == "0"
    assert environment["GIT_SSH_COMMAND"] == "/bin/false"
    for key in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "SSH_AUTH_SOCK"):
        assert key not in environment


def test_run_store_is_private_and_pid_identity_rejects_reuse(tmp_path) -> None:
    store = RunStore(tmp_path / "runs")
    run_id = "run-20260101T000000-deadbeef"
    directory = store.create(run_id, {"schema": "test"}, {"state": "ready"})
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "config.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((directory / "status.json").stat().st_mode) == 0o600
    store.append_event(run_id, {"kind": "test"})
    assert stat.S_IMODE((directory / "events.jsonl").stat().st_mode) == 0o600
    identity = process_identity(os.getpid())
    assert process_matches(identity)
    assert not process_matches({**identity, "start_ticks": identity["start_ticks"] + 1})


def test_run_store_reads_only_new_complete_event_records(tmp_path) -> None:
    store = RunStore(tmp_path / "runs")
    run_id = "run-20260101T000000-aabbccdd"
    store.create(run_id, {"schema": "test"}, {"state": "ready"})
    store.append_event(run_id, {"kind": "first"})
    first, offset = store.events_since(run_id)
    assert [event["kind"] for event in first] == ["first"]
    assert store.events_since(run_id, offset) == ([], offset)

    store.append_event(run_id, {"kind": "second"})
    second, next_offset = store.events_since(run_id, offset)
    assert [event["kind"] for event in second] == ["second"]
    assert next_offset > offset

    with pytest.raises(ProtocolError, match="non-negative integer"):
        store.events_since(run_id, -1)


def test_runner_reuses_one_private_controller_key_across_case_clones(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    first = _shared_controller_key("shared-controller")
    second = _shared_controller_key("shared-controller")
    assert public_key_text(first) == public_key_text(second)
    key_path = next((tmp_path / "config" / "boule" / "controller-keys").glob("*.pem"))
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_problem_query_prefers_the_only_case_with_durable_activity(monkeypatch) -> None:
    problems = [
        {
            "status": "LIVE",
            "case_id": "case-erdos-686-formal",
            "problem_id": "p-erdos-686-formal",
            "task_id": "task-formal",
            "title": "Erdos problem 686",
            "source_url": "https://conjectures.io/problems/erdos-686",
            "task_mode": "formalized",
            "event_count": 0,
        },
        {
            "status": "LIVE",
            "case_id": "case-erdos-686-counterexample",
            "problem_id": "p-erdos-686-counterexample",
            "task_id": "task-counterexample",
            "title": "Erdos problem 686",
            "source_url": "https://conjectures.io/problems/erdos-686?mode=counterexample",
            "task_mode": "counterexample",
            "event_count": 38,
        },
    ]
    monkeypatch.setattr(
        "boule.agent_runner.fetch_registry_index",
        lambda *args, **kwargs: {"problems": problems},
    )
    _, selected = resolve_registry_problem(
        "erdos-686",
        registry="https://registry.example",
        mode=None,
        clerk_key=None,
        trust_store=None,
        timeout=1,
    )
    assert selected["task_mode"] == "counterexample"


def test_cli_accepts_requested_agent_name_spellings() -> None:
    parser = build_parser()
    first = parser.parse_args(
        [
            "codex",
            "erdos-686",
            "--agent-name",
            "Daryxx1",
            "--max-tokens",
            "250000",
        ]
    )
    second = parser.parse_args(["codex", "erdos-686", "--agent_name", "Daryxx2"])
    resumed = parser.parse_args(["run", "resume", "run-example", "--max-tokens", "50000"])
    automatic = parser.parse_args(["codex", "--agent-name", "Daryxx3"])
    route = parser.parse_args(["route", "--router", "deterministic"])
    promote = parser.parse_args(["run", "promote", "run-example"])
    usage = parser.parse_args(["usage", "--days", "14"])
    progress = parser.parse_args(["progress", "run-example"])
    assert first.agent_name == "Daryxx1"
    assert first.max_tokens == 250_000
    assert second.agent_name == "Daryxx2"
    assert resumed.max_tokens == 50_000
    assert automatic.problem is None
    assert automatic.router == "deterministic"
    assert route.router == "deterministic"
    assert promote.confirm is False
    assert usage.days == 14
    assert progress.run_id == "run-example"


def test_non_finite_deadline_fails_before_provider_or_public_side_effects(tmp_path) -> None:
    with pytest.raises(ProtocolError, match="must be finite"):
        prepare_run(
            "codex",
            "anything",
            agent_name="Daryxx1",
            controller=None,
            registry=None,
            registry_clerk_key=None,
            trust_store=None,
            mode=None,
            model=None,
            effort=None,
            max_seconds=float("nan"),
            instruction=None,
            run_root=tmp_path / "runs",
        )
    assert not (tmp_path / "runs").exists()


def test_invalid_router_timeout_fails_before_provider_or_public_side_effects(tmp_path) -> None:
    with pytest.raises(ProtocolError, match="router timeout"):
        prepare_run(
            "codex",
            None,
            agent_name="Daryxx1",
            controller=None,
            registry=None,
            registry_clerk_key=None,
            trust_store=None,
            mode=None,
            model=None,
            effort=None,
            max_seconds=30,
            instruction=None,
            router_timeout=float("nan"),
            run_root=tmp_path / "runs",
        )
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_token_budget_fails_before_provider_or_public_side_effects(tmp_path, value) -> None:
    with pytest.raises(ProtocolError, match="positive integer"):
        prepare_run(
            "codex",
            "anything",
            agent_name="Daryxx1",
            controller=None,
            registry=None,
            registry_clerk_key=None,
            trust_store=None,
            mode=None,
            model=None,
            effort=None,
            max_seconds=30,
            instruction=None,
            max_tokens=value,
            run_root=tmp_path / "runs",
        )
    assert not (tmp_path / "runs").exists()


def _central_case(tmp_path: Path) -> tuple[Workspace, object]:
    maintainer = generate_private_key()
    root = tmp_path / "central"
    root.mkdir()
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "p-runner",
                "task": {
                    "task_id": "task-runner",
                    "task_commitment": "sha256:" + "1" * 64,
                    "formal_repository_pin": "2" * 40,
                },
            }
        ),
        encoding="utf-8",
    )
    workspace = Workspace.initialize(
        root,
        {
            "maintainer_key": public_key_text(maintainer),
            "lease_seconds": 3600,
            "absolute_lease_seconds": 7200,
            "stale_seconds": 900,
            "max_renewals": 2,
        },
    )
    return workspace, maintainer


def _clone_case(source: Workspace, destination: Path) -> Workspace:
    destination.mkdir()
    shutil.copy2(source.problem_path, destination / "problem.json")
    control = destination / ".boule"
    control.mkdir()
    shutil.copy2(source.config_path, control / "config.json")
    shutil.copy2(source.policy_path, control / "policy.json")
    (control / "events").mkdir()
    (control / "receipts").mkdir()
    (control / "lock").touch()
    return Workspace(destination)


def test_omitted_problem_routes_before_starting_the_research_session(monkeypatch, tmp_path) -> None:
    central, maintainer = _central_case(tmp_path)
    clone = _clone_case(central, tmp_path / "clone")
    run_root = tmp_path / "runs"
    selection = {
        "schema": "boule-research-routing-decision/0.1",
        "advisory_only": True,
        "method": "codex-advisor",
        "selected_case_id": "case-runner",
        "selected_title": "Routed problem",
        "confidence": "MEDIUM",
        "strategy": "COMPUTATION",
        "reason": "A signed handoff has one bounded computation ready.",
        "suggested_focus": "Reproduce the exact finite search.",
    }
    seen = {}

    monkeypatch.setattr("boule.agent_runner.resolve_provider_binary", lambda provider: "/bin/true")
    monkeypatch.setattr("boule.agent_runner.preflight_provider", lambda *args: "codex test")
    monkeypatch.setattr("boule.agent_runner._clone_case", lambda *args: clone)

    def fake_route(**kwargs):
        seen.update(kwargs)
        return (
            {
                "registry": "https://registry.example",
                "registry_key": "ed25519:registry",
                "registry_head": "a" * 64,
                "registry_key_trust": "explicit_pin",
            },
            {
                "case_id": "case-runner",
                "problem_id": "p-runner",
                "title": "Routed problem",
                "task_mode": "counterexample",
                "clerk_url": origin,
                "repository_commit": "b" * 40,
                "repo_url": "https://github.com/BouleProtocol/case-runner",
                "source_url": "https://conjectures.io/problems/case-runner",
            },
            selection,
        )

    with _server(central, maintainer) as origin:
        monkeypatch.setattr("boule.agent_runner.route_registry_problem", fake_route)
        prepared = prepare_run(
            "codex",
            None,
            agent_name="DaryxxAuto",
            controller="shared-controller",
            registry="https://registry.example",
            registry_clerk_key="ed25519:registry",
            trust_store=tmp_path / "trust.json",
            mode="counterexample",
            model="gpt-5.6-sol",
            effort="ultra",
            max_seconds=300,
            instruction=None,
            router="auto",
            router_model="gpt-5.6-terra",
            router_timeout=20,
            run_root=run_root,
        )

    assert seen["router"] == "auto"
    assert seen["model"] == "gpt-5.6-terra"
    assert seen["mode"] == "counterexample"
    store = RunStore(run_root)
    config = store.config(prepared["run_id"])
    assert config["query"] == "auto"
    assert config["selection"] == selection
    assert selection["reason"] in build_agent_prompt(config)
    assert "scheduling guidance, not mathematical evidence" in build_agent_prompt(config)
    routing_events = [
        item for item in store.events(prepared["run_id"]) if item.get("kind") == "routing.selected"
    ]
    assert len(routing_events) == 1
    assert routing_events[0]["case_id"] == "case-runner"
    assert routing_events[0]["method"] == "codex-advisor"
    assert routing_events[0]["strategy"] == "COMPUTATION"


@contextmanager
def _server(workspace: Workspace, maintainer: object):
    server = build_server(workspace, maintainer, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_successful_provider_exit_is_not_a_contribution_without_handoff(
    monkeypatch, tmp_path
) -> None:
    central, maintainer = _central_case(tmp_path)
    clone = _clone_case(central, tmp_path / "clone")
    fake = tmp_path / "fake-codex"
    fake.write_text(
        "#!/usr/bin/python3\n"
        "import json, sys\n"
        "sys.stdin.read()\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-test'}), flush=True)\n"
        "print(json.dumps({'type':'turn.completed','usage':"
        "{'input_tokens':7,'output_tokens':3}}), flush=True)\n",
        encoding="utf-8",
    )
    fake.chmod(0o700)
    monkeypatch.setattr("boule.agent_runner.resolve_provider_binary", lambda provider: str(fake))
    monkeypatch.setattr("boule.agent_runner.preflight_provider", lambda provider, binary: "fake 1")
    run_root = tmp_path / "runs"
    with _server(central, maintainer) as origin:
        prepared = prepare_run(
            "codex",
            "local-test",
            agent_name="Daryxx1",
            controller="shared-controller",
            registry=None,
            registry_clerk_key=None,
            trust_store=None,
            mode=None,
            model=None,
            effort=None,
            max_seconds=30,
            instruction=None,
            max_tokens=1_000,
            run_root=run_root,
            workspace_path=clone.root,
            workspace_server=origin,
        )
        assert not list((clone.control / "private" / "controllers").glob("*.pem"))
        launch_background(prepared["run_id"], run_root=run_root)
        deadline = time.monotonic() + 10
        while RunStore(run_root).status(prepared["run_id"])["state"] not in {
            "protocol_incomplete",
            "failed",
        }:
            assert time.monotonic() < deadline
            time.sleep(0.05)
    status = RunStore(run_root).status(prepared["run_id"])
    assert status["state"] == "protocol_incomplete"
    assert status["provider_session_id"] == "thread-test"
    assert status["usage"]["input_tokens"] == 7
    assert status["protocol"]["complete"] is False
    assert status["provider_turn_status"] == "completed"
    protocol_events = [
        event
        for event in RunStore(run_root).events(prepared["run_id"])
        if event.get("kind") == "protocol.updated"
    ]
    assert protocol_events
    assert all(isinstance(event.get("change"), str) for event in protocol_events)

    fake.write_text(
        "#!/usr/bin/python3\n"
        "import json, sys\n"
        "sys.stdin.read()\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-test'}), flush=True)\n"
        "print(json.dumps({'type':'turn.failed','error':{'message':'bounded failure'}}), "
        "flush=True)\n",
        encoding="utf-8",
    )
    recovered = prepare_resume(
        prepared["run_id"],
        max_seconds=20,
        instruction="record the preserved state",
        model=None,
        effort=None,
        run_root=run_root,
    )
    assert recovered["session_id"] == prepared["session_id"]
    assert recovered["workspace"] == prepared["workspace"]
    assert recovered["max_tokens"] == 1_000
    assert RunStore(run_root).config(recovered["run_id"])["max_tokens"] == 1_000
    with _server(central, maintainer):
        assert run_worker(recovered["run_id"], run_root=run_root) == 1
    recovered_status = RunStore(run_root).status(recovered["run_id"])
    assert recovered_status["state"] == "failed"
    assert recovered_status["provider_turn_status"] == "failed"


def test_worker_lease_rejects_duplicate_supervisor(tmp_path) -> None:
    store = RunStore(tmp_path / "runs")
    run_id = "run-20260101T000000-cafebabe"
    store.create(run_id, {"schema": "not-used"}, {"state": "ready"})
    lease = store.acquire_worker_lease(run_id)
    try:
        with pytest.raises(ProtocolError, match="active worker"):
            run_worker(run_id, run_root=store.root)
    finally:
        store.release_worker_lease(lease)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"state": "ready"}, "PREPARING"),
        ({"state": "starting"}, "STARTING PROVIDER"),
        ({"state": "running", "provider_started": True}, "ORIENTING"),
        (
            {
                "state": "running",
                "provider_started": True,
                "protocol": {"claim": {"route": "route"}},
            },
            "RESEARCHING",
        ),
        (
            {
                "state": "running",
                "protocol": {"handoff": {"outcome": "ADVANCE"}},
            },
            "HANDOFF RECORDED",
        ),
        ({"state": "completed"}, "HANDOFF SAVED · RUN CLOSED"),
        ({"state": "timed_out"}, "TIME LIMIT"),
        ({"state": "protocol_incomplete"}, "HANDOFF MISSING"),
    ],
)
def test_terminal_phase_is_evidence_based(status, expected) -> None:
    assert runtime_phase(status)[0] == expected


def _terminal_fixture() -> tuple[dict, dict, list[dict]]:
    config = {
        "query": "erdos-686",
        "model": "gpt-test",
        "effort": "ultra",
        "max_seconds": 600,
        "max_tokens": 1_000,
        "instruction": "PRIVATE PROMPT MUST NOT RENDER",
        "registry": {"origin": "https://boule.example"},
    }
    status = {
        "run_id": "run-20260101T000000-deadbeef",
        "agent_name": "Daryxx3",
        "provider": "codex",
        "provider_version": "codex-cli test",
        "provider_started": True,
        "provider_session_id": "PRIVATE-PROVIDER-SESSION",
        "session_id": "PRIVATE-BOULE-SESSION",
        "state": "running",
        "started_at": "2026-01-01T00:00:00Z",
        "problem_id": "problem-test",
        "task_mode": "counterexample",
        "workspace": "/tmp/private-workspace",
        "event_count": 5,
        "protocol_observation": {
            "at": "2026-01-01T00:02:00Z",
            "event_count": 42,
            "head_event_hash": "a" * 64,
        },
        "protocol": {
            "complete": False,
            "claim": {
                "route": "exact k=4 valuation route",
                "status": "active",
            },
            "handoff": None,
            "collaborators": [{"agent_name": "Daryxx2", "route": "large-prime route"}],
            "checkpoint_count": 1,
            "message_count": 2,
        },
        "usage": {
            "authoritative": True,
            "input_tokens": 247,
            "cache_read_tokens": 192,
            "output_tokens": 31,
            "reasoning_output_tokens": 12,
        },
    }
    events = [
        {
            "sequence": 1,
            "kind": "runtime.started",
            "observed_at": "2026-01-01T00:00:01Z",
        },
        {
            "sequence": 2,
            "kind": "tool.started",
            "tool_class": "command_execution",
            "item_id": "item-1",
            "command": "PRIVATE COMMAND MUST NOT RENDER",
            "observed_at": "2026-01-01T00:01:00Z",
        },
        {
            "sequence": 3,
            "kind": "tool.completed",
            "tool_class": "command_execution",
            "item_id": "item-1",
            "raw_reasoning": "PRIVATE REASONING MUST NOT RENDER",
            "observed_at": "2026-01-01T00:01:05Z",
        },
        {
            "sequence": 4,
            "kind": "message.completed",
            "summary": "\x1b[31mChecking [bold red]the exact modular obstruction[/]\x1b[0m",
            "observed_at": "2026-01-01T00:02:00Z",
        },
        {
            "sequence": 5,
            "kind": "protocol.updated",
            "change": "claim.recorded",
            "claim": {"route": "exact k=4 valuation route"},
            "observed_at": "2026-01-01T00:02:04Z",
        },
    ]
    return status, config, events


def test_rich_terminal_dashboard_shows_operational_context_without_raw_trace() -> None:
    status, config, events = _terminal_fixture()
    rendered = build_run_dashboard(
        status,
        config,
        events,
        now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
        width=140,
    )
    output = StringIO()
    Console(
        file=output,
        force_terminal=False,
        color_system=None,
        width=140,
        highlight=False,
    ).print(rendered)
    text = output.getvalue()
    for expected in (
        "B O U L E",
        "Daryxx3",
        "gpt-test",
        "ultra",
        "00:02:05 elapsed",
        "00:07:55",
        "remaining",
        "exact k=4 valuation route",
        "Daryxx2",
        "Checking [bold red]the exact modular obstruction[/]",
        "247 input",
        "192 cache read",
        "31",
        "output",
        "12 reasoning",
        "Token budget",
        "278 / 1,000 · 27.8%",
        "Activity is not mathematical progress or credit",
    ):
        assert expected in text
    for private in (
        "PRIVATE PROMPT MUST NOT RENDER",
        "PRIVATE COMMAND MUST NOT RENDER",
        "PRIVATE REASONING MUST NOT RENDER",
        "PRIVATE-PROVIDER-SESSION",
        "PRIVATE-BOULE-SESSION",
        "\x1b[31m",
    ):
        assert private not in text


def test_plain_terminal_fallback_is_stable_and_has_no_ansi() -> None:
    status, config, events = _terminal_fixture()
    line = format_runtime_line(
        status,
        config,
        events,
        now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
    )
    assert "[00:02:05] Daryxx3 · RUNNING / RESEARCHING" in line
    assert "codex/gpt-test/ultra" in line
    assert "activity: #5 protocol.updated (now)" in line
    assert "tokens: 247 in / 31 out (provider-reported)" in line
    assert "token accounting: 278 / 1,000 provider-reported · 27.8% · not hard" in line
    assert "\x1b" not in line


def test_terminal_makes_automatic_routing_visible_without_overstating_authority() -> None:
    status, config, events = _terminal_fixture()
    config["selection"] = {
        "method": "codex-advisor",
        "model": "gpt-5.6-terra",
        "strategy": "COMPUTATION",
        "reason": "The signed handoff has a bounded exact search ready.",
        "suggested_focus": "Reproduce the finite search and attach its certificate.",
    }
    events.append(
        {
            "sequence": 6,
            "kind": "routing.selected",
            "problem_title": "Erdos 686",
            "strategy": "COMPUTATION",
            "observed_at": "2026-01-01T00:02:05Z",
        }
    )
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
        )
    )
    text = output.getvalue()
    assert "Chosen by Boule" in text
    assert "codex-advisor / gpt-5.6-terra · COMPUTATION · advisory only" in text
    assert "bounded exact search" in text
    assert "Reproduce the finite search" in text

    line = format_runtime_line(
        status,
        config,
        events,
        now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
    )
    assert "Boule-selected: COMPUTATION via codex-advisor/gpt-5.6-terra" in line
    assert _timeline_label(events[-1]) == (
        "Router",
        "Boule selected Erdos 686 · COMPUTATION",
    )


def test_token_budget_waits_for_authoritative_usage_and_marks_overrun() -> None:
    status, config, events = _terminal_fixture()
    status["usage"] = None
    pending = StringIO()
    Console(file=pending, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
        )
    )
    assert "report pending · limit 1,000" in pending.getvalue()

    status["usage"] = {
        "authoritative": True,
        "input_tokens": 247,
        "cache_read_tokens": 192,
        "output_tokens": 31,
        "reasoning_output_tokens": 12,
    }
    config["max_tokens"] = 200
    exceeded = StringIO()
    Console(file=exceeded, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
        )
    )
    text = exceeded.getvalue()
    assert "278 / 200 · 139.0% · +78 over" in text


def test_in_session_usage_view_shows_current_and_daily_report_coverage() -> None:
    status, config, events = _terminal_fixture()
    pending = {
        "run_id": "run-20260101T010000-aabbccdd",
        "state": "running",
        "started_at": "2026-01-01T01:00:00Z",
        "updated_at": "2026-01-01T01:02:00Z",
        "usage": None,
    }
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
            view="usage",
            all_runs=[status, pending],
        )
    )
    text = output.getvalue()
    assert "Usage · current supervised turn" in text
    assert "247 input" in text
    assert "31 output" in text
    assert "278 / 1,000 provider-reported · 27.8%" in text
    assert "Local daily reports · UTC" in text
    assert "1/2 runs" in text
    assert "missing reports are never counted as zero" in text
    assert "never contribution credit" in text


def test_local_usage_report_counts_missing_provider_reports_separately() -> None:
    status, _config, _events = _terminal_fixture()
    pending = {
        "run_id": "run-20260101T010000-aabbccdd",
        "state": "running",
        "started_at": "2026-01-01T01:00:00Z",
        "usage": None,
    }
    report = usage_report(
        [status, pending],
        now=datetime(2026, 1, 1, 1, 5, tzinfo=UTC),
        days=1,
    )
    assert report["run_count"] == 2
    assert report["reported_run_count"] == 1
    assert report["missing_report_count"] == 1
    assert report["totals"]["total_tokens"] == 278
    assert report["days"][0]["reported_runs"] == 1
    assert report["days"][0]["runs"] == 2
    assert report["missing_reports_count_as_zero"] is False

    with pytest.raises(ProtocolError, match="between 1 and 31"):
        usage_report([status], days=0)


def test_top_level_local_reports_are_read_only(tmp_path, monkeypatch, capsys) -> None:
    run_id = "run-20260101T000000-aabbccdd"
    store = RunStore(tmp_path / "runs")
    store.create(
        run_id,
        {"schema": "boule-agent-run/0.1"},
        {
            "state": "running",
            "agent_name": "Daryxx1",
            "problem_id": "problem-test",
            "protocol": {"checkpoint_count": 1},
            "usage": {"input_tokens": 10, "output_tokens": 2},
        },
    )

    def forbidden_reconcile(*_args, **_kwargs):
        raise AssertionError("local reports must not reconcile or terminate a run")

    monkeypatch.setattr("boule.cli.reconcile_run", forbidden_reconcile)
    parser = build_parser()
    usage_args = parser.parse_args(
        ["usage", "--days", "2", "--run-root", str(store.root), "--json"]
    )
    assert usage_args.handler(usage_args) == 0
    usage_value = json.loads(capsys.readouterr().out)
    assert len(usage_value["days"]) == 2

    rendered = {}

    def capture_dashboard(*_args, **kwargs):
        rendered.update(kwargs)

    monkeypatch.setattr("boule.cli.print_run_dashboard", capture_dashboard)
    human_usage_args = parser.parse_args(["usage", "--days", "3", "--run-root", str(store.root)])
    assert human_usage_args.handler(human_usage_args) == 0
    assert rendered["usage_days"] == 3

    progress_args = parser.parse_args(["progress", run_id, "--run-root", str(store.root), "--json"])
    assert progress_args.handler(progress_args) == 0
    progress_value = json.loads(capsys.readouterr().out)
    assert progress_value["run_id"] == run_id


def test_usage_on_a_fresh_machine_does_not_create_local_state(tmp_path, capsys) -> None:
    run_root = tmp_path / "missing" / "runs"
    args = build_parser().parse_args(["usage", "--run-root", str(run_root), "--json"])
    assert args.handler(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["run_count"] == 0
    assert report["missing_report_count"] == 0
    assert not run_root.exists()


def test_in_session_progress_view_uses_signed_evidence_not_activity() -> None:
    status, config, events = _terminal_fixture()
    status["protocol"].update(
        {
            "problem_status": "OPEN",
            "last_checkpoint": {
                "summary": "Exact search certificate attached",
                "next_action": "Independent reproduction",
            },
            "network": {
                "sessions": 3,
                "handoffs": 2,
                "messages": 4,
                "feedback": 0,
                "handoffs_by_outcome": {"ADVANCE": 1, "NEGATIVE": 1},
                "candidates_by_status": {},
            },
        }
    )
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=140,
            view="progress",
        )
    )
    text = output.getvalue()
    assert "RESUMABLE_PROGRESS" in text
    assert "Exact search certificate attached" in text
    assert "Independent reproduction" in text
    assert "ADVANCE 1 · NEGATIVE 1" in text
    assert "operational report, not evidence" in text
    assert "No percentage solved" in text
    assert "27.8%" not in text


def test_local_progress_report_has_no_activity_derived_percentage() -> None:
    status, _config, _events = _terminal_fixture()
    status["protocol"].update(
        {
            "problem_status": "OPEN",
            "checkpoint_count": 1,
            "last_checkpoint": {
                "summary": "Exact search certificate attached",
                "next_action": "Independent reproduction",
            },
        }
    )
    report = progress_report(status)
    assert report["evidence_state"] == "RESUMABLE_PROGRESS"
    assert report["checkpoint_count"] == 1
    assert report["percentage_solved"] is None
    assert report["usage_or_activity_advances_progress"] is False


def test_in_session_progress_does_not_advance_from_provider_activity() -> None:
    status, config, events = _terminal_fixture()
    status["protocol"] = {
        "complete": False,
        "claim": None,
        "handoff": None,
        "collaborators": [],
        "checkpoint_count": 0,
        "message_count": 0,
    }
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(status, config, events, width=140, view="progress")
    )
    text = output.getvalue()
    assert "NO_DURABLE_PROGRESS" in text
    assert "5 tools" not in text


def test_run_terminal_supports_local_hotkeys_and_slash_commands(tmp_path) -> None:
    run_id = "run-20260101T000000-c0ffee00"
    status, config, _events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    terminal = RunTerminal(store, run_id, stream=StringIO(), input_stream=StringIO())

    assert terminal.handle_key("u") is True
    assert terminal.view == "usage"
    assert terminal.handle_key("p") is True
    assert terminal.view == "progress"
    assert terminal.handle_key("/usage\n") is True
    assert terminal.view == "usage"
    assert terminal.handle_key("/progress\r") is True
    assert terminal.view == "progress"
    assert terminal.handle_key("\x1b") is True
    assert terminal.view == "dashboard"
    assert terminal.handle_key("\x03") is False


def test_run_terminal_tty_navigation_restores_terminal_mode(tmp_path) -> None:
    run_id = "run-20260101T000000-bada55aa"
    status, config, _events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    try:
        with (
            os.fdopen(os.dup(slave), "w", encoding="utf-8", buffering=1) as output,
            os.fdopen(os.dup(slave), "r", encoding="utf-8", buffering=1) as input_stream,
        ):
            terminal = RunTerminal(store, run_id, stream=output, input_stream=input_stream)
            terminal.start()
            os.write(master, b"u")
            assert terminal.poll_input() is True
            assert terminal.view == "usage"
            os.write(master, b"/progress\n")
            assert terminal.poll_input() is True
            assert terminal.view == "progress"
            terminal.close()
        assert termios.tcgetattr(slave) == original
    finally:
        os.close(master)
        os.close(slave)


def test_terminal_elapsed_freezes_at_the_terminal_timestamp() -> None:
    status, config, events = _terminal_fixture()
    status.update(
        {
            "state": "completed",
            "finished_at": "2026-01-01T00:05:00Z",
        }
    )
    line = format_runtime_line(
        status,
        config,
        events,
        now=datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC),
    )
    assert line.startswith("[00:05:00]")


def test_non_tty_run_terminal_prints_complete_plain_lines(tmp_path) -> None:
    run_id = "run-20260101T000000-feedface"
    status, config, events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    for event in events:
        store.append_event(
            run_id,
            {key: value for key, value in event.items() if key not in {"sequence", "observed_at"}},
        )
    output = StringIO()
    terminal = RunTerminal(store, run_id, stream=output)
    terminal.start()
    terminal.close()
    text = output.getvalue()
    assert "Daryxx3" in text
    assert "RESEARCHING" in text
    assert "\x1b" not in text
    assert "\r" not in text


def test_tty_run_terminal_uses_one_live_rich_view(tmp_path) -> None:
    class TtyBuffer(StringIO):
        def isatty(self) -> bool:
            return True

    run_id = "run-20260101T000000-facefeed"
    status, config, events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    for event in events:
        store.append_event(
            run_id,
            {key: value for key, value in event.items() if key not in {"sequence", "observed_at"}},
        )
    output = TtyBuffer()
    terminal = RunTerminal(store, run_id, stream=output)
    terminal.start()
    terminal.refresh(force=True)
    terminal.close()
    text = output.getvalue()
    assert "B O U L E" in text
    assert "Daryxx3" in text
    assert "\x1b[" in text


def test_narrow_tty_live_view_does_not_flood_scrollback(monkeypatch, tmp_path) -> None:
    class TtyBuffer(StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setenv("COLUMNS", "40")
    monkeypatch.setenv("LINES", "10")
    run_id = "run-20260101T000000-1234abcd"
    status, config, events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    for event in events:
        store.append_event(
            run_id,
            {key: value for key, value in event.items() if key not in {"sequence", "observed_at"}},
        )
    output = TtyBuffer()
    terminal = RunTerminal(store, run_id, stream=output)
    terminal.start()
    terminal.refresh(force=True)
    terminal.close()
    assert terminal.disabled is False
    assert len(output.getvalue().splitlines()) < 60


def test_status_and_list_are_plain_when_redirected(tmp_path) -> None:
    run_id = "run-20260101T000000-1122aabb"
    status, config, events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    for event in events:
        store.append_event(
            run_id,
            {key: value for key, value in event.items() if key not in {"sequence", "observed_at"}},
        )
    status_output = StringIO()
    print_run_dashboard(store, run_id, stream=status_output)
    list_output = StringIO()
    print_run_list(store, [store.status(run_id)], stream=list_output)
    for text in (status_output.getvalue(), list_output.getvalue()):
        assert "Daryxx3" in text
        assert "gpt-test" in text
        assert "╭" not in text
        assert "\x1b" not in text
        assert "\r" not in text


def test_terminal_redacts_credential_like_protocol_and_event_text() -> None:
    status, config, events = _terminal_fixture()
    token = "sk" + "-" + "terminalfixture123456789"
    status["protocol"]["latest_message"] = {
        "topic": "coordination",
        "body": "AUTHORIZATION:Bearer " + token,
    }
    events.append(
        {
            "sequence": 6,
            "kind": "message.completed",
            "summary": "OPENAI_API_KEY=" + token,
            "observed_at": "2026-01-01T00:02:05Z",
        }
    )
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 6, tzinfo=UTC),
            width=140,
        )
    )
    text = output.getvalue()
    assert token not in text
    assert "[redacted]" in text


def test_terminal_shows_valid_provider_duration_and_hides_invalid_cost() -> None:
    status, config, events = _terminal_fixture()
    status["provider_duration_ms"] = 12_345
    status["provider_reported_cost_usd"] = float("nan")
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=140).print(
        build_run_dashboard(status, config, events, width=140)
    )
    text = output.getvalue()
    assert "12.345s" in text
    assert "$nan" not in text


def test_terminal_output_failure_never_fails_the_research_runtime(tmp_path) -> None:
    class BrokenOutput(StringIO):
        def write(self, value: str) -> int:
            raise BrokenPipeError

    run_id = "run-20260101T000000-badf00d0"
    status, config, _events = _terminal_fixture()
    status["run_id"] = run_id
    store = RunStore(tmp_path / "runs")
    store.create(run_id, config, {key: value for key, value in status.items() if key != "run_id"})
    terminal = RunTerminal(store, run_id, stream=BrokenOutput())
    terminal.start()
    terminal.refresh(force=True)
    terminal.close()
    assert terminal.disabled is True


def test_terminal_timeline_is_bounded_to_five_material_events() -> None:
    status, config, _events = _terminal_fixture()
    events = [
        {
            "sequence": index,
            "kind": "message.completed",
            "summary": f"timeline-message-{index}",
            "observed_at": f"2026-01-01T00:00:{index:02d}Z",
        }
        for index in range(1, 9)
    ]
    output = StringIO()
    Console(file=output, force_terminal=False, color_system=None, width=120).print(
        build_run_dashboard(
            status,
            config,
            events,
            now=datetime(2026, 1, 1, 0, 2, 5, tzinfo=UTC),
            width=120,
        )
    )
    text = output.getvalue()
    assert "timeline-message-3" not in text
    assert "timeline-message-4" in text
    assert "timeline-message-8" in text
