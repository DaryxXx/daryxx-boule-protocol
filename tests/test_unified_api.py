from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from boule.canonical import canonical_bytes
from boule.clerk_api import ClerkService
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.registry import Registry
from boule.registry_api import build_server
from boule.remote_client import RemoteClient
from boule.remote_protocol import build_envelope, verify_snapshot
from boule.workspace import Workspace


def _case(tmp_path, case_id: str, suffix: str):
    problem_id = f"problem-{case_id}"
    commitment = "sha256:" + suffix * 64
    problem = {
        "schema": "boule-problem/0.1",
        "problem_id": problem_id,
        "problem": {"title": f"Problem {case_id}"},
        "source": {
            "provider": "conjectures.io",
            "canonical_problem_url": f"https://conjectures.io/problems/{case_id}",
        },
        "task": {
            "mode": "formalized",
            "task_id": f"task-{case_id}",
            "task_commitment": commitment,
            "formal_repository_pin": suffix * 40,
            "pinned_source_url": (
                f"https://github.com/example/formal/blob/{suffix * 40}/{case_id}.lean"
            ),
        },
    }
    root = tmp_path / case_id
    root.mkdir()
    (root / "problem.json").write_text(json.dumps(problem), encoding="utf-8")
    key = generate_private_key()
    workspace = Workspace.initialize(
        root,
        {
            "maintainer_key": public_key_text(key),
            "lease_seconds": 3600,
            "absolute_lease_seconds": 7200,
            "stale_seconds": 900,
            "max_renewals": 2,
        },
    )
    return problem, workspace, key


def _record_case(
    registry: Registry,
    case_id: str,
    problem: dict,
    workspace: Workspace,
    *,
    live_url: str | None,
    repository_id: int,
) -> None:
    registry.record_proposal({"case_id": case_id, "problem": problem})
    registry.admit(case_id)
    registry.start_provisioning(case_id)
    registry.record_repository(
        case_id,
        f"https://github.com/BouleProtocol/{case_id}",
        workspace.config["maintainer_key"],
        "c" * 64,
        "d" * 40,
        repository_id,
        f"R_{repository_id}",
    )
    if live_url is not None:
        registry.mark_live(case_id, live_url, None, 0)


@contextmanager
def _running_api(registry: Registry, services: dict[str, ClerkService]):
    server = build_server(registry, case_loader=services.__getitem__)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    url: str,
    *,
    method: str = "GET",
    value: dict | None = None,
    host: str | None = None,
):
    body = canonical_bytes(value) if value is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if host is not None:
        headers["Host"] = host
    try:
        with urlopen(
            Request(url, data=body, headers=headers, method=method), timeout=5
        ) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_one_api_hosts_isolated_case_ledgers(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    alpha_id = "case-alpha-001"
    beta_id = "case-beta-002"
    alpha_problem, alpha, alpha_key = _case(tmp_path, alpha_id, "a")
    beta_problem, beta, beta_key = _case(tmp_path, beta_id, "b")
    _record_case(
        registry,
        alpha_id,
        alpha_problem,
        alpha,
        live_url="https://alpha-clerk.example",
        repository_id=1,
    )
    _record_case(
        registry,
        beta_id,
        beta_problem,
        beta,
        live_url=None,
        repository_id=2,
    )
    services = {
        alpha_id: ClerkService(alpha, alpha_key),
        beta_id: ClerkService(beta, beta_key),
    }

    with _running_api(registry, services) as origin:
        status, health = _request(origin + "/healthz")
        assert status == 200
        assert health["service"] == "boule-api"
        status, registry_state = _request(origin + "/v1/problems", host="alpha-clerk.example")
        assert status == 200
        assert len(registry_state["problems"]) == 2
        status, invalid_path = _request(origin + f"/cases//{alpha_id}/v1/state")
        assert status == 400
        assert invalid_path["error"]["code"] == "invalid_path"

        status, alpha_state = _request(origin + f"/cases/{alpha_id}/v1/state")
        assert status == 200
        verify_snapshot(
            alpha_state["snapshot"],
            alpha_state["state"],
            problem_id=alpha_problem["problem_id"],
            clerk_key=alpha.config["maintainer_key"],
        )
        client_state = RemoteClient(alpha, origin + f"/cases/{alpha_id}").fetch_state()
        assert client_state["snapshot"]["event_count"] == 0

        # A provisioned case must expose its signed state so activation can
        # verify it, but it cannot accept participant writes yet.
        status, beta_state = _request(origin + f"/cases/{beta_id}/v1/state")
        assert status == 200
        assert beta_state["snapshot"]["event_count"] == 0
        status, rejected = _request(origin + f"/cases/{beta_id}/v1/append", method="POST", value={})
        assert status == 409
        assert rejected["error"]["code"] == "case_not_live"

        for _slot in range(8):
            assert services[alpha_id].acquire_request() is True
        try:
            assert services[alpha_id].acquire_request() is False
            status, busy = _request(origin + f"/cases/{alpha_id}/v1/state")
            assert status == 503
            assert busy["error"]["code"] == "case_busy"
            assert _request(origin + f"/cases/{beta_id}/v1/state")[0] == 200
            assert _request(origin + "/healthz")[0] == 200
        finally:
            for _slot in range(8):
                services[alpha_id].release_request()

        controller = generate_private_key()
        envelope = build_envelope(
            request_id="5a8ebd80-bff2-4a45-8b0d-5909e3aa6408",
            problem_id=alpha_problem["problem_id"],
            clerk_key=alpha.config["maintainer_key"],
            base_event_hash=None,
            kind="session_started",
            payload={
                "problem_id": alpha_problem["problem_id"],
                "participant_id": "agent-alpha",
                "controller_id": "controller-alpha",
                "controller_key": public_key_text(controller),
                "session_id": "session-alpha",
                "session_key": public_key_text(generate_private_key()),
                "not_after": (datetime.now(UTC) + timedelta(hours=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "policy_digest": alpha.config["policy_digest"],
            },
            private_key=controller,
        )
        status, accepted = _request(
            origin + f"/cases/{alpha_id}/v1/append",
            method="POST",
            value=envelope,
        )
        assert status == 201
        assert accepted["receipt"]["seq"] == 0

        registry.mark_live(
            beta_id,
            f"https://boule.example/cases/{beta_id}",
            None,
            0,
        )
        status, cross_case = _request(
            origin + f"/cases/{beta_id}/v1/append",
            method="POST",
            value=envelope,
        )
        assert status == 422
        assert cross_case["error"]["code"] == "event_rejected"
        assert _request(origin + f"/cases/{beta_id}/v1/state")[1]["snapshot"]["event_count"] == 0

        status, root_write = _request(origin + "/v1/problems", method="POST", value={})
        assert status == 405
        assert root_write["error"]["code"] == "read_only"
        status, wrong_method = _request(
            origin + f"/cases/{alpha_id}/v1/append", method="PUT", value=envelope
        )
        assert status == 405
        assert wrong_method["error"]["code"] == "method_not_allowed"


def test_remote_client_accepts_only_a_canonical_case_path(tmp_path) -> None:
    _problem, workspace, _key = _case(tmp_path, "case-path-001", "c")
    client = RemoteClient(
        workspace,
        "https://boule.example/cases/case-path-001",
    )
    assert client.server == "https://boule.example/cases/case-path-001"
    assert (
        RemoteClient(workspace, "https://boule.example/cases/case-path-001/").server
        == client.server
    )
    assert (
        RemoteClient(workspace, "https://clerk.example/custom/case-path-001").server
        == "https://clerk.example/custom/case-path-001"
    )

    for invalid in (
        "https://boule.example/cases/../other",
        "https://boule.example/cases//case-path-001",
        "https://boule.example/cases/%2e%2e/other",
        "https://boule.example/cases/case-path-001?case=other",
    ):
        with pytest.raises(ProtocolError):
            RemoteClient(workspace, invalid)


def test_registry_records_only_a_client_usable_clerk_url(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    case_id = "case-url-001"
    problem, workspace, _key = _case(tmp_path, case_id, "d")
    _record_case(
        registry,
        case_id,
        problem,
        workspace,
        live_url=None,
        repository_id=4,
    )
    with pytest.raises(ProtocolError):
        registry.mark_live(
            case_id,
            f"https://boule.example/cases/{case_id}?wrong=1",
            None,
            0,
        )
    record = registry.mark_live(
        case_id,
        f"https://boule.example/cases/{case_id}/",
        None,
        0,
    )
    assert record["clerk_url"] == f"https://boule.example/cases/{case_id}"
