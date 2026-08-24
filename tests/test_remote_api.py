from __future__ import annotations

import json
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import boule.remote_client as remote_client_module
from boule.canonical import canonical_bytes
from boule.clerk_api import build_server
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError, RemoteTransportError
from boule.remote_client import RemoteClient
from boule.remote_protocol import build_envelope, verify_chain_proof, verify_snapshot
from boule.session_store import SessionStore
from boule.workspace import Workspace


def central_case(tmp_path):
    maintainer = generate_private_key()
    root = tmp_path / "central"
    root.mkdir()
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "p-api",
                "task": {
                    "task_id": "task-api",
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


@contextmanager
def running_server(workspace, maintainer):
    server = build_server(workspace, maintainer, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def raw_request(url: str, method: str, body: bytes | None = None):
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, method=method, headers=headers)
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def clone_case(source: Workspace, destination: Path) -> Workspace:
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


def start_remote_session(clone: Workspace, server: str, participant: str):
    client = RemoteClient(clone, server)
    result = {}

    def append(kind, payload, key):
        result.update(client.append(kind, payload, key))
        return result["event"]

    profile = SessionStore(clone).start(
        participant_id=participant,
        controller_id=f"controller-{participant}",
        label=f"Codex {participant}",
        not_after=(datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        appender=append,
    )
    loaded, key = SessionStore(clone).load(profile["session_id"])
    return loaded, key, result


def claim_payload(problem_id: str, profile: dict, claim_id: str):
    return {
        "problem_id": problem_id,
        "participant_id": profile["participant_id"],
        "session_id": profile["session_id"],
        "claim_id": claim_id,
        "route": f"route-{claim_id}",
        "success_gate": "reproducible result",
        "falsifier": "exact counterexample",
        "parallel": False,
    }


def test_http_contract_strict_json_auth_idempotence_and_restart(tmp_path):
    workspace, maintainer = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    controller = generate_private_key()
    session = generate_private_key()
    payload = {
        "problem_id": "p-api",
        "participant_id": "agent-http",
        "controller_id": "controller-http",
        "controller_key": public_key_text(controller),
        "session_id": "session-http",
        "session_key": public_key_text(session),
        "not_after": (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "policy_digest": clone.config["policy_digest"],
    }
    with running_server(workspace, maintainer) as server:
        status, state = raw_request(server + "/v1/state", "GET")
        assert status == 200
        verify_snapshot(
            state["snapshot"],
            state["state"],
            problem_id="p-api",
            clerk_key=workspace.config["maintainer_key"],
        )

        duplicate_json = b'{"schema":"x","schema":"y"}'
        status, error = raw_request(server + "/v1/append", "POST", duplicate_json)
        assert (status, error["error"]["code"]) == (400, "invalid_json")

        long_lived = build_envelope(
            request_id="2fa6a936-346f-4821-b3b4-71a2ba6040ad",
            problem_id="p-api",
            clerk_key=workspace.config["maintainer_key"],
            base_event_hash=None,
            kind="session_started",
            payload={
                **payload,
                "not_after": (datetime.now(UTC) + timedelta(days=365))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            private_key=controller,
        )
        status, error = raw_request(server + "/v1/append", "POST", canonical_bytes(long_lived))
        assert (status, error["error"]["code"]) == (422, "event_rejected")

        signed = build_envelope(
            request_id="4f3d1d15-5023-41f9-aa11-29410e005ea7",
            problem_id="p-api",
            clerk_key=workspace.config["maintainer_key"],
            base_event_hash=None,
            kind="session_started",
            payload=payload,
            private_key=controller,
        )
        tampered = {**signed, "payload": {**payload, "participant_id": "thief"}}
        status, error = raw_request(server + "/v1/append", "POST", canonical_bytes(tampered))
        assert (status, error["error"]["code"]) == (401, "signature_invalid")

        forbidden = {**signed, "kind": "candidate_feedback_recorded"}
        status, error = raw_request(server + "/v1/append", "POST", canonical_bytes(forbidden))
        assert (status, error["error"]["code"]) == (403, "maintainer_event_forbidden")

        first_status, first = raw_request(server + "/v1/append", "POST", canonical_bytes(signed))
        retry_status, retry = raw_request(server + "/v1/append", "POST", canonical_bytes(signed))
        assert first_status == 201
        assert retry_status == 200
        assert retry["receipt"] == first["receipt"]
        proof_status, proof = raw_request(server + "/v1/chain/0/1", "GET")
        assert proof_status == 200
        verified_proof = verify_chain_proof(
            proof,
            problem_id="p-api",
            clerk_key=workspace.config["maintainer_key"],
            from_count=0,
            from_head=None,
            to_count=1,
        )
        assert verified_proof["to_head"] == first["event"]["event_hash"]
        with pytest.raises(ProtocolError, match="requested range"):
            verify_chain_proof(
                proof,
                problem_id="p-api",
                clerk_key=workspace.config["maintainer_key"],
                from_count=0,
                from_head="f" * 64,
                to_count=1,
            )
        conflicting = build_envelope(
            request_id=signed["request_id"],
            problem_id="p-api",
            clerk_key=workspace.config["maintainer_key"],
            base_event_hash=None,
            kind="session_started",
            payload={**payload, "label": "conflicting retry"},
            private_key=controller,
        )
        status, error = raw_request(server + "/v1/append", "POST", canonical_bytes(conflicting))
        assert (status, error["error"]["code"]) == (409, "request_id_conflict")
        receipt_status, recovered = raw_request(
            server + "/v1/receipts/" + signed["request_id"], "GET"
        )
        assert receipt_status == 200
        assert recovered["receipt"] == first["receipt"]

    with running_server(Workspace(workspace.root), maintainer) as restarted:
        retry_status, retry = raw_request(restarted + "/v1/append", "POST", canonical_bytes(signed))
        assert retry_status == 200
        assert retry["receipt"] == first["receipt"]


def test_two_clones_concurrently_retry_stale_head_and_keep_receipts(tmp_path):
    workspace, maintainer = central_case(tmp_path)
    first_clone = clone_case(workspace, tmp_path / "clone-a")
    second_clone = clone_case(workspace, tmp_path / "clone-b")
    with running_server(workspace, maintainer) as server:
        first_profile, first_key, first_start = start_remote_session(first_clone, server, "agent-a")
        second_profile, second_key, second_start = start_remote_session(
            second_clone, server, "agent-b"
        )
        assert first_start["receipt"]["seq"] == 0
        assert second_start["receipt"]["seq"] == 1

        barrier = threading.Barrier(2)

        class BarrierClient(RemoteClient):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.wait_once = True

            def fetch_state(self):
                value = super().fetch_state()
                if self.wait_once:
                    self.wait_once = False
                    barrier.wait(timeout=5)
                return value

        clients = [BarrierClient(first_clone, server), BarrierClient(second_clone, server)]
        payloads = [
            claim_payload("p-api", first_profile, "claim-a"),
            claim_payload("p-api", second_profile, "claim-b"),
        ]
        keys = [first_key, second_key]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(client.append, "work_claimed", payload, key)
                for client, payload, key in zip(clients, payloads, keys, strict=True)
            ]
            results = [future.result(timeout=10) for future in futures]

        assert {result["receipt"]["seq"] for result in results} == {2, 3}
        state = RemoteClient(first_clone, server).fetch_state()["state"]
        assert {claim["claim_id"] for claim in state["claims"]} == {"claim-a", "claim-b"}
        assert not list((first_clone.control / "private" / "remote-outbox").glob("*.json"))
        assert not list((second_clone.control / "private" / "remote-outbox").glob("*.json"))
        assert len(list((first_clone.control / "private" / "remote-receipts").glob("*.json"))) == 2
        assert len(list((second_clone.control / "private" / "remote-receipts").glob("*.json"))) == 2


def test_lost_response_recovers_committed_event_without_duplicate(tmp_path):
    workspace, maintainer = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    with running_server(workspace, maintainer) as server:
        profile, key, _ = start_remote_session(clone, server, "agent-a")

        class LoseFirstResponse(RemoteClient):
            lost = False

            def _submit_envelope(self, envelope):
                result = super()._submit_envelope(envelope)
                if not self.lost:
                    self.lost = True
                    raise RemoteTransportError("simulated response loss after durable commit")
                return result

        client = LoseFirstResponse(clone, server)
        result = client.append("work_claimed", claim_payload("p-api", profile, "claim-a"), key)
        assert result["created"] is False
        assert result["receipt"]["seq"] == 1
        assert len(workspace._events()) == 2
        assert not list((clone.control / "private" / "remote-outbox").glob("*.json"))


def test_snapshot_clock_correction_is_not_treated_as_chain_rollback(tmp_path):
    workspace, maintainer = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    later = workspace.remote_snapshot("2030-01-01T00:00:00Z", maintainer)
    earlier = workspace.remote_snapshot("2029-01-01T00:00:00Z", maintainer)
    responses = iter((later, earlier))
    client = RemoteClient(clone, "http://127.0.0.1:8787")
    client._http = lambda *_args, **_kwargs: (200, next(responses))

    assert client.fetch_state()["snapshot"]["at"] == "2030-01-01T00:00:00Z"
    assert client.fetch_state()["snapshot"]["at"] == "2029-01-01T00:00:00Z"


def test_state_cache_lock_serializes_distinct_clients(tmp_path):
    workspace, _ = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    first = RemoteClient(clone, "http://127.0.0.1:8787")
    second = RemoteClient(clone, "http://127.0.0.1:8787")
    acquired = threading.Event()

    def acquire_second():
        with second._state_cache_lock():
            acquired.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with first._state_cache_lock():
            future = pool.submit(acquire_second)
            assert not acquired.wait(timeout=0.1)
        future.result(timeout=5)
    assert acquired.is_set()


def test_confirmed_remote_event_preserves_outbox_if_local_finalize_fails(tmp_path):
    workspace, maintainer = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    with running_server(workspace, maintainer) as server:
        profile, key, _ = start_remote_session(clone, server, "agent-a")

        class BrokenFinalize(RemoteClient):
            def _finalize(self, envelope, receipt, event=None):
                raise OSError("simulated local disk failure")

        client = BrokenFinalize(clone, server)
        with pytest.raises(RemoteTransportError, match="local receipt finalization failed"):
            client.append("work_claimed", claim_payload("p-api", profile, "claim-a"), key)

        assert len(workspace._events()) == 2
        assert len(list((clone.control / "private" / "remote-outbox").glob("*.json"))) == 1


def test_concurrent_exact_finalization_converges_on_one_completed_bundle(tmp_path, monkeypatch):
    workspace, maintainer = central_case(tmp_path)
    clone = clone_case(workspace, tmp_path / "clone")
    with running_server(workspace, maintainer) as server:
        profile, key, _ = start_remote_session(clone, server, "agent-a")
        first = RemoteClient(clone, server)
        snapshot = first.fetch_state()["snapshot"]
        envelope = build_envelope(
            request_id="36b69922-6b9a-42b7-8e3f-254f838c0367",
            problem_id="p-api",
            clerk_key=clone.config["maintainer_key"],
            base_event_hash=snapshot["head_event_hash"],
            kind="work_claimed",
            payload=claim_payload("p-api", profile, "claim-a"),
            private_key=key,
        )
        first._persist_outbox(envelope)
        accepted = first._submit_envelope(envelope)
        destination = first._completed_path(envelope["request_id"])
        original_write = remote_client_module._write_private_json
        collision = threading.Barrier(2)

        def synchronized_write(path, value, *, exclusive):
            if path == destination and exclusive:
                collision.wait(timeout=5)
            return original_write(path, value, exclusive=exclusive)

        monkeypatch.setattr(remote_client_module, "_write_private_json", synchronized_write)
        clients = [first, RemoteClient(clone, server)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    client._finalize_or_preserve,
                    envelope,
                    accepted["receipt"],
                    accepted["event"],
                )
                for client in clients
            ]
            results = [future.result(timeout=10) for future in futures]

        assert {result["completed_path"] for result in results} == {str(destination)}
        assert destination.exists()
        assert not first._outbox_path(envelope["request_id"]).exists()
