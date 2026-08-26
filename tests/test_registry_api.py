from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from boule.canonical import digest_bytes
from boule.case_anchor_store import CaseAnchorStore
from boule.cli import main
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.registry import Registry, verify_registry_snapshot
from boule.registry_api import (
    LiveProjector,
    build_server,
    fetch_case_state,
    maintainer_runtime_status,
)
from boule.remote_protocol import build_chain_proof, build_snapshot
from boule.trust_store import trust_registry_snapshot


def problem() -> dict[str, object]:
    return {
        "case_id": "case-registry-001",
        "problem": {
            "problem_id": "conjectures:fc-registry-formalized-v1",
            "problem": {"title": "A pinned problem"},
            "source": {
                "provider": "conjectures.io",
                "canonical_problem_url": "https://conjectures.io/problems/registry",
            },
            "task": {
                "mode": "formalized",
                "task_id": "fc-registry-formalized-v1",
                "task_commitment": "sha256:" + "a" * 64,
                "formal_repository_pin": "1" * 40,
                "pinned_source_url": "https://github.com/x/y/blob/" + "1" * 40 + "/A.lean",
            },
        },
    }


@contextmanager
def running_registry(registry, *, live_projector=None):
    server = build_server(registry, live_projector=live_projector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def request(url: str, method: str = "GET") -> tuple[int, dict[str, object], object]:
    try:
        with urlopen(Request(url, method=method), timeout=5) as response:
            return response.status, json.loads(response.read()), response.headers
    except HTTPError as exc:
        return exc.code, json.loads(exc.read()), exc.headers


def test_read_only_registry_api_exposes_signed_minimal_snapshots(tmp_path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk, "2026-01-01T00:00:00Z")
    registry.record_proposal(problem(), "2026-01-01T00:00:01Z")
    registry.admit("case-registry-001", "2026-01-01T00:00:02Z")
    registry.start_provisioning("case-registry-001", "2026-01-01T00:00:03Z")
    registry.record_repository(
        "case-registry-001",
        "https://github.com/boule/case-registry-001",
        public_key_text(generate_private_key()),
        "c" * 64,
        "d" * 40,
        101,
        "R_registry101",
        "2026-01-01T00:00:04Z",
    )
    registry.mark_live(
        "case-registry-001",
        "https://clerk.example/case-registry-001",
        "b" * 64,
        4,
        "2026-01-01T00:00:05Z",
    )
    with running_registry(registry) as origin:
        status, value, headers = request(origin + "/v1/live")
        assert status == 200
        assert len(value["problems"]) == 1
        assert value["problems"][0]["status"] == "LIVE"
        assert value["problems"][0]["live_stale"] is True
        assert headers["X-Content-Type-Options"] == "nosniff"

        status, value, _ = request(origin + "/v1/problems/x")
        assert status == 400
        assert value["error"]["code"] == "invalid_case_id"

        status, value, _ = request(origin + "/v1/problems/case-registry-999")
        assert status == 404
        assert value["error"]["code"] == "case_not_found"

        status, value, _ = request(origin + "/v1/problems", "POST")
        assert status == 405
        assert value["error"]["code"] == "read_only"


def _live_problem(case_id: str, commitment: str) -> dict[str, object]:
    value = deepcopy(problem())
    value["case_id"] = case_id
    value["problem"]["task"]["task_commitment"] = commitment
    return value


def _mark_live(registry: Registry, case_id: str) -> None:
    registry.record_proposal(_live_problem(case_id, "sha256:" + case_id[-1] * 64))
    registry.admit(case_id)
    registry.start_provisioning(case_id)
    registry.record_repository(
        case_id,
        f"https://github.example/boule/{case_id}",
        public_key_text(generate_private_key()),
        "c" * 64,
        "d" * 40,
        int(case_id[-1]),
        f"R_{case_id}",
    )
    registry.mark_live(case_id, f"https://clerk.example/{case_id}", "e" * 64, 2)


def test_registry_api_refreshes_durable_state_and_cli_verifies_signed_shape(
    tmp_path, capsys
) -> None:
    clerk = generate_private_key()
    path = tmp_path / "registry.jsonl"
    reader = Registry.create(path, clerk)
    writer = Registry.open(path, clerk)

    with running_registry(reader) as origin:
        status, empty, _ = request(origin + "/v1/problems")
        assert status == 200
        assert empty["problems"] == []

        writer.record_proposal(problem())
        status, snapshot, headers = request(origin + "/v1/problems")
        verified = verify_registry_snapshot(snapshot, clerk_key=reader.clerk_key)
        assert status == 200
        assert verified["problems"][0]["case_id"] == "case-registry-001"
        assert headers["Cache-Control"] == "no-store"

        assert (
            main(["problems", "--server", origin, "--clerk-key", reader.clerk_key, "--json"]) == 0
        )
        cli_value = json.loads(capsys.readouterr().out)
        assert set(cli_value) == {
            "problems",
            "registry",
            "registry_head",
            "registry_key",
            "registry_key_pinned",
            "registry_key_trust",
        }
        assert cli_value["registry_key_trust"] == "explicit_pin"
        assert cli_value["problems"] == verified["problems"]

        with urlopen(origin + "/", timeout=5) as response:
            page = response.read().decode("utf-8")
            assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
        assert "Live problem index" in page
        assert "not yet an authenticated Conjectures attestation" in page
        assert 'src="app.js"' in page
        with urlopen(origin + "/app.js", timeout=5) as response:
            script = response.read().decode("utf-8")
        with urlopen(origin + "/styles.css", timeout=5) as response:
            styles = response.read().decode("utf-8")
        assert "raw.received_at" in script
        assert '"Observed by Boule"' in script
        assert ">Agents on record<" in page
        assert ">Active claims<" in page
        assert 'id="pulse-roster"' in page
        assert "function agentsOnRecord" in script
        assert "function signingIdentityGroups" in script
        assert '"same signer · "' in script
        assert 'return "Boule review pending"' in script
        assert "COLLAPSED_ROSTER_LIMIT = 2" in script
        assert 'toggle.setAttribute("aria-expanded"' in script
        assert '"Show fewer"' in script
        assert '"roster-toggle"' in script
        assert ".roster-agent[hidden]" in styles
        assert "COLLAPSED_TIMELINE_LIMIT = 4" in script
        assert '"timeline-toggle"' in script
        assert 'toggle.setAttribute("aria-controls", els.timelineList.id)' in script
        assert ".timeline li[hidden]" in styles
        assert "function renderClaims" in script
        assert "function fmtDeadline" in script
        assert '"claim-route"' in script
        assert "agent labels may be aliases or sessions" in script
        assert "No signed handoffs yet" in script
        assert "display-name groups derived" in script
        assert "innerHTML" not in script
        assert "Maintainer Running" in page
        assert "Open Boule on GitHub" in page
        assert "github.com/BouleProtocol/boule-protocol" in page
        assert "github.com/DaryxXx/boule-protocol" not in page
        assert '<body id="top">' in page
        assert 'class="brand" href="#top"' in page
        assert ">by conjectures.io</a>" in page
        assert "agent α · claim" in page
        assert "agent β · checkpoint" in page
        assert "agent γ resumes" in page
        assert "session α" not in page
        assert "MAINTAINER_URL" in script


def test_registry_api_reports_fresh_and_stale_maintainer_heartbeat(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    control = tmp_path / ".boule"
    control.mkdir()
    watcher = control / "watcher.json"
    watcher.write_text(
        json.dumps(
            {
                "pid": 99,
                "cycle": 12,
                "last_tick_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "interval_seconds": 30,
                "automatic_admission": True,
                "automatic_provisioning": False,
                "provider_sync_enabled": True,
                "provider_sync_observations": 3,
                "provider_sync_events": 2,
                "error_cases": [],
            }
        ),
        encoding="utf-8",
    )

    with running_registry(registry) as origin:
        status, value, headers = request(origin + "/v1/maintainer")
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        runtime = value["maintainer"]
        assert runtime["status"] == "running"
        assert runtime["basis"] == "unsigned_local_watcher_heartbeat"
        assert runtime["cycle"] == 12
        assert runtime["automatic_admission"] is True
        assert runtime["automatic_provisioning"] is False
        assert runtime["provider_sync_enabled"] is True
        assert runtime["provider_sync_observations"] == 3
        assert runtime["provider_sync_events"] == 2
        assert runtime["error_case_count"] == 0
        assert "pid" not in runtime

        watcher.write_text(
            json.dumps(
                {
                    "cycle": 13,
                    "last_tick_at": "2020-01-01T00:00:00Z",
                    "interval_seconds": 30,
                    "error_cases": ["case-one"],
                }
            ),
            encoding="utf-8",
        )
        status, value, _headers = request(origin + "/v1/maintainer")
        assert status == 200
        assert value["maintainer"]["status"] == "stale"
        assert value["maintainer"]["error_case_count"] == 1


def test_maintainer_heartbeat_bounds_untrusted_interval_and_exact_freshness(tmp_path) -> None:
    watcher = tmp_path / "watcher.json"
    heartbeat = {
        "cycle": 1,
        "last_tick_at": "2030-01-01T00:00:00Z",
        "interval_seconds": 30,
    }
    watcher.write_text(json.dumps(heartbeat), encoding="utf-8")
    boundary = datetime.fromisoformat("2030-01-01T00:01:30+00:00")
    assert maintainer_runtime_status(watcher, observed_at=boundary)["status"] == "running"
    after_boundary = datetime.fromisoformat("2030-01-01T00:01:31+00:00")
    assert maintainer_runtime_status(watcher, observed_at=after_boundary)["status"] == "stale"

    heartbeat["interval_seconds"] = 1e308
    heartbeat["provider_sync_enabled"] = "yes"
    heartbeat["provider_sync_observations"] = -1
    heartbeat["provider_sync_events"] = True
    watcher.write_text(json.dumps(heartbeat), encoding="utf-8")
    bounded = maintainer_runtime_status(watcher, observed_at=boundary)
    assert bounded["status"] == "running"
    assert bounded["fresh_for_seconds"] == 120
    assert bounded["provider_sync_enabled"] is None
    assert bounded["provider_sync_observations"] is None
    assert bounded["provider_sync_events"] is None

    watcher.write_bytes(b"{" + b" " * (64 * 1024) + b"}")
    assert maintainer_runtime_status(watcher, observed_at=boundary)["status"] == "unknown"


def test_registry_cli_persists_and_enforces_tofu_pin(tmp_path, capsys) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk)
    trust_store = tmp_path / "client" / "trust.json"
    with running_registry(registry) as origin:
        command = [
            "problems",
            "--server",
            origin,
            "--trust-store",
            str(trust_store),
            "--json",
        ]
        assert main(command) == 0
        first = json.loads(capsys.readouterr().out)
        assert first["registry_key_trust"] == "tofu_first_use"
        assert main(command) == 0
        second = json.loads(capsys.readouterr().out)
        assert second["registry_key_trust"] == "tofu_pinned"

        registry.record_proposal(problem())
        status, chain, _ = request(origin + "/v1/chain/1/2")
        assert status == 200
        assert set(chain) == {
            "schema",
            "clerk",
            "from_count",
            "from_head",
            "to_count",
            "to_head",
            "links",
            "signature",
        }
        assert set(chain["links"][0]) == {
            "seq",
            "prev_hash",
            "entry_hash",
            "clerk_signature",
        }
        assert "event" not in json.dumps(chain)
        assert main(command) == 0
        advanced = json.loads(capsys.readouterr().out)
        assert advanced["registry_key_trust"] == "tofu_advanced"
        assert advanced["registry_head"] == registry.head

        conflicting_store = tmp_path / "client" / "conflicting.json"
        trust_registry_snapshot(
            conflicting_store,
            origin,
            public_key_text(generate_private_key()),
            1,
            "a" * 64,
        )
        assert (
            main(
                [
                    "problems",
                    "--server",
                    origin,
                    "--trust-store",
                    str(conflicting_store),
                    "--json",
                ]
            )
            == 2
        )
        assert "registry key changed" in capsys.readouterr().err


def test_live_projection_returns_verified_case_and_stale_partial_failure(tmp_path) -> None:
    clerk = generate_private_key()
    registry = Registry.create(tmp_path / "registry.jsonl", clerk)
    _mark_live(registry, "case-live-001")
    _mark_live(registry, "case-live-002")

    def fetcher(record: dict[str, object]) -> dict[str, object]:
        if record["case_id"] == "case-live-002":
            raise ProtocolError("simulated clerk outage")
        return {
            "state": {
                "problem_status": "ACTIVE",
                "sessions": [
                    {
                        "participant_id": "agent-1",
                        "session_id": "session-1",
                        "controller_id": "shared-controller",
                        "controller_key": "controller-key-one",
                        "label": "Proof route",
                        "status": "active",
                    },
                    {
                        "participant_id": "agent-finished",
                        "session_id": "session-finished",
                        "controller_id": "finished-controller",
                        "controller_key": "controller-key-finished",
                        "label": "Completed route",
                        "status": "active",
                    },
                    {
                        "participant_id": "agent-finished",
                        "session_id": "session-finished-other",
                        "controller_id": "other-controller",
                        "controller_key": "controller-key-other",
                        "label": "Same display name, independent controller",
                        "status": "active",
                    },
                    {
                        "participant_id": "agent-stale",
                        "session_id": "session-stale",
                        "controller_id": "shared-controller",
                        "controller_key": "controller-key-stale",
                        "label": "Stale route",
                        "status": "active",
                    },
                ],
                "claims": [
                    {
                        "claim_id": "claim-1",
                        "session_id": "session-1",
                        "route": "route-1",
                        "status": "active",
                        "deadline": "2026-01-01T01:00:00Z",
                        "parallel": False,
                    },
                    {
                        "claim_id": "claim-stale",
                        "session_id": "session-stale",
                        "route": "route-stale",
                        "status": "stale",
                        "deadline": "2026-01-01T00:30:00Z",
                        "parallel": False,
                    },
                ],
                "checkpoints": [
                    {
                        "event_id": "checkpoint-1",
                        "participant_id": "agent-1",
                        "session_id": "session-1",
                        "summary": "verified local result",
                        "received_at": "2026-01-01T00:01:00Z",
                    }
                ],
                "handoffs": [
                    {
                        "handoff_id": "handoff-finished",
                        "participant_id": "agent-finished",
                        "session_id": "session-finished",
                        "outcome": "ADVANCE",
                        "status": "queued_for_review",
                        "summary": "completed evidence-linked route",
                        "received_at": "2026-01-01T00:01:30Z",
                    },
                    {
                        "handoff_id": "handoff-older",
                        "participant_id": "agent-1",
                        "session_id": "session-1",
                        "outcome": "NEGATIVE",
                        "status": "queued_for_review",
                        "summary": "older signed falsifier",
                        "received_at": "2025-12-31T23:59:00Z",
                    },
                    {
                        "handoff_id": "handoff-name-clash",
                        "participant_id": "agent-finished",
                        "session_id": "session-finished-other",
                        "outcome": "NO_SIGNAL",
                        "status": "queued_for_review",
                        "summary": "distinct controller using the same public display name",
                        "received_at": "2026-01-01T00:01:45Z",
                    },
                ],
                "feedback": [
                    {
                        "event_id": "00000002-feedback",
                        "stage": "review",
                        "summary": "needs one more lemma",
                        "received_at": "2026-01-01T00:02:00Z",
                    }
                ],
                "external_status_trust": {
                    "mode": "trusted_clerk_observation",
                    "authenticated_external_attestation": False,
                },
            },
            "snapshot": {
                "at": "2026-01-01T00:01:00Z",
                "head_event_hash": "f" * 64,
                "event_count": 3,
            },
        }

    projector = LiveProjector(fetcher=fetcher, ttl_seconds=0)
    with running_registry(registry, live_projector=projector) as origin:
        status, snapshot, _ = request(origin + "/v1/live")

    assert status == 200
    live = {item["case_id"]: item for item in snapshot["problems"]}
    assert live["case-live-001"]["status"] == "ACTIVE"
    assert live["case-live-001"]["live_stale"] is False
    assert live["case-live-001"]["active_agents"] == [
        {
            "participant_id": "agent-1",
            "controller_id": "shared-controller",
            "session_id": "session-1",
            "label": "Proof route",
            "status": "active",
        }
    ]
    assert live["case-live-001"]["agents_on_record"] == [
        {
            "participant_id": "agent-1",
            "identity_id": "controller-key-sha256:" + digest_bytes(b"controller-key-one"),
            "active": True,
            "work_status": "active",
            "session_count": 1,
            "handoff_count": 1,
            "latest_outcome": "NEGATIVE",
            "latest_handoff_id": "handoff-older",
            "latest_at": "2025-12-31T23:59:00Z",
            "review_status": "queued_for_review",
            "controller_ids": ["shared-controller"],
        },
        {
            "participant_id": "agent-finished",
            "identity_id": "controller-key-sha256:" + digest_bytes(b"controller-key-other"),
            "active": False,
            "work_status": None,
            "session_count": 1,
            "handoff_count": 1,
            "latest_outcome": "NO_SIGNAL",
            "latest_handoff_id": "handoff-name-clash",
            "latest_at": "2026-01-01T00:01:45Z",
            "review_status": "queued_for_review",
            "controller_ids": ["other-controller"],
        },
        {
            "participant_id": "agent-finished",
            "identity_id": "controller-key-sha256:" + digest_bytes(b"controller-key-finished"),
            "active": False,
            "work_status": None,
            "session_count": 1,
            "handoff_count": 1,
            "latest_outcome": "ADVANCE",
            "latest_handoff_id": "handoff-finished",
            "latest_at": "2026-01-01T00:01:30Z",
            "review_status": "queued_for_review",
            "controller_ids": ["finished-controller"],
        },
        {
            "participant_id": "agent-stale",
            "identity_id": "controller-key-sha256:" + digest_bytes(b"controller-key-stale"),
            "active": False,
            "work_status": "stale",
            "session_count": 1,
            "handoff_count": 0,
            "latest_outcome": None,
            "latest_handoff_id": None,
            "latest_at": None,
            "review_status": None,
            "controller_ids": ["shared-controller"],
        },
    ]
    assert live["case-live-001"]["recent_activity"][0]["summary"] == "needs one more lemma"
    assert live["case-live-001"]["recent_activity"][0]["kind"] == "review_feedback"
    assert live["case-live-001"]["external_status_trust"] == {
        "mode": "trusted_clerk_observation",
        "authenticated_external_attestation": False,
    }
    assert live["case-live-001"]["status_source"] == "case_clerk_projection"
    assert live["case-live-002"]["live_stale"] is True
    assert live["case-live-002"]["agents_on_record"] == []
    assert live["case-live-002"]["live_error"] == "case clerk unavailable or unverifiable"


def test_fetch_case_state_requires_signed_extension_from_registry_anchor(monkeypatch) -> None:
    clerk = generate_private_key()
    clerk_key = public_key_text(clerk)
    first_head = "a" * 64
    second_head = "b" * 64
    problem_id = "conjectures:anchored"
    state = {"problem_id": problem_id, "problem_status": "ACTIVE"}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    snapshot = build_snapshot(
        problem_id=problem_id,
        at=now,
        event_count=2,
        head_event_hash=second_head,
        state=state,
        clerk_private_key=clerk,
    )
    proof = build_chain_proof(
        problem_id=problem_id,
        from_count=1,
        start_head=first_head,
        events=[{"seq": 1, "prev_event_hash": first_head, "event_hash": second_head}],
        clerk_private_key=clerk,
    )
    payloads = {
        "https://clerk.example/v1/state": {"state": state, "snapshot": snapshot},
        "https://clerk.example/v1/chain/1/2": proof,
    }

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args):  # noqa: ANN002, ANN204
            return None

        def read(self, _maximum: int) -> bytes:
            return json.dumps(payloads[self.url]).encode()

        def geturl(self) -> str:
            return self.url

    monkeypatch.setattr(
        "boule.registry_api.urlopen", lambda request, timeout: Response(request.full_url)
    )
    record = {
        "clerk_url": "https://clerk.example",
        "problem_id": problem_id,
        "clerk_key": clerk_key,
        "event_count": 1,
        "head_event_hash": first_head,
    }
    assert fetch_case_state(record)["snapshot"]["head_event_hash"] == second_head

    forged = build_chain_proof(
        problem_id=problem_id,
        from_count=1,
        start_head="f" * 64,
        events=[{"seq": 1, "prev_event_hash": "f" * 64, "event_hash": second_head}],
        clerk_private_key=clerk,
    )
    payloads["https://clerk.example/v1/chain/1/2"] = forged
    with pytest.raises(ProtocolError, match="requested range"):
        fetch_case_state(record)


def test_fetch_case_state_accepts_more_than_4096_proven_events(monkeypatch) -> None:
    clerk = generate_private_key()
    clerk_key = public_key_text(clerk)
    problem_id = "conjectures:long-chain"
    events = [
        {
            "seq": index,
            "prev_event_hash": None if index == 0 else f"{index:064x}",
            "event_hash": f"{index + 1:064x}",
        }
        for index in range(4_097)
    ]
    state = {"problem_id": problem_id, "problem_status": "ACTIVE"}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    snapshot = build_snapshot(
        problem_id=problem_id,
        at=now,
        event_count=len(events),
        head_event_hash=events[-1]["event_hash"],
        state=state,
        clerk_private_key=clerk,
    )
    payloads = {"https://clerk.example/v1/state": {"state": state, "snapshot": snapshot}}
    for start in range(0, len(events), 256):
        finish = min(start + 256, len(events))
        payloads[f"https://clerk.example/v1/chain/{start}/{finish}"] = build_chain_proof(
            problem_id=problem_id,
            from_count=start,
            start_head=None if start == 0 else events[start - 1]["event_hash"],
            events=events[start:finish],
            clerk_private_key=clerk,
        )

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):  # noqa: ANN204
            return self

        def __exit__(self, *_args):  # noqa: ANN002, ANN204
            return None

        def read(self, _maximum: int) -> bytes:
            return json.dumps(payloads[self.url]).encode()

        def geturl(self) -> str:
            return self.url

    monkeypatch.setattr(
        "boule.registry_api.urlopen", lambda request, timeout: Response(request.full_url)
    )
    record = {
        "clerk_url": "https://clerk.example",
        "problem_id": problem_id,
        "clerk_key": clerk_key,
        "event_count": 0,
        "head_event_hash": None,
    }

    assert fetch_case_state(record, timeout=10)["snapshot"]["event_count"] == 4_097


def test_partial_case_chain_progress_survives_projector_restart(monkeypatch, tmp_path) -> None:
    clerk = generate_private_key()
    clerk_key = public_key_text(clerk)
    problem_id = "conjectures:checkpointed-chain"
    events = [
        {
            "seq": index,
            "prev_event_hash": None if index == 0 else f"{index:064x}",
            "event_hash": f"{index + 1:064x}",
        }
        for index in range(600)
    ]
    state = {"problem_id": problem_id, "problem_status": "ACTIVE"}
    snapshot = build_snapshot(
        problem_id=problem_id,
        at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        event_count=len(events),
        head_event_hash=events[-1]["event_hash"],
        state=state,
        clerk_private_key=clerk,
    )
    payloads = {"https://clerk.example/v1/state": {"state": state, "snapshot": snapshot}}
    for start in range(0, len(events), 256):
        finish = min(start + 256, len(events))
        payloads[f"https://clerk.example/v1/chain/{start}/{finish}"] = build_chain_proof(
            problem_id=problem_id,
            from_count=start,
            start_head=None if start == 0 else events[start - 1]["event_hash"],
            events=events[start:finish],
            clerk_private_key=clerk,
        )
    monkeypatch.setattr(
        "boule.registry_api._fetch_json",
        lambda endpoint, timeout, maximum: payloads[endpoint],
    )
    registry_record = {
        "case_id": "case-checkpointed-chain",
        "task_commitment": "sha256:" + "c" * 64,
        "clerk_url": "https://clerk.example",
        "problem_id": problem_id,
        "clerk_key": clerk_key,
        "event_count": 0,
        "head_event_hash": None,
    }
    store_path = tmp_path / "private" / "anchors.json"
    store = CaseAnchorStore(store_path)

    moments = iter((0.0, 0.0, 0.001, 0.02))
    monkeypatch.setattr("boule.registry_api.time.monotonic", lambda: next(moments))
    with pytest.raises(ProtocolError, match="timed out"):
        fetch_case_state(
            registry_record,
            timeout=0.01,
            checkpoint=lambda count, head: store.advance(registry_record, count, head),
        )
    assert CaseAnchorStore(store_path).anchor_for(registry_record) == (
        256,
        events[255]["event_hash"],
    )

    restart_record = dict(registry_record)
    restart_record["event_count"], restart_record["head_event_hash"] = CaseAnchorStore(
        store_path
    ).anchor_for(registry_record)
    moments = iter((0.0, 0.0, 0.001, 0.002))
    assert (
        fetch_case_state(
            restart_record,
            timeout=0.01,
            checkpoint=lambda count, head: CaseAnchorStore(store_path).advance(
                registry_record, count, head
            ),
        )["snapshot"]["event_count"]
        == 600
    )
    assert CaseAnchorStore(store_path).anchor_for(registry_record) == (
        600,
        events[-1]["event_hash"],
    )


def test_live_projector_reuses_verified_high_water_anchor(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    _mark_live(registry, "case-live-001")
    observed_anchors: list[tuple[int, str | None]] = []
    advanced_head = "f" * 64

    def fetcher(record: dict[str, object]) -> dict[str, object]:
        observed_anchors.append((record["event_count"], record["head_event_hash"]))
        return {
            "state": {"problem_status": "ACTIVE"},
            "snapshot": {
                "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "head_event_hash": advanced_head,
                "event_count": 5_000,
            },
        }

    projector = LiveProjector(fetcher=fetcher, ttl_seconds=0)
    projector.problems(registry)
    projector.problems(registry)

    assert observed_anchors == [(2, "e" * 64), (5_000, advanced_head)]
    projector.close()


def test_live_projector_clears_refresh_flag_after_preparation_failure(
    tmp_path, monkeypatch
) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    projector = LiveProjector(ttl_seconds=0)
    original = registry.problems
    calls = 0

    def flaky_problems(*, live_only: bool = False):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ProtocolError("simulated replay failure")
        return original(live_only=live_only)

    monkeypatch.setattr(registry, "problems", flaky_problems)
    with pytest.raises(ProtocolError, match="simulated replay failure"):
        projector.problems(registry)
    assert projector.problems(registry) == []
    projector.close()


def test_live_projector_does_not_queue_refreshes_behind_a_stuck_fetch(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    _mark_live(registry, "case-live-001")
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    def fetcher(record: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        started.set()
        try:
            assert release.wait(timeout=5)
            return {
                "state": {"problem_status": "ACTIVE"},
                "snapshot": {
                    "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "head_event_hash": record["head_event_hash"],
                    "event_count": record["event_count"],
                },
            }
        finally:
            finished.set()

    projector = LiveProjector(
        fetcher=fetcher,
        ttl_seconds=0,
        max_workers=1,
        refresh_timeout=0.01,
    )
    first = projector.problems(registry)
    assert first[0]["live_error"] == "case clerk projection timed out"
    assert started.wait(timeout=1)
    for _attempt in range(5):
        current = projector.problems(registry)
        assert current[0]["live_error"] == "case clerk projection capacity is exhausted"
    assert calls == 1
    assert projector._executor._work_queue.qsize() == 0  # noqa: SLF001
    release.set()
    assert finished.wait(timeout=1)
    projector.close()


def test_live_projector_schedules_all_cases_with_bounded_in_flight_work(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    case_ids = [f"case-live-00{index}" for index in range(1, 10)]
    for case_id in case_ids:
        _mark_live(registry, case_id)
    fetched: list[str] = []

    def fetcher(record: dict[str, object]) -> dict[str, object]:
        fetched.append(str(record["case_id"]))
        return {
            "state": {"problem_status": "ACTIVE"},
            "snapshot": {
                "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "head_event_hash": record["head_event_hash"],
                "event_count": record["event_count"],
            },
        }

    projector = LiveProjector(
        fetcher=fetcher,
        ttl_seconds=0,
        max_workers=2,
        refresh_timeout=2,
    )
    projected = projector.problems(registry)
    assert {item["case_id"] for item in projected} == set(case_ids)
    assert set(fetched) == set(case_ids)
    assert all(item["live_stale"] is False for item in projected)
    projector.close()


def test_live_response_retries_if_registry_changes_during_projection(tmp_path) -> None:
    registry = Registry.create(tmp_path / "registry.jsonl", generate_private_key())
    _mark_live(registry, "case-live-001")
    first_fetch_started = threading.Event()
    allow_first_fetch = threading.Event()
    calls = 0

    def fetcher(record: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            first_fetch_started.set()
            assert allow_first_fetch.wait(timeout=5)
        return {
            "state": {"problem_status": "ACTIVE"},
            "snapshot": {
                "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "head_event_hash": record["head_event_hash"],
                "event_count": record["event_count"],
            },
        }

    projector = LiveProjector(fetcher=fetcher, ttl_seconds=60)
    response: list[tuple[int, dict[str, object], object]] = []
    with running_registry(registry, live_projector=projector) as origin:
        thread = threading.Thread(target=lambda: response.append(request(origin + "/v1/live")))
        thread.start()
        assert first_fetch_started.wait(timeout=5)
        _mark_live(registry, "case-live-002")
        allow_first_fetch.set()
        thread.join(timeout=10)
        assert not thread.is_alive()

    status, snapshot, _headers = response[0]
    assert status == 200
    verify_registry_snapshot(snapshot, clerk_key=registry.clerk_key)
    assert snapshot["head"] == registry.head
    assert {item["case_id"] for item in snapshot["problems"]} == {
        "case-live-001",
        "case-live-002",
    }
