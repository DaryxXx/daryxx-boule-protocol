from __future__ import annotations

import json
from datetime import datetime

import pytest

from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.session_store import SessionStore
from boule.workspace import Workspace


def workspace(tmp_path):
    root = tmp_path / "problem"
    root.mkdir()
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "conjectures:task-1",
                "task": {
                    "task_id": "task-1",
                    "task_commitment": "sha256:" + "a" * 64,
                    "formal_repository_pin": "b" * 40,
                },
            }
        ),
        encoding="utf-8",
    )
    maintainer = generate_private_key()
    return Workspace.initialize(
        root,
        {
            "maintainer_key": public_key_text(maintainer),
            "lease_seconds": 120,
            "absolute_lease_seconds": 600,
            "stale_seconds": 60,
            "max_renewals": 2,
        },
        clock=lambda: datetime.fromisoformat("2030-01-01T00:00:00+00:00"),
    )


def test_start_and_load_session_without_exposing_private_bytes(tmp_path):
    work = workspace(tmp_path)
    store = SessionStore(work)
    profile = store.start(
        participant_id="agent-a",
        controller_id="shared-daryxx",
        label="Codex A",
        not_after="2030-01-02T00:00:00Z",
    )

    loaded, key = store.load(profile["session_id"])
    assert loaded["controller_id"] == "shared-daryxx"
    assert loaded["policy_digest"] == work.config["policy_digest"]
    assert public_key_text(key) == loaded["session_key"]
    assert "PRIVATE KEY" not in json.dumps(profile)
    assert (store.sessions / f"{profile['session_id']}.pem").stat().st_mode & 0o777 == 0o600
    assert work.state("2030-01-01T00:00:01Z")["sessions"][0]["label"] == "Codex A"


def test_profile_and_key_mismatch_fail_closed(tmp_path):
    work = workspace(tmp_path)
    store = SessionStore(work)
    profile = store.start(
        participant_id="agent-a",
        controller_id="owner",
        label=None,
        not_after="2030-01-02T00:00:00Z",
    )
    path = store.profiles / f"{profile['session_id']}.json"
    value = json.loads(path.read_text())
    value["problem_id"] = "another"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ProtocolError, match="another problem"):
        store.load(profile["session_id"])


def test_external_append_interruption_preserves_session_material_for_recovery(tmp_path):
    work = workspace(tmp_path)
    store = SessionStore(work)

    def interrupted(*_args):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        store.start(
            participant_id="agent-a",
            controller_id="owner",
            label="remote",
            not_after="2030-01-02T00:00:00Z",
            appender=interrupted,
        )

    assert len(list(store.sessions.glob("*.pem"))) == 1
    assert len(list(store.profiles.glob("*.json"))) == 1


def test_delegated_controller_key_can_remain_outside_the_case_checkout(tmp_path):
    work = workspace(tmp_path)
    store = SessionStore(work)
    controller_key = generate_private_key()
    profile = store.start(
        participant_id="agent-a",
        controller_id="shared-controller",
        label="supervised",
        not_after="2030-01-02T00:00:00Z",
        appender=lambda *_args: None,
        controller_key=controller_key,
        persist_controller_key=False,
    )

    assert profile["controller_key"] == public_key_text(controller_key)
    assert not list(store.controllers.glob("*.pem"))


def test_delegated_controller_must_match_an_existing_local_controller(tmp_path):
    work = workspace(tmp_path)
    store = SessionStore(work)
    store.start(
        participant_id="agent-a",
        controller_id="owner",
        label=None,
        not_after="2030-01-02T00:00:00Z",
    )

    with pytest.raises(ProtocolError, match="differs from the local controller"):
        store.start(
            participant_id="agent-b",
            controller_id="owner",
            label=None,
            not_after="2030-01-02T00:00:00Z",
            controller_key=generate_private_key(),
            persist_controller_key=False,
        )
