from __future__ import annotations

import json

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
