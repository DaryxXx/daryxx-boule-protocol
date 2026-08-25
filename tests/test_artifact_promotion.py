from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from boule.artifact_promotion import _load_capture, promote_run_artifacts
from boule.crypto import generate_private_key, public_key_text
from boule.errors import ProtocolError
from boule.policy import build_case_policy
from boule.run_store import RunStore
from boule.workspace import Workspace

RUN_ID = "run-20260101T000000-a1b2c3d4"
SESSION_ID = "s-test-session"
HANDOFF_ID = "h-test-handoff"
REPOSITORY_URL = "https://github.com/BouleProtocol/test-case.git"


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _fixture(
    tmp_path: Path,
    artifact_name: str = "proof.txt",
    content: bytes = b"proof\n",
    disclosure: str = "public",
):
    root = tmp_path / "case"
    root.mkdir(parents=True)
    (root / "problem.json").write_text(
        json.dumps(
            {
                "schema": "boule-problem/0.1",
                "problem_id": "p-promotion",
                "task": {
                    "task_id": "task-promotion",
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
            "maintainer_key": public_key_text(generate_private_key()),
            "lease_seconds": 3600,
            "absolute_lease_seconds": 7200,
            "stale_seconds": 900,
            "max_renewals": 2,
        },
        policy=build_case_policy(
            json.loads((root / "problem.json").read_text(encoding="utf-8")), disclosure
        ),
    )
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Test Maintainer")
    _git(root, "config", "user.email", "maintainer@example.invalid")
    _git(
        root,
        "add",
        "-f",
        "problem.json",
        ".boule/config.json",
        ".boule/policy.json",
    )
    _git(root, "commit", "-m", "pinned case")
    base_commit = _git(root, "rev-parse", "HEAD")
    _git(root, "remote", "add", "origin", REPOSITORY_URL)

    artifact = root / artifact_name
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(content)
    digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    handoff = {
        "event_id": "event-handoff",
        "session_id": SESSION_ID,
        "handoff_id": HANDOFF_ID,
        "outcome": "ADVANCE",
        "provenance": "original",
        "depends_on": [],
        "evidence": [{"ref": artifact_name, "sha256": digest}],
    }
    run_root = tmp_path / "runs"
    store = RunStore(run_root)
    store.create(
        RUN_ID,
        {
            "schema": "boule-agent-run/0.1",
            "workspace": str(root),
            "server": "https://clerk.example",
            "session_id": SESSION_ID,
            "agent_name": "Daryxx1",
            "problem_id": "p-promotion",
            "task_id": "task-promotion",
            "repository_url": REPOSITORY_URL,
            "repository_commit": base_commit,
        },
        {
            "state": "completed",
            "protocol": {
                "complete": True,
                "handoff": {"handoff_id": HANDOFF_ID},
            },
        },
    )
    return workspace, store, handoff, artifact, base_commit


def _state(handoff: dict) -> dict:
    return {"handoffs": [handoff]}


def test_promotion_retains_exact_bytes_and_prepares_only_an_isolated_local_branch(
    tmp_path,
) -> None:
    workspace, store, handoff, _artifact, base_commit = _fixture(tmp_path)
    unrelated = workspace.root / "private-notes.txt"
    unrelated.write_text("not declared evidence\n", encoding="utf-8")

    preview = promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    assert preview["status"] == "review_required"
    assert preview["published"] is False
    assert preview["artifact_count"] == 1
    assert _git(workspace.root, "rev-parse", "HEAD") == base_commit
    assert (
        store.directory(RUN_ID) / "evidence" / HANDOFF_ID / "files" / "proof.txt"
    ).read_bytes() == b"proof\n"
    assert (
        stat_mode(store.directory(RUN_ID) / "evidence" / HANDOFF_ID / "files" / "proof.txt")
        == 0o600
    )

    result = promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        confirm=True,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    assert result["status"] == "prepared_for_human_push"
    assert result["published"] is False
    assert result["branch"] == f"boule/handoff/{HANDOFF_ID}"
    assert "push_command" not in result
    assert result["publication"] == {
        "source_repository": str(workspace.root),
        "target_repository_url": REPOSITORY_URL,
        "branch": f"boule/handoff/{HANDOFF_ID}",
        "commit": result["commit"],
        "requires_separate_maintainer_checkout": True,
    }
    assert _git(workspace.root, "rev-parse", "HEAD") == base_commit
    assert _git(workspace.root, "show", "-s", "--format=%an <%ae>", result["commit"]) == (
        "Test Maintainer <maintainer@example.invalid>"
    )
    assert (
        _git(
            workspace.root,
            "show",
            f"{result['commit']}:artifacts/boule/{HANDOFF_ID}/proof.txt",
        )
        + "\n"
    ).encode() == b"proof\n"
    changed = set(
        _git(
            workspace.root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            result["commit"],
        ).splitlines()
    )
    assert changed == {
        f"artifacts/boule/{HANDOFF_ID}/manifest.json",
        f"artifacts/boule/{HANDOFF_ID}/proof.txt",
    }
    assert "private-notes.txt" not in changed

    repeated = promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        confirm=True,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    assert repeated["idempotent"] is True
    assert repeated["commit"] == result["commit"]


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


def test_promotion_rejects_a_run_without_a_completed_signed_handoff(tmp_path) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path)
    store.update(RUN_ID, protocol={"complete": False, "handoff": None})
    with pytest.raises(ProtocolError, match="closed with a signed handoff"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


def test_capture_rejects_changed_or_symlinked_signed_artifacts(tmp_path) -> None:
    _workspace, store, handoff, artifact, _base_commit = _fixture(tmp_path / "changed")
    artifact.write_text("changed after handoff\n", encoding="utf-8")
    with pytest.raises(ProtocolError, match="signed digest"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )

    workspace, store, handoff, artifact, _base_commit = _fixture(tmp_path / "symlink")
    target = workspace.root / "target.txt"
    artifact.rename(target)
    artifact.symlink_to(target.name)
    with pytest.raises(ProtocolError, match="symlink"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


def test_promotion_refuses_credential_shaped_artifact_bytes(tmp_path) -> None:
    token = "sk" + "-" + "fixturevalue123456789"
    _workspace, store, handoff, _artifact, _base_commit = _fixture(
        tmp_path,
        content=f"OPENAI_API_KEY={token}\n".encode(),
    )
    with pytest.raises(ProtocolError, match="credential-shaped text"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


@pytest.mark.parametrize("disclosure", ["commitment_only", "committee"])
def test_non_public_policy_can_retain_but_not_prepare_a_git_release(tmp_path, disclosure) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path, disclosure=disclosure)
    preview = promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    assert preview["status"] == "review_required"
    assert preview["disclosure"] == disclosure
    assert preview["published"] is False

    with pytest.raises(ProtocolError, match="does not authorize a Git artifact release"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            confirm=True,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


@pytest.mark.parametrize(
    "artifact_name",
    [".netrc", "credentials.json", ".ssh/config", ".kube/config", ".azure/profile.json"],
)
def test_promotion_refuses_common_credential_paths(tmp_path, artifact_name) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(
        tmp_path,
        artifact_name=artifact_name,
        content=b"fixture without a credential value\n",
    )
    with pytest.raises(ProtocolError, match="credential-shaped artifact paths"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


def test_promotion_revalidates_the_private_snapshot_before_commit(tmp_path) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path)
    promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    retained = store.directory(RUN_ID) / "evidence" / HANDOFF_ID / "files" / "proof.txt"
    retained.write_bytes(b"changed private snapshot\n")
    with pytest.raises(ProtocolError, match="signed digest"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            confirm=True,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


def test_promotion_binds_private_manifest_paths_to_signed_handoff(tmp_path) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path)
    promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    capture_root = store.directory(RUN_ID) / "evidence" / HANDOFF_ID
    injected = capture_root / "files" / "injected.txt"
    injected.write_bytes(b"unsigned material\n")
    digest = f"sha256:{hashlib.sha256(injected.read_bytes()).hexdigest()}"
    manifest_path = capture_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0].update(
        {
            "source_ref": "injected.txt",
            "snapshot_ref": "files/injected.txt",
            "sha256": digest,
            "bytes": len(injected.read_bytes()),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    os.chmod(manifest_path, 0o600)
    with pytest.raises(ProtocolError, match="differs from the signed handoff"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            confirm=True,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )


def test_promotion_rejects_a_redirected_private_manifest_path(tmp_path) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path)
    promote_run_artifacts(
        RUN_ID,
        run_root=store.root,
        state_fetcher=lambda _workspace, _server: _state(handoff),
    )
    outside = store.directory(RUN_ID) / "unrelated.json"
    outside.write_text('{"schema":"boule-run-evidence/0.1"}', encoding="utf-8")
    os.chmod(outside, 0o600)
    status = store.status(RUN_ID)
    redirected = {**status["artifact_capture"], "manifest": "unrelated.json"}

    with pytest.raises(ProtocolError, match="has no manifest"):
        _load_capture(store, RUN_ID, redirected)


def test_promotion_requires_the_clerk_handoff_from_the_exact_session(tmp_path) -> None:
    _workspace, store, handoff, _artifact, _base_commit = _fixture(tmp_path)
    handoff["session_id"] = "s-other-session"
    with pytest.raises(ProtocolError, match="no matching signed clerk handoff"):
        promote_run_artifacts(
            RUN_ID,
            run_root=store.root,
            state_fetcher=lambda _workspace, _server: _state(handoff),
        )
