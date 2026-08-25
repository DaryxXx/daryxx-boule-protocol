from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from boule.canonical import canonical_bytes
from boule.errors import ProtocolError
from boule.repository_migration import (
    inspect_github_repository,
    validate_ref_manifest,
)


def _bare_repository(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    remote = tmp_path / "source.git"
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(work)],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(work), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (work / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(work), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(work), "commit", "-m", "fixture"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "clone", "--mirror", str(work), str(remote)],
        check=True,
        capture_output=True,
    )
    return remote


def _metadata(name: str) -> dict[str, object]:
    return {
        "id": 202,
        "node_id": "R_kgDOBoule202",
        "name": name,
        "full_name": f"BouleProtocol/{name}",
        "owner": {"login": "BouleProtocol"},
        "private": True,
        "default_branch": "main",
        "html_url": f"https://github.com/BouleProtocol/{name}",
        "ssh_url": f"git@github.com:BouleProtocol/{name}.git",
    }


def test_lookup_only_github_inspector_derives_identity_and_clones(
    tmp_path: Path, monkeypatch
) -> None:
    source = _bare_repository(tmp_path)
    name = "boule-case-example-aaaaaaaaaaaa"
    observed: list[list[str]] = []

    def run(args: list[str], *, cwd=None) -> bytes:  # noqa: ANN001
        observed.append(args)
        if args == ["gh", "api", "--hostname", "github.com", "user"]:
            return canonical_bytes({"login": "DaryxXx"})
        if args == [
            "gh",
            "api",
            "--hostname",
            "github.com",
            f"repos/BouleProtocol/{name}",
        ]:
            return canonical_bytes(_metadata(name))
        if args[:3] == ["git", "clone", "--mirror"]:
            destination = Path(args[-1])
            subprocess.run(
                ["git", "clone", "--mirror", str(source), str(destination)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(destination),
                    "remote",
                    "set-url",
                    "origin",
                    f"git@github.com:BouleProtocol/{name}.git",
                ],
                check=True,
            )
            return b""
        raise AssertionError(args)

    monkeypatch.setattr("boule.repository_migration._run", run)
    with inspect_github_repository(
        "BouleProtocol", name, expected_account="DaryxXx", private=True
    ) as inspection:
        assert inspection.repository.repository_id == 202
        assert inspection.repository.repository_node_id == "R_kgDOBoule202"
        assert inspection.repository.local_path is not None
        assert inspection.repository.local_path.is_dir()
        inspection.revalidate()
    assert not any(command[:3] == ["gh", "api", "--method"] for command in observed)
    assert (
        sum(command[-1] == f"repos/BouleProtocol/{name}" for command in observed) == 2
    )


def test_github_inspector_rejects_wrong_boundary_without_cloning(monkeypatch) -> None:
    name = "boule-case-example-aaaaaaaaaaaa"
    observed: list[list[str]] = []

    def run(args: list[str], *, cwd=None) -> bytes:  # noqa: ANN001
        observed.append(args)
        if args == ["gh", "api", "--hostname", "github.com", "user"]:
            return canonical_bytes({"login": "DaryxXx"})
        payload = _metadata(name)
        payload["private"] = False
        return canonical_bytes(payload)

    monkeypatch.setattr("boule.repository_migration._run", run)
    with pytest.raises(ProtocolError, match="migration boundary"):
        with inspect_github_repository(
            "BouleProtocol", name, expected_account="DaryxXx", private=True
        ):
            pass
    assert not any(command[:3] == ["git", "clone", "--mirror"] for command in observed)


@pytest.mark.parametrize(
    "bad_ref",
    [
        "refs/pull/1/head",
        "refs/heads/a..b",
        "refs/heads/a lock",
        "refs/heads/x.lock",
        "refs/heads/x.lock/work",
        "refs/heads/.hidden",
        "refs/heads/método",
    ],
)
def test_ref_manifest_rejects_noncanonical_or_unmigratable_refs(bad_ref: str) -> None:
    with pytest.raises(ProtocolError, match="manifest entry"):
        validate_ref_manifest(
            {
                "schema": "boule-git-ref-manifest/0.1",
                "refs": [
                    {"name": bad_ref, "object_id": "a" * 40},
                    {"name": "refs/heads/main", "object_id": "a" * 40},
                ],
            }
        )
