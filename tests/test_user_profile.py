from __future__ import annotations

import json
import stat
from datetime import UTC, datetime

import pytest

from boule.cli import build_parser, main
from boule.errors import ProtocolError
from boule.user_profile import load_profile, resolve_agent_name, save_profile


def test_private_profile_is_created_once_and_reused(tmp_path) -> None:
    path = tmp_path / "config" / "boule" / "profile.json"
    created = save_profile(
        "Daryxx1",
        path=path,
        now=lambda: datetime(2026, 8, 26, 10, 0, tzinfo=UTC),
    )

    assert created == {
        "schema": "boule-user-profile/0.1",
        "agent_name": "Daryxx1",
        "created_at": "2026-08-26T10:00:00Z",
    }
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_profile(path) == created
    assert resolve_agent_name(None, interactive=False, path=path).value == "Daryxx1"

    override = resolve_agent_name("Daryxx2", interactive=False, path=path)
    assert override.value == "Daryxx2"
    assert load_profile(path)["agent_name"] == "Daryxx1"
    with pytest.raises(ProtocolError, match="already exists"):
        save_profile("Daryxx3", path=path)


def test_first_explicit_name_bootstraps_profile_and_noninteractive_missing_fails(tmp_path) -> None:
    path = tmp_path / "profile.json"
    resolved = resolve_agent_name("Daryxx3", interactive=False, path=path)
    assert resolved.profile_created is True
    assert resolved.source == "explicit"
    assert load_profile(path)["agent_name"] == "Daryxx3"

    with pytest.raises(ProtocolError, match="boule setup"):
        resolve_agent_name(None, interactive=False, path=tmp_path / "missing.json")


def test_profile_rejects_public_permissions_and_symlinks(tmp_path) -> None:
    path = tmp_path / "profile.json"
    save_profile("Agent1", path=path)
    path.chmod(0o644)
    with pytest.raises(ProtocolError, match="0600"):
        load_profile(path)

    target = tmp_path / "target.json"
    save_profile("Agent2", path=target)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ProtocolError, match="regular file"):
        load_profile(link)


def test_setup_command_and_runner_name_are_frictionless(monkeypatch, tmp_path, capsys) -> None:
    profile_path = tmp_path / "private" / "profile.json"
    monkeypatch.setenv("BOULE_PROFILE", str(profile_path))

    assert main(["setup", "--name", "Researcher1", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["agent_name"] == "Researcher1"
    assert result["changed"] is True

    parser = build_parser()
    args = parser.parse_args(["codex", "auto"])
    assert args.agent_name is None
    assert resolve_agent_name(None, interactive=False).value == "Researcher1"

    assert main(["setup", "--name", "Researcher2", "--replace", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["agent_name"] == "Researcher2"
