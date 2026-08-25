from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ENV_KEYS = {
    "BOULE_GITHUB_APP_ID",
    "BOULE_GITHUB_APP_KEY_HOST_PATH",
    "BOULE_GITHUB_INSTALLATION_ID",
    "BOULE_GITHUB_ORG",
}
PRIVATE_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"}
PRIVATE_ROOTS = {"boule-data", "demo-output", "knowledge", "problems", "secrets"}


def test_env_example_contains_configuration_not_secret_material() -> None:
    settings: dict[str, str] = {}
    for raw_line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        assert separator, key
        assert key not in settings, key
        settings[key] = value

    assert settings.keys() == EXPECTED_ENV_KEYS
    assert settings["BOULE_GITHUB_ORG"] == ""
    assert settings["BOULE_GITHUB_APP_ID"] == ""
    assert settings["BOULE_GITHUB_INSTALLATION_ID"] == ""
    assert settings["BOULE_GITHUB_APP_KEY_HOST_PATH"].startswith("/")


def test_automatic_github_actions_require_the_explicit_overlay() -> None:
    credentials = (ROOT / "compose.github.yml").read_text(encoding="utf-8")
    automation = (ROOT / "compose.github-auto.yml").read_text(encoding="utf-8")
    for flag in ("--auto-admit", "--auto-provision"):
        assert flag not in credentials
        assert flag in automation
    for setting in EXPECTED_ENV_KEYS:
        assert setting in automation


def test_git_does_not_track_private_runtime_or_credential_files() -> None:
    if not (ROOT / ".git").is_dir():
        pytest.skip("Git metadata is unavailable in this source distribution")
    tracked = (
        subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .split("\0")
    )
    tracked = [Path(name) for name in tracked if name]

    env_files = sorted(path.as_posix() for path in tracked if path.name.startswith(".env"))
    assert env_files == [".env.example"]
    assert not [path for path in tracked if path.suffix.lower() in PRIVATE_SUFFIXES]
    assert not [path for path in tracked if path.parts and path.parts[0] in PRIVATE_ROOTS]


def test_deployment_preflight_is_executable() -> None:
    preflight = ROOT / "deploy" / "preflight.sh"
    assert preflight.is_file()
    assert preflight.stat().st_mode & 0o111
