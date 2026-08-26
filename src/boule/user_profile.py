"""Private first-use profile for a contributor's default public agent name."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .canonical import canonical_bytes
from .errors import ProtocolError
from .remote_protocol import strict_json_bytes

PROFILE_SCHEMA = "boule-user-profile/0.1"
AGENT_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})\Z")
MAX_PROFILE_BYTES = 16 * 1024


@dataclass(frozen=True)
class ResolvedAgentName:
    value: str
    source: str
    profile_created: bool = False


def validate_agent_name(value: str) -> str:
    if not isinstance(value, str) or AGENT_NAME.fullmatch(value) is None:
        raise ProtocolError("agent name must be 1-64 safe identifier characters")
    return value


def default_profile_path() -> Path:
    override = os.environ.get("BOULE_PROFILE")
    if override:
        return Path(override).expanduser()
    config = os.environ.get("XDG_CONFIG_HOME")
    root = Path(config).expanduser() if config else Path.home() / ".config"
    return root / "boule" / "profile.json"


def _validate_private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProtocolError(f"cannot inspect Boule profile: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ProtocolError("Boule profile must be a regular file, not a link")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProtocolError("Boule profile permissions must be 0600")
    if metadata.st_size > MAX_PROFILE_BYTES:
        raise ProtocolError("Boule profile exceeds the size limit")


def load_profile(path: str | Path | None = None) -> dict[str, str] | None:
    selected = Path(path) if path is not None else default_profile_path()
    if selected.is_symlink():
        raise ProtocolError("Boule profile must be a regular file, not a link")
    if not selected.exists():
        return None
    _validate_private_file(selected)
    try:
        value = strict_json_bytes(selected.read_bytes())
    except (OSError, ProtocolError) as exc:
        raise ProtocolError(f"cannot load Boule profile: {selected}") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "agent_name", "created_at"}:
        raise ProtocolError("Boule profile has invalid fields")
    if value["schema"] != PROFILE_SCHEMA:
        raise ProtocolError("Boule profile has an unsupported schema")
    validate_agent_name(value["agent_name"])
    if not isinstance(value["created_at"], str) or not value["created_at"].endswith("Z"):
        raise ProtocolError("Boule profile has an invalid creation time")
    try:
        datetime.fromisoformat(value["created_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("Boule profile has an invalid creation time") from exc
    return value


def save_profile(
    agent_name: str,
    *,
    path: str | Path | None = None,
    replace: bool = False,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, str]:
    selected = Path(path) if path is not None else default_profile_path()
    validate_agent_name(agent_name)
    if selected.is_symlink() or selected.parent.is_symlink():
        raise ProtocolError("Boule profile path must not use a symbolic link")
    parent_existed = selected.parent.exists()
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if selected.parent.is_symlink() or not selected.parent.is_dir():
        raise ProtocolError("Boule profile directory must be a private directory")
    if not parent_existed:
        selected.parent.chmod(0o700)
    elif stat.S_IMODE(selected.parent.stat().st_mode) & 0o077:
        raise ProtocolError("Boule profile directory permissions must be 0700")
    if selected.exists() and not replace:
        raise ProtocolError("Boule profile already exists; pass --replace to change its name")
    if selected.exists():
        _validate_private_file(selected)
    profile = {
        "schema": PROFILE_SCHEMA,
        "agent_name": agent_name,
        "created_at": now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    descriptor, temporary = tempfile.mkstemp(prefix=f".{selected.name}.", dir=selected.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(profile) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, selected)
        else:
            try:
                os.link(temporary, selected)
            except FileExistsError as exc:
                raise ProtocolError("Boule profile was created concurrently") from exc
        os.chmod(selected, 0o600)
        directory = os.open(selected.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return profile


def resolve_agent_name(
    explicit: str | None,
    *,
    interactive: bool,
    path: str | Path | None = None,
    prompt: Callable[[str], str] = input,
) -> ResolvedAgentName:
    profile = load_profile(path)
    if explicit is not None:
        value = validate_agent_name(explicit)
        if profile is None:
            save_profile(value, path=path)
            return ResolvedAgentName(value, "explicit", True)
        return ResolvedAgentName(value, "explicit")
    if profile is not None:
        return ResolvedAgentName(profile["agent_name"], "profile")
    if not interactive:
        raise ProtocolError(
            "no default agent name is configured; run `boule setup --name YOUR_NAME`"
        )
    try:
        value = prompt("Choose your public Boule agent name: ").strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise ProtocolError("Boule setup was cancelled") from exc
    value = validate_agent_name(value)
    save_profile(value, path=path)
    return ResolvedAgentName(value, "interactive_setup", True)
