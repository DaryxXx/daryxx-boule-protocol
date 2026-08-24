"""Local private-key profiles for Boule participant and maintainer commands."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest_object
from .crypto import (
    generate_private_key,
    load_private_key,
    public_key_text,
    write_private_key,
)
from .errors import ProtocolError
from .workspace import Workspace

IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})\Z")
PROFILE_SCHEMA = "boule-session-profile/0.1"


def _identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be 1-64 safe identifier characters")
    return value


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ProtocolError(f"private profile already exists: {path}") from exc


class SessionStore:
    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.root = workspace.control / "private"
        self.controllers = self.root / "controllers"
        self.sessions = self.root / "sessions"
        self.profiles = self.root / "profiles"
        for path in (self.root, self.controllers, self.sessions, self.profiles):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)

    def _controller_path(self, controller_id: str) -> Path:
        suffix = digest_object({"controller_id": controller_id})[:20]
        return self.controllers / f"controller-{suffix}.pem"

    def start(
        self,
        *,
        participant_id: str,
        controller_id: str,
        label: str | None,
        not_after: str,
    ) -> dict[str, Any]:
        participant_id = _identifier(participant_id, "participant")
        controller_id = _identifier(controller_id, "controller")
        if label is not None and (not label.strip() or len(label) > 120):
            raise ProtocolError("label must be non-empty text up to 120 characters")
        controller_path = self._controller_path(controller_id)
        if controller_path.exists():
            controller_key = load_private_key(controller_path)
        else:
            controller_key = generate_private_key()
            try:
                write_private_key(controller_path, controller_key)
            except ProtocolError:
                if not controller_path.exists():
                    raise
                controller_key = load_private_key(controller_path)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        session_id = f"s-{stamp}-{secrets.token_hex(5)}"
        session_key = generate_private_key()
        session_path = self.sessions / f"{session_id}.pem"
        profile_path = self.profiles / f"{session_id}.json"
        write_private_key(session_path, session_key)
        profile = {
            "schema": PROFILE_SCHEMA,
            "problem_id": self.workspace.problem["problem_id"],
            "participant_id": participant_id,
            "controller_id": controller_id,
            "controller_key": public_key_text(controller_key),
            "session_id": session_id,
            "session_key": public_key_text(session_key),
            "not_after": not_after,
            "label": label,
            "policy_digest": self.workspace.config["policy_digest"],
        }
        try:
            _write_private_json(profile_path, profile)
            payload = {
                key: value
                for key, value in profile.items()
                if key != "schema" and not (key == "label" and value is None)
            }
            self.workspace.append("session_started", payload, controller_key)
        except BaseException:
            profile_path.unlink(missing_ok=True)
            session_path.unlink(missing_ok=True)
            raise
        return {**profile, "profile_path": str(profile_path)}

    def load(self, session_id: str) -> tuple[dict[str, Any], Any]:
        session_id = _identifier(session_id, "session")
        profile_path = self.profiles / f"{session_id}.json"
        key_path = self.sessions / f"{session_id}.pem"
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"cannot load local session profile: {session_id}") from exc
        required = {
            "schema",
            "problem_id",
            "participant_id",
            "controller_id",
            "controller_key",
            "session_id",
            "session_key",
            "not_after",
            "label",
            "policy_digest",
        }
        if not isinstance(profile, dict) or set(profile) != required:
            raise ProtocolError("local session profile has invalid fields")
        if profile["schema"] != PROFILE_SCHEMA or profile["session_id"] != session_id:
            raise ProtocolError("local session profile identity mismatch")
        if profile["problem_id"] != self.workspace.problem["problem_id"]:
            raise ProtocolError("local session profile belongs to another problem")
        key = load_private_key(key_path)
        if public_key_text(key) != profile["session_key"]:
            raise ProtocolError("local session key does not match its profile")
        return profile, key


def maintainer_key_path(workspace: Workspace) -> Path:
    return workspace.control / "private" / "maintainer.pem"


def load_maintainer_key(workspace: Workspace) -> Any:
    key = load_private_key(maintainer_key_path(workspace))
    if public_key_text(key) != workspace.config["maintainer_key"]:
        raise ProtocolError("local maintainer key does not match workspace config")
    return key
