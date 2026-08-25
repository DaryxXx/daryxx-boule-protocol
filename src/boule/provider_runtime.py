"""Provider command construction and privacy-preserving event projection."""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .errors import ProtocolError
from .text_safety import redact_sensitive_text

PROVIDERS = frozenset({"codex", "claude-code"})
PROVIDER_EFFORTS = {
    "codex": frozenset({"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}),
    "claude-code": frozenset({"low", "medium", "high", "xhigh", "max"}),
}


def validate_provider_options(provider: str, effort: str | None) -> None:
    if provider not in PROVIDERS:
        raise ProtocolError(f"unsupported provider: {provider}")
    if effort is not None and effort not in PROVIDER_EFFORTS[provider]:
        allowed = ", ".join(sorted(PROVIDER_EFFORTS[provider]))
        raise ProtocolError(f"unsupported {provider} effort {effort!r}; choose {allowed}")


def resolve_provider_binary(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ProtocolError(f"unsupported provider: {provider}")
    name = "codex" if provider == "codex" else "claude"
    candidates: list[str] = []
    found = shutil.which(name)
    if found:
        candidates.append(found)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            candidates.append(str(candidate))
    for raw in dict.fromkeys(candidates):
        path = Path(raw).resolve()
        try:
            head = path.read_bytes()[:2048]
        except OSError:
            continue
        # Mirror's interactive recorder introduces a PTY and banners. Structured
        # workers need the underlying Codex binary instead.
        if name == "codex" and b"mirror_linux.codex_record" in head:
            continue
        return str(path)
    raise ProtocolError(f"{name} CLI is not installed or not executable")


def preflight_provider(provider: str, binary: str) -> str:
    """Check capabilities and local authentication without starting a model turn."""

    validate_provider_options(provider, None)
    checks = (
        [[binary, "exec", "--help"], [binary, "login", "status"], [binary, "--version"]]
        if provider == "codex"
        else [[binary, "--help"], [binary, "auth", "status", "--json"], [binary, "--version"]]
    )
    outputs: list[str] = []
    for command in checks:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError(f"{provider} preflight could not run") from exc
        if result.returncode != 0:
            raise ProtocolError(f"{provider} is not ready; authenticate its local CLI first")
        outputs.append(result.stdout + result.stderr)
    help_text, auth_text, version_text = outputs
    required = (
        ("--json", "--approve-for-me", "--output-last-message")
        if provider == "codex"
        else ("stream-json", "--permission-mode", "--name")
    )
    if any(flag not in help_text for flag in required):
        raise ProtocolError(f"installed {provider} CLI lacks required structured-run features")
    if provider == "codex":
        if "logged in" not in auth_text.lower():
            raise ProtocolError("codex is not authenticated")
    else:
        try:
            auth = json.loads(auth_text)
        except json.JSONDecodeError as exc:
            raise ProtocolError("claude-code returned an invalid authentication status") from exc
        if not isinstance(auth, dict) or auth.get("loggedIn") is not True:
            raise ProtocolError("claude-code is not authenticated")
    version = " ".join(version_text.split())[:120]
    if not version:
        raise ProtocolError(f"{provider} did not report a version")
    return version


def build_provider_command(
    provider: str,
    *,
    binary: str,
    workspace: Path,
    final_message: Path,
    agent_name: str,
    model: str | None,
    effort: str | None,
    resume_session_id: str | None = None,
) -> list[str]:
    validate_provider_options(provider, effort)
    if provider == "codex":
        if resume_session_id:
            command = [
                binary,
                "exec",
                "resume",
                "--json",
                "--output-last-message",
                str(final_message),
            ]
        else:
            command = [
                binary,
                "exec",
                "--json",
                "--color",
                "never",
                "--approve-for-me",
                "--cd",
                str(workspace),
                "--output-last-message",
                str(final_message),
            ]
        if model:
            command.extend(["--model", model])
        if effort:
            command.extend(["--config", f'model_reasoning_effort="{effort}"'])
        if resume_session_id:
            command.append(resume_session_id)
        command.append("-")
        return command
    if provider == "claude-code":
        command = [
            binary,
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "auto",
            "--name",
            agent_name,
        ]
        if model:
            command.extend(["--model", model])
        if effort:
            command.extend(["--effort", effort])
        if resume_session_id:
            command.extend(["--resume", resume_session_id])
        return command
    raise ProtocolError(f"unsupported provider: {provider}")


def provider_environment(
    provider: str, session_id: str, server: str, boule_bin_dir: Path
) -> dict[str, str]:
    """Pass only the small environment needed by the local provider and Boule CLI."""

    allowed = {
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LANGUAGE",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "SHELL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
    }
    allowed.add("OPENAI_API_KEY" if provider == "codex" else "ANTHROPIC_API_KEY")
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment["BOULE_SESSION"] = session_id
    environment["BOULE_SERVER"] = server
    environment["GIT_SSH_COMMAND"] = "/bin/false"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GH_PROMPT_DISABLED"] = "1"
    environment["PATH"] = str(boule_bin_dir) + os.pathsep + os.environ.get("PATH", "")
    return environment


def _usage(raw: Any, provider: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    if provider == "codex":
        names = {
            "input_tokens": "input_tokens",
            "cached_input_tokens": "cache_read_tokens",
            "output_tokens": "output_tokens",
            "reasoning_output_tokens": "reasoning_output_tokens",
        }
    else:
        names = {
            "input_tokens": "input_tokens",
            "cache_read_input_tokens": "cache_read_tokens",
            "cache_creation_input_tokens": "cache_write_tokens",
            "output_tokens": "output_tokens",
        }
    value: dict[str, Any] = {"authoritative": True}
    for source, target in names.items():
        item = raw.get(source)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            value[target] = item
    return value if len(value) > 1 else None


def _excerpt(value: Any, maximum: int = 360) -> str | None:
    if not isinstance(value, str):
        return None
    compact = " ".join(value.split())
    safe = redact_sensitive_text(compact)
    return safe[:maximum] if safe else None


def normalize_provider_event(provider: str, raw: Any) -> dict[str, Any] | None:
    """Project only lifecycle, bounded messages, and authoritative usage."""

    if not isinstance(raw, dict) or not isinstance(raw.get("type"), str):
        return None
    event_type = raw["type"]
    result: dict[str, Any] = {"provider": provider, "raw_type": event_type}
    if provider == "codex":
        if event_type == "thread.started" and isinstance(raw.get("thread_id"), str):
            return {**result, "kind": "session.started", "session_id": raw["thread_id"]}
        if event_type == "turn.started":
            return {**result, "kind": "turn.started"}
        if event_type in {"turn.completed", "turn.failed"}:
            value = {
                **result,
                "kind": "turn.completed" if event_type == "turn.completed" else "turn.failed",
            }
            usage = _usage(raw.get("usage"), provider)
            if usage:
                value["usage"] = usage
            error = raw.get("error")
            if isinstance(error, dict):
                message = _excerpt(error.get("message"))
                if message:
                    value["summary"] = message
            return value
        if event_type in {"item.started", "item.completed"} and isinstance(raw.get("item"), dict):
            item = raw["item"]
            item_type = item.get("type")
            item_id = item.get("id") if isinstance(item.get("id"), str) else None
            if item_type == "agent_message" and event_type == "item.completed":
                value = {**result, "kind": "message.completed"}
                if item_id:
                    value["item_id"] = item_id[:160]
                text = _excerpt(item.get("text"))
                if text:
                    value["summary"] = text
                return value
            if item_type in {"reasoning", "plan_update", "todo_list"}:
                return {
                    **result,
                    "kind": "plan.updated",
                    **({"item_id": item_id[:160]} if item_id else {}),
                }
            if item_type in {
                "command_execution",
                "file_change",
                "mcp_tool_call",
                "web_search",
            }:
                return {
                    **result,
                    "kind": "tool.completed" if event_type == "item.completed" else "tool.started",
                    "tool_class": item_type,
                    **({"item_id": item_id[:160]} if item_id else {}),
                }
            return None
        if event_type == "error":
            summary = _excerpt(raw.get("message"))
            return {**result, "kind": "provider.error", **({"summary": summary} if summary else {})}
        return {**result, "kind": "provider.event"}

    if provider == "claude-code":
        if event_type == "system" and raw.get("subtype") == "init":
            value = {**result, "kind": "session.started"}
            if isinstance(raw.get("session_id"), str):
                value["session_id"] = raw["session_id"]
            return value
        if event_type == "assistant" and isinstance(raw.get("message"), dict):
            content = raw["message"].get("content")
            tool_classes = []
            texts = []
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") == "tool_use" and isinstance(item.get("name"), str):
                        tool_classes.append(item["name"])
                    elif item.get("type") == "text" and isinstance(item.get("text"), str):
                        texts.append(item["text"])
            if tool_classes:
                value = {
                    **result,
                    "kind": "tool.started",
                    "tool_class": tool_classes[0],
                    "tool_classes": tool_classes[:16],
                    "tool_count": len(tool_classes),
                }
                text = _excerpt(" ".join(texts))
                if text:
                    value["summary"] = text
                return value
            text = _excerpt(" ".join(texts))
            if text:
                return {**result, "kind": "message.completed", "summary": text}
            return None
        if event_type == "result":
            failed = bool(raw.get("is_error")) or raw.get("subtype") not in {None, "success"}
            value = {**result, "kind": "turn.failed" if failed else "turn.completed"}
            usage = _usage(raw.get("usage"), provider)
            if usage:
                value["usage"] = usage
            cost = raw.get("total_cost_usd")
            if (
                isinstance(cost, (int, float))
                and not isinstance(cost, bool)
                and math.isfinite(float(cost))
                and cost >= 0
            ):
                value["provider_reported_cost_usd"] = cost
            duration = raw.get("duration_ms")
            if isinstance(duration, int) and not isinstance(duration, bool) and duration >= 0:
                value["provider_duration_ms"] = raw["duration_ms"]
            summary = _excerpt(raw.get("result"))
            if summary:
                value["summary"] = summary
            return value
        if event_type == "user" and isinstance(raw.get("message"), dict):
            content = raw["message"].get("content")
            count = 0
            if isinstance(content, list):
                count = sum(
                    1
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "tool_result"
                )
            if count:
                return {**result, "kind": "tool.completed", "tool_count": count}
            return None
        if event_type == "rate_limit_event":
            return {**result, "kind": "provider.status", "status": "rate_limited"}
        if event_type == "system":
            subtype = raw.get("subtype")
            return {
                **result,
                "kind": "provider.status",
                **({"status": subtype[:80]} if isinstance(subtype, str) else {}),
            }
        if event_type == "stream_event":
            return None
        if event_type == "prompt_suggestion":
            return {**result, "kind": "provider.status", "status": "prompt_suggestion"}
        return {**result, "kind": "provider.event"}
    raise ProtocolError(f"unsupported provider: {provider}")
