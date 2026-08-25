"""High-level local supervisor for Codex and Claude Code research sessions."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import threading
import time
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .crypto import generate_private_key, load_private_key, write_private_key
from .errors import ProtocolError
from .protocol_change import classify_protocol_change
from .provider_runtime import (
    build_provider_command,
    normalize_provider_event,
    preflight_provider,
    provider_environment,
    resolve_provider_binary,
    validate_provider_options,
)
from .registry_client import fetch_registry_index
from .remote_client import RemoteClient
from .run_store import (
    TERMINAL_STATES,
    RunStore,
    default_work_root,
    process_identity,
    process_matches,
    terminate_process_group,
    utc_now,
)
from .session_store import SessionStore
from .terminal_ui import RunTerminal
from .workspace import Workspace

DEFAULT_REGISTRY = "https://boule.207.180.245.67.nip.io"
RUN_SCHEMA = "boule-agent-run/0.1"
MAX_STRUCTURED_LINE = 1024 * 1024
MAX_STDERR_CHARS = 256 * 1024


def _safe_slug(value: str, maximum: int = 40) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")
    return (slug or "agent")[:maximum].strip("-")


def _search_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().lower()
    return " ".join(re.findall(r"[a-z0-9]+", normalized))


def default_controller_id() -> str:
    try:
        machine = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        machine = "local-machine"
    digest = hashlib.sha256(f"{os.getuid()}:{machine}".encode()).hexdigest()[:16]
    return f"local-control-{digest}"


def _shared_controller_key(controller_id: str) -> Any:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    root = config_home / "boule" / "controller-keys"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    suffix = hashlib.sha256(controller_id.encode()).hexdigest()[:24]
    path = root / f"controller-{suffix}.pem"
    lock_path = root / ".lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if path.exists():
            return load_private_key(path)
        key = generate_private_key()
        write_private_key(path, key)
        return key
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def resolve_registry_problem(
    query: str,
    *,
    registry: str,
    mode: str | None,
    clerk_key: str | None,
    trust_store: str | Path | None,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    index = fetch_registry_index(
        registry,
        clerk_key=clerk_key,
        trust_store=trust_store,
        timeout=timeout,
    )
    tokens = _search_text(query).split()
    if not tokens:
        raise ProtocolError("problem query must contain letters or numbers")
    matches = []
    for problem in index["problems"]:
        if problem.get("status") != "LIVE":
            continue
        if mode and problem.get("task_mode") != mode:
            continue
        haystack = _search_text(
            " ".join(
                str(problem.get(key, ""))
                for key in ("case_id", "problem_id", "task_id", "title", "source_url")
            )
        )
        if all(token in haystack.split() for token in tokens):
            matches.append(problem)
    if not matches:
        suffix = f" in mode {mode}" if mode else ""
        raise ProtocolError(f"no LIVE Boule problem matches {query!r}{suffix}")
    if len(matches) > 1:
        maximum = max(int(item.get("event_count", 0)) for item in matches)
        active = [item for item in matches if int(item.get("event_count", 0)) == maximum]
        if len(active) == 1 and maximum > 0:
            matches = active
        else:
            choices = ", ".join(
                f"{item.get('task_mode')}:{item.get('case_id')}" for item in matches
            )
            raise ProtocolError(f"problem query is ambiguous; pass --mode ({choices})")
    return index, matches[0]


def _repository_url(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("registry problem has no repository URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolError("registry repository must be a credential-free HTTPS URL")
    return value


def _git(command: list[str], *, timeout: float = 120.0) -> str:
    environment = dict(os.environ)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProtocolError("Git could not prepare the private case workspace") from exc
    if result.returncode != 0:
        raise ProtocolError("Git could not prepare the private case workspace")
    return result.stdout.strip()


def _clone_case(
    problem: dict[str, Any], destination: Path, run_id: str, agent_name: str
) -> Workspace:
    repository = _repository_url(problem.get("repo_url"))
    commit = problem.get("repository_commit")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise ProtocolError("registry problem has an invalid repository commit")
    destination.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
    destination.parent.chmod(0o700)
    _git(["git", "clone", "--quiet", "--no-checkout", repository, str(destination)])
    branch = f"agent/{_safe_slug(agent_name)}/{run_id[-8:]}"
    _git(["git", "-C", str(destination), "checkout", "--quiet", "-b", branch, commit])
    if _git(["git", "-C", str(destination), "rev-parse", "HEAD"]) != commit:
        raise ProtocolError("cloned case does not match the registry-pinned commit")
    _git(
        [
            "git",
            "-C",
            str(destination),
            "config",
            "--local",
            "remote.origin.pushurl",
            "disabled://boule-runner-no-push",
        ]
    )
    hook = destination / ".git" / "hooks" / "pre-push"
    hook.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'Boule runs do not push; publish after human review.' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    workspace = Workspace(destination)
    if workspace.problem["problem_id"] != problem.get("problem_id"):
        raise ProtocolError("cloned case problem identity differs from the signed registry")
    task = workspace.problem["task"]
    if task["task_id"] != problem.get("task_id") or task["task_commitment"] != problem.get(
        "task_commitment"
    ):
        raise ProtocolError("cloned case task identity differs from the signed registry")
    return workspace


def _start_session(
    workspace: Workspace,
    *,
    server: str,
    agent_name: str,
    controller: str,
    provider: str,
    lifetime_seconds: float,
) -> dict[str, Any]:
    client = RemoteClient(workspace, server)

    def append(kind: str, payload: dict[str, Any], key: Any) -> dict[str, Any]:
        return client.append(kind, payload, key)["event"]

    return SessionStore(workspace).start(
        participant_id=agent_name,
        controller_id=controller,
        label=f"{provider} supervised by Boule",
        not_after=(datetime.now(UTC) + timedelta(seconds=lifetime_seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        appender=append,
        controller_key=_shared_controller_key(controller),
        persist_controller_key=False,
    )


def prepare_run(
    provider: str,
    query: str,
    *,
    agent_name: str,
    controller: str | None,
    registry: str | None,
    registry_clerk_key: str | None,
    trust_store: str | Path | None,
    mode: str | None,
    model: str | None,
    effort: str | None,
    max_seconds: float,
    instruction: str | None,
    max_tokens: int | None = None,
    run_root: str | Path | None = None,
    work_root: str | Path | None = None,
    workspace_path: str | Path | None = None,
    workspace_server: str | None = None,
) -> dict[str, Any]:
    validate_provider_options(provider, effort)
    if not math.isfinite(max_seconds) or max_seconds <= 0 or max_seconds > 167 * 3600:
        raise ProtocolError("--max-seconds must be finite, greater than 0, and at most 601200")
    if max_tokens is not None and (
        isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0
    ):
        raise ProtocolError("--max-tokens must be a positive integer")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})", agent_name):
        raise ProtocolError("agent name must be 1-64 safe identifier characters")
    # Resolve the harness before cloning or creating a public signed session.
    binary = resolve_provider_binary(provider)
    provider_version = preflight_provider(provider, binary)
    chosen_controller = controller or os.environ.get("BOULE_CONTROLLER") or default_controller_id()
    run_id = f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(4)}"
    store = RunStore(run_root)
    store.reserve(
        run_id,
        {
            "state": "preparing",
            "provider": provider,
            "provider_version": provider_version,
            "agent_name": agent_name,
            "problem_id": None,
            "task_mode": mode,
            "session_id": None,
            "workspace": None,
            "max_seconds": max_seconds,
            "max_tokens": max_tokens,
            "event_count": 0,
            "usage": None,
            "protocol": {
                "complete": False,
                "claim": None,
                "handoff": None,
                "collaborators": [],
            },
        },
    )
    selected_registry = registry or os.environ.get("BOULE_REGISTRY") or DEFAULT_REGISTRY
    case: dict[str, Any] | None
    index: dict[str, Any] | None
    try:
        if workspace_path is None:
            index, case = resolve_registry_problem(
                query,
                registry=selected_registry,
                mode=mode,
                clerk_key=registry_clerk_key,
                trust_store=trust_store,
                timeout=15.0,
            )
            work_base = Path(work_root) if work_root else default_work_root()
            workspace = _clone_case(case, work_base / run_id / "workspace", run_id, agent_name)
            server = str(case["clerk_url"])
            registry_metadata = {
                "origin": index["registry"],
                "key": index["registry_key"],
                "head": index["registry_head"],
                "trust": index["registry_key_trust"],
            }
            task_mode = case.get("task_mode")
        else:
            workspace = Workspace(Path(workspace_path).expanduser().resolve(strict=True))
            server = workspace_server or os.environ.get("BOULE_SERVER", "")
            if not server:
                raise ProtocolError("--workspace requires BOULE_SERVER for its trusted clerk")
            case = None
            registry_metadata = None
            task_mode = workspace.problem["task"].get("mode")
        workspace_value = str(workspace.root.resolve())
        store.update(
            run_id,
            workspace=workspace_value,
            problem_id=workspace.problem["problem_id"],
            task_mode=task_mode,
        )
        session = _start_session(
            workspace,
            server=server,
            agent_name=agent_name,
            controller=chosen_controller,
            provider=provider,
            lifetime_seconds=max_seconds + 3600,
        )
        config = {
            "schema": RUN_SCHEMA,
            "provider": provider,
            "provider_version": provider_version,
            "query": query,
            "agent_name": agent_name,
            "controller_id": chosen_controller,
            "workspace": workspace_value,
            "server": server,
            "session_id": session["session_id"],
            "problem_id": workspace.problem["problem_id"],
            "problem_title": (workspace.problem.get("problem") or {}).get("title") or query,
            "task_id": workspace.problem["task"]["task_id"],
            "case_id": case.get("case_id") if case else None,
            "task_mode": task_mode,
            "repository_commit": case.get("repository_commit") if case else None,
            "repository_url": case.get("repo_url") if case else None,
            "source_url": case.get("source_url") if case else None,
            "registry": registry_metadata,
            "provider_binary": binary,
            "model": model,
            "effort": effort,
            "max_seconds": max_seconds,
            "max_tokens": max_tokens,
            "instruction": instruction,
            "boule_bin_dir": str(Path(sys.executable).resolve().parent),
        }
        store.set_config(run_id, config)
        return store.transition(
            run_id,
            expected={"preparing"},
            state="ready",
            session_id=session["session_id"],
        )
    except BaseException as exc:
        store.update(
            run_id,
            state="failed",
            finished_at=utc_now(),
            error=f"preparation failed: {type(exc).__name__}: {str(exc)[:200]}",
        )
        raise


def prepare_resume(
    parent_run_id: str,
    *,
    max_seconds: float,
    instruction: str | None,
    model: str | None,
    effort: str | None,
    max_tokens: int | None = None,
    run_root: str | Path | None = None,
) -> dict[str, Any]:
    store = RunStore(run_root)
    parent = reconcile_run(parent_run_id, run_root=run_root)
    if parent.get("state") not in {
        "timed_out",
        "failed",
        "protocol_incomplete",
        "interrupted",
        "stopped",
    }:
        raise ProtocolError("only a terminal incomplete run can be resumed")
    provider_session_id = parent.get("provider_session_id")
    if not isinstance(provider_session_id, str) or not provider_session_id:
        raise ProtocolError("the parent run has no provider session handle to resume")
    validate_provider_options(str(parent["provider"]), effort)
    if not math.isfinite(max_seconds) or not 0 < max_seconds <= 167 * 3600:
        raise ProtocolError("--max-seconds must be finite, greater than 0, and at most 601200")
    parent_config = store.config(parent_run_id)
    effective_max_tokens = max_tokens if max_tokens is not None else parent_config.get("max_tokens")
    if effective_max_tokens is not None and (
        isinstance(effective_max_tokens, bool)
        or not isinstance(effective_max_tokens, int)
        or effective_max_tokens <= 0
    ):
        raise ProtocolError("--max-tokens must be a positive integer")
    workspace = Workspace(parent_config["workspace"])
    profile, _key = SessionStore(workspace).load(parent_config["session_id"])
    not_after = datetime.fromisoformat(profile["not_after"].replace("Z", "+00:00"))
    if datetime.now(UTC) + timedelta(seconds=max_seconds) >= not_after:
        raise ProtocolError("the delegated Boule session expires before this recovery could finish")
    for candidate in store.list():
        if (
            candidate.get("run_id") != parent_run_id
            and candidate.get("workspace") == parent_config["workspace"]
            and candidate.get("state") not in TERMINAL_STATES
        ):
            raise ProtocolError("this workspace already has an active supervised run")
    binary = resolve_provider_binary(parent_config["provider"])
    provider_version = preflight_provider(parent_config["provider"], binary)
    run_id = f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(4)}"
    effective_instruction = instruction or (
        "Recovery only: inspect the preserved work, record any reproducible evidence, and publish "
        "an honest handoff for the existing claim before doing further research."
    )
    config = {
        **parent_config,
        "provider_binary": binary,
        "provider_version": provider_version,
        "resume_provider_session_id": provider_session_id,
        "parent_run_id": parent_run_id,
        "model": model or parent_config.get("model"),
        "effort": effort or parent_config.get("effort"),
        "max_seconds": max_seconds,
        "max_tokens": effective_max_tokens,
        "instruction": effective_instruction,
    }
    status = {
        "state": "ready",
        "provider": config["provider"],
        "provider_version": provider_version,
        "agent_name": config["agent_name"],
        "problem_id": config["problem_id"],
        "task_mode": config["task_mode"],
        "session_id": config["session_id"],
        "workspace": config["workspace"],
        "parent_run_id": parent_run_id,
        "max_seconds": max_seconds,
        "max_tokens": effective_max_tokens,
        "event_count": 0,
        "usage": None,
        "protocol": parent.get("protocol")
        or {"complete": False, "claim": None, "handoff": None, "collaborators": []},
    }
    store.create(run_id, config, status)
    return store.status(run_id)


def _prompt(config: dict[str, Any]) -> str:
    additional = config.get("instruction")
    extra = (
        f"\nAdditional bounded objective from the operator:\n{additional.strip()}\n"
        if additional
        else ""
    )
    recovery = ""
    claim_step = (
        "3. Resume your existing active claim. Only create a claim if the signed state says none "
        "exists.\n"
        if config.get("resume_provider_session_id")
        else "3. Choose one narrow route that does not duplicate active work, then run\n"
        "   `boule claim . --route ... --success-gate ... --falsifier ...`.\n"
    )
    if config.get("resume_provider_session_id"):
        recovery = (
            "\nThis is a recovery turn for an interrupted provider thread and the same Boule "
            "session. Inspect the preserved working tree first. Prioritize checkpointing and "
            "publishing the honest handoff before doing more research.\n"
        )
    token_budget = ""
    if config.get("max_tokens") is not None:
        token_budget = (
            f" The operator also set an accounting budget of {config['max_tokens']:,} "
            "provider-reported input plus output tokens. Boule may only observe usage when the "
            "provider reports it, so this is not an exact provider-side cutoff."
        )
    return f"""You are {config["agent_name"]}, an autonomous research participant in Boule.

Work only on the exact pinned case in the current directory. Your public identity is
{config["agent_name"]} and your Boule session is already created. The local Boule CLI
has BOULE_SESSION and BOULE_SERVER configured.

Before research:
1. Run `boule brief .` and `boule status .`.
2. Inspect existing claims, handoffs, evidence, AGENTS.md, and CLAUDE.md.
{claim_step}

During work, record only real reusable progress. Use `boule agent checkpoint --help`
when you have evidence. You must finish with `boule agent handoff --help` and publish
an honest ADVANCE, NEGATIVE, or NO_SIGNAL handoff. A failed route is useful only with
a reproducible falsifier, boundary, or negative result.

Do not push Git, contact Conjectures.io, submit a bounty, pay, use wallets, expose
credentials, or read/copy private session key material directly. Boule CLI commands
may use the delegated session internally. Leave all artifacts inside this workspace.
Do not claim that compute, messages, or elapsed time are contributions.
{recovery}
{extra}
The supervisor will stop this run after {int(config["max_seconds"])} seconds.{token_budget}
Preserve a handoff before the available budget is exhausted. Start now.
"""


def _protocol_projection(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    workspace = Workspace(config["workspace"])
    response = RemoteClient(workspace, config["server"]).fetch_state()
    state = response["state"]
    snapshot = response["snapshot"]
    session_id = config["session_id"]
    claims = [item for item in state.get("claims", []) if item.get("session_id") == session_id]
    handoffs = [item for item in state.get("handoffs", []) if item.get("session_id") == session_id]
    checkpoints = [
        item for item in state.get("checkpoints", []) if item.get("session_id") == session_id
    ]
    messages = [item for item in state.get("messages", []) if item.get("session_id") == session_id]
    claim = claims[-1] if claims else None
    handoff = handoffs[-1] if handoffs else None
    collaborators = []
    sessions = {item.get("session_id"): item for item in state.get("sessions", [])}
    for item in state.get("claims", []):
        if item.get("session_id") == session_id or item.get("status") != "active":
            continue
        owner = sessions.get(item.get("session_id"), {})
        collaborators.append(
            {
                "agent_name": owner.get("participant_id"),
                "route": item.get("route"),
                "claim_id": item.get("claim_id"),
            }
        )
    projection = {
        "complete": bool(handoff) and (claim is None or claim.get("status") == "completed"),
        "claim": (
            {
                key: claim.get(key)
                for key in ("claim_id", "route", "status", "deadline", "parallel")
                if claim.get(key) is not None
            }
            if claim
            else None
        ),
        "handoff": (
            {
                **{
                    key: handoff.get(key)
                    for key in (
                        "handoff_id",
                        "outcome",
                        "summary",
                        "next_action",
                        "limitations",
                        "status",
                    )
                    if handoff.get(key) is not None
                },
                "evidence_count": len(handoff.get("evidence", [])),
                "dependency_count": len(handoff.get("depends_on", [])),
            }
            if handoff
            else None
        ),
        "collaborators": collaborators,
        "checkpoint_count": len(checkpoints),
        "last_checkpoint": (
            {
                key: checkpoints[-1].get(key)
                for key in ("summary", "next_action", "received_at")
                if checkpoints[-1].get(key) is not None
            }
            if checkpoints
            else None
        ),
        "message_count": len(messages),
        "latest_message": (
            {
                key: messages[-1].get(key)
                for key in ("topic", "body", "received_at")
                if messages[-1].get(key) is not None
            }
            if messages
            else None
        ),
        "network": {
            "sessions": len(state.get("sessions", [])),
            "handoffs": len(state.get("handoffs", [])),
            "messages": len(state.get("messages", [])),
        },
    }
    observation = {
        "at": snapshot["at"],
        "event_count": snapshot["event_count"],
        "head_event_hash": snapshot["head_event_hash"],
    }
    return projection, observation


def _refresh_protocol(
    store: RunStore,
    run_id: str,
    config: dict[str, Any],
    *,
    required: bool = False,
) -> dict[str, Any]:
    try:
        projection, observation = _protocol_projection(config)
    except ProtocolError as exc:
        if required:
            raise
        return store.update(run_id, protocol_error=str(exc))
    current = store.status(run_id)
    if projection != current.get("protocol"):
        change = classify_protocol_change(current.get("protocol"), projection)
        store.append_event(
            run_id,
            {
                "kind": "protocol.updated",
                "change": change,
                "claim": projection.get("claim"),
                "handoff": projection.get("handoff"),
                "collaborator_count": len(projection.get("collaborators", [])),
                "checkpoint_count": projection.get("checkpoint_count"),
                "message_count": projection.get("message_count"),
            },
        )
    return store.update(
        run_id,
        protocol=projection,
        protocol_observation=observation,
        protocol_error=None,
    )


def _die_with_parent() -> None:
    """Ask Linux to terminate the provider if its Boule supervisor disappears."""

    try:
        import ctypes

        libc = ctypes.CDLL(None)
        libc.prctl(1, signal.SIGTERM)
        if os.getppid() == 1:
            os.kill(os.getpid(), signal.SIGTERM)
    except (OSError, AttributeError):
        pass


def run_worker(run_id: str, *, run_root: str | Path | None = None, render: bool = False) -> int:
    store = RunStore(run_root)
    lease = store.acquire_worker_lease(run_id)
    try:
        return _run_worker_locked(run_id, store=store, render=render)
    finally:
        store.release_worker_lease(lease)


def _run_worker_locked(run_id: str, *, store: RunStore, render: bool) -> int:
    config = store.config(run_id)
    if config.get("schema") != RUN_SCHEMA:
        raise ProtocolError("run config schema is unsupported")
    run_dir = store.directory(run_id)
    workspace = Path(config["workspace"])
    final_message = run_dir / "final-message.md"
    stderr_path = run_dir / "provider.stderr.log"
    stderr_descriptor = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    command = build_provider_command(
        config["provider"],
        binary=config["provider_binary"],
        workspace=workspace,
        final_message=final_message,
        agent_name=config["agent_name"],
        model=config.get("model"),
        effort=config.get("effort"),
        resume_session_id=config.get("resume_provider_session_id"),
    )
    started_at = utc_now()
    store.transition(
        run_id,
        expected={"ready", "starting"},
        state="starting",
        started_at=started_at,
        worker_process=process_identity(os.getpid()),
    )
    dashboard = RunTerminal(store, run_id) if render else None
    stop_requested = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    previous_term = signal.signal(signal.SIGTERM, request_stop)
    process: subprocess.Popen[str] | None = None
    try:
        with os.fdopen(stderr_descriptor, "w", encoding="utf-8", errors="replace") as stderr_handle:
            if dashboard is not None:
                dashboard.start()
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=provider_environment(
                    config["provider"],
                    config["session_id"],
                    config["server"],
                    Path(config["boule_bin_dir"]),
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
                preexec_fn=_die_with_parent,
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise ProtocolError("provider process did not expose structured pipes")

            stderr_truncated = False

            def drain_stderr() -> None:
                nonlocal stderr_truncated
                remaining = MAX_STDERR_CHARS
                for chunk in iter(lambda: process.stderr.read(4096), ""):
                    available = remaining
                    if remaining > 0:
                        kept = chunk[:remaining]
                        stderr_handle.write(kept)
                        stderr_handle.flush()
                        remaining -= len(kept)
                    if len(chunk) > available:
                        stderr_truncated = True

            stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
            stderr_thread.start()
            process.stdin.write(_prompt(config))
            process.stdin.close()
            identity = process_identity(process.pid)
            store.update(run_id, state="running", provider_process=identity)
            store.append_event(
                run_id,
                {"kind": "runtime.started", "provider": config["provider"]},
            )
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            started = time.monotonic()
            last_protocol = 0.0
            parse_errors = 0
            timed_out = False
            output_violation = False
            provider_started = False
            provider_terminal: str | None = None
            term_sent = False
            last_render = 0.0

            def consume(line: str) -> dict[str, Any] | None:
                nonlocal output_violation, parse_errors, provider_started, provider_terminal
                if len(line) > MAX_STRUCTURED_LINE:
                    output_violation = True
                    parse_errors += 1
                    violation = {
                        "kind": "provider.protocol_error",
                        "provider": config["provider"],
                        "summary": "structured provider line exceeded the local limit",
                    }
                    store.append_event(run_id, violation)
                    return violation
                try:
                    raw = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    parse_errors += 1
                    return None
                projected = normalize_provider_event(config["provider"], raw)
                if projected is None:
                    return None
                store.append_event(run_id, projected)
                changes: dict[str, Any] = {}
                if projected.get("session_id"):
                    changes["provider_session_id"] = projected["session_id"]
                if projected.get("kind") == "session.started":
                    provider_started = True
                    changes["provider_started"] = True
                if projected.get("kind") in {"turn.completed", "turn.failed"}:
                    provider_terminal = (
                        "completed" if projected["kind"] == "turn.completed" else "failed"
                    )
                    changes["provider_turn_status"] = provider_terminal
                if projected.get("usage"):
                    changes["usage"] = projected["usage"]
                if projected.get("provider_reported_cost_usd") is not None:
                    changes["provider_reported_cost_usd"] = projected["provider_reported_cost_usd"]
                if projected.get("provider_duration_ms") is not None:
                    changes["provider_duration_ms"] = projected["provider_duration_ms"]
                if changes:
                    store.update(run_id, **changes)
                if dashboard is not None:
                    dashboard.refresh()
                return projected

            while process.poll() is None:
                current = store.status(run_id)
                if current.get("stop_requested"):
                    stop_requested = True
                if stop_requested and not term_sent:
                    if identity:
                        terminate_process_group(identity, grace=5.0, force=False)
                    term_sent = True
                if time.monotonic() - started >= float(config["max_seconds"]):
                    timed_out = True
                    if identity:
                        terminate_process_group(identity, grace=5.0, force=True)
                    break
                for key, _mask in selector.select(timeout=0.5):
                    line = key.fileobj.readline(MAX_STRUCTURED_LINE + 1)
                    if not line:
                        continue
                    projected = consume(line)
                    if projected is None:
                        continue
                if time.monotonic() - last_protocol >= 4.0:
                    _refresh_protocol(store, run_id, config)
                    if dashboard is not None:
                        dashboard.refresh()
                    last_protocol = time.monotonic()
                if dashboard is not None and time.monotonic() - last_render >= 1.0:
                    dashboard.refresh()
                    last_render = time.monotonic()
            process.wait(timeout=10)
            while line := process.stdout.readline(MAX_STRUCTURED_LINE + 1):
                consume(line)
            stderr_thread.join(timeout=2)
            selector.close()
            final_observed = False
            try:
                final = _refresh_protocol(store, run_id, config, required=True)
                final_observed = True
            except ProtocolError as exc:
                final = store.update(run_id, protocol_error=str(exc))
            protocol_complete = final_observed and bool(
                (final.get("protocol") or {}).get("complete")
            )
            stop_requested = stop_requested or bool(store.status(run_id).get("stop_requested"))
            provider_ok = (
                provider_started
                and provider_terminal == "completed"
                and parse_errors == 0
                and not output_violation
            )
            terminal_error = None
            if stop_requested:
                state = "stopped"
            elif timed_out:
                state = "timed_out"
            elif process.returncode != 0 or provider_terminal == "failed":
                state = "failed"
                terminal_error = "provider process or structured turn failed"
            elif not provider_ok:
                state = "failed"
                terminal_error = "provider structured lifecycle was incomplete or malformed"
            elif not final_observed:
                state = "protocol_incomplete"
                terminal_error = "final signed clerk observation failed"
            elif protocol_complete:
                state = "completed"
            else:
                state = "protocol_incomplete"
            final = store.transition(
                run_id,
                expected={"running", "stop_requested", "starting"},
                state=state,
                exit_code=process.returncode,
                finished_at=utc_now(),
                parse_error_count=parse_errors,
                stderr_truncated=stderr_truncated,
                provider_started=provider_started,
                provider_turn_status=provider_terminal,
                protocol_final_observed=final_observed,
                provider_process=None,
                worker_process=None,
                **({"error": terminal_error} if terminal_error else {}),
            )
            store.append_event(
                run_id,
                {
                    "kind": "runtime.finished",
                    "state": state,
                    "exit_code": process.returncode,
                    "protocol_complete": protocol_complete,
                },
            )
            if final_message.exists():
                final_message.chmod(0o600)
            if dashboard is not None:
                dashboard.refresh(force=True)
            return 0 if state == "completed" else 1
    except KeyboardInterrupt:
        if process is not None:
            identity = process_identity(process.pid)
            if identity:
                terminate_process_group(identity, grace=3.0, force=True)
        store.update(
            run_id,
            state="interrupted",
            finished_at=utc_now(),
            provider_process=None,
            worker_process=None,
        )
        if dashboard is not None:
            dashboard.refresh(force=True)
        return 130
    except BaseException as exc:
        if process is not None:
            identity = process_identity(process.pid)
            if identity:
                terminate_process_group(identity, grace=3.0, force=True)
        store.update(
            run_id,
            state="failed",
            finished_at=utc_now(),
            provider_process=None,
            worker_process=None,
            error=f"{type(exc).__name__}: {str(exc)[:240]}",
        )
        if dashboard is not None:
            dashboard.refresh(force=True)
        raise
    finally:
        if dashboard is not None:
            dashboard.close()
        signal.signal(signal.SIGTERM, previous_term)


def launch_background(run_id: str, *, run_root: str | Path | None = None) -> dict[str, Any]:
    store = RunStore(run_root)
    store.transition(run_id, expected={"ready"}, state="starting")
    directory = store.directory(run_id)
    log_path = directory / "worker.log"
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    environment = dict(os.environ)
    environment["BOULE_RUN_ROOT"] = str(store.root)
    gate_read, gate_write = os.pipe()
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "boule",
                    "_run-worker",
                    run_id,
                    "--gate-fd",
                    str(gate_read),
                ],
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=handle,
                cwd=Path(__file__).resolve().parents[2],
                env=environment,
                start_new_session=True,
                text=True,
                pass_fds=(gate_read,),
            )
        os.close(gate_read)
        store.update(run_id, worker_process=process_identity(process.pid))
        os.write(gate_write, b"1")
    except BaseException as exc:
        return store.transition(
            run_id,
            expected={"starting"},
            state="failed",
            finished_at=utc_now(),
            error=f"background worker could not start: {type(exc).__name__}",
        )
    finally:
        for descriptor_to_close in (gate_read, gate_write):
            try:
                os.close(descriptor_to_close)
            except OSError:
                pass
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        status = store.status(run_id)
        if status.get("state") != "starting":
            return status
        if process.poll() is not None:
            return store.update(
                run_id,
                state="failed",
                finished_at=utc_now(),
                error="background worker exited before provider startup",
            )
        time.sleep(0.1)
    return store.status(run_id)


def stop_run(
    run_id: str, *, run_root: str | Path | None = None, force: bool = False
) -> dict[str, Any]:
    store = RunStore(run_root)
    status = store.status(run_id)
    if status.get("state") in TERMINAL_STATES:
        return status
    status = store.transition(
        run_id,
        expected={"preparing", "ready", "starting", "running", "stop_requested", "orphaned"},
        state="stop_requested",
        stop_requested=True,
    )
    provider = status.get("provider_process")
    if isinstance(provider, dict) and process_matches(provider):
        terminate_process_group(provider, grace=5.0, force=force)
        return store.status(run_id)
    worker = status.get("worker_process")
    if isinstance(worker, dict) and process_matches(worker):
        terminate_process_group(worker, grace=5.0, force=force)
        return store.status(run_id)
    return store.transition(
        run_id,
        expected={"stop_requested"},
        state="stopped",
        finished_at=utc_now(),
    )


def reconcile_run(run_id: str, *, run_root: str | Path | None = None) -> dict[str, Any]:
    """Fail closed when a recorded supervisor disappeared without a terminal state."""

    store = RunStore(run_root)
    status = store.status(run_id)
    if status.get("state") in TERMINAL_STATES or status.get("state") in {
        "preparing",
        "ready",
    }:
        return status
    if status.get("state") == "starting":
        try:
            updated = datetime.fromisoformat(str(status["updated_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError):
            updated = datetime.now(UTC) - timedelta(seconds=60)
        if (datetime.now(UTC) - updated).total_seconds() < 10:
            return status
    worker = status.get("worker_process")
    provider = status.get("provider_process")
    if isinstance(worker, dict) and process_matches(worker):
        return status
    if isinstance(provider, dict) and process_matches(provider):
        terminate_process_group(provider, grace=3.0, force=True)
    return store.update(
        run_id,
        state="failed",
        finished_at=utc_now(),
        worker_process=None,
        provider_process=None,
        error="supervisor exited without a terminal runtime event",
    )
