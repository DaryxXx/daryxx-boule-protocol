"""Information-rich, privacy-bounded terminal views for supervised runs."""

from __future__ import annotations

import math
import re
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from .errors import ProtocolError
from .run_store import TERMINAL_STATES, RunStore
from .text_safety import redact_sensitive_text

GOLD = "#e0c45c"
GREEN = "#79d99b"
RED = "#ff7474"
CYAN = "#76c7df"
MUTED = "#84918c"
WHITE = "#e8eee9"
ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
MATERIAL_EVENT_KINDS = frozenset(
    {
        "runtime.started",
        "session.started",
        "turn.started",
        "message.completed",
        "plan.updated",
        "protocol.updated",
        "provider.status",
        "provider.error",
        "provider.protocol_error",
        "turn.completed",
        "turn.failed",
        "runtime.finished",
    }
)


class BouleConsole(Console):
    """Keep a closed output stream from mutating global stdout or ending a run."""

    def on_broken_pipe(self) -> None:
        self.quiet = True
        raise BrokenPipeError


def _clean(value: Any, maximum: int = 320) -> str:
    if not isinstance(value, str):
        return ""
    value = ANSI_ESCAPE.sub("", value)
    printable = "".join(character if character.isprintable() else " " for character in value)
    home = str(Path.home())
    printable = printable.replace(home, "~")
    printable = redact_sensitive_text(printable)
    compact = " ".join(printable.split())
    if len(compact) <= maximum:
        return compact
    return compact[: max(1, maximum - 1)].rstrip() + "…"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _seconds_since(value: Any, now: datetime) -> int | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds()))


def _duration(seconds: int | float | None) -> str:
    if seconds is None:
        return "—"
    bounded = max(0, int(seconds))
    return f"{bounded // 3600:02d}:{bounded % 3600 // 60:02d}:{bounded % 60:02d}"


def _provider_duration(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    seconds, milliseconds = divmod(value, 1000)
    if seconds < 60:
        return f"{seconds}.{milliseconds:03d}s"
    return f"{_duration(seconds)}.{milliseconds:03d}"


def _reported_cost(value: Any) -> str | None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
    ):
        return None
    return f"${float(value):,.4f}"


def _age(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 5:
        return "now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def _elapsed_seconds(status: dict[str, Any], now: datetime) -> int:
    started = _parse_time(status.get("started_at") or status.get("created_at"))
    if started is None:
        return 0
    end = now
    if status.get("state") in TERMINAL_STATES:
        end = _parse_time(status.get("finished_at")) or now
    return max(0, int((end - started).total_seconds()))


def _short(value: Any, maximum: int = 28) -> str:
    cleaned = _clean(value, maximum=max(maximum, 8))
    if len(cleaned) <= maximum:
        return cleaned
    keep = max(3, (maximum - 1) // 2)
    return f"{cleaned[:keep]}…{cleaned[-keep:]}"


def _local_path(value: Any) -> str:
    cleaned = _clean(value, 180)
    if not cleaned:
        return "—"
    home = str(Path.home())
    return (
        "~" + cleaned[len(home) :] if cleaned == home or cleaned.startswith(home + "/") else cleaned
    )


def _state_style(state: str) -> str:
    if state == "completed":
        return GREEN
    if state in {"failed", "timed_out", "protocol_incomplete"}:
        return RED
    if state in {"stopped", "interrupted"}:
        return GOLD
    return CYAN


def runtime_phase(status: dict[str, Any]) -> tuple[str, int]:
    state = str(status.get("state") or "unknown")
    protocol = status.get("protocol") if isinstance(status.get("protocol"), dict) else {}
    if state == "completed":
        return "COMPLETED", 5
    if state == "failed":
        return "FAILED", 5
    if state == "timed_out":
        return "TIME LIMIT", 5
    if state == "protocol_incomplete":
        return "HANDOFF MISSING", 5
    if state in {"stopped", "interrupted"}:
        return "STOPPED", 5
    if protocol.get("handoff"):
        return "HANDOFF RECORDED", 4
    if protocol.get("claim"):
        return "RESEARCHING", 3
    if status.get("provider_started"):
        return "ORIENTING", 1
    if state in {"ready", "preparing"}:
        return "PREPARING", 0
    return "STARTING PROVIDER", 0


def _event_metrics(events: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    # RunStore is append-only and already emits sequence order. Avoid sorting the
    # complete history on every live refresh.
    ordered = [event for event in events if isinstance(event, dict)]
    counts = Counter(str(event.get("kind")) for event in ordered)
    active_tools: set[str] = set()
    tool_classes: Counter[str] = Counter()
    latest_tool: dict[str, Any] | None = None
    latest_message: dict[str, Any] | None = None
    material: list[dict[str, Any]] = []
    for event in ordered:
        kind = str(event.get("kind"))
        item_id = event.get("item_id")
        if kind == "tool.started":
            if isinstance(item_id, str):
                active_tools.add(item_id)
            tool_class = _clean(event.get("tool_class"), 40) or "tool"
            tool_classes[tool_class] += 1
            latest_tool = event
        elif kind == "tool.completed":
            if isinstance(item_id, str):
                active_tools.discard(item_id)
            latest_tool = event
        if kind == "message.completed":
            latest_message = event
        if kind in MATERIAL_EVENT_KINDS:
            material.append(event)
    latest = ordered[-1] if ordered else None
    return {
        "counts": counts,
        "active_tools": len(active_tools),
        "tool_classes": tool_classes,
        "latest_tool": latest_tool,
        "latest_message": latest_message,
        "latest": latest,
        "latest_age": _seconds_since(latest.get("observed_at"), now) if latest else None,
        "material": material[-5:],
    }


def _details(rows: list[tuple[str, Any]]) -> Table:
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(style=MUTED, no_wrap=True, width=17)
    table.add_column(style=WHITE, ratio=1, overflow="fold")
    for label, value in rows:
        rendered = value if hasattr(value, "__rich_console__") else Text(str(value), style=WHITE)
        table.add_row(Text(label, style=MUTED), rendered)
    return table


def _stages(status: dict[str, Any]) -> Text:
    labels = ("SETUP", "ORIENT", "CLAIM", "RESEARCH", "HANDOFF", "DONE")
    phase, current = runtime_phase(status)
    terminal_failure = status.get("state") in {
        "failed",
        "timed_out",
        "protocol_incomplete",
        "stopped",
        "interrupted",
    }
    line = Text()
    for index, label in enumerate(labels):
        if index:
            line.append("  ›  ", style=MUTED)
        if index < current:
            line.append("✓ " + label, style=GREEN)
        elif index == current:
            style = RED if terminal_failure else GOLD
            line.append("● " + (phase if index == 5 else label), style=f"bold {style}")
        else:
            line.append("○ " + label, style=MUTED)
    return line


def _timeline_label(event: dict[str, Any]) -> tuple[str, str]:
    kind = str(event.get("kind"))
    if kind == "runtime.started":
        return "Runtime", "Supervisor started the provider"
    if kind == "session.started":
        return "Provider", "Structured provider session opened"
    if kind == "turn.started":
        return "Provider", "Research turn started"
    if kind == "message.completed":
        return "Agent", _clean(event.get("summary"), 260) or "High-level update received"
    if kind == "plan.updated":
        return "Plan", "Research plan updated privately"
    if kind == "protocol.updated":
        if event.get("handoff"):
            return "Boule", "Signed handoff observed by the clerk"
        if event.get("claim"):
            route = _clean((event.get("claim") or {}).get("route"), 210)
            return "Boule", f"Signed claim recorded · {route}" if route else "Signed claim recorded"
        return "Boule", "Signed collaboration state updated"
    if kind == "turn.completed":
        return "Provider", "Provider reported the turn complete"
    if kind == "turn.failed":
        return "Provider", _clean(event.get("summary"), 240) or "Provider reported a failed turn"
    if kind == "provider.status":
        return "Provider", _clean(event.get("status"), 100) or "Provider status changed"
    if kind in {"provider.error", "provider.protocol_error"}:
        return "Provider", _clean(event.get("summary"), 240) or "Provider stream error"
    if kind == "runtime.finished":
        return "Runtime", f"Supervisor finished · {_clean(event.get('state'), 40)}"
    return "Runtime", _clean(kind, 80)


def _timeline(events: list[dict[str, Any]], now: datetime) -> Table:
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(style=MUTED, no_wrap=True, width=9)
    table.add_column(style=CYAN, no_wrap=True, width=10)
    table.add_column(style=WHITE, ratio=1, overflow="fold")
    if not events:
        table.add_row("—", "Waiting", "No structured provider event observed yet")
        return table
    for event in events:
        seconds = _seconds_since(event.get("observed_at"), now)
        label, message = _timeline_label(event)
        table.add_row(
            Text(_age(seconds), style=MUTED),
            Text(label, style=CYAN),
            Text(message, style=WHITE),
        )
    return table


def build_run_dashboard(
    status: dict[str, Any],
    config: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    width: int = 120,
    height: int = 50,
) -> Group:
    """Build one deterministic Rich renderable from allowlisted run projections."""

    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    metrics = _event_metrics(events, current_time)
    state = _clean(status.get("state"), 40) or "unknown"
    phase, _stage = runtime_phase(status)
    state_color = _state_style(state)
    elapsed = _elapsed_seconds(status, current_time)
    maximum_raw = config.get("max_seconds")
    maximum = (
        float(maximum_raw)
        if isinstance(maximum_raw, (int, float))
        and not isinstance(maximum_raw, bool)
        and math.isfinite(float(maximum_raw))
        and maximum_raw > 0
        else 0.0
    )
    remaining = max(0, int(maximum - elapsed)) if maximum > 0 else None
    protocol = status.get("protocol") if isinstance(status.get("protocol"), dict) else {}
    claim = protocol.get("claim") if isinstance(protocol.get("claim"), dict) else None
    handoff = protocol.get("handoff") if isinstance(protocol.get("handoff"), dict) else None
    collaborators = (
        protocol.get("collaborators") if isinstance(protocol.get("collaborators"), list) else []
    )

    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right", no_wrap=True)
    brand = Text("◉  B O U L E", style=f"bold {GOLD}")
    brand.append("  open-source agentic research", style=MUTED)
    state_text = Text(f"● {state.upper()}  ", style=f"bold {state_color}")
    state_text.append(_duration(elapsed), style=WHITE)
    header.add_row(brand, state_text)
    run_line = Text()
    run_line.append(_clean(status.get("agent_name"), 64) or "agent", style=f"bold {WHITE}")
    run_line.append("  ·  ", style=MUTED)
    run_line.append(_clean(status.get("provider"), 30) or "provider", style=CYAN)
    model = _clean(config.get("model"), 60) or "provider default"
    effort = _clean(config.get("effort"), 30) or "default effort"
    run_line.append(f" / {model} / {effort}", style=MUTED)
    header.add_row(run_line, Text(_short(status.get("run_id"), 42), style=MUTED))
    header_panel = Panel(header, border_style=GOLD, box=box.ROUNDED, padding=(0, 1))

    stage_panel = Panel(
        _stages(status),
        title=f"[bold {GOLD}]Current phase · {phase}[/]",
        border_style="#3b4a43",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    problem_label = (
        _clean(config.get("problem_title"), 120)
        or _clean(config.get("query"), 80)
        or _short(status.get("problem_id"), 70)
    )
    latest_message = metrics.get("latest_message") or {}
    update = _clean(latest_message.get("summary"), 420)
    if not update:
        update = "Waiting for the agent's first high-level research update."
    claim_route = _clean(claim.get("route"), 360) if claim else ""
    claim_text = (
        f"{_clean(claim.get('status'), 30)} · {claim_route}"
        if claim
        else "Not recorded yet · agent is inspecting existing work"
    )
    research_rows: list[tuple[str, Any]] = [
        ("Problem", problem_label),
        ("Mode", _clean(status.get("task_mode"), 40) or "—"),
        ("Signed claim", claim_text),
        ("Latest update", update),
    ]
    if claim and claim.get("success_gate"):
        research_rows.append(("Success gate", _clean(claim.get("success_gate"), 260)))
    if claim and claim.get("falsifier"):
        research_rows.append(("Falsifier", _clean(claim.get("falsifier"), 260)))
    if claim and claim.get("deadline"):
        research_rows.append(("Claim deadline", _clean(claim.get("deadline"), 80)))
    checkpoint_count = protocol.get("checkpoint_count")
    if isinstance(checkpoint_count, int):
        research_rows.append(("Checkpoints", str(checkpoint_count)))
    last_checkpoint = (
        protocol.get("last_checkpoint")
        if isinstance(protocol.get("last_checkpoint"), dict)
        else None
    )
    if last_checkpoint:
        research_rows.append(
            ("Latest evidence", _clean(last_checkpoint.get("summary"), 300) or "Recorded")
        )
    if handoff:
        research_rows.extend(
            [
                (
                    "Handoff",
                    f"{_clean(handoff.get('outcome'), 30)} · {_clean(handoff.get('summary'), 300)}",
                ),
                ("Review state", _clean(handoff.get("status"), 60) or "queued for review"),
            ]
        )
        if "evidence_count" in handoff or "dependency_count" in handoff:
            research_rows.append(
                (
                    "Evidence",
                    f"{int(handoff.get('evidence_count', 0))} artifacts · "
                    f"{int(handoff.get('dependency_count', 0))} dependencies",
                )
            )
        research_rows.append(("Next action", _clean(handoff.get("next_action"), 260) or "—"))
        if handoff.get("limitations"):
            research_rows.append(("Limitations", _clean(handoff.get("limitations"), 260)))
    research_panel = Panel(
        _details(research_rows),
        title=f"[bold {GOLD}]Research[/]",
        subtitle="Signed protocol state + bounded agent updates",
        border_style="#3b4a43",
        box=box.ROUNDED,
    )

    latest_tool = metrics.get("latest_tool") or {}
    tool_state = "idle"
    if latest_tool:
        tool_state = (
            f"{_clean(latest_tool.get('tool_class'), 40) or 'tool'} · "
            f"{'running' if latest_tool.get('kind') == 'tool.started' else 'completed'}"
        )
    tool_count = int(metrics["counts"].get("tool.completed", 0))
    message_count = int(metrics["counts"].get("message.completed", 0))
    plan_count = int(metrics["counts"].get("plan.updated", 0))
    event_age = metrics.get("latest_age")
    protocol_observation = status.get("protocol_observation")
    protocol_age = None
    if isinstance(protocol_observation, dict):
        protocol_age = _seconds_since(protocol_observation.get("at"), current_time)
    activity_rows = [
        ("Provider activity", tool_state),
        ("Tools", f"{tool_count} completed · {metrics['active_tools']} active"),
        ("Agent updates", f"{message_count} messages · {plan_count} plan changes"),
        ("Latest event", f"#{status.get('event_count', 0)} · {_age(event_age)}"),
        ("Clerk sync", _age(protocol_age)),
    ]
    activity_panel = Panel(
        _details(activity_rows),
        title=f"[bold {CYAN}]Live activity[/]",
        subtitle="Activity is not mathematical progress or credit",
        border_style="#3b4a43",
        box=box.ROUNDED,
    )

    usage = status.get("usage") if isinstance(status.get("usage"), dict) else None
    if usage:
        accounting = (
            f"{usage.get('input_tokens', 0):,} input "
            f"({usage.get('cache_read_tokens', 0):,} cache read) · "
            f"{usage.get('output_tokens', 0):,} output"
        )
        if usage.get("reasoning_output_tokens") is not None:
            accounting += f" · {usage.get('reasoning_output_tokens', 0):,} reasoning"
        if usage.get("cache_write_tokens") is not None:
            accounting += f" · {usage.get('cache_write_tokens', 0):,} cache write"
    else:
        accounting = "Unavailable until the provider reports a completed turn"
    runtime_rows: list[tuple[str, Any]] = [
        ("Time", f"{_duration(elapsed)} elapsed · {_duration(remaining)} remaining"),
        ("Accounting", accounting),
        ("Provider", _clean(status.get("provider_version"), 90) or "—"),
        ("Workspace", _local_path(status.get("workspace"))),
    ]
    provider_duration = _provider_duration(status.get("provider_duration_ms"))
    if provider_duration is not None:
        runtime_rows.append(("Provider duration", provider_duration))
    reported_cost = _reported_cost(status.get("provider_reported_cost_usd"))
    if reported_cost is not None:
        runtime_rows.append(("Reported cost", reported_cost))
    if state in TERMINAL_STATES:
        runtime_rows.extend(
            [
                ("Provider turn", _clean(status.get("provider_turn_status"), 40) or "—"),
                ("Exit code", str(status.get("exit_code", "—"))),
                ("Protocol", "complete" if protocol.get("complete") else "incomplete"),
            ]
        )
    if status.get("error"):
        runtime_rows.append(("Error", _clean(status.get("error"), 220)))
    if reported_cost is None:
        runtime_rows.append(("Cost", "Not reported by this provider"))
    progress = ProgressBar(
        total=max(1.0, maximum),
        completed=min(maximum, float(elapsed)) if maximum > 0 else 0,
        width=None,
        style="#26352e",
        complete_style=GOLD,
        finished_style=RED if state == "timed_out" else GREEN,
    )
    budget_label = Text("Time budget", style=MUTED)
    runtime_content = Group(_details(runtime_rows), Text(), budget_label, progress)
    runtime_panel = Panel(
        runtime_content,
        title=f"[bold {GOLD}]Runtime & accounting[/]",
        subtitle="Provider-reported · never contribution credit",
        border_style="#3b4a43",
        box=box.ROUNDED,
    )

    network_rows: list[tuple[str, Any]] = []
    if collaborators:
        for index, collaborator in enumerate(collaborators[:4], start=1):
            name = _clean(collaborator.get("agent_name"), 64) or "agent"
            route = _clean(collaborator.get("route"), 210) or "route not declared"
            network_rows.append((f"Agent {index}", f"{name} · {route}"))
    else:
        network_rows.append(("Active agents", "No other active claim observed"))
    controller = _clean(config.get("controller_id"), 80)
    if controller:
        control_label = (
            "shared local machine" if controller.startswith("local-control-") else controller
        )
        network_rows.append(("Declared control", control_label))
    message_total = protocol.get("message_count")
    network_rows.extend(
        [
            (
                "Signed chat",
                f"{message_total} messages by this session"
                if isinstance(message_total, int)
                else "not projected by this run version",
            ),
            (
                "Ledger",
                f"{(protocol_observation or {}).get('event_count', '—')} signed events · "
                f"head {_short((protocol_observation or {}).get('head_event_hash'), 18)}",
            ),
        ]
    )
    latest_signed_message = (
        protocol.get("latest_message") if isinstance(protocol.get("latest_message"), dict) else None
    )
    if latest_signed_message:
        topic = _clean(latest_signed_message.get("topic"), 50) or "coordination"
        body = _clean(latest_signed_message.get("body"), 240) or "message recorded"
        network_rows.append(("Latest chat", f"{topic} · {body}"))
    network = protocol.get("network") if isinstance(protocol.get("network"), dict) else None
    if network:
        network_rows.append(
            (
                "Case history",
                f"{int(network.get('sessions', 0))} sessions · "
                f"{int(network.get('handoffs', 0))} handoffs · "
                f"{int(network.get('messages', 0))} chat messages",
            )
        )
    network_panel = Panel(
        _details(network_rows),
        title=f"[bold {CYAN}]Collaboration network[/]",
        subtitle="Declared control ≠ proven independence",
        border_style="#3b4a43",
        box=box.ROUNDED,
    )

    body = Table.grid(expand=True, padding=(0, 1))
    if width >= 108:
        body.add_column(ratio=3)
        body.add_column(ratio=2)
        body.add_row(research_panel, runtime_panel)
        body.add_row(activity_panel, network_panel)
        body_renderable: Any = body
    else:
        body_renderable = Group(research_panel, runtime_panel, activity_panel, network_panel)

    timeline_panel = Panel(
        _timeline(metrics["material"], current_time),
        title=f"[bold {GOLD}]Recent high-level timeline[/]",
        subtitle="No prompts, reasoning, tool arguments, commands, or raw traces",
        border_style="#3b4a43",
        box=box.ROUNDED,
    )

    footer = Text()
    run_id = _clean(status.get("run_id"), 80)
    if state not in TERMINAL_STATES:
        footer.append("Ctrl-C", style=f"bold {GOLD}")
        footer.append(" stop safely  ·  ", style=MUTED)
        footer.append(f"boule run status {run_id}", style=CYAN)
        footer.append("  ·  ", style=MUTED)
        footer.append(f"boule run stop {run_id}", style=CYAN)
    elif state != "completed" and status.get("provider_session_id"):
        footer.append(f"boule run resume {run_id}", style=CYAN)
    registry = config.get("registry")
    if isinstance(registry, dict) and registry.get("origin"):
        footer.append("  ·  " if footer else "", style=MUTED)
        footer.append("Live: ", style=MUTED)
        footer.append(_clean(registry.get("origin"), 120), style=CYAN)

    if height < 38:
        very_compact = height < 30
        claim_limit = 120 if very_compact else 180
        update_limit = 140 if very_compact else 220
        result_limit = 130 if very_compact else 200
        timeline_count = 2 if very_compact else 3
        checkpoint_total = protocol.get("checkpoint_count")
        checkpoint_text = str(checkpoint_total) if isinstance(checkpoint_total, int) else "—"
        compact_rows: list[tuple[str, Any]] = [
            ("Problem", f"{problem_label} · {_clean(status.get('task_mode'), 40) or '—'}"),
            ("Claim", _clean(claim_text, claim_limit)),
            ("Latest update", _clean(update, update_limit)),
            (
                "Activity",
                f"{tool_count} tools · {metrics['active_tools']} active · "
                f"{message_count} updates · latest {_age(event_age)}",
            ),
            ("Time budget", f"{_duration(elapsed)} elapsed · {_duration(remaining)} remaining"),
            (
                "Runtime",
                f"{_clean(status.get('provider_version'), 70) or 'provider'} · "
                f"{_local_path(status.get('workspace'))}",
            ),
            ("Accounting", accounting),
            (
                "Collaboration",
                ", ".join(
                    _clean(item.get("agent_name"), 40) or "agent" for item in collaborators[:4]
                )
                or "no other active claim observed",
            ),
            (
                "Signed state",
                f"claim {'yes' if claim else 'no'} · "
                f"{checkpoint_text} checkpoints · "
                f"handoff {_clean(handoff.get('outcome'), 30) if handoff else 'pending'} · "
                f"clerk {_age(protocol_age)}",
            ),
        ]
        if provider_duration is not None:
            compact_rows.append(("Provider duration", provider_duration))
        if reported_cost is not None:
            compact_rows.append(("Reported cost", reported_cost))
        if handoff:
            compact_rows.append(
                (
                    "Result",
                    f"{_clean(handoff.get('status'), 50) or 'queued for review'} · "
                    f"{_clean(handoff.get('summary'), result_limit)}",
                )
            )
        compact_panel = Panel(
            _details(compact_rows),
            title=f"[bold {GOLD}]Live research overview[/]",
            subtitle="Observed activity ≠ mathematical progress or credit",
            border_style="#3b4a43",
            box=box.ROUNDED,
        )
        compact_timeline = Panel(
            _timeline(metrics["material"][-timeline_count:], current_time),
            title=f"[bold {CYAN}]Latest events[/]",
            subtitle="Privacy-bounded projection",
            border_style="#3b4a43",
            box=box.ROUNDED,
        )
        return Group(
            header_panel,
            stage_panel,
            compact_panel,
            compact_timeline,
            Panel(footer, border_style="#3b4a43", box=box.ROUNDED, padding=(0, 1)),
        )

    return Group(
        header_panel,
        stage_panel,
        body_renderable,
        timeline_panel,
        Panel(footer, border_style="#3b4a43", box=box.ROUNDED, padding=(0, 1)),
    )


def format_runtime_line(
    status: dict[str, Any],
    config: dict[str, Any] | None = None,
    events: list[dict[str, Any]] | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Plain one-line fallback for logs and compact run listings."""

    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    elapsed = _elapsed_seconds(status, current_time)
    phase, _stage = runtime_phase(status)
    metrics = _event_metrics(events or [], current_time)
    protocol = status.get("protocol") if isinstance(status.get("protocol"), dict) else {}
    claim = protocol.get("claim") if isinstance(protocol.get("claim"), dict) else None
    fields = [
        f"[{_duration(elapsed)}]",
        _clean(status.get("agent_name"), 64) or "agent",
        f"· {str(status.get('state', 'unknown')).upper()} / {phase}",
    ]
    provider = _clean(status.get("provider"), 30) or "provider"
    model = _clean((config or {}).get("model"), 50) or "default-model"
    effort = _clean((config or {}).get("effort"), 24) or "default-effort"
    fields.append(f"· {provider}/{model}/{effort}")
    if claim and claim.get("route"):
        fields.append(f"· route: {_clean(claim.get('route'), 100)}")
    latest = metrics.get("latest")
    if latest:
        activity = _clean(latest.get("kind"), 40)
        if latest.get("tool_class"):
            activity += f"/{_clean(latest.get('tool_class'), 40)}"
        fields.append(
            f"· activity: #{latest.get('sequence', status.get('event_count', 0))} "
            f"{activity} ({_age(metrics.get('latest_age'))})"
        )
    usage = status.get("usage") if isinstance(status.get("usage"), dict) else None
    if usage:
        fields.append(
            f"· tokens: {usage.get('input_tokens', 0):,} in / "
            f"{usage.get('output_tokens', 0):,} out (provider-reported)"
        )
    else:
        fields.append("· tokens: pending provider report")
    provider_duration = _provider_duration(status.get("provider_duration_ms"))
    if provider_duration is not None:
        fields.append(f"· provider time: {provider_duration}")
    reported_cost = _reported_cost(status.get("provider_reported_cost_usd"))
    if reported_cost is not None:
        fields.append(f"· reported cost: {reported_cost}")
    return " ".join(fields)


class RunTerminal:
    """One renderer shared by foreground execution and `boule run watch`."""

    def __init__(
        self,
        store: RunStore,
        run_id: str,
        *,
        stream: TextIO | None = None,
        heartbeat_seconds: float = 30.0,
    ) -> None:
        self.store = store
        self.run_id = run_id
        self.console = BouleConsole(
            file=stream or sys.stdout,
            force_terminal=None,
            color_system="auto",
            highlight=False,
            soft_wrap=False,
        )
        self.heartbeat_seconds = heartbeat_seconds
        self.live: Live | None = None
        self.last_plain_signature: tuple[Any, ...] | None = None
        self.last_plain_at = 0.0
        self.disabled = False
        self._event_offset = 0
        self._events: list[dict[str, Any]] = []
        self._config: dict[str, Any] | None = None

    def _values(self) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        if self._config is None:
            self._config = self.store.config(self.run_id)
        appended, offset = self.store.events_since(self.run_id, self._event_offset)
        self._event_offset = offset
        self._events.extend(appended)
        return self.store.status(self.run_id), self._config, self._events

    def _render(self) -> Group:
        status, config, events = self._values()
        return build_run_dashboard(
            status,
            config,
            events,
            width=self.console.size.width,
            height=self.console.size.height,
        )

    def start(self) -> None:
        if self.disabled:
            return
        try:
            if self.console.is_terminal:
                self.live = Live(
                    self._render(),
                    console=self.console,
                    auto_refresh=False,
                    transient=False,
                    vertical_overflow="ellipsis",
                )
                self.live.start(refresh=True)
            else:
                self.refresh(force=True)
        except Exception:
            self._disable()

    def refresh(self, *, force: bool = False) -> None:
        if self.disabled:
            return
        try:
            status, config, events = self._values()
            if self.live is not None:
                self.live.update(
                    build_run_dashboard(
                        status,
                        config,
                        events,
                        width=self.console.size.width,
                        height=self.console.size.height,
                    ),
                    refresh=True,
                )
                return
            protocol = status.get("protocol") or {}
            latest = events[-1] if events else {}
            signature = (
                status.get("state"),
                status.get("event_count"),
                status.get("usage"),
                protocol.get("claim"),
                protocol.get("handoff"),
                protocol.get("collaborators"),
                latest.get("kind"),
                latest.get("tool_class"),
            )
            clock = time.monotonic()
            if (
                force
                or signature != self.last_plain_signature
                or clock - self.last_plain_at >= self.heartbeat_seconds
            ):
                self.console.print(format_runtime_line(status, config, events))
                self.last_plain_signature = signature
                self.last_plain_at = clock
        except Exception:
            self._disable()

    def close(self) -> None:
        if self.disabled:
            return
        try:
            if self.live is not None:
                self.refresh(force=True)
                if self.live is not None:
                    # Rich deliberately switches to visible overflow on stop. On
                    # a very short terminal, leave one useful summary instead of
                    # dumping the entire dashboard into scrollback.
                    if self.console.size.height < 30:
                        status, config, events = self._values()
                        self.live.update(Text(format_runtime_line(status, config, events)))
                    self.live.stop()
                    self.live = None
        except Exception:
            self._disable()

    def _disable(self) -> None:
        live, self.live = self.live, None
        self.disabled = True
        if live is not None:
            try:
                live.stop()
            except Exception:
                pass


def print_run_dashboard(store: RunStore, run_id: str, *, stream: TextIO | None = None) -> None:
    console = BouleConsole(
        file=stream or sys.stdout,
        force_terminal=None,
        color_system="auto",
        highlight=False,
        soft_wrap=False,
    )
    status = store.status(run_id)
    config = store.config(run_id)
    events = store.events(run_id)
    if not console.is_terminal:
        console.print(format_runtime_line(status, config, events))
        return
    console.print(
        build_run_dashboard(
            status,
            config,
            events,
            width=console.size.width,
            height=console.size.height,
        )
    )


def print_run_list(
    store: RunStore, values: list[dict[str, Any]], *, stream: TextIO | None = None
) -> None:
    console = BouleConsole(
        file=stream or sys.stdout,
        force_terminal=None,
        color_system="auto",
        highlight=False,
    )
    table = Table(
        title="BOULE · SUPERVISED RESEARCH RUNS",
        title_style=f"bold {GOLD}",
        box=box.ROUNDED,
        border_style="#3b4a43",
        header_style=f"bold {MUTED}",
        expand=True,
    )
    table.add_column("RUN", no_wrap=True)
    table.add_column("AGENT", no_wrap=True)
    table.add_column("PROVIDER")
    table.add_column("PHASE")
    table.add_column("ELAPSED", justify="right", no_wrap=True)
    table.add_column("ACTIVITY")
    table.add_column("ROUTE", ratio=2, overflow="ellipsis")
    now = datetime.now(UTC)
    if not console.is_terminal:
        for value in values:
            try:
                config = store.config(str(value["run_id"]))
                events = store.events(str(value["run_id"]))
            except (KeyError, OSError, ProtocolError):
                config, events = {}, []
            console.print(
                f"{_clean(value.get('run_id'), 80)}  "
                f"{format_runtime_line(value, config, events, now=now)}"
            )
        return
    for value in values:
        try:
            config = store.config(str(value["run_id"]))
            events = store.events(str(value["run_id"]))
        except (KeyError, OSError, ProtocolError):
            config, events = {}, []
        phase, _stage = runtime_phase(value)
        metrics = _event_metrics(events, now)
        latest = metrics.get("latest") or {}
        activity = _clean(latest.get("kind"), 32) or "—"
        if latest.get("tool_class"):
            activity += f"/{_clean(latest.get('tool_class'), 24)}"
        protocol = value.get("protocol") if isinstance(value.get("protocol"), dict) else {}
        claim = protocol.get("claim") if isinstance(protocol.get("claim"), dict) else None
        elapsed = _elapsed_seconds(value, now)
        provider = _clean(value.get("provider"), 20) or "—"
        model = _clean(config.get("model"), 28)
        if model:
            provider += f"/{model}"
        table.add_row(
            Text(_short(value.get("run_id"), 24)),
            Text(_clean(value.get("agent_name"), 32) or "—"),
            Text(provider),
            Text(phase, style=_state_style(str(value.get("state")))),
            Text(_duration(elapsed)),
            Text(activity),
            Text(_clean(claim.get("route"), 90) if claim else "—"),
        )
    console.print(table)
