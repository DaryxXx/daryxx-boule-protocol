from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
from .community import CommunityLedger, replay_community_ledger
from .community_demo import (
    build_community_demo,
    render_agent_prompt,
    render_frontier_markdown,
    render_join_brief_markdown,
)
from .crypto import generate_private_key, public_key_text, write_private_key
from .demo import build_demo_session
from .errors import ProtocolError
from .ledger import Ledger
from .maintainer_advisor import ALLOWED_MODELS, advise
from .policy import DISCLOSURE_MODES, build_case_policy
from .problem_import import import_problem
from .protocol import replay_ledger
from .session_store import SessionStore, load_maintainer_key, maintainer_key_path
from .workspace import Workspace


def _print(value: Any, compact: bool) -> None:
    if compact:
        print(canonical_bytes(value).decode("utf-8"))
    else:
        print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _demo(args: argparse.Namespace) -> int:
    session = build_demo_session()
    if args.output:
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=False)
    else:
        output = Path(tempfile.mkdtemp(prefix="boule-demo-"))
    ledger_path = session.ledger.write(output / "ledger.jsonl")
    summary = session.state.summary()
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    result = {"ledger": str(ledger_path), "summary": summary}
    _print(result, args.json)
    return 0


def _verify(args: argparse.Namespace) -> int:
    ledger = Ledger.read(args.path)
    state = replay_ledger(ledger)
    if args.require_decision and state.decision is None:
        raise ProtocolError("ledger is valid but has no provisional decision")
    _print(state.summary(), args.json)
    return 0


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _community_demo(args: argparse.Namespace) -> int:
    demo = build_community_demo()
    if args.output:
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=False)
    else:
        output = Path(tempfile.mkdtemp(prefix="boule-community-demo-"))
    community = demo.session
    ledger_path = community.ledger.write(output / "ledger.jsonl")
    summary = community.state.summary()
    _write_json(output / "case-manifest.json", community.state.manifest)
    _write_json(output / "summary.json", summary)
    _write_json(output / "mock-payout-plan.json", community.state.payout_plan)
    _write_json(
        output / "mock-checks.json",
        {
            "cold_resumes": demo.cold_resumes,
            "incomplete_attribution_blocked": demo.incomplete_attribution_blocked,
            "simulation": True,
        },
    )
    (output / "frontier.md").write_text(render_frontier_markdown(community), encoding="utf-8")
    (output / "join-brief.md").write_text(render_join_brief_markdown(community), encoding="utf-8")
    (output / "agent-prompt.md").write_text(render_agent_prompt(community), encoding="utf-8")
    with (output / "chat.jsonl").open("x", encoding="utf-8", newline="\n") as handle:
        for message_id, message in community.state.messages.items():
            payload = message["payload"]
            session = community.state.sessions[payload["session_id"]]
            handle.write(
                canonical_bytes(
                    {
                        "message_id": message_id,
                        "participant_id": session.participant_id,
                        "received_at": message["received_at"],
                        "payload": payload,
                        "entry_hash": message["entry_hash"],
                    }
                ).decode("utf-8")
                + "\n"
            )
    _print(
        {
            "ledger": str(ledger_path),
            "output": str(output),
            "mock_checks": {
                "cold_resumes": demo.cold_resumes,
                "incomplete_attribution_blocked": demo.incomplete_attribution_blocked,
            },
            "summary": summary,
        },
        args.json,
    )
    return 0


def _verify_community(args: argparse.Namespace) -> int:
    ledger = CommunityLedger.read(args.path)
    state = replay_community_ledger(ledger)
    if args.require_allocation and (
        state.allocation is None or state.allocation["status"] != "decided"
    ):
        raise ProtocolError("community ledger is valid but has no decided allocation")
    if args.require_mock_paid and state.phase != "mock_paid":
        raise ProtocolError("community ledger is valid but mock payout is not complete")
    _print(state.summary(), args.json)
    return 0


def _community_join_brief(args: argparse.Namespace) -> int:
    ledger = CommunityLedger.read(args.path)
    state = replay_community_ledger(ledger)
    if args.markdown:
        # The renderer only needs a state-bearing session-like object.
        class _View:
            def __init__(self, state):
                self.state = state

        print(render_join_brief_markdown(_View(state), args.at), end="")
    else:
        _print(state.join_brief(args.at), args.json)
    return 0


def _community_agent_prompt(args: argparse.Namespace) -> int:
    ledger = CommunityLedger.read(args.path)
    state = replay_community_ledger(ledger)

    class _View:
        def __init__(self, state):
            self.state = state

    print(render_agent_prompt(_View(state), args.at), end="")
    return 0


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _public_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event["event_id"],
        "event_hash": event["event_hash"],
        "kind": event["kind"],
        "received_at": event["received_at"],
    }


def _write_case_support_files(problem_dir: Path) -> None:
    ignore = problem_dir / ".boule" / ".gitignore"
    if not ignore.exists():
        ignore.write_text(
            "private/\nlock\nprojection.json\nmaintainer-receipt.json\n"
            "advisories/\nwatcher.json\n",
            encoding="utf-8",
        )
    guide = problem_dir / "BOULE.md"
    if not guide.exists():
        problem = json.loads((problem_dir / "problem.json").read_text(encoding="utf-8"))
        policy = json.loads(
            (problem_dir / ".boule" / "policy.json").read_text(encoding="utf-8")
        )
        guide.write_text(
            "# Continue this Boule problem\n\n"
            f"Problem: {problem['problem']['title']}\n\n"
            "Run `boule brief .`, start or load your session, choose one bounded route "
            "that is not already claimed, and publish a signed checkpoint or handoff "
            f"before stopping. The frozen evidence disclosure mode is `{policy['disclosure']}`. "
            "Signed summaries and chat are public metadata; keep undisclosed methods behind "
            "digests or authorized evidence references. Chat coordinates work but is not "
            "contribution evidence. "
            "Do not submit a result, spend funds, or expose private prompts or secrets.\n",
            encoding="utf-8",
        )
    agent_rules = (
        "# Boule case session\n\n"
        "Run `boule brief .` and `boule status .` before substantive work. Use the "
        "assigned `BOULE_SESSION`, or ask the controller to create one with `boule agent "
        "start`. Choose one narrow unclaimed route; roles are optional labels only. Keep the "
        "claim alive with a heartbeat, publish a signed checkpoint after reusable progress, "
        "and publish ADVANCE, NEGATIVE, BLOCKED, or NO_SIGNAL before stopping. Declare every "
        "handoff dependency and citation. Chat coordinates work but is not prize evidence. "
        "Never submit, spend funds, expose secrets/private traces, claim another session's "
        "work, or treat maintainer advice as mathematical review.\n"
    )
    for name in ("AGENTS.md", "CLAUDE.md"):
        path = problem_dir / name
        if not path.exists():
            path.write_text(agent_rules, encoding="utf-8")


def _init_problem(args: argparse.Namespace) -> int:
    result = import_problem(
        args.url,
        args.root,
        mode=args.mode,
        refresh_snapshot=args.refresh_snapshot,
    )
    control = result.path / ".boule"
    initialized = False
    if not control.exists():
        maintainer_key = generate_private_key()
        workspace = Workspace.initialize(
            result.path,
            {
                "maintainer_key": public_key_text(maintainer_key),
                "lease_seconds": args.lease_seconds,
                "absolute_lease_seconds": args.absolute_lease_seconds,
                "stale_seconds": args.stale_seconds,
                "max_renewals": args.max_renewals,
            },
            policy=build_case_policy(result.manifest, args.disclosure),
        )
        write_private_key(maintainer_key_path(workspace), maintainer_key)
        initialized = True
    else:
        Workspace(result.path)
    _write_case_support_files(result.path)
    _print(
        {
            "created": result.created,
            "initialized": initialized,
            "path": str(result.path.resolve()),
            "problem_id": result.manifest["problem_id"],
            "task_id": result.manifest["task"]["task_id"],
            "task_commitment": result.manifest["task"]["task_commitment"],
            "snapshot_created": result.snapshot_created,
            "disclosure": Workspace(result.path).policy["disclosure"],
            "next": f"boule agent start {result.path} --participant NAME --controller CONTROLLER",
        },
        args.json,
    )
    return 0


def _workspace(args: argparse.Namespace) -> Workspace:
    return Workspace(Path(args.problem))


def _session(args: argparse.Namespace) -> tuple[Workspace, dict[str, Any], Any]:
    workspace = _workspace(args)
    session_id = args.session or os.environ.get("BOULE_SESSION")
    if not session_id:
        raise ProtocolError("pass --session or set BOULE_SESSION")
    profile, key = SessionStore(workspace).load(session_id)
    return workspace, profile, key


def _identity_payload(workspace: Workspace, profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "problem_id": workspace.problem["problem_id"],
        "participant_id": profile["participant_id"],
        "session_id": profile["session_id"],
    }


def _active_claim(workspace: Workspace, profile: dict[str, Any], claim_id: str | None) -> str:
    state = workspace.state(_now())
    if claim_id:
        return claim_id
    session = next(
        (item for item in state["sessions"] if item["session_id"] == profile["session_id"]),
        None,
    )
    if session is None or session["active_claim"] is None:
        raise ProtocolError("session has no active claim; pass --claim when referring to history")
    return str(session["active_claim"])


def _evidence(problem: Path, artifacts: list[str], references: list[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    root = problem.resolve()
    for raw in artifacts:
        path = Path(raw).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ProtocolError("artifact paths must be inside the problem directory") from exc
        if not path.is_file():
            raise ProtocolError(f"artifact is not a file: {raw}")
        items.append(
            {
                "ref": relative.as_posix(),
                "sha256": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
            }
        )
    for raw in references:
        try:
            reference, digest = raw.rsplit("=", 1)
        except ValueError as exc:
            raise ProtocolError("--evidence must be REF=sha256:HEX") from exc
        items.append({"ref": reference, "sha256": digest})
    if len(items) != len({(item["ref"], item["sha256"]) for item in items}):
        raise ProtocolError("duplicate evidence reference")
    return items


def _agent_start(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    if not math.isfinite(args.hours) or not 0 < args.hours <= 168:
        raise ProtocolError("session lifetime must be greater than 0 and at most 168 hours")
    started = datetime.now(UTC)
    profile = SessionStore(workspace).start(
        participant_id=args.participant,
        controller_id=args.controller,
        label=args.label,
        not_after=(started + timedelta(hours=args.hours)).isoformat().replace("+00:00", "Z"),
    )
    _print(
        {
            "problem_id": profile["problem_id"],
            "participant_id": profile["participant_id"],
            "controller_id": profile["controller_id"],
            "session_id": profile["session_id"],
            "session_key": profile["session_key"],
            "not_after": profile["not_after"],
            "profile_path": profile["profile_path"],
            "next": f"boule brief {workspace.root} --session {profile['session_id']}",
        },
        args.json,
    )
    return 0


def _agent_claim(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = args.claim_id or f"c-{secrets.token_hex(8)}"
    event = workspace.append(
        "work_claimed",
        {
            **_identity_payload(workspace, profile),
            "claim_id": claim_id,
            "route": args.route,
            "success_gate": args.success_gate,
            "falsifier": args.falsifier,
            "parallel": args.parallel,
        },
        key,
    )
    _print({**_public_event(event), "claim_id": claim_id}, args.json)
    return 0


def _agent_heartbeat(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim)
    progress_digest = f"sha256:{hashlib.sha256(args.progress.encode()).hexdigest()}"
    event = workspace.append(
        "claim_heartbeat",
        {
            **_identity_payload(workspace, profile),
            "claim_id": claim_id,
            "progress_digest": progress_digest,
        },
        key,
    )
    _print(
        {**_public_event(event), "claim_id": claim_id, "progress_digest": progress_digest},
        args.json,
    )
    return 0


def _agent_checkpoint(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim)
    event = workspace.append(
        "checkpoint_published",
        {
            **_identity_payload(workspace, profile),
            "claim_id": claim_id,
            "summary": args.summary,
            "next_action": args.next_action,
            "evidence": _evidence(workspace.root, args.artifact, args.evidence),
        },
        key,
    )
    _print({**_public_event(event), "claim_id": claim_id}, args.json)
    return 0


def _agent_chat(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    event = workspace.append(
        "message_posted",
        {
            **_identity_payload(workspace, profile),
            "claim_id": args.claim,
            "topic": args.topic,
            "body": args.body,
        },
        key,
    )
    _print({**_public_event(event), "coordination_only": True}, args.json)
    return 0


def _agent_release(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim)
    event = workspace.append(
        "claim_released",
        {**_identity_payload(workspace, profile), "claim_id": claim_id, "reason": args.reason},
        key,
    )
    _print({**_public_event(event), "claim_id": claim_id}, args.json)
    return 0


def _agent_handoff(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim)
    handoff_id = args.handoff_id or f"h-{secrets.token_hex(8)}"
    event = workspace.append(
        "handoff_published",
        {
            **_identity_payload(workspace, profile),
            "claim_id": claim_id,
            "handoff_id": handoff_id,
            "outcome": args.outcome,
            "summary": args.summary,
            "next_action": args.next_action,
            "limitations": args.limitations,
            "reproduce": args.reproduce,
            "evidence": _evidence(workspace.root, args.artifact, args.evidence),
            "depends_on": args.depends_on,
            "provenance": args.provenance,
            "citations": args.citation,
        },
        key,
    )
    _print({**_public_event(event), "claim_id": claim_id, "handoff_id": handoff_id}, args.json)
    return 0


def _status(args: argparse.Namespace) -> int:
    _print(_workspace(args).state(args.at or _now()), args.json)
    return 0


def _agents(args: argparse.Namespace) -> int:
    state = _workspace(args).state(args.at or _now())
    claims = {claim["claim_id"]: claim for claim in state["claims"]}
    result = []
    for session in state["sessions"]:
        active = session["active_claim"]
        result.append(
            {
                "session_id": session["session_id"],
                "participant_id": session["participant_id"],
                "controller_id": session["controller_id"],
                "label": session.get("label"),
                "status": session["status"],
                "active_claim": claims.get(active) if active else None,
            }
        )
    _print({"problem_id": state["problem_id"], "sessions": result}, args.json)
    return 0


def _chat(args: argparse.Namespace) -> int:
    state = _workspace(args).state(args.at or _now())
    _print(
        {
            "problem_id": state["problem_id"],
            "coordination_only": True,
            "messages": state["messages"],
        },
        args.json,
    )
    return 0


def _history(args: argparse.Namespace) -> int:
    state = _workspace(args).state(args.at or _now())
    _print(
        {
            "problem_id": state["problem_id"],
            "sessions": state["sessions"],
            "claims": state["claims"],
            "checkpoints": state["checkpoints"],
            "handoffs": state["handoffs"],
        },
        args.json,
    )
    return 0


def _brief(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    state = workspace.state(args.at or _now())
    problem = workspace.problem
    task = problem["task"]
    active = [claim for claim in state["claims"] if claim["status"] in {"active", "stale"}]
    lines = [
        f"# {problem['problem']['title']}",
        "",
        f"- Problem id: `{problem['problem_id']}`",
        f"- Conjectures task: `{task['task_id']}` ({task['mode']})",
        f"- Task commitment: `{task['task_commitment']}`",
        f"- Source pin: `{task['formal_repository_pin']}`",
        f"- Active/stale claims: {len(active)}",
        f"- Queued handoffs: {len(state['handoffs'])}",
        "",
        "## Current work",
        "",
    ]
    if active:
        for claim in active:
            lines.append(
                f"- `{claim['claim_id']}` [{claim['status']}]: {claim['route']} "
                f"(session `{claim['session_id']}`)"
            )
    else:
        lines.append("- No active claims.")
    lines.extend(
        [
            "",
            "## Agent instruction",
            "",
            "Read this brief and the accepted artifacts. Choose one narrow useful route that "
            "does not duplicate an active claim, or declare `--parallel` deliberately. Record "
            "a heartbeat/checkpoint while working and a signed ADVANCE, NEGATIVE, BLOCKED, or "
            "NO_SIGNAL handoff before stopping. Declare dependencies and citations. Chat is "
            "coordination only. Do not submit, spend funds, expose secrets, or claim another "
            "session's work.",
        ]
    )
    if args.session:
        lines.extend(["", f"Local session: `{args.session}` (or set `BOULE_SESSION`)."])
    print("\n".join(lines) + "\n")
    return 0


def _maintainer_tick(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    tick = workspace.maintainer_tick(args.at or _now(), load_maintainer_key(workspace))
    _print(tick, args.json)
    return 0


def _maintainer_advise(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    tick = workspace.maintainer_tick(args.at or _now(), load_maintainer_key(workspace))
    suggestion = advise(
        workspace.root,
        tick,
        model=args.model,
        reasoning="low",
        timeout=args.timeout,
    )
    _print({"tick": tick, "advisory": suggestion}, args.json)
    return 0


def _write_watcher_status(workspace: Workspace, value: dict[str, Any]) -> None:
    Workspace._write(workspace.control / "watcher.json", value)


def _maintainer_watch(args: argparse.Namespace) -> int:
    if args.cycles < 0 or args.interval < 0:
        raise ProtocolError("watch cycles and interval must be non-negative")
    if args.cycles == 0 and args.interval < 5:
        raise ProtocolError("continuous watch interval must be at least 5 seconds")
    workspace = _workspace(args)
    key = load_maintainer_key(workspace)
    cycle = 0
    last: dict[str, Any] | None = None
    try:
        while args.cycles == 0 or cycle < args.cycles:
            cycle += 1
            tick = workspace.maintainer_tick(_now(), key)
            advisory = None
            if args.advisor:
                advisory = advise(
                    workspace.root,
                    tick,
                    model=args.model,
                    reasoning="low",
                    timeout=args.timeout,
                )
            last = {"cycle": cycle, "tick": tick, "advisory": advisory}
            _write_watcher_status(
                workspace,
                {
                    "pid": os.getpid(),
                    "cycle": cycle,
                    "last_tick_at": tick["status"]["at"],
                    "status_digest": tick["receipt"]["status_digest"],
                    "advisor_enabled": args.advisor,
                },
            )
            if args.cycles == 0 or cycle < args.cycles:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    if last is None:
        raise ProtocolError("watcher did not run")
    _print(last, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="boule")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="create a local synthetic collaboration transcript")
    demo.add_argument("--output", help="new directory for ledger.jsonl and summary.json")
    demo.add_argument("--json", action="store_true", help="emit compact machine-readable JSON")
    demo.set_defaults(handler=_demo)

    verify = subparsers.add_parser(
        "verify-ledger", help="verify ledger integrity and replay its protocol state"
    )
    verify.add_argument("path", help="path to a Boule JSONL ledger")
    verify.add_argument("--json", action="store_true", help="emit compact machine-readable JSON")
    verify.add_argument(
        "--require-decision",
        action="store_true",
        help="fail when the valid transcript has not recorded a provisional decision",
    )
    verify.set_defaults(handler=_verify)

    community_demo = subparsers.add_parser(
        "community-demo",
        help="create a local zero-value asynchronous handoff fixture",
    )
    community_demo.add_argument("--output", help="new directory for the community mock artifacts")
    community_demo.add_argument(
        "--json", action="store_true", help="emit compact machine-readable JSON"
    )
    community_demo.set_defaults(handler=_community_demo)

    community_verify = subparsers.add_parser(
        "verify-community-ledger",
        help="verify and replay a Boule Community mock ledger",
    )
    community_verify.add_argument("path", help="path to the community ledger JSONL")
    community_verify.add_argument(
        "--require-allocation",
        action="store_true",
        help="fail unless a decided causal allocation exists",
    )
    community_verify.add_argument(
        "--require-mock-paid",
        action="store_true",
        help="fail unless every simulated payout leg is finalized",
    )
    community_verify.add_argument(
        "--json", action="store_true", help="emit compact machine-readable JSON"
    )
    community_verify.set_defaults(handler=_verify_community)

    join = subparsers.add_parser(
        "community-join-brief",
        help="render the minimum cold-resume brief from a community ledger",
    )
    join.add_argument("path", help="path to the community ledger JSONL")
    join.add_argument("--at", help="ISO-8601 time used to evaluate active route leases")
    join.add_argument("--markdown", action="store_true", help="render a human brief")
    join.add_argument("--json", action="store_true", help="emit compact JSON")
    join.set_defaults(handler=_community_join_brief)

    prompt = subparsers.add_parser(
        "community-agent-prompt",
        help="render a copyable zero-value agent prompt from a community ledger",
    )
    prompt.add_argument("path", help="path to the community ledger JSONL")
    prompt.add_argument("--at", help="ISO-8601 time used to evaluate active route leases")
    prompt.set_defaults(handler=_community_agent_prompt)

    init = subparsers.add_parser(
        "init", help="import and initialize one pinned Conjectures.io problem"
    )
    init.add_argument("url", help="https://conjectures.io/problems/<slug> URL")
    init.add_argument("--root", default="problems", help="directory containing local cases")
    init.add_argument("--mode", choices=["formalized", "counterexample"])
    init.add_argument("--refresh-snapshot", action="store_true")
    init.add_argument(
        "--disclosure",
        choices=sorted(DISCLOSURE_MODES),
        default="commitment_only",
        help="frozen evidence disclosure mode",
    )
    init.add_argument("--lease-seconds", type=int, default=3600)
    init.add_argument("--absolute-lease-seconds", type=int, default=14400)
    init.add_argument("--stale-seconds", type=int, default=900)
    init.add_argument("--max-renewals", type=int, default=3)
    init.add_argument("--json", action="store_true", help="emit compact JSON")
    init.set_defaults(handler=_init_problem)

    def read_command(name: str, help_text: str, handler: Any) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("problem", help="initialized problem directory")
        command.add_argument("--at", help="ISO-8601 UTC observation time")
        command.add_argument("--json", action="store_true", help="emit compact JSON")
        command.set_defaults(handler=handler)
        return command

    status = read_command("status", "show current verified workspace state", _status)
    agents = read_command("agents", "list sessions and their active work", _agents)
    chat_view = read_command("chat", "show problem coordination chat", _chat)
    history = read_command("history", "show durable session and handoff history", _history)
    # Keep local variables referenced for static linters and future parser extensions.
    del status, agents, chat_view, history

    brief = subparsers.add_parser("brief", help="render a short cold-resume agent brief")
    brief.add_argument("problem", help="initialized problem directory")
    brief.add_argument("--session", help="local session id to mention in the brief")
    brief.add_argument("--at", help="ISO-8601 UTC observation time")
    brief.set_defaults(handler=_brief)

    agent = subparsers.add_parser("agent", help="append signed participant activity")
    agent_commands = agent.add_subparsers(dest="agent_command", required=True)

    start = agent_commands.add_parser("start", help="create and delegate a local session key")
    start.add_argument("problem", help="initialized problem directory")
    start.add_argument("--participant", required=True, help="stable participant id")
    start.add_argument("--controller", required=True, help="self-declared common controller id")
    start.add_argument("--label", help="optional descriptive session label")
    start.add_argument("--hours", type=float, default=24.0, help="session lifetime")
    start.add_argument("--json", action="store_true", help="emit compact JSON")
    start.set_defaults(handler=_agent_start)

    def participant_command(name: str, help_text: str, handler: Any) -> argparse.ArgumentParser:
        command = agent_commands.add_parser(name, help=help_text)
        command.add_argument("problem", help="initialized problem directory")
        command.add_argument("--session", help="session id; defaults to BOULE_SESSION")
        command.add_argument("--json", action="store_true", help="emit compact JSON")
        command.set_defaults(handler=handler)
        return command

    claim = participant_command("claim", "claim one bounded work route", _agent_claim)
    claim.add_argument("--claim-id", help="optional stable claim id")
    claim.add_argument("--route", required=True, help="narrow question being attempted")
    claim.add_argument("--success-gate", required=True, help="objective success condition")
    claim.add_argument("--falsifier", required=True, help="result that would close this route")
    claim.add_argument("--parallel", action="store_true", help="deliberate independent overlap")

    heartbeat = participant_command(
        "heartbeat", "renew an active claim with a progress commitment", _agent_heartbeat
    )
    heartbeat.add_argument("--claim", help="claim id; defaults to session active claim")
    heartbeat.add_argument("--progress", required=True, help="progress text hashed locally")

    def evidence_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--artifact", action="append", default=[], help="file inside the problem to hash"
        )
        command.add_argument(
            "--evidence",
            action="append",
            default=[],
            metavar="REF=sha256:HEX",
            help="precomputed evidence reference",
        )

    checkpoint = participant_command(
        "checkpoint", "preserve resumable progress on an active claim", _agent_checkpoint
    )
    checkpoint.add_argument("--claim", help="claim id; defaults to session active claim")
    checkpoint.add_argument("--summary", required=True)
    checkpoint.add_argument("--next", "--next-action", dest="next_action", required=True)
    evidence_arguments(checkpoint)

    chat = participant_command("chat", "post a signed coordination-only message", _agent_chat)
    chat.add_argument("--claim", help="optional existing claim being discussed")
    chat.add_argument("--topic", required=True)
    chat.add_argument("--body", required=True)

    release = participant_command(
        "release", "release an active claim without a handoff", _agent_release
    )
    release.add_argument("--claim", help="claim id; defaults to session active claim")
    release.add_argument("--reason", required=True)

    handoff = participant_command(
        "handoff", "publish a signed evidence-linked research handoff", _agent_handoff
    )
    handoff.add_argument("--claim", help="claim id; defaults to session active claim")
    handoff.add_argument("--handoff-id", help="optional stable handoff id")
    handoff.add_argument(
        "--outcome", required=True, choices=["ADVANCE", "NEGATIVE", "BLOCKED", "NO_SIGNAL"]
    )
    handoff.add_argument("--summary", required=True)
    handoff.add_argument("--next", "--next-action", dest="next_action", required=True)
    handoff.add_argument("--limitations", default="No additional limitations declared.")
    handoff.add_argument("--reproduce", required=True)
    handoff.add_argument("--depends-on", action="append", default=[])
    handoff.add_argument(
        "--provenance",
        choices=["original", "adapted", "reproduction", "unknown"],
        default="unknown",
    )
    handoff.add_argument("--citation", action="append", default=[])
    evidence_arguments(handoff)

    maintainer = subparsers.add_parser(
        "maintainer", help="run deterministic maintenance or optional read-only advice"
    )
    maintainer_commands = maintainer.add_subparsers(dest="maintainer_command", required=True)

    tick = maintainer_commands.add_parser("tick", help="verify, project, expire, and sign state")
    tick.add_argument("problem", help="initialized problem directory")
    tick.add_argument("--at", help="ISO-8601 UTC receipt time")
    tick.add_argument("--json", action="store_true", help="emit compact JSON")
    tick.set_defaults(handler=_maintainer_tick)

    def advisor_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--model", choices=sorted(ALLOWED_MODELS), default="gpt-5.6-sol")
        command.add_argument("--timeout", type=float, default=120.0)

    advisory = maintainer_commands.add_parser(
        "advise", help="request one advisory-only low-reasoning Codex opinion"
    )
    advisory.add_argument("problem", help="initialized problem directory")
    advisory.add_argument("--at", help="ISO-8601 UTC receipt time")
    advisory.add_argument("--json", action="store_true", help="emit compact JSON")
    advisor_arguments(advisory)
    advisory.set_defaults(handler=_maintainer_advise)

    watch = maintainer_commands.add_parser(
        "watch", help="run bounded or continuous deterministic maintenance"
    )
    watch.add_argument("problem", help="initialized problem directory")
    watch.add_argument("--interval", type=float, default=60.0, help="seconds between ticks")
    watch.add_argument("--cycles", type=int, default=1, help="0 means run until interrupted")
    watch.add_argument("--advisor", action="store_true", help="run advice once per state digest")
    watch.add_argument("--json", action="store_true", help="emit compact JSON")
    advisor_arguments(watch)
    watch.set_defaults(handler=_maintainer_watch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ProtocolError, FileExistsError, OSError) as exc:
        print(f"boule: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
