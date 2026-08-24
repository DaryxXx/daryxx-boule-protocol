from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import stat
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .canonical import canonical_bytes
from .case_scaffold import write_case_support_files
from .clerk_api import build_server as build_clerk_server
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
from .hub import Hub
from .ledger import Ledger
from .maintainer_advisor import ALLOWED_MODELS, advise
from .policy import DISCLOSURE_MODES, build_case_policy
from .problem_import import import_problem
from .protocol import replay_ledger
from .provisioner import GitHubAppRepositoryProvider, LocalRepositoryProvider
from .registry import MAX_CHAIN_PROOF_ENTRIES, verify_registry_snapshot
from .registry_api import build_server as build_registry_server
from .remote_client import RemoteClient
from .session_store import SessionStore, load_maintainer_key, maintainer_key_path
from .trust_store import read_registry_trust, trust_registry_snapshot
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
    write_case_support_files(result.path)
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
            "next": f"boule agent start {result.path} --name NAME --controller CONTROLLER",
        },
        args.json,
    )
    return 0


def _workspace(args: argparse.Namespace) -> Workspace:
    return Workspace(Path(args.problem))


def _server(args: argparse.Namespace, *, required: bool = False) -> str | None:
    value = getattr(args, "server", None) or os.environ.get("BOULE_SERVER")
    if required and not value:
        raise ProtocolError("pass --server or set BOULE_SERVER")
    return value


def _remote_client(workspace: Workspace, args: argparse.Namespace) -> RemoteClient | None:
    server = _server(args)
    return RemoteClient(workspace, server) if server else None


def _workspace_state(workspace: Workspace, args: argparse.Namespace) -> dict[str, Any]:
    client = _remote_client(workspace, args)
    if client is not None:
        if getattr(args, "at", None):
            raise ProtocolError("--at is not supported with a remote signed snapshot")
        return client.fetch_state()["state"]
    return workspace.state(getattr(args, "at", None) or _now())


def _remote_metadata(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    receipt = result["receipt"]
    return {
        "remote": True,
        "request_id": receipt["request_id"],
        "clerk_receipt": receipt,
        "receipt_path": result["completed_path"],
    }


def _append_participant(
    args: argparse.Namespace,
    workspace: Workspace,
    kind: str,
    payload: dict[str, Any],
    private_key: Any,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    client = _remote_client(workspace, args)
    if client is None:
        return workspace.append(kind, payload, private_key), None
    result = client.append(kind, payload, private_key)
    return result["event"], result


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


def _task_payload(workspace: Workspace) -> dict[str, str]:
    task = workspace.problem["task"]
    return {
        "task_id": task["task_id"],
        "task_commitment": task["task_commitment"],
        "formal_repository_pin": task["formal_repository_pin"],
    }


def _active_claim(
    workspace: Workspace,
    profile: dict[str, Any],
    claim_id: str | None,
    args: argparse.Namespace,
) -> str:
    state = _workspace_state(workspace, args)
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
    client = _remote_client(workspace, args)
    remote_result: dict[str, Any] | None = None

    def append(kind: str, payload: dict[str, Any], key: Any) -> dict[str, Any]:
        nonlocal remote_result
        if client is None:
            return workspace.append(kind, payload, key)
        remote_result = client.append(kind, payload, key)
        return remote_result["event"]

    profile = SessionStore(workspace).start(
        participant_id=args.participant,
        controller_id=args.controller,
        label=args.label,
        not_after=(started + timedelta(hours=args.hours)).isoformat().replace("+00:00", "Z"),
        appender=append if client is not None else None,
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
            **_remote_metadata(remote_result),
        },
        args.json,
    )
    return 0


def _agent_claim(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = args.claim_id or f"c-{secrets.token_hex(8)}"
    event, remote = _append_participant(
        args,
        workspace,
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
    _print({**_public_event(event), "claim_id": claim_id, **_remote_metadata(remote)}, args.json)
    return 0


def _agent_heartbeat(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim, args)
    progress_digest = f"sha256:{hashlib.sha256(args.progress.encode()).hexdigest()}"
    event, remote = _append_participant(
        args,
        workspace,
        "claim_heartbeat",
        {
            **_identity_payload(workspace, profile),
            "claim_id": claim_id,
            "progress_digest": progress_digest,
        },
        key,
    )
    _print(
        {
            **_public_event(event),
            "claim_id": claim_id,
            "progress_digest": progress_digest,
            **_remote_metadata(remote),
        },
        args.json,
    )
    return 0


def _agent_checkpoint(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim, args)
    event, remote = _append_participant(
        args,
        workspace,
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
    _print({**_public_event(event), "claim_id": claim_id, **_remote_metadata(remote)}, args.json)
    return 0


def _agent_chat(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    event, remote = _append_participant(
        args,
        workspace,
        "message_posted",
        {
            **_identity_payload(workspace, profile),
            "claim_id": args.claim,
            "topic": args.topic,
            "body": args.body,
        },
        key,
    )
    _print(
        {**_public_event(event), "coordination_only": True, **_remote_metadata(remote)},
        args.json,
    )
    return 0


def _agent_release(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim, args)
    event, remote = _append_participant(
        args,
        workspace,
        "claim_released",
        {**_identity_payload(workspace, profile), "claim_id": claim_id, "reason": args.reason},
        key,
    )
    _print({**_public_event(event), "claim_id": claim_id, **_remote_metadata(remote)}, args.json)
    return 0


def _agent_handoff(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    claim_id = _active_claim(workspace, profile, args.claim, args)
    handoff_id = args.handoff_id or f"h-{secrets.token_hex(8)}"
    event, remote = _append_participant(
        args,
        workspace,
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
    _print(
        {
            **_public_event(event),
            "claim_id": claim_id,
            "handoff_id": handoff_id,
            **_remote_metadata(remote),
        },
        args.json,
    )
    return 0


def _submit_candidate(args: argparse.Namespace) -> int:
    workspace, profile, key = _session(args)
    candidate_id = args.candidate_id or f"candidate-{secrets.token_hex(8)}"
    artifact = _evidence(workspace.root, [args.artifact], [])[0]
    event, remote = _append_participant(
        args,
        workspace,
        "submission_candidate_published",
        {
            **_identity_payload(workspace, profile),
            "candidate_id": candidate_id,
            "handoff_ids": args.handoff,
            **_task_payload(workspace),
            "artifact": artifact,
            "summary": args.summary,
            "reproduce": args.reproduce,
            "limitations": args.limitations,
        },
        key,
    )
    _print(
        {
            **_public_event(event),
            "candidate_id": candidate_id,
            "candidate_status": "CANDIDATE_READY",
            "external_submission_id": None,
            "local_candidate_only": True,
            "payment_authorized": False,
            "next": "A maintainer may separately record an already completed external submission.",
            **_remote_metadata(remote),
        },
        args.json,
    )
    return 0


def _status(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    _print(_workspace_state(workspace, args), args.json)
    return 0


def _agents(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    state = _workspace_state(workspace, args)
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
    workspace = _workspace(args)
    state = _workspace_state(workspace, args)
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
    workspace = _workspace(args)
    state = _workspace_state(workspace, args)
    _print(
        {
            "problem_id": state["problem_id"],
            "sessions": state["sessions"],
            "claims": state["claims"],
            "checkpoints": state["checkpoints"],
            "handoffs": state["handoffs"],
            "candidates": state["candidates"],
            "feedback": state["feedback"],
            "resolutions": state["resolutions"],
        },
        args.json,
    )
    return 0


def _brief(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    state = _workspace_state(workspace, args)
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
        f"- Problem status: `{state['problem_status']}`",
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
    resume = state["research_resume"]
    lines.extend(["", "## Submission/review state", "", f"- Next action: `{resume['action']}`"])
    if resume.get("candidate_id"):
        lines.append(f"- Candidate: `{resume['candidate_id']}`")
    if resume.get("submission_id"):
        lines.append(f"- External submission: `{resume['submission_id']}`")
    if resume.get("feedback"):
        feedback = resume["feedback"]
        lines.extend(
            [
                f"- Trusted-clerk observation: `{feedback['stage']} / {feedback['decision']}`",
                f"- Reason code: `{feedback['reason_code']}`",
                f"- Feedback: {feedback['summary']}",
                f"- Requested next action: {feedback['next_action']}",
            ]
        )
    lines.extend(
        [
            "",
            "## Agent instruction",
            "",
            "Read this brief and the accepted artifacts. Choose one narrow useful route that "
            "does not duplicate an active claim, or declare `--parallel` deliberately. Record "
            "a heartbeat/checkpoint while working and a signed ADVANCE, NEGATIVE, BLOCKED, or "
            "NO_SIGNAL handoff before stopping. Declare dependencies and citations. Chat is "
            "coordination only. A local `boule submit` candidate is not an external submission. "
            "Do not spend funds, perform an external submission, expose secrets, or claim another "
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


def _reference(raw: str, name: str) -> dict[str, str]:
    try:
        reference, digest = raw.rsplit("=", 1)
    except ValueError as exc:
        raise ProtocolError(f"{name} must be REF=sha256:HEX") from exc
    if not reference:
        raise ProtocolError(f"{name} must include a reference")
    return {"ref": reference, "sha256": digest}


def _canonical_result_reference(raw: str, result_url: str, name: str) -> dict[str, str]:
    if raw.startswith("sha256:"):
        return {"ref": result_url, "sha256": raw}
    return _reference(raw, name)


def _candidate(workspace: Workspace, candidate_id: str) -> dict[str, Any]:
    state = workspace.state(_now())
    candidate = next(
        (item for item in state["candidates"] if item["candidate_id"] == candidate_id), None
    )
    if candidate is None:
        raise ProtocolError("candidate does not exist")
    return candidate


def _maintainer_record_submission(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    candidate = _candidate(workspace, args.candidate)
    result_url = args.public_result_url or (f"https://conjectures.io/results/{args.submission_id}")
    event = workspace.append_maintainer(
        "external_submission_receipted",
        {
            "problem_id": workspace.problem["problem_id"],
            "candidate_id": args.candidate,
            "submission_id": args.submission_id,
            **_task_payload(workspace),
            "artifact_sha256": candidate["artifact"]["sha256"],
            "submitted_at": args.submitted_at or _now(),
            "public_result_url": result_url,
            "source": "trusted-clerk/conjectures.io-submission",
            "receipt": _canonical_result_reference(args.receipt, result_url, "--receipt"),
        },
        load_maintainer_key(workspace),
    )
    _print(
        {
            **_public_event(event),
            "candidate_id": args.candidate,
            "submission_id": args.submission_id,
            "candidate_status": "VERIFICATION_PENDING",
            "external_observation_only": True,
            "payment_performed": False,
        },
        args.json,
    )
    return 0


def _maintainer_feedback(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    candidate = _candidate(workspace, args.candidate)
    submission = candidate.get("submission")
    if not submission:
        raise ProtocolError("candidate has no recorded external submission")
    submission_id = submission["submission_id"]
    result_url = args.public_result_url or f"https://conjectures.io/results/{submission_id}"
    event = workspace.append_maintainer(
        "candidate_feedback_recorded",
        {
            "problem_id": workspace.problem["problem_id"],
            "candidate_id": args.candidate,
            "submission_id": submission_id,
            **_task_payload(workspace),
            "artifact_sha256": candidate["artifact"]["sha256"],
            "stage": args.stage,
            "decision": args.decision,
            "reason_code": args.reason_code,
            "summary": args.summary,
            "next_action": args.next_action,
            "public_result_url": result_url,
            "source": {
                "verifier": "trusted-clerk/conjectures.io-lean-verifier",
                "review": "trusted-clerk/conjectures.io-human-review",
                "reward": "trusted-clerk/conjectures.io-reward-eligibility",
            }[args.stage],
            "report": _canonical_result_reference(args.report, result_url, "--report"),
        },
        load_maintainer_key(workspace),
    )
    state = workspace.state(_now())
    _print(
        {
            **_public_event(event),
            "candidate_id": args.candidate,
            "submission_id": submission_id,
            "stage": args.stage,
            "decision": args.decision,
            "problem_status": state["problem_status"],
            "research_resume": state["research_resume"],
            "external_observation_only": True,
            "payment_performed": False,
        },
        args.json,
    )
    return 0


def _maintainer_finalize(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    candidate = _candidate(workspace, args.candidate)
    submission = candidate.get("submission")
    review = candidate.get("review")
    if not submission or not review:
        raise ProtocolError("candidate has no completed external review to finalize")
    event = workspace.append_maintainer(
        "case_resolution_recorded",
        {
            "problem_id": workspace.problem["problem_id"],
            "candidate_id": args.candidate,
            "submission_id": submission["submission_id"],
            **_task_payload(workspace),
            "artifact_sha256": candidate["artifact"]["sha256"],
            "public_result_url": submission["public_result_url"],
            "source": "trusted-clerk/conjectures.io-human-review",
            "resolution": "SOLVED",
            "review_event_id": review["event_id"],
            "note": args.note,
        },
        load_maintainer_key(workspace),
    )
    state = workspace.state(_now())
    _print(
        {
            **_public_event(event),
            "candidate_id": args.candidate,
            "submission_id": submission["submission_id"],
            "problem_status": state["problem_status"],
            "trusted_clerk_finalization": True,
            "authenticated_external_attestation": False,
            "payment_performed": False,
        },
        args.json,
    )
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
    if args.cycles < 0:
        raise ProtocolError("watch cycles must be non-negative")
    if not math.isfinite(args.interval) or not 0 <= args.interval <= 300:
        raise ProtocolError("watch interval must be between 0 and 300 seconds")
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


def _clerk_serve(args: argparse.Namespace) -> int:
    if not 0 <= args.port <= 65535:
        raise ProtocolError("clerk port must be between 0 and 65535")
    loopback = {"127.0.0.1", "::1", "localhost"}
    if args.host not in loopback and not args.allow_insecure_bind:
        raise ProtocolError(
            "non-loopback bind requires --allow-insecure-bind and a separate TLS proxy"
        )
    workspace = _workspace(args)
    server = build_clerk_server(
        workspace,
        load_maintainer_key(workspace),
        host=args.host,
        port=args.port,
    )
    host, port = server.server_address[:2]
    _print(
        {
            "listening": f"http://{host}:{port}",
            "problem_id": workspace.problem["problem_id"],
            "mode": "trusted-clerk-prototype",
            "tls_built_in": False,
            "participant_events_only": True,
        },
        args.json,
    )
    sys.stdout.flush()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _remote_recover(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    server = _server(args, required=True)
    result = RemoteClient(workspace, server).recover(args.request_id)
    _print(
        {
            **_public_event(result["event"]),
            **_remote_metadata(result),
            "created": result["created"],
            "recovered": True,
        },
        args.json,
    )
    return 0


def _registry_init(args: argparse.Namespace) -> int:
    hub = Hub.initialize(args.registry)
    _print(
        {
            "registry": str(hub.root.resolve()),
            "registry_key": hub.registry.clerk_key,
            "status": "READY",
            "next": f"boule propose URL --registry {hub.root}",
        },
        args.json,
    )
    return 0


def _propose_problem(args: argparse.Namespace) -> int:
    hub = Hub(args.registry)
    record, created = hub.propose(args.url, mode=args.mode)
    _print(
        {
            "created": created,
            "case": record,
            "automatic_repository_created": False,
            "next": (
                "The trusted maintainer must independently revalidate and admit this proposal."
            ),
        },
        args.json,
    )
    return 0


def _registry_list(args: argparse.Namespace) -> int:
    hub = Hub(args.registry)
    hub.registry.refresh()
    _print(
        {
            "registry_key": hub.registry.clerk_key,
            "registry_head": hub.registry.head,
            "problems": hub.registry.problems(),
        },
        args.json,
    )
    return 0


def _registry_admit(args: argparse.Namespace) -> int:
    record = Hub(args.registry).admit(args.case)
    _print(
        {
            "case": record,
            "source_revalidated": True,
            "repository_created": False,
            "next": f"boule registry provision {args.registry} {args.case} [provider options]",
        },
        args.json,
    )
    return 0


def _private_key_file(path_value: str | None) -> bytes:
    if not path_value:
        raise ProtocolError(
            "pass --github-key-file or set BOULE_GITHUB_APP_KEY_FILE to a mounted 0600 PEM"
        )
    path = Path(path_value)
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise ProtocolError("GitHub App private key must be a regular non-symlink file")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ProtocolError("GitHub App private key file permissions must be 0600")
        return path.read_bytes()
    except ProtocolError:
        raise
    except OSError as exc:
        raise ProtocolError("cannot read the GitHub App private key file") from exc


def _repository_provider(args: argparse.Namespace, hub: Hub):
    if args.provider == "local":
        return LocalRepositoryProvider(
            args.repository_root or hub.root / "repositories",
            public_base_url=args.public_repo_base,
        )
    organization = args.github_org or os.environ.get("BOULE_GITHUB_ORG")
    app_id = args.github_app_id or os.environ.get("BOULE_GITHUB_APP_ID")
    installation_id = args.github_installation_id or os.environ.get("BOULE_GITHUB_INSTALLATION_ID")
    key_file = args.github_key_file or os.environ.get("BOULE_GITHUB_APP_KEY_FILE")
    if not organization or not app_id or not installation_id:
        raise ProtocolError("GitHub App organization, app id, and installation id are required")
    return GitHubAppRepositoryProvider(
        organization,
        app_id=app_id,
        installation_id=installation_id,
        private_key_pem=_private_key_file(key_file),
        private=args.visibility == "private",
    )


def _registry_provision(args: argparse.Namespace) -> int:
    hub = Hub(args.registry)
    result = hub.provision(args.case, _repository_provider(args, hub))
    record = hub.registry.problem(args.case)
    _print(
        {
            "case": record,
            "repository_name": result.repository_name,
            "repository_url": result.repository_url,
            "repository_created": result.repository_created,
            "workspace": str(result.local_path),
            "marker_digest": result.marker_digest,
            "next": (
                "Start the case clerk behind TLS, then run boule registry activate "
                f"{args.registry} {args.case} --clerk-url HTTPS_ORIGIN"
            ),
        },
        args.json,
    )
    return 0


def _registry_activate(args: argparse.Namespace) -> int:
    record = Hub(args.registry).activate(args.case, args.clerk_url)
    _print(
        {
            "case": record,
            "case_snapshot_verified": True,
            "status": "LIVE",
        },
        args.json,
    )
    return 0


def _registry_tick(args: argparse.Namespace) -> int:
    _print(Hub(args.registry).tick(), args.json)
    return 0


def _registry_watch(args: argparse.Namespace) -> int:
    if args.cycles < 0:
        raise ProtocolError("watch cycles must be non-negative")
    if not math.isfinite(args.interval) or not 0 <= args.interval <= 300:
        raise ProtocolError("watch interval must be between 0 and 300 seconds")
    if args.cycles == 0 and args.interval < 5:
        raise ProtocolError("continuous watch interval must be at least 5 seconds")
    hub = Hub(args.registry)
    provider = _repository_provider(args, hub) if args.auto_provision else None
    cycle = 0
    last: dict[str, Any] | None = None
    try:
        while args.cycles == 0 or cycle < args.cycles:
            cycle += 1
            errors: dict[str, str] = {}
            initial = hub.tick()
            if args.auto_admit:
                for case_id in initial["actions"]["validate"]:
                    try:
                        hub.admit(case_id)
                    except ProtocolError as exc:
                        errors[case_id] = str(exc)
            if provider is not None:
                current = hub.tick()
                candidates = current["actions"]["provision"] + current["actions"]["recover"]
                for case_id in candidates:
                    try:
                        hub.provision(case_id, provider)
                    except ProtocolError as exc:
                        errors[case_id] = str(exc)
            if args.clerk_url_template:
                current = hub.tick()
                for case_id in current["actions"]["activate"]:
                    record = hub.registry.problem(case_id)
                    if record["repo_url"] is None:
                        continue
                    try:
                        clerk_url = args.clerk_url_template.format(case_id=case_id)
                        hub.activate(case_id, clerk_url)
                    except (KeyError, ProtocolError) as exc:
                        errors[case_id] = str(exc)
            tick = hub.tick()
            last = {"cycle": cycle, "tick": tick, "errors": errors}
            hub.write_watcher_status(
                {
                    "pid": os.getpid(),
                    "cycle": cycle,
                    "last_tick_at": _now(),
                    "interval_seconds": args.interval,
                    "registry_head": tick["registry_head"],
                    "status_counts": tick["status_counts"],
                    "error_cases": sorted(errors),
                    "automatic_admission": args.auto_admit,
                    "automatic_provisioning": args.auto_provision,
                }
            )
            if args.cycles == 0 or cycle < args.cycles:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    if last is None:
        raise ProtocolError("registry watcher did not run")
    _print(last, args.json)
    return 0


def _registry_serve(args: argparse.Namespace) -> int:
    if not 0 <= args.port <= 65535:
        raise ProtocolError("registry port must be between 0 and 65535")
    if args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_insecure_bind:
        raise ProtocolError(
            "non-loopback bind requires --allow-insecure-bind and a separate TLS proxy"
        )
    hub = Hub(args.registry)
    server = build_registry_server(hub.registry, args.host, args.port)
    host, port = server.server_address[:2]
    _print(
        {
            "listening": f"http://{host}:{port}",
            "mode": "trusted-registry-staging",
            "registry_key": hub.registry.clerk_key,
            "mutations_exposed": False,
            "tls_built_in": False,
        },
        args.json,
    )
    sys.stdout.flush()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _registry_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolError("registry server must be an HTTP(S) origin without credentials")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise ProtocolError("remote registry HTTP is allowed only on loopback; use HTTPS remotely")
    return value.rstrip("/")


def _problems(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        raise ProtocolError("registry request timeout must be positive")
    origin = _registry_origin(args.server)
    request = Request(
        origin + "/v1/problems",
        headers={"Accept": "application/json", "User-Agent": "Boule/0.6"},
    )
    try:
        with urlopen(request, timeout=args.timeout) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if (
                response.status != 200
                or len(raw) > 4 * 1024 * 1024
                or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise ProtocolError("registry returned an invalid response")
            if response.geturl() != origin + "/v1/problems":
                raise ProtocolError("registry response redirected")
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ProtocolError("registry request failed") from exc
    from .remote_protocol import strict_json_bytes

    snapshot = verify_registry_snapshot(strict_json_bytes(raw), clerk_key=args.clerk_key)
    if args.clerk_key is not None:
        trust = "explicit_pin"
    else:
        trust = None
        for attempt in range(2):
            anchor = read_registry_trust(args.trust_store, origin)
            proofs = []
            if (
                anchor is not None
                and anchor["key"] == snapshot["clerk"]
                and anchor["count"] < snapshot["count"]
            ):
                proof_deadline = time.monotonic() + args.timeout
                current = anchor["count"]
                while current < snapshot["count"]:
                    remaining = proof_deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProtocolError("registry chain verification timed out")
                    target = min(current + MAX_CHAIN_PROOF_ENTRIES, snapshot["count"])
                    proof_request = Request(
                        f"{origin}/v1/chain/{current}/{target}",
                        headers={"Accept": "application/json", "User-Agent": "Boule/0.6"},
                    )
                    try:
                        with urlopen(proof_request, timeout=remaining) as response:
                            proof_raw = response.read(4 * 1024 * 1024 + 1)
                            if (
                                response.status != 200
                                or len(proof_raw) > 4 * 1024 * 1024
                                or response.geturl() != f"{origin}/v1/chain/{current}/{target}"
                                or response.headers.get("Content-Type", "")
                                .split(";", 1)[0]
                                .strip()
                                .lower()
                                != "application/json"
                            ):
                                raise ProtocolError(
                                    "registry chain endpoint returned an invalid response"
                                )
                    except (HTTPError, URLError, TimeoutError) as exc:
                        raise ProtocolError("registry chain request failed") from exc
                    proofs.append(strict_json_bytes(proof_raw))
                    current = target
            try:
                trust_state = trust_registry_snapshot(
                    args.trust_store,
                    origin,
                    snapshot["clerk"],
                    snapshot["count"],
                    snapshot["head"],
                    proofs,
                )
                trust = f"tofu_{trust_state}"
                break
            except ProtocolError as exc:
                if attempt == 0 and "does not match the requested range" in str(exc):
                    continue
                raise
        if trust is None:
            raise ProtocolError("registry trust anchor changed concurrently")
    _print(
        {
            "registry": origin,
            "registry_key": snapshot["clerk"],
            "registry_key_pinned": True,
            "registry_key_trust": trust,
            "registry_head": snapshot["head"],
            "problems": snapshot["problems"],
        },
        args.json,
    )
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

    propose = subparsers.add_parser(
        "propose", help="propose one source task to a local trusted registry"
    )
    propose.add_argument("url", help="source problem URL; v0.6 accepts Conjectures.io")
    propose.add_argument("--registry", required=True, help="local Boule registry directory")
    propose.add_argument("--mode", choices=["formalized", "counterexample"])
    propose.add_argument("--json", action="store_true", help="emit compact JSON")
    propose.set_defaults(handler=_propose_problem)

    problems = subparsers.add_parser(
        "problems", help="list a remote registry's signed problem index"
    )
    problems.add_argument("--server", required=True, help="registry HTTPS origin")
    problems.add_argument("--clerk-key", help="expected registry Ed25519 key")
    problems.add_argument(
        "--trust-store",
        default=str(Path.home() / ".config" / "boule" / "trusted-registries.json"),
        help="mode-0600 TOFU pin store used when --clerk-key is omitted",
    )
    problems.add_argument("--timeout", type=float, default=15.0)
    problems.add_argument("--json", action="store_true", help="emit compact JSON")
    problems.set_defaults(handler=_problems)

    registry = subparsers.add_parser("registry", help="operate the local trusted problem registry")
    registry_commands = registry.add_subparsers(dest="registry_command", required=True)

    registry_init = registry_commands.add_parser("init", help="initialize a signed registry")
    registry_init.add_argument("registry", help="new registry runtime directory")
    registry_init.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_init.set_defaults(handler=_registry_init)

    registry_list = registry_commands.add_parser("list", help="list local registry state")
    registry_list.add_argument("registry", help="registry runtime directory")
    registry_list.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_list.set_defaults(handler=_registry_list)

    registry_admit = registry_commands.add_parser(
        "admit", help="revalidate and admit one proposed source task"
    )
    registry_admit.add_argument("registry", help="registry runtime directory")
    registry_admit.add_argument("case", help="proposed case id")
    registry_admit.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_admit.set_defaults(handler=_registry_admit)

    def repository_provider_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--provider", choices=["github-app", "local"], default="github-app")
        command.add_argument("--repository-root", help="local mock repository directory")
        command.add_argument(
            "--public-repo-base",
            help="HTTPS base representing locally hosted mock repositories",
        )
        command.add_argument("--github-org", help="organization; or BOULE_GITHUB_ORG")
        command.add_argument("--github-app-id", help="app id; or BOULE_GITHUB_APP_ID")
        command.add_argument(
            "--github-installation-id",
            help="installation id; or BOULE_GITHUB_INSTALLATION_ID",
        )
        command.add_argument(
            "--github-key-file",
            help="mounted 0600 PEM path; or BOULE_GITHUB_APP_KEY_FILE",
        )
        command.add_argument("--visibility", choices=["public", "private"], default="private")

    registry_provision = registry_commands.add_parser(
        "provision", help="idempotently create and bootstrap one admitted case repository"
    )
    registry_provision.add_argument("registry", help="registry runtime directory")
    registry_provision.add_argument("case", help="admitted case id")
    repository_provider_arguments(registry_provision)
    registry_provision.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_provision.set_defaults(handler=_registry_provision)

    registry_activate = registry_commands.add_parser(
        "activate", help="verify a TLS case clerk and publish the case as LIVE"
    )
    registry_activate.add_argument("registry", help="registry runtime directory")
    registry_activate.add_argument("case", help="provisioned case id")
    registry_activate.add_argument("--clerk-url", required=True, help="case clerk HTTPS origin")
    registry_activate.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_activate.set_defaults(handler=_registry_activate)

    registry_tick = registry_commands.add_parser(
        "tick", help="verify registry state and print deterministic pending actions"
    )
    registry_tick.add_argument("registry", help="registry runtime directory")
    registry_tick.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_tick.set_defaults(handler=_registry_tick)

    registry_watch = registry_commands.add_parser(
        "watch", help="continuously validate and optionally provision admitted proposals"
    )
    registry_watch.add_argument("registry", help="registry runtime directory")
    registry_watch.add_argument("--interval", type=float, default=30.0)
    registry_watch.add_argument("--cycles", type=int, default=1, help="0 runs continuously")
    registry_watch.add_argument("--auto-admit", action="store_true")
    registry_watch.add_argument("--auto-provision", action="store_true")
    registry_watch.add_argument(
        "--clerk-url-template",
        help="HTTPS origin template with {case_id}; activates only after verification",
    )
    repository_provider_arguments(registry_watch)
    registry_watch.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_watch.set_defaults(handler=_registry_watch)

    registry_serve = registry_commands.add_parser(
        "serve", help="serve the landing and signed read-only registry API"
    )
    registry_serve.add_argument("registry", help="registry runtime directory")
    registry_serve.add_argument("--host", default="127.0.0.1")
    registry_serve.add_argument("--port", type=int, default=8786)
    registry_serve.add_argument("--allow-insecure-bind", action="store_true")
    registry_serve.add_argument("--json", action="store_true", help="emit compact JSON")
    registry_serve.set_defaults(handler=_registry_serve)

    def server_argument(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--server",
            help="trusted clerk origin; defaults to BOULE_SERVER (HTTPS except loopback)",
        )

    def read_command(name: str, help_text: str, handler: Any) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("problem", help="initialized problem directory")
        command.add_argument("--at", help="ISO-8601 UTC observation time")
        command.add_argument("--json", action="store_true", help="emit compact JSON")
        server_argument(command)
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
    server_argument(brief)
    brief.set_defaults(handler=_brief)

    submit = subparsers.add_parser(
        "submit",
        help="seal a local solution candidate without contacting Conjectures.io",
    )
    submit.add_argument("problem", help="initialized problem directory")
    submit.add_argument("--session", help="session id; defaults to BOULE_SESSION")
    submit.add_argument("--candidate-id", help="optional stable candidate id")
    submit.add_argument(
        "--handoff",
        action="append",
        required=True,
        help="earlier ADVANCE handoff causally used by this candidate",
    )
    submit.add_argument(
        "--artifact", required=True, help="exact solution file inside the problem directory"
    )
    submit.add_argument("--summary", required=True, help="what the candidate claims to solve")
    submit.add_argument("--reproduce", required=True, help="exact local verification command")
    submit.add_argument("--limitations", default="No additional limitations declared.")
    submit.add_argument("--json", action="store_true", help="emit compact JSON")
    server_argument(submit)
    submit.set_defaults(handler=_submit_candidate)

    agent = subparsers.add_parser("agent", help="append signed participant activity")
    agent_commands = agent.add_subparsers(dest="agent_command", required=True)

    start = agent_commands.add_parser("start", help="create and delegate a local session key")
    start.add_argument("problem", help="initialized problem directory")
    start.add_argument(
        "--participant",
        "--name",
        dest="participant",
        required=True,
        help="chosen stable public agent name",
    )
    start.add_argument("--controller", required=True, help="self-declared common controller id")
    start.add_argument("--label", help="optional descriptive session label")
    start.add_argument("--hours", type=float, default=24.0, help="session lifetime")
    start.add_argument("--json", action="store_true", help="emit compact JSON")
    server_argument(start)
    start.set_defaults(handler=_agent_start)

    def participant_command(name: str, help_text: str, handler: Any) -> argparse.ArgumentParser:
        command = agent_commands.add_parser(name, help=help_text)
        command.add_argument("problem", help="initialized problem directory")
        command.add_argument("--session", help="session id; defaults to BOULE_SESSION")
        command.add_argument("--json", action="store_true", help="emit compact JSON")
        server_argument(command)
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

    record_submission = maintainer_commands.add_parser(
        "record-submission",
        help="record an already completed external submission from its receipt",
    )
    record_submission.add_argument("problem", help="initialized problem directory")
    record_submission.add_argument("--candidate", required=True, help="local candidate id")
    record_submission.add_argument(
        "--submission-id", required=True, help="canonical Conjectures result UUID"
    )
    record_submission.add_argument(
        "--receipt",
        required=True,
        metavar="sha256:HEX",
        help="digest of the canonical Conjectures result page (URL=sha256:HEX also accepted)",
    )
    record_submission.add_argument(
        "--submitted-at", help="official ISO-8601 UTC submission time; defaults to now"
    )
    record_submission.add_argument(
        "--public-result-url", help="canonical Conjectures result URL; derived by default"
    )
    record_submission.add_argument("--json", action="store_true", help="emit compact JSON")
    record_submission.set_defaults(handler=_maintainer_record_submission)

    feedback = maintainer_commands.add_parser(
        "feedback", help="record evidence-backed verifier, review, or reward feedback"
    )
    feedback.add_argument("problem", help="initialized problem directory")
    feedback.add_argument("--candidate", required=True, help="local candidate id")
    feedback.add_argument("--stage", required=True, choices=["verifier", "review", "reward"])
    feedback.add_argument(
        "--decision",
        required=True,
        help=("VERIFIED/REJECTED, APPROVED/REJECTED/PARTIAL_AWARD, or ELIGIBLE/INELIGIBLE"),
    )
    feedback.add_argument("--reason-code", required=True, help="official reason code or label")
    feedback.add_argument("--summary", required=True, help="concise official feedback summary")
    feedback.add_argument(
        "--next", "--next-action", dest="next_action", required=True, help="next safe action"
    )
    feedback.add_argument(
        "--report",
        required=True,
        metavar="sha256:HEX",
        help="digest of the canonical Conjectures result page (URL=sha256:HEX also accepted)",
    )
    feedback.add_argument(
        "--public-result-url", help="canonical Conjectures result URL; derived by default"
    )
    feedback.add_argument("--json", action="store_true", help="emit compact JSON")
    feedback.set_defaults(handler=_maintainer_feedback)

    finalize = maintainer_commands.add_parser(
        "finalize", help="close the local case after an APPROVED review observation"
    )
    finalize.add_argument("problem", help="initialized problem directory")
    finalize.add_argument("--candidate", required=True, help="approved local candidate id")
    finalize.add_argument(
        "--note",
        default="Trusted clerk finalized the case from the recorded approved review.",
    )
    finalize.add_argument("--json", action="store_true", help="emit compact JSON")
    finalize.set_defaults(handler=_maintainer_finalize)

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

    clerk = subparsers.add_parser("clerk", help="operate the trusted append clerk")
    clerk_commands = clerk.add_subparsers(dest="clerk_command", required=True)
    serve = clerk_commands.add_parser(
        "serve", help="serve one case append API; put TLS and rate limits in a proxy"
    )
    serve.add_argument("problem", help="canonical initialized problem directory")
    serve.add_argument("--host", default="127.0.0.1", help="listen address")
    serve.add_argument("--port", type=int, default=8787, help="listen port; 0 chooses one")
    serve.add_argument(
        "--allow-insecure-bind",
        action="store_true",
        help="explicitly allow a non-loopback plaintext bind for controlled environments",
    )
    serve.add_argument("--json", action="store_true", help="emit compact startup JSON")
    serve.set_defaults(handler=_clerk_serve)

    remote = subparsers.add_parser("remote", help="recover ambiguous remote appends")
    remote_commands = remote.add_subparsers(dest="remote_command", required=True)
    recover = remote_commands.add_parser(
        "recover", help="query or safely replay one signed outbox request"
    )
    recover.add_argument("problem", help="local problem clone containing the outbox")
    recover.add_argument("request_id", help="UUID printed by the ambiguous append")
    server_argument(recover)
    recover.add_argument("--json", action="store_true", help="emit compact JSON")
    recover.set_defaults(handler=_remote_recover)
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
