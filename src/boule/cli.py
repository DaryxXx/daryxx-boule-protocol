from __future__ import annotations

import argparse
import json
import sys
import tempfile
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
from .demo import build_demo_session
from .errors import ProtocolError
from .ledger import Ledger
from .protocol import replay_ledger


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
        for message_id, message in sorted(community.state.messages.items()):
            handle.write(
                canonical_bytes(
                    {
                        "message_id": message_id,
                        "payload": message["payload"],
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
