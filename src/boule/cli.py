from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes
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
