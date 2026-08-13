from __future__ import annotations

import json

from boule.cli import main
from boule.demo import build_demo_session
from boule.protocol import replay_ledger


def test_complete_demo_separates_verification_from_allocation() -> None:
    session = build_demo_session()
    replayed = replay_ledger(session.ledger)

    assert replayed.technical_receipt is not None
    assert replayed.technical_receipt["status"] == "pass"
    assert replayed.decision is not None
    assert replayed.decision["status"] == "decided"
    assert sum(replayed.decision["allocation_bps"].values()) == 10_000
    assert set(replayed.decision["allocation_bps"]) == set(replayed.case["agents"])


def test_cli_creates_and_verifies_a_transcript(tmp_path, capsys) -> None:
    output = tmp_path / "demo"

    assert main(["demo", "--output", str(output), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["phase"] == "provisional"
    assert (output / "ledger.jsonl").is_file()
    assert (output / "summary.json").is_file()

    assert main(["verify-ledger", str(output / "ledger.jsonl"), "--json"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["decision"] == result["summary"]["decision"]


def test_cli_rejects_tampered_transcript(tmp_path, capsys) -> None:
    output = tmp_path / "demo"
    assert main(["demo", "--output", str(output)]) == 0
    capsys.readouterr()
    ledger_path = output / "ledger.jsonl"
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["event"]["payload"]["summary"] = "tampered"
    lines[1] = json.dumps(entry, separators=(",", ":"), sort_keys=True)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["verify-ledger", str(ledger_path)]) == 2
    assert "signature verification failed" in capsys.readouterr().err


def test_cli_can_require_a_decision(tmp_path, capsys) -> None:
    output = tmp_path / "demo"
    assert main(["demo", "--output", str(output)]) == 0
    capsys.readouterr()
    ledger_path = output / "ledger.jsonl"
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    ledger_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    assert main(["verify-ledger", str(ledger_path)]) == 0
    assert '"transcript_status": "partial"' in capsys.readouterr().out
    assert main(["verify-ledger", str(ledger_path), "--require-decision"]) == 2
    assert "valid but has no provisional decision" in capsys.readouterr().err
