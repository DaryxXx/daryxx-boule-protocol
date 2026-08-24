from __future__ import annotations

import json
from pathlib import Path

from boule.cli import main
from boule.problem_import import FetchResponse, import_problem

FIXTURE = Path(__file__).parent / "fixtures" / "conjectures" / "erdos686-formalized.html"
URL = "https://conjectures.io/problems/erdos686-erdos-686-variants-four"


def initialize(monkeypatch, tmp_path, capsys):
    def offline(url, root, **kwargs):
        return import_problem(
            url,
            root,
            mode=kwargs.get("mode"),
            refresh_snapshot=kwargs.get("refresh_snapshot", False),
            fetcher=lambda _: FetchResponse(FIXTURE.read_bytes(), URL),
        )

    monkeypatch.setattr("boule.cli.import_problem", offline)
    assert main(["init", URL, "--root", str(tmp_path / "problems"), "--json"]) == 0
    initialized = json.loads(capsys.readouterr().out)
    return Path(initialized["path"])


def start(problem, capsys, participant="agent-a", label="Codex A"):
    assert (
        main(
            [
                "agent",
                "start",
                str(problem),
                "--participant",
                participant,
                "--controller",
                "shared-daryxx",
                "--label",
                label,
                "--json",
            ]
        )
        == 0
    )
    return json.loads(capsys.readouterr().out)["session_id"]


def claim(problem, session, capsys, route="route-x"):
    assert (
        main(
            [
                "agent",
                "claim",
                str(problem),
                "--session",
                session,
                "--route",
                route,
                "--success-gate",
                "reproducible certificate",
                "--falsifier",
                "counterexample",
                "--json",
            ]
        )
        == 0
    )
    return json.loads(capsys.readouterr().out)["claim_id"]


def test_complete_participant_and_maintainer_cli_flow(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    session = start(problem, capsys)
    claim_id = claim(problem, session, capsys)

    assert main(["brief", str(problem), "--session", session]) == 0
    assert "Agent instruction" in capsys.readouterr().out
    assert (
        main(
            [
                "agent",
                "heartbeat",
                str(problem),
                "--session",
                session,
                "--progress",
                "checked the first reduction",
                "--json",
            ]
        )
        == 0
    )
    assert "progress_digest" in json.loads(capsys.readouterr().out)
    assert (
        main(
            [
                "agent",
                "checkpoint",
                str(problem),
                "--session",
                session,
                "--summary",
                "one obligation remains",
                "--next",
                "reproduce the rank calculation",
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "agent",
                "chat",
                str(problem),
                "--session",
                session,
                "--claim",
                claim_id,
                "--topic",
                "coordination",
                "--body",
                "I am checking the rank calculation.",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["coordination_only"] is True
    assert (
        main(
            [
                "agent",
                "handoff",
                str(problem),
                "--session",
                session,
                "--outcome",
                "BLOCKED",
                "--summary",
                "rank certificate is still missing",
                "--next",
                "independently compute the Mordell-Weil rank",
                "--reproduce",
                "make verify-rank",
                "--evidence",
                "fixture=sha256:" + "f" * 64,
                "--provenance",
                "original",
                "--json",
            ]
        )
        == 0
    )
    handoff = json.loads(capsys.readouterr().out)
    assert handoff["handoff_id"].startswith("h-")

    assert main(["maintainer", "tick", str(problem), "--json"]) == 0
    tick = json.loads(capsys.readouterr().out)
    assert tick["status"]["handoffs_queued"] == [handoff["handoff_id"]]
    assert "payment" in tick["status"]["limitations"]
    assert main(["history", str(problem), "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["checkpoints"]) == 1
    assert main(["chat", str(problem), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["coordination_only"] is True
    assert (
        main(
            [
                "maintainer",
                "watch",
                str(problem),
                "--cycles",
                "2",
                "--interval",
                "0",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["cycle"] == 2

    private = problem / ".boule" / "private"
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in private.rglob("*.pem"))
    assert (problem / ".boule" / "receipts").is_dir()
    assert (problem / ".boule" / "policy.json").is_file()
    assert (problem / "BOULE.md").is_file()
    assert "roles are optional" in (problem / "AGENTS.md").read_text()
    assert (problem / "CLAUDE.md").read_text() == (problem / "AGENTS.md").read_text()


def test_two_declared_common_control_sessions_surface_overlap(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    first = start(problem, capsys, "agent-a", "Codex A")
    second = start(problem, capsys, "agent-b", "Codex B")
    claim(problem, first, capsys, "same-route")
    claim(problem, second, capsys, "same-route")

    assert main(["agents", str(problem), "--json"]) == 0
    sessions = json.loads(capsys.readouterr().out)["sessions"]
    assert {item["controller_id"] for item in sessions} == {"shared-daryxx"}
    assert all(item["active_claim"] is not None for item in sessions)
    assert main(["maintainer", "tick", str(problem), "--json"]) == 0
    warnings = json.loads(capsys.readouterr().out)["status"]["warnings"]
    claim_ids = sorted([item["active_claim"]["claim_id"] for item in sessions])
    assert warnings == [{"claims": claim_ids, "kind": "overlap"}]
