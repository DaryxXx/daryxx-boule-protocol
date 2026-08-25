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


def test_agent_can_choose_public_name(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    assert (
        main(
            [
                "agent",
                "start",
                str(problem),
                "--name",
                "Daryxx1",
                "--controller",
                "daryxx-common-control",
                "--label",
                "Erdos 686 session",
                "--json",
            ]
        )
        == 0
    )
    started = json.loads(capsys.readouterr().out)
    assert started["participant_id"] == "Daryxx1"
    assert main(["history", str(problem), "--json"]) == 0
    history = json.loads(capsys.readouterr().out)
    assert history["sessions"][0]["participant_id"] == "Daryxx1"

    assert (
        main(
            [
                "maintainer",
                "watch",
                str(problem),
                "--cycles",
                "1",
                "--interval",
                "nan",
                "--json",
            ]
        )
        == 2
    )
    assert "watch interval must be between 0 and 300 seconds" in capsys.readouterr().err


def test_top_level_claim_shortcut_matches_agent_claim(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    session = start(problem, capsys)

    assert (
        main(
            [
                "claim",
                str(problem),
                "--session",
                session,
                "--route",
                "bounded shortcut route",
                "--success-gate",
                "one reproducible result",
                "--falsifier",
                "one exact counterexample",
                "--json",
            ]
        )
        == 0
    )
    claimed = json.loads(capsys.readouterr().out)
    assert claimed["claim_id"].startswith("c-")

    assert main(["status", str(problem), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    active = [item for item in status["claims"] if item["status"] == "active"]
    assert active[0]["route"] == "bounded shortcut route"


def publish_solution(problem, session, capsys, handoff_id="h-proof"):
    solution = problem / "Solution.lean"
    solution.write_text("example : True := by trivial\n", encoding="utf-8")
    assert (
        main(
            [
                "agent",
                "handoff",
                str(problem),
                "--session",
                session,
                "--handoff-id",
                handoff_id,
                "--outcome",
                "ADVANCE",
                "--summary",
                "exact pinned artifact is ready",
                "--next",
                "seal a local candidate",
                "--reproduce",
                "lake env lean Solution.lean",
                "--artifact",
                str(solution),
                "--provenance",
                "original",
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    return solution


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


def test_submit_feedback_rejection_and_resume_cli(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    session = start(problem, capsys)
    claim(problem, session, capsys)
    solution = publish_solution(problem, session, capsys)
    assert (
        main(
            [
                "submit",
                str(problem),
                "--session",
                session,
                "--candidate-id",
                "candidate-cli",
                "--handoff",
                "h-proof",
                "--artifact",
                str(solution),
                "--summary",
                "solves the exact pinned task",
                "--reproduce",
                "lake env lean Solution.lean",
                "--json",
            ]
        )
        == 0
    )
    local = json.loads(capsys.readouterr().out)
    assert local["local_candidate_only"] is True
    assert local["external_submission_id"] is None
    assert local["payment_authorized"] is False

    submission_id = "af89c6c1-a843-4e5d-a9ad-1716430cc1e2"
    result_url = f"https://conjectures.io/results/{submission_id}"
    evidence = f"{result_url}=sha256:" + "a" * 64
    assert (
        main(
            [
                "maintainer",
                "record-submission",
                str(problem),
                "--candidate",
                "candidate-cli",
                "--submission-id",
                submission_id,
                "--receipt",
                evidence,
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["payment_performed"] is False
    assert (
        main(
            [
                "maintainer",
                "feedback",
                str(problem),
                "--candidate",
                "candidate-cli",
                "--stage",
                "verifier",
                "--decision",
                "REJECTED",
                "--reason-code",
                "LEAN_REJECTED",
                "--summary",
                "the exact submitted file did not verify",
                "--next",
                "repair the reported Lean error and create a new artifact",
                "--report",
                evidence,
                "--json",
            ]
        )
        == 0
    )
    feedback = json.loads(capsys.readouterr().out)
    assert feedback["problem_status"] == "OPEN_AFTER_FEEDBACK"
    assert feedback["research_resume"]["action"] == "CONTINUE_RESEARCH_FROM_FEEDBACK"
    assert feedback["external_observation_only"] is True
    assert main(["brief", str(problem)]) == 0
    brief = capsys.readouterr().out
    assert "LEAN_REJECTED" in brief
    assert "repair the reported Lean error" in brief
    assert claim(problem, session, capsys, "repair-submission").startswith("c-")


def test_approved_review_needs_explicit_local_finalization_cli(monkeypatch, tmp_path, capsys):
    problem = initialize(monkeypatch, tmp_path, capsys)
    session = start(problem, capsys)
    claim(problem, session, capsys)
    solution = publish_solution(problem, session, capsys)

    def network_forbidden(*_args, **_kwargs):
        raise AssertionError("candidate/review lifecycle must not open a network socket")

    monkeypatch.setattr("socket.socket", network_forbidden)
    assert (
        main(
            [
                "submit",
                str(problem),
                "--session",
                session,
                "--candidate-id",
                "candidate-approved",
                "--handoff",
                "h-proof",
                "--artifact",
                str(solution),
                "--summary",
                "solves the exact pinned task",
                "--reproduce",
                "lake env lean Solution.lean",
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    submission_id = "82ab85ee-5dfc-4775-b3e1-8abc16e213b9"
    evidence = "sha256:" + "b" * 64
    assert (
        main(
            [
                "maintainer",
                "record-submission",
                str(problem),
                "--candidate",
                "candidate-approved",
                "--submission-id",
                submission_id,
                "--receipt",
                evidence,
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    for stage, decision, reason in (
        ("verifier", "VERIFIED", "LEAN_VERIFIED"),
        ("review", "APPROVED", "REVIEW_APPROVED"),
    ):
        assert (
            main(
                [
                    "maintainer",
                    "feedback",
                    str(problem),
                    "--candidate",
                    "candidate-approved",
                    "--stage",
                    stage,
                    "--decision",
                    decision,
                    "--reason-code",
                    reason,
                    "--summary",
                    f"recorded {reason}",
                    "--next",
                    "advance the local workflow",
                    "--report",
                    evidence,
                    "--json",
                ]
            )
            == 0
        )
        result = json.loads(capsys.readouterr().out)
    assert result["problem_status"] == "ACCEPTANCE_RECORDED"
    assert result["payment_performed"] is False
    assert (
        main(
            [
                "maintainer",
                "finalize",
                str(problem),
                "--candidate",
                "candidate-approved",
                "--json",
            ]
        )
        == 0
    )
    finalized = json.loads(capsys.readouterr().out)
    assert finalized["problem_status"] == "SOLVED"
    assert finalized["authenticated_external_attestation"] is False
    assert finalized["payment_performed"] is False
