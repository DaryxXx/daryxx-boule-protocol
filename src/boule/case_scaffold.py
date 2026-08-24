"""Public support files shared by local and provisioned Boule cases."""

from __future__ import annotations

from pathlib import Path

from .workspace import Workspace

PUBLIC_SUPPORT_PATHS = (
    "README.md",
    "BOULE.md",
    "AGENTS.md",
    "CLAUDE.md",
    ".boule/.gitignore",
)


def support_files(workspace: Workspace) -> dict[str, bytes]:
    problem = workspace.problem
    title = problem["problem"]["title"]
    source_url = problem["source"]["canonical_problem_url"]
    disclosure = workspace.policy["disclosure"]
    readme = (
        f"# {title}\n\n"
        "This repository is one Boule collaboration case pinned to an exact source task.\n\n"
        f"- Source: {source_url}\n"
        f"- Problem id: `{problem['problem_id']}`\n"
        f"- Task commitment: `{problem['task']['task_commitment']}`\n"
        f"- Disclosure: `{disclosure}`\n\n"
        "Install the Boule CLI, run `boule brief .`, then start or load a signed "
        "session. Work on a case-scoped branch and publish an evidence-linked checkpoint "
        "or handoff before stopping. The signed ledger records statements and receipt order; "
        "it does not prove originality, mathematical truth, prize eligibility, or payment.\n"
    )
    guide = (
        "# Continue this Boule problem\n\n"
        f"Problem: {title}\n\n"
        "Run `boule brief .`, start or load your session, choose one bounded route "
        "that is not already claimed, and publish a signed checkpoint or handoff "
        f"before stopping. The frozen evidence disclosure mode is `{disclosure}`. "
        "Signed summaries and chat are public metadata; keep undisclosed methods behind "
        "digests or authorized evidence references. Chat coordinates work but is not "
        "contribution evidence. A completed artifact may be sealed locally with `boule "
        "submit`; that command does not contact Conjectures.io, authorize a fee, or establish "
        "acceptance. Do not perform an external submission, spend funds, or expose private "
        "prompts or secrets.\n"
    )
    agent_rules = (
        "# Boule case session\n\n"
        "Run `boule brief .` and `boule status .` before substantive work. Use the "
        "assigned `BOULE_SESSION`, or ask the controller to create one with `boule agent "
        "start`. Choose one narrow unclaimed route; roles are optional labels only. Keep the "
        "claim alive with a heartbeat, publish a signed checkpoint after reusable progress, "
        "and publish ADVANCE, NEGATIVE, BLOCKED, or NO_SIGNAL before stopping. Declare every "
        "handoff dependency and citation. Chat coordinates work but is not prize evidence. "
        "If an exact solution artifact is evidence in an ADVANCE handoff, `boule submit` may "
        "seal a local candidate. It never submits externally or authorizes payment. Never "
        "perform an external submission, spend funds, expose secrets/private traces, claim "
        "another session's work, or treat maintainer advice as mathematical review.\n"
    )
    ignore = "private/\nlock\nprojection.json\nmaintainer-receipt.json\nadvisories/\nwatcher.json\n"
    return {
        "README.md": readme.encode(),
        "BOULE.md": guide.encode(),
        "AGENTS.md": agent_rules.encode(),
        "CLAUDE.md": agent_rules.encode(),
        ".boule/.gitignore": ignore.encode(),
    }


def write_case_support_files(problem_dir: str | Path) -> None:
    workspace = Workspace(problem_dir)
    for relative, content in support_files(workspace).items():
        path = workspace.root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
