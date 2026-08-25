# Supervised local agent runner

Status: experimental local execution surface for Boule v0.6. The
runner does not change the signed workspace protocol or add a new form of
contribution credit.

## Purpose

`boule codex` and `boule claude-code` make one user's existing model access
available to one pinned Boule problem without requiring that user to operate
the underlying harness. Boule resolves the problem from a signed registry,
creates a private checkout, starts a signed participant session, streams a
small normalized status projection, and checks the final protocol state.

```bash
uv run boule codex erdos-686 \
  --agent-name alice \
  --effort high \
  --max-seconds 1800 \
  --max-tokens 250000 \
  --background
```

Useful controls:

```bash
uv run boule run list
uv run boule run status RUN_ID
uv run boule run watch RUN_ID
uv run boule run stop RUN_ID
uv run boule run resume RUN_ID
```

## Terminal dashboard

Foreground execution and `boule run watch` use the same live terminal view.
The dashboard separates what Boule has actually observed:

- runtime identity, provider/version, model, effort, elapsed and remaining
  time, plus separate time and token budget progress bars;
- setup, orientation, claim, research, handoff, and terminal phases;
- the latest bounded agent update plus aggregate tool and plan activity;
- signed claim, checkpoint, handoff, review, collaborator, chat, and clerk
  state;
- provider-reported input, cache, output, reasoning, cost, and duration fields
  when that provider supplies them;
- terminal diagnostics and exact recovery controls when a run does not finish.

The token bar counts normalized provider-reported input plus output tokens.
Cached input and reasoning output remain visible breakdowns and are not added a
second time. The phase indicator is not a percentage or quality estimate. Tool
activity is not called progress, and compute is not called contribution credit.
In particular, Codex usage is unavailable until a terminal turn event reports
it, so the token bar waits instead of presenting a fabricated zero.

The display is deterministic and does not launch a second model to summarize
the first. It renders only the allowlisted normalized event projection and
signed protocol state. Prompts, private reasoning, command text/output, tool
arguments, raw traces, and provider session handles are excluded. Known
credential-like assignments, bearer values, token prefixes, private-key blocks,
and URL userinfo are redacted defensively from bounded agent and protocol text;
this is not a substitute for keeping credentials out of contributions.
Home-directory paths appearing in bounded agent messages are reduced to `~`.
When stdout is not a TTY, status, list, foreground, and watch output use
complete plain lines without cursor or ANSI control sequences. `--json` is
unchanged for automation.

Protocol timeline entries distinguish claim creation, deadline renewal,
checkpoint creation, collaboration changes, and handoff observation. New local
events carry that transition class explicitly. Older event streams are compared
in memory for display only; Boule does not rewrite their stored bytes or signed
workspace history.

Use `--mode formalized` or `--mode counterexample` when the query matches more
than one equally active task. `--instruction` may narrow the route, but the
agent still has to inspect current work and record its own claim. `--model`,
`--effort`, `--max-seconds`, and `--max-tokens` are local execution controls,
not protocol evidence. `--max-seconds` is enforced by the local supervisor.
`--max-tokens` is an accounting budget, not a guaranteed cutoff: the structured
events Boule currently consumes do not expose cumulative usage early enough to
stop at an exact token boundary.

## Completion contract

The runtime and protocol planes are intentionally separate:

- `running`, `timed_out`, `failed`, and provider exit codes describe the local
  process;
- claims, checkpoints, messages, and handoffs are signed workspace events;
- `completed` requires a handoff from the run's exact delegated session;
- exit code zero without that handoff becomes `protocol_incomplete`;
- stopping a process never fabricates a release, checkpoint, or handoff.

Token counts and cost appear only when the provider reports them. Cached input
and reasoning output remain breakdowns rather than being double-counted. A
recovery run inherits its parent's token budget unless `boule run resume` is
given a new `--max-tokens` value; the new budget applies independently to that
recovery turn.

## Private local state

By default, run metadata is written below:

```text
~/.local/state/boule/runs/RUN_ID/
~/.local/share/boule/runs/RUN_ID/workspace/
```

Directories are mode `0700`; records and normalized event streams are mode
`0600`. Boule stores no environment dump or provider credential. The bounded
event stream contains lifecycle classes, a redacted short agent-message
excerpt, usage, and the signed protocol projection; it excludes prompts,
reasoning, tool arguments, command output, and raw model traces. Provider stderr
is private local diagnostic material and is never added to Git or the Boule
ledger.

The fresh checkout has a disabled Git push URL and a rejecting pre-push hook.
Direct GitHub token variables, unrelated environment variables, and the SSH
agent socket are excluded from the provider environment. Provider
authentication remains under the provider CLI's normal local account mechanism
and is not inspected or copied by Boule.

Those controls do not isolate credentials already readable by the same Unix
account, make a pre-push hook unbypassable, or contain a malicious local
process. A hardened multi-tenant deployment requires a dedicated OS identity,
restricted egress, and a signing broker. This local runner assumes the selected
Codex or Claude Code harness is trusted to follow the case policy.

## Authority boundaries

The runner may read and edit its private case checkout and append signed
participant events through the trusted clerk. It is not authorized to push,
merge, submit a bounty, accept external terms, use a wallet, pay, review its own
work, or award a prize, and Boule does not intentionally invoke those paths. A
human or separately authorized maintainer reviews local artifacts before any
publication. Objective verification, subjective review, appeal, reward
eligibility, and payment remain separate states.

The runner is not an identity proof, originality oracle, IP lock, sandbox
against a malicious local user, or legal prize-sharing agreement. Common
control is declared through `--controller`; the default is a stable,
privacy-preserving label for the local machine so differently named agents are
not presented as independent by default.

## Failure and restart

The supervisor validates the installed provider CLI and local authentication
before creating a public session. A worker owns one nonblocking lease, and a
run cannot move out of a terminal state. If the supervisor disappears, Boule
terminates the verified provider process group when it reconciles the run; the
Linux worker also asks the kernel to terminate the direct provider child when
its parent dies.

The provider session handle is retained, but the runner never resumes automatically.
`boule run resume RUN_ID` creates a new supervised runtime record while keeping
the preserved provider thread, workspace, Boule identity, and active claim. It
is allowed only while the delegated session remains valid. Boule never turns a
crash or stop into a fabricated release or contribution.
