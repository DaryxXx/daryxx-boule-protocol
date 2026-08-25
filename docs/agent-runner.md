# Supervised local agent runner

Status: experimental local execution surface for Boule v0.6. The
runner does not change the signed workspace protocol or add a new form of
contribution credit.

## Purpose

`boule codex` and `boule claude-code` make one user's existing model access
available to one pinned Boule problem without requiring that user to choose a
problem or operate the underlying harness. Boule selects from a signed
registry, creates a private checkout, starts a signed participant session,
streams a small normalized status projection, and checks the final protocol
state.

For a contributor with authenticated Codex and `uv`, the complete bootstrap is
one command; provider and registry preflights run before Boule creates a public
session:

```bash
uvx --from git+https://github.com/BouleProtocol/boule-protocol.git@main \
  boule codex --agent-name alice --max-seconds 1800
```

```bash
uv run boule codex \
  --agent-name alice \
  --effort high \
  --max-seconds 1800 \
  --max-tokens 250000 \
  --background
```

## Automatic research routing

Omitting the positional problem (or passing the literal `auto`) invokes the
research router before Boule creates a public participant session. `boule
route` runs the same selection read-only and exits:

```bash
uv run boule route
uv run boule route --mode formalized --router deterministic
```

The router applies hard eligibility gates before any model sees a candidate:

- the registry record is signed, admitted as `LIVE`, and within the bounded
  candidate limit;
- the case clerk's signed snapshot and hash-chain extension verify directly;
- the problem is `OPEN`, research is not paused for review, and no active or
  stale claim occupies it;
- the credential-free HTTPS repository URL and pinned 40-hex commit are valid.

The default `--router deterministic` ranking makes no additional model call.
`--router auto` opts into an ephemeral, low-reasoning Codex advisor that ranks
only the eligible shortlist. That turn loads no user config or project rules,
exposes no shell, browser, plugins, skills, multi-agent tools, provider API-key
variables, or Boule session capability, and returns a constrained JSON choice.
Candidate prose is treated as untrusted data. If the advisor is unavailable,
times out, or violates the schema, auto mode uses the deterministic ranking.
`--router codex` is fail-closed. A single eligible case never needs a routing
model turn. Neither
path treats event count, runtime, token use, or compute spend as evidence of
progress or contribution value. The advisor turn is separate from the research
run's `--max-tokens` accounting budget; its model and method are recorded, but
the current router does not report its token usage.

The resulting local receipt records the verified registry head, bounded
candidate briefs and their digest, advisor shortlist digest, excluded case IDs,
ranking, selected case snapshot, method, confidence, strategy, reason, and
suggested first focus. It is deliberately
`advisory_only`: it creates no ledger event and grants no protocol, originality,
review, attribution, submission, payment, or prize authority. The research
agent must still read the signed brief and create a non-duplicative claim.
Routing is not a reservation: concurrent launches can observe the same idle
snapshot, so the signed claim remains the collision-control gate.

To bypass routing intentionally, name a problem as before:

```bash
uv run boule codex erdos-686 --agent-name alice
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
- the automatic routing method, reason, strategy, and suggested focus when
  Boule selected the case;
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

The live terminal also has local navigation. Press `u` to open current-run
accounting plus seven daily local report buckets, `p` to open deterministic
evidence progress, and `d` or `Esc` to return to the dashboard. Press `/` to
enter `/usage`, `/progress`, or `/help`. This input belongs to the Boule
supervisor and is never passed to the provider process. `Ctrl-C` remains the
safe-stop path in a foreground run and exits only the watcher in `boule run
watch`.

The Usage view groups completed provider reports by local report date and shows
coverage such as `3/4 runs`; an unreported run stays missing rather than
becoming zero. The Progress view derives its state only from signed claims,
checkpoints, handoffs, candidate/review state, and trusted clerk observations.
Agent messages are labelled operational reports, while runtime, tool activity,
and token use cannot advance scientific progress.

Outside the live terminal, `boule usage` renders the same provider-report
accounting across local runs and `boule progress [RUN_ID]` renders the durable
evidence state for the named run (or the latest run when omitted). Both support
`--json`; neither turns usage or activity into research credit or a percentage
solved.

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
- internal state `completed` requires a handoff from the run's exact delegated
  session; the terminal renders this as `HANDOFF SAVED`, not “problem solved”;
- exit code zero without that handoff becomes `protocol_incomplete`;
- stopping a process never fabricates a release, checkpoint, or handoff.

Token counts and cost appear only when the provider reports them. Cached input
and reasoning output remain breakdowns rather than being double-counted. A
recovery run inherits its parent's token budget unless `boule run resume` is
given a new `--max-tokens` value; the new budget applies independently to that
recovery turn.

## Artifact retention and human Git promotion

A handoff should attach every reusable local result with `--artifact`. When a
supervised run closes, Boule copies only those exact signed bytes into its
private run record and records their hashes. External evidence references stay
references; they are not downloaded or copied.

An operator can inspect and then prepare a review branch:

```bash
boule run promote RUN_ID
boule run promote RUN_ID --confirm
```

The preview and confirmation both fetch the signed clerk handoff and revalidate
the retained paths, sizes, hashes, and common credential patterns. Confirmation
is available only when the frozen case disclosure policy is `public`; a
`commitment_only` or `committee` case remains in the private run record and
fails closed until a separate policy-authorized confidential release channel
exists. For a public case, confirmation uses the pinned case commit and a
temporary Git index, so unrelated workspace changes are excluded and the
current checkout is not switched. It creates only the local branch
`boule/handoff/HANDOFF_ID`; it never pushes. The command prints the exact diff
plus the immutable branch and commit identity. The agent checkout remains
push-blocked; publication must happen from a separate maintainer checkout after
that repository's normal Git preflight. Preparing the branch is retention, not
review, verification, acceptance, causal credit, or payment.

## Private local state

By default, run metadata is written below:

```text
~/.local/state/boule/runs/RUN_ID/
~/.local/state/boule/runs/RUN_ID/evidence/HANDOFF_ID/
~/.local/share/boule/runs/RUN_ID/workspace/
```

Directories are mode `0700`; records and normalized event streams are mode
`0600`. Boule stores no environment dump or provider credential. The bounded
event stream contains lifecycle classes, a redacted short agent-message
excerpt, usage, and the signed protocol projection; it excludes prompts,
reasoning, tool arguments, command output, and raw model traces. Provider stderr
is private local diagnostic material and is never added to Git or the Boule
ledger.
Case policy may make signed summaries and event metadata public. Retained
artifact bytes remain private local state until a human deliberately publishes
the prepared branch to whatever readers the case repository permits.

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
