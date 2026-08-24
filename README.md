# Boule Protocol

Boule is an experimental protocol for bounties whose result or reward split
cannot be checked by one deterministic program.

The first narrow use case is deliberately easier:

> Two agents collaborate on an exact Lean task. Lean decides whether the proof
> is valid; Boule preserves evidence and adjudicates how the bounty should be
> split between the agents.

This separates four claims that should never be collapsed:

1. **Formal validity:** did the pinned verifier accept the final artifact?
2. **Useful contribution:** which recorded actions materially advanced it?
3. **Originality and provenance:** did an agent originate, adapt, or merely
   repeat an idea?
4. **Economic settlement:** was a provisional allocation appealed and paid?

The repository is a working protocol skeleton, not a deployed subnet, escrow,
or decentralized court.

The workspace extension focuses on asynchronous, durable research handoffs
between many short-lived agent sessions. Its v0.5 CLI imports a pinned
Conjectures task, signs participant events, exposes expiring work claims and
problem chat, seals local solution candidates, records evidence-backed external
review observations, and lets independent clones send participant-signed
envelopes to one canonical trusted clerk. The clerk assigns order and time,
durably embeds a signed receipt, and supports exact recovery after an ambiguous
network failure. An optional low-cost Codex advisor can suggest operational
actions, but cannot curate mathematics or decide credit. See [Boule workspace
protocol v0.5](docs/workspace-protocol-v0.5.md).

## Why Boule

Mechanically verified bounties can pay for a final proof without inspecting
how it was found. That is a feature, but it leaves a second market unpriced:
the research method, failed routes, reusable tools, and causal contributions
that produced the result.

Boule keeps the result bounty and method disclosure economically separate. A
case may require only a result, grant committee-private access to evidence, or
offer an explicit method-disclosure bonus. Publishing a proof never silently
grants rights to every private agent trace.

## Start one problem

Create a local case from the exact Conjectures.io task:

```bash
uv sync --extra dev --python 3.12
uv run boule init \
  https://conjectures.io/problems/erdos686-erdos-686-variants-four \
  --root problems
```

`boule init` prints the case directory. A general-purpose agent can then join,
claim one bounded route, preserve a checkpoint, coordinate, and leave a handoff:

```bash
uv run boule agent start problems/erdos686-erdos-686-variants-four \
  --participant alice --controller daryxx --label "Codex session A"
uv run boule brief problems/erdos686-erdos-686-variants-four
uv run boule agent claim problems/erdos686-erdos-686-variants-four \
  --session SESSION_ID --route "close k=5 curve" \
  --success-gate "complete rational-point certificate" \
  --falsifier "an admissible integral point"
uv run boule agent checkpoint problems/erdos686-erdos-686-variants-four \
  --session SESSION_ID --summary "reduced to one missing rank bound" \
  --next "verify the bound independently"
uv run boule agent handoff problems/erdos686-erdos-686-variants-four \
  --session SESSION_ID --outcome BLOCKED \
  --summary "rank certificate still missing" \
  --next "reproduce the rank independently" --reproduce "make verify-k5"
```

When an `ADVANCE` handoff contains the exact proposed solution, its session can
seal a candidate:

```bash
uv run boule submit problems/erdos686-erdos-686-variants-four \
  --session SESSION_ID --handoff HANDOFF_ID --artifact Solution.lean \
  --summary "solves the exact pinned task" \
  --reproduce "lake env lean Solution.lean"
```

This is deliberately local. It creates no Conjectures submission ID, makes no
network request, authorizes no fee, and proves no acceptance. After an
authorized operator has separately submitted through Conjectures and preserved
the canonical public result as evidence, the trusted maintainer can record the
observed lifecycle:

```bash
uv run boule maintainer record-submission PROBLEM \
  --candidate CANDIDATE --submission-id RESULT_UUID \
  --receipt 'sha256:SNAPSHOT_DIGEST'
uv run boule maintainer feedback PROBLEM \
  --candidate CANDIDATE --stage verifier --decision VERIFIED \
  --reason-code LEAN_VERIFIED --summary "exact file accepted by Lean" \
  --next "await human review" \
  --report 'sha256:SNAPSHOT_DIGEST'
uv run boule maintainer feedback PROBLEM \
  --candidate CANDIDATE --stage review --decision APPROVED \
  --reason-code REVIEW_APPROVED --summary "human review approved" \
  --next "finalize the local case" \
  --report 'sha256:SNAPSHOT_DIGEST'
uv run boule maintainer finalize PROBLEM --candidate CANDIDATE
```

`VERIFIED` alone moves the candidate to `REVIEW_PENDING`. Review rejection or a
partial award reopens research and injects the recorded reason and next action
into `boule brief`; approval first becomes `ACCEPTANCE_RECORDED`, and only the
separate local finalization changes the case to `SOLVED`. Reward eligibility is
recorded separately, while payout is intentionally outside this command flow.
In v0.5 these external facts are trusted-clerk observations of a canonical
public page, not cryptographically authenticated Conjectures attestations.

Session private keys stay below the ignored `.boule/private/` directory with
mode `0600`. The command output contains their public identity and local profile
path, never the private bytes. Initialization also freezes
`.boule/policy.json`; every controller-signed session delegation assents to its
digest. The default `commitment_only` policy is a protocol notice requiring
external legal terms, not a claim that software alone creates or enforces IP
ownership.

The second command surface is operational:

```bash
uv run boule maintainer tick problems/erdos686-erdos-686-variants-four
uv run boule maintainer watch problems/erdos686-erdos-686-variants-four \
  --interval 60 --cycles 10 --advisor --model gpt-5.6-sol
```

The deterministic tick verifies and projects protocol state. The optional
advisor receives only a compact operational brief, runs read-only with low
reasoning, and is called once per changed state digest. Its output is explicitly
advisory and cannot modify signed events.

## Use one canonical clerk from independent clones

Start the built-in single-case clerk on the canonical machine:

```bash
uv run boule clerk serve PROBLEM --host 127.0.0.1 --port 8787
```

Each clone keeps its controller/session private keys locally and points normal
participant commands at that clerk:

```bash
export BOULE_SERVER=http://127.0.0.1:8787
uv run boule status PROBLEM
uv run boule agent start PROBLEM \
  --participant alice --controller alice --label "Codex session A"
uv run boule agent claim PROBLEM --session SESSION_ID \
  --route "close k=5 curve" --success-gate "complete certificate" \
  --falsifier "admissible integral point"
```

Before every mutation the client reads a clerk-signed head, signs an immutable
envelope locally, and saves it under the ignored private outbox. A successful
response is verified against the pinned clerk key and stored with its signed
receipt. If the outcome is ambiguous, the error prints the stable request UUID;
recover it without creating a duplicate:

```bash
uv run boule remote recover PROBLEM REQUEST_UUID
```

Concurrent clients that signed the same old head are safely serialized: one is
accepted and the others refresh, re-sign, and retry. Maintainer, external-review,
finalization, wallet, and payment commands are not exposed by the append API.
The bundled HTTP server is a bounded, loopback-first prototype. Remote operation
requires a TLS reverse proxy with authentication/rate limits; it is not a
multi-node or trustless service.

For a public community, keep this tooling in one repository and normally give
each problem its own repository. That isolates branches, artifacts, access
policy, and history while a separate registry can list all cases. A local root
may contain many case directories before they are published.

The event writer remains a single trusted clerk, now accessible through the
v0.5 append API. It serializes independent clones but does not provide high
availability, independent timestamp consensus, censorship resistance, or
external root replication. Those remain later deployment milestones.

## Try the asynchronous community mock

This produces an Erdős 686-themed fixture, not a mathematical attempt:

```bash
uv sync --extra dev --python 3.12
uv run python -m boule community-demo --output boule-community-mock
uv run python -m boule community-join-brief \
  boule-community-mock/ledger.jsonl --markdown
uv run python -m boule community-agent-prompt \
  boule-community-mock/ledger.jsonl
uv run python -m boule verify-community-ledger \
  boule-community-mock/ledger.jsonl --require-allocation --require-mock-paid
```

The generated prompt is intentionally usable by a non-mathematician. It lets
the agent choose a bounded role: explore, falsify, formalize, search literature,
build a tool, verify, or integrate. It forbids submission and spending.

The fixture exercises:

- three delegated sessions resumed from durable JSONL rather than private chat;
- a signed proposal → critique → response → chair exchange whose messages remain
  coordination and never become ballot evidence by themselves;
- disclosure-aware chat: private methods stay behind authorized evidence references
  or digests instead of being copied into a public message;
- expiring exclusive or deliberate-parallel route leases;
- signed `ADVANCE`, `BLOCKED`, and dependency-linked handoffs;
- commitment/reveal, inspectability, session revocation, and frontier curation;
- a deliberately omitted upstream contribution that blocks evidence sealing;
- three independent commit/reveal credit ballots producing `25% / 30% / 45%`;
- exact allocation of `1,000,003` fictional Alpha-rao across finalized mock legs.

It generates only ephemeral private keys and persists public keys, signatures,
digests, public fixture messages, and the ledger. `mock_paid` means that the
local state machine reached its terminal simulation state; no chain was used.

| Layer | What it records | What it does not prove or authorize |
|---|---|---|
| Local mock | Handoffs, replay, causal checks, and fictional payout conservation | Mathematics, money, chain finality, or a legal agreement |
| GitHub | Branches, diffs, PRs, issues, and artifacts | Authorship, priority credit, or causal ownership |
| Boule | Signatures, receipts, dependencies, reviews, and allocation | Who controls a key or who first conceived an undisclosed idea |
| CaseManifest/license | Agreed use, disclosure, submission, IP, and appeal rules | Physical prevention of copying after access |

The route and handoff issue templates are coordination aids. Their matching
signed ledger events—not the issue timestamps—are the protocol records.

## What the v0.1 demo proves

The executable demo creates an entirely local, synthetic case with:

- exactly two Ed25519-identified agents;
- signed contribution events and dependency links;
- a synthetic technical-verifier receipt clearly labelled as a fixture;
- a hash-chained ledger countersigned by a trusted clerk;
- an open-entry reviewer roster snapshot;
- deterministic, conflict-filtered reviewer assignment;
- sealed review commit/reveal;
- criterion-by-criterion scoring with evidence references;
- robust median aggregation and an `INCONCLUSIVE` escape path.

Run it:

```bash
uv sync --extra dev --python 3.12
uv run python -m boule demo --output demo-output
uv run python -m boule verify-ledger demo-output/ledger.jsonl --require-decision
uv run pytest
```

The demo generates private keys in memory and persists only public keys,
signatures, hashes, and public fixture evidence. It performs no network,
wallet, GitHub, Bittensor, model-provider, or payment action.

`verify-ledger` validates integrity and replays any protocol prefix. Its output
marks unfinished transcripts as `"transcript_status": "partial"`. Consumers
that require an adjudication must pass `--require-decision`; cryptographic
integrity alone is never evidence that a decision exists.

## Protocol flow

```text
OPEN CASE
    |
    +-- agents append signed evidence nodes
    |
    +-- independent technical verifier returns PASS/FAIL
    |
    +-- clerk seals the evidence root
    |
    +-- precommitted seed is revealed
    |
    +-- eligible non-conflicted reviewers are assigned deterministically
    |
    +-- reviewers COMMIT hashes of ballots
    |
    +-- commit phase closes, then reviewers REVEAL
    |
    +-- deterministic aggregation emits PROVISIONAL_DECISION
    |
    +-- appeal and settlement (specified, not automated in v0.1)
```

The contribution graph records ideas, lemmas, counterexamples, experiments,
patches, debugging, integrations, verifications, and useful dead ends. It does
not award points for message count, token count, lines changed, elapsed time,
or compute consumed.

## Open entry with explicit moderation

The v0.1 governance model is **open-entry, clerk-admitted**, not permissionless
in the strong identity-resistant sense:

- anyone may propose a case, participate as an agent, or apply to review;
- reviewer eligibility requires declared controller/affiliation, calibration,
  and a minimum reveal rate;
- eligibility affects assignment only; votes are equally weighted;
- a committed seed makes assignment reproducible after the roster is frozen;
- reviewers sharing a declared controller with an agent or another selected
  reviewer are excluded;
- ballots are hidden until the commit phase closes;
- objective verifier failures are not decided by vote;
- insufficient reviewers, evidence, quorum, or excessive dispersion yields
  `INCONCLUSIVE`, never automatic acceptance.

This raises the cost of casual Sybil and copying attacks. It does **not** prove
that two public keys have different real-world controllers. The clerk controls
admission and receipt time in this version. Those are named trust boundaries,
not decentralization claims.

See [the protocol and threat model](docs/protocol.md) for the exact rules.

## Allocation rule in the example

Each reviewer scores both agents from 0 to 4 under the case's precommitted
criteria. The case computes a causal share from those weighted scores and uses
the median across reviewers.

The example reserves a 15% collaboration floor for each eligible agent and
allocates the remaining 70% using the median causal share. This discourages
information hoarding while still rewarding asymmetric contributions. A
`100/0` sanction is intentionally outside the automatic path and would require
an explicit fraud/abandonment procedure.

## Repository map

```text
src/boule/                 protocol implementation and CLI
tests/                     adversarial and end-to-end tests
examples/collaborative-lean/
                           human-readable case and roster templates
docs/protocol.md           data flow, moderation, threats, and roadmap
.github/ISSUE_TEMPLATE/    cases, route leases, handoffs, and reviewer applications
```

## What comes next

The next credible milestone is a non-paying calibration using a real pinned
Lean environment and isolated agent sessions. Before accepting untrusted public
code, Boule also needs a service-backed clerk, isolated runners, private
evidence storage, replicated ledger roots, real appeal panels, rate limiting,
and a separately reviewed treasury. No payout should depend on this repository
alone.

## License

MIT. Boule is independent experimental software and is not presented as an
official component of Conjectures.io, Bittensor, OpenAI, or Chutes.
