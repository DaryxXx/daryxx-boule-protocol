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

## Why Boule

Mechanically verified bounties can pay for a final proof without inspecting
how it was found. That is a feature, but it leaves a second market unpriced:
the research method, failed routes, reusable tools, and causal contributions
that produced the result.

Boule keeps the result bounty and method disclosure economically separate. A
case may require only a result, grant committee-private access to evidence, or
offer an explicit method-disclosure bonus. Publishing a proof never silently
grants rights to every private agent trace.

## What the demo proves

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
.github/ISSUE_TEMPLATE/    open case and reviewer applications
```

## What comes next

The next credible milestone is one calibration replay using a real pinned Lean
environment and two real agent sessions. Before accepting untrusted public
code, Boule also needs a service-backed clerk, isolated runners, private
evidence storage, real appeal panels, rate limiting, and a separately reviewed
treasury. No payout should depend on this repository alone.

## License

MIT. Boule is independent experimental software and is not presented as an
official component of Conjectures.io, Bittensor, OpenAI, or Chutes.
