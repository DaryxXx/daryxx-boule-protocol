# Boule workspace protocol v0.3

> **Status:** Historical compatibility layer, superseded operationally by
> [workspace v0.5](workspace-protocol-v0.5.md). Existing v0.3 ledgers remain
> replayable; this is not the current remote-clerk contract.

## Scope

This layer preserves useful progress between short-lived Codex, Claude Code,
human, or other sessions working on one pinned problem. It is a coordination
and provenance layer. It is not a mathematical judge, an IP registry, an
escrow, or a Conjectures.io submission service.

The normal flow does not assign specialist roles. A session reads the current
state, claims one bounded question, records checkpoints, and leaves a signed
handoff. An optional label can describe a session without changing its powers.

## Repository boundary

The recommended public deployment has three distinct repositories:

1. this protocol and CLI repository;
2. one case repository per problem, with its own disclosure policy, history,
   branches, artifacts, and protected default branch; and
3. a small registry repository that links active case repositories.

A local installation may instead place several problem directories below one
root. The on-disk protocol is the same, so moving one directory into its own
repository does not rewrite its signed history.

The v0.3 writer is deliberately single-clerk: every event append must pass
through one canonical workspace or service. `flock` serializes sessions sharing
that filesystem. Two independent Git clones must not each append a next ledger
event and then merge; their competing sequence numbers form a fork and replay
fails closed. Git branches may propose code and artifacts, while a future clerk
API must receipt distributed signed envelopes before this becomes a genuinely
multi-writer service.

`boule init` freezes stable Conjectures task identity into `problem.json`.
Mutable values such as bounty size and attempt count are observations, not task
identity, and belong in separately timestamped snapshots. Until Conjectures.io
offers a signed machine API, import is fail-closed parsing of a bounded HTTPS
response and the imported source identifiers must be independently checked
before bounty submission.

## Two command surfaces

Participant commands use a delegated session signing key and can only append
their own statements:

```text
boule agent start
boule agent claim
boule agent heartbeat
boule agent checkpoint
boule agent chat
boule agent handoff
boule agent release
```

Maintainer commands use a separate operational authority:

```text
boule maintainer tick
boule maintainer watch
boule maintainer advise
```

The deterministic maintainer verifies schemas, signatures and append-only
ordering, projects current state, expires stale leases, reports overlap, and
queues handoffs for later reproduction. It cannot sign a participant's work,
change a handoff, judge mathematical truth, allocate credit, decide an appeal,
submit a result, or pay a bounty.

The canonical clerk assigns event receipt time; participant commands cannot
supply it. The injectable library clock is part of the trusted embedding and is
used by deterministic tests, not a field accepted from a remote participant.

An optional low-cost model may read a redacted maintainer brief and suggest
duplicate routes, coordination messages, or the next operational action. Its
output is advisory and never changes protocol state by itself. The watcher only
calls it after a new state digest, which bounds spend and prevents repeated
model calls while nothing changed.

## Session and claim lifecycle

Every controller-signed session delegation names the public session key, a
self-declared controller, exact problem identity, and frozen policy digest.
Every later event names that session and the preceding event hash. The claim
payload names its bounded route while its signed event envelope binds the exact
base-state hash. Signatures establish which key made a statement; a controller
declaration does not prove independent human control.

A session may have one active work claim. A claim contains a narrow question,
a success gate, a falsifier, and an overlap intention; its signed envelope binds
the base event hash. The projection derives its lease expiry and absolute
deadline. A heartbeat may extend the lease within the frozen renewal and
deadline limits, but cannot broaden the question or change the base state.
Silence changes the deterministic projection from active to stale and then
expired; it does not delete history.

A checkpoint is a compact, signed progress record with evidence references and
the next smallest action. It helps a later session resume but is not a curated
contribution. Chat is coordination only and cannot be cited as prize evidence.

A handoff records `ADVANCE`, `NEGATIVE`, `BLOCKED`, or `NO_SIGNAL`, its exact
claim, artifact digests and reproduction commands, limitations, citations, and
explicit dependency edges. The maintainer can queue it for independent
reproduction. Only a later curation/review process can accept it into the
research frontier or use it in a partial-prize allocation.

`ADVANCE` and `NEGATIVE` require at least one evidence digest. `BLOCKED`
requires either evidence or an explicit dependency on an earlier handoff.
`NO_SIGNAL` may preserve closure without claiming protocol credit.

## Provenance and IP boundary

Git provides distribution, diffs, branch coordination, and durable replication.
It does not prove conception, prevent copying after disclosure, or determine a
reward split. Boule adds signed commitments, receipt order, exact dependency
edges, disclosure-aware access receipts, and a causal result manifest. A case
contract supplies permitted use, submission authority, licensing, appeal, and
settlement terms. Initialization freezes `.boule/policy.json`; a controller's
signed session delegation includes its digest. The supplied policy is a protocol
notice and explicitly requires external legal terms—it is not legal advice or,
by itself, proof that a real person assented.

Private prompts, hidden reasoning traces, provider credentials, wallet material,
and unrelated method IP are never protocol evidence. Public Git must contain
only intentionally disclosed material or commitments/digests. Confidential
evidence requires a separate authorized store and a signed access receipt before
release.

## Trust and failure model

The v0.3 local workspace still has a trusted receipt/order service. External
root replication and an independently operated timestamp witness are required
to detect equivocation by that service. Reviewers must disclose common control;
when evidence cannot distinguish ownership, the correct output is joint credit
or `INCONCLUSIVE`, not invented precision.

Objective verification, semantic reproduction, causal attribution, appeal, and
payment remain separate state machines. A green test, a valid signature, an LLM
recommendation, a GitHub timestamp, or a maintainer receipt satisfies only its
own narrow check.
