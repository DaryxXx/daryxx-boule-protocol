# Boule workspace protocol v0.5

> **Status:** Current case-workspace contract. It runs below the
> [v0.6 hub](hub-protocol-v0.6.md) and preserves replay compatibility with v0.3
> and v0.4 events.

## Scope

Version 0.5 adds a central append path for independent Git clones without
changing the v0.4 research, candidate, verifier-feedback, review, or
finalization state machines. It is a trusted-clerk protocol: the participant
signs the exact intention; the clerk chooses durable order and receipt time.

It does not prove human identity, originality, mathematical usefulness, legal
ownership, reviewer independence, external acceptance, reward eligibility, or
payment. Cryptography can make copying and omitted dependency claims auditable
after disclosure; it cannot prevent someone who can read an idea from copying
it. Enforceable permitted use and prize allocation still require case terms and
causal review.

## Topology

One canonical workspace holds the event chain and maintainer key. Each person or
agent clone holds only its local controller/session private keys, the pinned case
bundle (`problem.json`, policy, config with clerk public key), a private outbox,
and verified receipts. Private keys never cross the HTTP boundary.

The frozen default policy is open self-declared participant admission and public
metadata visibility. A case that needs restricted participation or confidential
metadata requires a future policy/authentication version; v0.5 must not be
deployed as if it already supplied that access control.

## Signed envelope

The client sends exactly these fields:

```json
{
  "schema": "boule-workspace-envelope/0.5",
  "request_id": "canonical UUID",
  "problem_id": "pinned problem id",
  "clerk_key": "ed25519:...",
  "base_event_hash": "64 lowercase hex or null",
  "kind": "participant event kind",
  "actor": "ed25519:...",
  "payload": {},
  "signature": "ed25519sig:..."
}
```

The actor signature uses domain `boule-workspace-envelope-v0.5` and covers every
field except `signature`. `actor` is derived from the local private key.
`problem_id`, `clerk_key`, and `payload.problem_id` must match the pinned case.
Only participant events are remotely admitted. A session delegation is limited
to 168 hours by the ledger, not merely by the CLI.

`base_event_hash` is exact-state consent. It prevents the clerk from silently
rebasing a signed action over unseen work. An unaccepted envelope has no client
timestamp or priority claim: canonical priority begins at the clerk receipt.
Session expiry plus the exact-head check bound delayed participant envelopes.

## Clerk event and receipt

Under one case lock, the clerk:

1. replays and verifies the existing v0.4/v0.5 chain;
2. returns the original receipt for the same request UUID and envelope digest;
3. rejects reuse of that UUID with different signed bytes;
4. checks that the signed base is the current head;
5. authorizes the event against current protocol state;
6. chooses `received_at = max(UTC clock, previous received_at)`;
7. writes one v0.5 event containing both envelope evidence and clerk receipt;
8. fsyncs a temporary file, publishes it exclusively, then fsyncs the directory.

The receipt is signed with domain `boule-workspace-clerk-receipt-v0.5` and binds
the request UUID, exact envelope digest, sequence, event ID, clerk time, previous
hash, resulting event hash, problem, clerk key, and event count. If a process
falls after publication but before the response, an exact retry or receipt
lookup recovers the same bytes without a second event.

Legacy v0.4 entries keep their original actor signature and replay unchanged.
The first v0.5 envelope may name a v0.4 head, so no history rewrite or migration
is needed.

## Client durability and concurrency

Before POST, the client atomically publishes a mode-0600 outbox record containing
the signed envelope. After verifying the clerk receipt, it atomically publishes
a completed bundle and removes the outbox entry. Session keys and profiles use
the same temp/fsync/exclusive-publication pattern. An ambiguous failure preserves
the request UUID and outbox; `boule remote recover` first asks for its receipt and
then safely replays the identical signed envelope if needed.

Clients serialize cache updates across local processes, persist the newest
signed event high-water mark seen from each server, and reject a lower event
count or a conflicting head at the same count. Snapshot wall-clock time is not a
rollback invariant because a corrected clerk clock may move backwards while the
append-only head remains unchanged. This detects event-chain rollback after a
clone's first trusted observation. TLS and an independent replicated root are
still needed against first-contact replay and a malicious clerk.

Two different envelopes based on one head race through compare-and-swap. One is
ordered; the loser receives `stale_head`, fetches a signed current snapshot,
creates a new request UUID, re-signs, and retries. Domain uniqueness rules still
decide whether the now-current action remains semantically valid.

## HTTP surface

The built-in single-case development service exposes these routes at its root.
The hub's shared API exposes the same contract below
`/cases/<case_id>` while retaining a separate key, ledger, lock, and receipts
for every case:

- `GET /healthz` — liveness and public case identity;
- `GET /v1/state` — public metadata plus a clerk-signed snapshot;
- `GET /v1/receipts/<request_id>` — durable receipt recovery;
- `POST /v1/append` — participant envelopes only.

It rejects non-JSON, duplicate-key/non-finite JSON, compression, transfer
encoding, missing or multiple content lengths, and bodies over 64 KiB. It uses a
bounded worker set, connection/body timeout, atomic event writes, and complete
ledger preflight before binding. Status codes distinguish new (`201`), identical
retry (`200`), malformed (`400`), invalid signature (`401`), forbidden maintainer
event (`403`), missing (`404`), stale/request conflict (`409`), oversized (`413`),
wrong media (`415`), semantic rejection (`422`), and busy/internal (`503`/`500`).

The service deliberately has no remote route for maintainer observations,
external submission, verifier/reviewer feedback, finalization, wallet action,
allocation, or payment.

## Git and evidence flow

The clerk records signed metadata; it is not an artifact store. Work should live
on a case-scoped Git branch. Before an `ADVANCE` or `NEGATIVE` handoff depends on
bytes needed by others, commit and push those bytes, then cite a stable Git
commit/path and SHA-256 through `--evidence`. A local `--artifact` path records a
digest but does not by itself make the file available to another clone.

A normal handoff is therefore:

1. read `boule brief/status` from the canonical clerk;
2. start/load a local session and claim a narrow route;
3. work and coordinate in a case branch;
4. commit/push reusable artifacts and record their immutable references;
5. publish a signed checkpoint or handoff and retain its clerk receipt;
6. let later agents declare `depends_on` when their result causally uses it.

Git demonstrates disclosed bytes and repository chronology. The signed envelope
demonstrates control of an actor key over an exact statement. The clerk receipt
demonstrates canonical receipt order. Causal review—not commit count, tokens,
runtime, or compute—determines possible partial credit.

## Operational boundary

`boule clerk serve` defaults to loopback and refuses a non-loopback plaintext
bind unless explicitly overridden. The built-in server is suitable for local
simulation or use behind an authenticated TLS reverse proxy with connection,
header, request, and actor rate limits. It replays an append-only file ledger per
request and is not a horizontally scaled production service. Do not use `flock`
as multi-host/NFS consensus, expose the maintainer key to clients, or describe
the service as trustless, permissionless, escrow, or a Bittensor subnet.

## Verified acceptance cases

The v0.5 suite covers mixed v0.4/v0.5 replay, signature and receipt tampering,
same-request concurrency, request-ID conflict, stale-head retry, backwards clerk
clock, restart/recovery, strict JSON/auth HTTP behavior, maximum session life,
two independent clones racing from the same head, atomic private records, and a
simulated lost response after durable commit. These checks establish the stated
software behavior only; they do not validate a mathematical contribution or a
real bounty decision.
