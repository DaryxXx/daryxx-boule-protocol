# Boule workspace protocol v0.4

## Scope

This layer preserves useful progress between short-lived Codex, Claude Code,
human, or other sessions working on one pinned Conjectures problem. It adds an
auditable candidate and review-feedback lifecycle to the v0.3 coordination
ledger. It is not a mathematical oracle, an IP registry, a Conjectures.io
submission client, an escrow, or a payment service.

The writer remains single-clerk. Existing v0.3 event logs replay without a
migration because the problem, policy, config, and event envelope schemas are
unchanged; v0.4 only adds recognized event kinds and derived projection fields.

## Authorities and commands

Participant sessions sign only their own research statements:

```text
boule agent start | claim | heartbeat | checkpoint | chat | handoff | release
boule submit
```

`boule submit` is intentionally named for the human workflow but has a narrow
protocol meaning: it seals a **local candidate**. It never contacts
Conjectures.io, creates an external submission ID, authorizes the submission
fee, or claims that the result is valid.

The trusted maintainer may record external observations and finalize local case
state:

```text
boule maintainer record-submission
boule maintainer feedback
boule maintainer finalize
boule maintainer tick | watch | advise
```

The maintainer key attests that the clerk recorded a particular canonical URL
and snapshot digest in a particular order. It does not prove that Conjectures,
its verifier, or its reviewers signed the observation. Until a signed API or
independent attestation is integrated, every projection exposes:

```json
{
  "external_status_trust": {
    "mode": "trusted_clerk_observation",
    "authenticated_external_attestation": false
  }
}
```

## Candidate binding

A local candidate binds all of the following in one signed event:

- the exact problem and task ID;
- the task commitment and formal repository commit pin;
- one exact solution artifact reference and SHA-256 digest;
- one or more earlier `ADVANCE` handoffs;
- a reproduction command, summary, and limitations;
- the proposing participant and delegated session.

The artifact must already occur as evidence in a linked handoff. Reusing the
same artifact digest under another candidate ID fails. This makes causal
dependencies explicit without pretending that the final submitter authored all
upstream work.

## External observation binding

`record-submission` accepts an already-existing canonical Conjectures result
UUID. It binds that UUID and public result URL back to the candidate's exact
task commitment, repository pin, and artifact digest. Its evidence reference
must be the canonical URL itself and its digest should be computed from the
preserved response bytes. The CLI derives that reference from the result UUID,
so ordinary input is only `--receipt sha256:...`.

No participant can append this event. Exact retries by the maintainer are
idempotent; a changed receipt, reused result UUID, task-pin drift, wrong
artifact, or noncanonical result URL fails closed.

`feedback` records one of three independent stages:

| Stage | Allowed observation | Effect |
|---|---|---|
| `verifier` | `VERIFIED`, `REJECTED` | `VERIFIED` advances to human review; `REJECTED` reopens research. |
| `review` | `APPROVED`, `REJECTED`, `PARTIAL_AWARD` | Approval awaits explicit local finalization; rejection and partial award reopen research. |
| `reward` | `ELIGIBLE`, `INELIGIBLE` | Records eligibility only and never changes problem resolution. |

Every feedback event includes a reason code, summary, next action, canonical
result URL, a stage-specific source label, and digest of the observed public
result. The source label prevents a submission receipt, Lean result, human
review, or reward-eligibility observation from being replayed as another stage;
it remains a trusted-clerk assertion rather than an external signature. `PAID`
is deliberately not an allowed feedback decision: settlement requires a
separate payment receipt and authority and is outside v0.4.

## Derived workflow

```text
OPEN
  -> CANDIDATE_READY                 local artifact sealed
  -> VERIFICATION_PENDING            external submission receipt recorded
  -> REVIEW_PENDING                  Lean VERIFIED observed
  -> ACCEPTANCE_RECORDED             human APPROVED observed
  -> SOLVED                          trusted clerk explicitly finalizes case

VERIFICATION_PENDING -- Lean REJECTED --> OPEN_AFTER_FEEDBACK
REVIEW_PENDING -- review REJECTED ------> OPEN_AFTER_FEEDBACK
REVIEW_PENDING -- PARTIAL_AWARD --------> OPEN_AFTER_FEEDBACK
```

`OPEN_AFTER_FEEDBACK` exposes the terminal report, reason, and requested next
action through `status`, `history`, and `brief`; a new session can immediately
claim a corrected route. Pending verification or review does not globally
freeze research, so a stalled or fabricated observation cannot indefinitely
exclude independent work. Only finalized `SOLVED` blocks new claims and
candidates.

A partial award does not, by itself, prove a formalization defect or solve the
informal problem. Its reason may recommend importing a corrected task, but the
generic state remains open rather than inferring that diagnosis.

## What finalization means

`maintainer finalize` requires the exact earlier `APPROVED` review event and
records a separate signed local resolution. This prevents a Lean pass or an
unfinalized review observation from silently closing the case. It still rests
on the named trusted-clerk boundary above; it is not an external signature or a
claim of trustlessness.

Resolution, causal attribution, appeal, reward eligibility, and actual payout
remain separate state machines. `SOLVED` does not imply that a bounty was paid,
and a payment failure could not reopen a mathematically accepted case.

## Concurrency and Git

Sessions may continue independent research while a candidate is pending, but
the maintainer records at most one live external submission at a time. `flock`
serializes a canonical workspace. Two independent Git clones must not each
append the next event and merge their competing sequence numbers; distributed
deployment still needs a receipt service.

Git carries branches, artifacts, and replicated signed events. It does not
prove conception, prevent copying after disclosure, or determine prize shares.
The frozen case policy and external legal terms govern permitted use, while
Boule records priority, dependencies, and evidence for later causal review.

## Security boundaries

- No command in this lifecycle contains a wallet, payment amount, destination,
  provider callback, or external submission implementation.
- Public Git contains artifact digests and intentionally disclosed evidence,
  never wallet material, credentials, private prompts, or raw model traces.
- A valid signature proves control of one delegated key, not an independent
  person or original conception.
- A maintainer observation is not authenticated reviewer authorship.
- Lean verification applies only to the exact pinned artifact; it does not
  establish novelty, intended informal meaning, review approval, or payment.
- Chat coordinates work but cannot substitute for an evidence-linked handoff.
