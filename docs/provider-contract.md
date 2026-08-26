# Problem provider contract

Status: current Boule v0.6 integration contract. It defines external problem,
verification, resolution, feedback, and settlement semantics; it does not grant
submission or payment authority.

## Why it exists

A Boule case should not hard-code one bounty site into its collaboration
ledger. A provider adapter imports a pinned problem definition, and the
resulting immutable `problem.json` embeds a
`boule-provider-contract/0.1`. The case can then be replayed later without
guessing which external identifiers, result URLs, decisions, or source labels
were valid when it started.

The signed registry proposal records the exact manifest and publishes its
provider-contract digest. Provisioning rechecks that digest, and the case
policy plus signed repository marker bind it again. Changing provider semantics
therefore requires a new admitted case; it cannot silently reinterpret an
existing ledger.

The built-in adapter is Conjectures.io. Additional providers implement the
`ProblemDefinitionProvider` interface in `boule.problem_import` and return the
same provider ID in both the parsed problem source and contract. URL dispatch
must select exactly one adapter; unknown or ambiguous sources fail closed.

## Normalized lifecycle

The public API and problem index expose four provider-resolution states:

| State | Meaning | Research open? | Terminal? |
|---|---|---:|---:|
| `OPEN` | No external attempt is under review. A sealed local candidate is still local. | yes | no |
| `PENDING_VERIFICATION` | An external receipt exists and verification, review, or final local resolution is pending. The submitted attempt is locked, but independent routes may continue. | yes | no |
| `FAILED` | The latest verifier or reviewer decision rejected that attempt. Evidence-backed feedback is retained. | yes | no |
| `SOLVED` | The contract's successful review was bound to an explicit trusted-clerk resolution event. | no | yes |

`FAILED` never claims the mathematical problem is false or impossible. It
means “this attempt failed”, and its `reason_code`, `summary`, `next_action`,
report digest, candidate ID, submission ID, and result URL remain available for
the next session.

The detailed compatibility state (`CANDIDATE_READY`,
`VERIFICATION_PENDING`, `REVIEW_PENDING`, `ACCEPTANCE_RECORDED`,
`OPEN_AFTER_FEEDBACK`, or `SOLVED`) is retained as `detailed_status`.

## Contract fields

Each contract declares:

- provider identity, display name, definition adapter, and source kind;
- submission ID format, canonical HTTPS result URL template, and receipt source;
- normalized `verifier` and `review` stages, including their native status
  field, pending/success/failure decisions, and evidence source;
- the stage and source that may produce a final `SOLVED` resolution;
- that feedback is evidence-linked and retained after failure;
- a separate settlement field and decisions, plus whether Boule manages it.

The contract supports canonical UUID or bounded safe-string submission IDs.
All result URLs are derived from the frozen template. A maintainer observation
with the wrong provider source, identifier, URL, stage, decision, artifact,
task pin, or evidence reference is rejected.

## Conjectures.io mapping

The current built-in contract maps the provider's independent native axes as
follows:

| Boule stage | Native field | Pending | Success | Failure |
|---|---|---|---|---|
| verifier | `verification_status` | `UNVERIFIED` | `VERIFIED` | `REJECTED` |
| review | `manual_review_status` | `UNREVIEWED` | `APPROVED` | `REJECTED` |
| settlement | `reward_status` | `INELIGIBLE` | provider settlement decisions | independent of resolution |

This follows Conjectures.io's published separation between automated Lean
verification, manual review, and reward state. Boule records current external
status as a trusted-clerk observation with an evidence digest; it does not
pretend that the provider signed Boule's event. See the official
[submission API](https://github.com/conjectures-io/conjectures-validator/blob/main/docs/API.md)
and [public results API](https://github.com/conjectures-io/conjectures-validator/blob/main/docs/PUBLIC_API.md).

## Public status synchronization

The registry maintainer enables provider synchronization by default. For each
submitted candidate still awaiting a decision, it asks the installed read-only
observer for the provider's current native statuses. The Conjectures.io
observer reads the credential-free public submissions feed in bounded 100-row
pages, validates the submission ID and pinned task ID, and rejects impossible
state combinations such as an approved review before verification succeeds.

Pending observations do not create ledger noise. Newly terminal verifier or
review decisions create evidence-linked, maintainer-signed feedback events; an
approved review also creates the explicit case-resolution event. Exact retries
are idempotent. A rejected verifier or review produces `FAILED`, retains public
feedback, and reopens research. It never means that the underlying conjecture
has been disproved.

The evidence digest covers the canonical public API row, and its reference is
the exact bounded feed URL observed. The human result URL remains separately
bound to the candidate. These events prove what Boule's trusted maintainer
observed, not an authenticated provider signature. Some public rejected rows
do not expose a detailed verifier report; in that case Boule records the public
status and digest without inventing a reason. An operator can later attach a
richer official report with the manual feedback command.

```bash
# One candidate, on demand
boule maintainer sync-provider PROBLEM --candidate CANDIDATE_ID

# The normal single registry watcher does this for every LIVE case
boule registry watch REGISTRY --cycles 0 --interval 30

# Explicitly disable outbound provider reads when required
boule registry watch REGISTRY --cycles 0 --no-provider-sync
```

The public maintainer heartbeat reports whether synchronization is enabled and
how many observations and signed events the latest cycle produced. That
heartbeat is operational metadata, not protocol evidence.

## Bounty boundary

The Conjectures.io contract currently freezes
`settlement.managed_by_boule: false`. `SOLVED` therefore does not trigger a
wallet, claim a bounty, mark a reward paid, or allocate contribution credit.
The API returns `bounty.status: NOT_MANAGED` and the next action
`BOUNTY_MANAGEMENT_NOT_IMPLEMENTED`. Settlement can be added later as a
separate authorized workflow without weakening verification or rewriting old
case contracts.

## Adding a provider

An adapter must:

1. recognize and canonicalize only its own public problem URLs;
2. fetch within Boule's bounded transport and redirect policy;
3. parse a deterministic pinned task manifest and snapshot;
4. return a validated provider contract whose ID matches the manifest source;
5. supply tests for canonicalization, conflicting identity, decisions, result
   URLs, failed feedback, and successful resolution.

Providers that expose a public status API may additionally install a bounded
`SubmissionObserver` in `boule.provider_observer`. Providers without one still
use the same contract and lifecycle, but their authorized maintainer records
evidence-backed feedback manually.

Adding an adapter changes source ingestion, not contribution credit. The
provider still supplies problem truth and external decisions; Boule supplies
signed continuity, dependency history, and an inspectable local projection.
