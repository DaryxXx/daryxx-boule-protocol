# Boule Hub Protocol v0.6

> **Status:** Current experimental hub contract. See the
> [documentation index](README.md) for the active workspace layer and operator
> guides.

## Purpose and scope

The v0.6 hub is a small, trusted control plane for a public registry of Boule
cases. It coordinates intake and publication; it is not a decentralized
registry, an escrow, a Bittensor subnet, or a payment service.

The current importer uses Conjectures as its source and adapter for exact
formal tasks. That is a current integration choice, not an architectural
requirement: a future adapter can supply another source as long as it produces
the pinned task identity and evidence required by the case protocol.

The hub has one common, clerk-signed registry and normally one repository per
problem. The common registry makes cases discoverable. A case repository
isolates its branches, artifacts, history, and access/disclosure policy from
other problems.

## Registry state machine

The registry is an append-only, clerk-signed JSONL ledger. It records a public
subset of the imported problem identity, including its canonical source URL,
task commitment, mode, and formal repository pin. It has these states:

```text
PROPOSED -> ADMITTED -> PROVISIONING -> LIVE
                         |
                         v
                 PROVISION_FAILED -- retry (bounded) --> PROVISIONING
```

- `PROPOSED`: the source has been imported and its task commitment is recorded.
  This is an intake record only. A public proposal does **not** create a GitHub
  repository, start a clerk, admit participants, authorize a submission, or
  promise a reward.
- `ADMITTED`: a maintainer has re-imported the source and verified that its
  identity still matches the proposal. No repository is created by admission.
- `PROVISIONING`: the hub is creating or recovering the local case workspace
  and its dedicated repository. The provisioner binds the case identity with a
  signed marker before writing the public scaffold.
- `PROVISION_FAILED`: provisioning failed after it began. A maintainer may
  retry through the registry's bounded retry path; this does not create a new
  case identity.
- `LIVE`: the repository has been recorded and the hub has verified the
  case-clerk snapshot at a credential-free HTTPS origin. The registry records
  the verified case head and event count at activation.

Only `LIVE` cases are included in the live public projection. The projection
can display case activity fetched from each case clerk, but it marks a case
stale when that clerk is unavailable or its signed state cannot be verified.

## Provisioning and GitHub boundary

Each provisioned case gets a deterministic repository name derived from the
case slug and pinned task commitment. The first remote object is
`.boule/case-marker.json`: a marker signed by the case maintainer key and bound
to the case id, problem id, task commitment, formal pin, policy digest, and
maintainer public key. It also binds GitHub's immutable numeric repository id
and node id (or a staging-local repository identity). An existing repository
is acceptable only when that marker verifies for the same case and repository
identity.

The GitHub integration is intentionally minimal. The GitHub App obtains a
short-lived installation token and needs only the operations used to:

1. look up or create the requested organization repository;
2. read a committed file on `main`; and
3. create the marker and public scaffold files on `main`.

It should be installed only for the intended organization and configured with
the smallest permissions that support those operations: organization
administration/repository creation, repository contents read/write, and
metadata read. It is not a general user GitHub credential and is not used to act as a case
participant, reviewer, submitter, or payer. Keep its private key in a
restricted local secret mechanism; do not commit it, put it in issue text, or
send it to a case clerk.

### One-shot staging repository migration

A case first provisioned by the staging-local provider may be moved to its
deterministic private GitHub repository without rewriting the original signed
marker. This is a one-shot `LIVE` self-transition, not a second case and not a
native GitHub ownership transfer. The original `local:*` repository id remains
the marker identity; the current top-level repository fields become the
verified GitHub id, node id, URL, and `main` commit.

The maintainer command is lookup-only: it cannot create the destination. It
requires an exact active `gh` account, validates owner/name/URL/private
visibility/default branch/id/node from GitHub, and makes a fresh SSH mirror
clone. Before appending anything it:

1. runs strict Git integrity checks on both bare repositories;
2. requires an identical, bounded, canonical manifest of every branch and tag;
3. requires the destination `main` commit to equal the manifest's `main` ref;
4. reads `.boule/case-marker.json` at the original pinned commit in both
   repositories, compares the bytes, and verifies its clerk signature and
   original local repository identity;
5. fetches and verifies the current case-clerk chain head; and
6. compares the registry head supplied by the operator inside the registry
   write lock.

Only then does the registry clerk append `repository_migrated`. The signed
event contains the complete old and new bindings, the original marker-blob
digest, the canonical manifest schema/count/main/digest, and the verified
case-clerk head/count. Its public migration history also names the exact
registry sequence and entry hash. The exact ref names and object ids remain in
`0600` maintainer evidence rather than leaking private branch names through the
public registry. A failed check leaves the registry unchanged; an exact retry
after an ambiguous success is idempotent.

The canonical manifest schema is `boule-git-ref-manifest/0.1`: at most 256
lexicographically ordered, unique `refs/heads/*` and `refs/tags/*` entries,
each with its lowercase Git object id, encoded with Boule canonical JSON. Any
other ref namespace is rejected so it cannot disappear silently during the
move. The original local bare repository is retained as rollback evidence.

After migration, the marker alone no longer identifies the current host.
Verification requires both the unchanged marker and the clerk-signed registry
migration history. A rollback must be a future explicit signed transition;
operators must not edit the event or silently repoint the current fields.

## Case-clerk and API boundary

The registry HTTP service is read-only. It publishes signed registry snapshots,
bounded redacted hash-link extension proofs, and a static observatory; proof
responses contain sequence/hash/signature links, not intake event payloads.
Registry mutations remain maintainer-local. The CLI's TOFU store persists the
registry key plus its last accepted count/head, rejecting rollback and
requiring a valid extension proof before advancing that high-water mark.

Each `LIVE` case has its own trusted-clerk service. The v0.5 case API exposes
only public state/health, durable receipt recovery, and participant-signed
append requests. The client signs its own exact envelope; the clerk serializes
accepted events and signs a receipt. The API has no remote endpoint for
maintainer observations, external submission, verifier/reviewer feedback,
finalization, wallet action, allocation, or payment.

The observatory bounds concurrent case fetches and persists each verified case
chain chunk in a private high-water store. A slow long-lived case may be shown
as stale for one refresh, but the next refresh or process restart resumes from
the last durable verified chunk. A stored rollback, same-height fork, or case
identity replacement fails closed.

Deploy a remote clerk only behind authenticated TLS and suitable rate limits.
The bundled services are single-clerk prototypes, not multi-host consensus or
high-availability infrastructure.

## Relationship to the case protocol

Hub v0.6 does not replace the per-problem case protocol v0.5. In that protocol,
these are intentionally separate facts and decisions:

1. a local candidate is created;
2. an authorized external submission occurs;
3. verifier feedback is recorded;
4. human review is recorded;
5. local case finalization occurs; and
6. reward eligibility and any payment occur separately.

For the current Conjectures adapter, maintainer commands record evidence-backed
observations of an already completed external submission, verifier result,
human review, or reward status. They are not authenticated Conjectures
attestations and do not perform a payment.

## What a signature or receipt proves

A valid participant signature demonstrates control of the signing key over the
signed statement. A valid clerk receipt demonstrates that this clerk accepted
the bound envelope and placed it at a particular point in its durable event
order. A registry signature similarly authenticates the registry clerk's
record.

Those facts do **not** prove the human or organization behind a key, independent
control, identity, originality, inventorship, IP ownership, mathematical truth,
usefulness, external acceptance, causal attribution, or entitlement to a prize.
They also do not prevent a reader from copying disclosed work. Attribution and
partial prizes require disclosed dependencies, evidence, independent review,
and applicable case terms.

## Operational checklist

1. Import and inspect a source task; treat the resulting `PROPOSED` record as
   intake only.
2. Revalidate its pinned identity before admitting it.
3. Provision one isolated case repository with the minimal GitHub App.
4. Start the case clerk behind authenticated TLS, then activate only after its
   signed snapshot verifies against the recorded clerk key.
5. Use the case protocol and its disclosure policy for collaboration,
   submission observations, review, and any allocation discussion.
6. Use written terms and qualified legal review for IP, confidentiality,
   submission authority, disputes, and payment obligations.
