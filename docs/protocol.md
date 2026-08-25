# Boule v0.1 protocol and threat model

> **Status:** Retained core-adjudication fixture and compatibility reference.
> The current service contract is [hub v0.6](hub-protocol-v0.6.md) with
> [workspace v0.5](workspace-protocol-v0.5.md).

## Claim ceiling

Given a frozen case, signed evidence, a verifier receipt, a roster snapshot,
and revealed ballots, Boule v0.1 can reproduce how a provisional contribution
allocation was obtained. It cannot prove that the evidence is complete, that
public keys have independent controllers, that a subjective verdict is true,
or that any payment occurred.

## Case constitution

A case fixes before work begins:

- exactly two agent public keys and their declared controllers;
- the objective and pinned verifier contract;
- admissible contribution kinds and disclosure policy;
- weighted contribution criteria;
- reviewer eligibility, panel, quorum, and dispersion limits;
- a reviewer-roster digest and random-seed commitment;
- submission, review-commit, review-reveal, and appeal deadlines;
- result bounty, optional method-disclosure bonus, and settlement mode.

Changing any field creates a new case version and hash. It never mutates the
old case.

## Evidence graph

Each contribution has a stable ID, signed agent identity, kind, summary,
artifact digest, visibility, and dependency IDs. Accepted kinds are:

```text
idea, lemma, counterexample, experiment, source, patch,
debugging, integration, verification, dead_end
```

The artifact bytes may be public or committee-private. A hash-only claim can
establish prior commitment but cannot receive substantive credit until the
authorized committee can inspect the committed bytes.

## Objective gate

Review cannot begin without one verifier receipt bound to the case and final
artifact. In the intended Lean adapter this means a clean checkout, exact
statement, pinned toolchain, and explicit rejection of forbidden axioms or
statement changes. The included demo uses a synthetic receipt and says so in
the receipt; it tests protocol mechanics, not Lean.

## Reviewer eligibility and assignment

Anyone may apply. A trusted clerk freezes a roster snapshot. A reviewer is
eligible when all of the following are true:

- status is `active`;
- at least two of three calibration cases passed;
- reveal rate is at least 70%;
- no declared conflict with the case;
- controller differs from both agents and every already selected reviewer.

The case commits before submissions close to the canonical JSON digest of:

```json
{"domain":"boule-review-seed-v1","seed":"<32-byte-lowercase-hex>"}
```

After evidence is sealed, the clerk reveals `seed`. Eligible reviewers are
sorted by the SHA-256 digest of canonical JSON with sorted keys, compact
separators, UTF-8 encoding, and no NaN or infinity:

```json
{
  "domain": "boule-review-assignment-v1",
  "seed": "<seed>",
  "case_id": "<case_id>",
  "evidence_root": "<evidence_root>",
  "reviewer_id": "<reviewer_public_key>"
}
```

The first distinct controllers fill the panel. If the panel cannot be filled,
the case is unreviewed. Reputation is an eligibility gate, not vote weight.

## Sealed review

A ballot binds the case, evidence root, reviewer, decision, confidence,
criterion scores, evidence references, and findings. During the commit phase a
reviewer publishes the SHA-256 digest of this exact canonical JSON object:

```json
{
  "domain": "boule-ballot-commit-v1",
  "ballot": {"...": "the complete ballot object"},
  "salt": "<32-byte-lowercase-hex>"
}
```

After every assigned reviewer has committed, the clerk closes the phase.
Reveals are then accepted only when the hash matches. This prevents ordinary
anchoring and copying; it does not prevent reviewers from coordinating through
an external channel.

## Aggregation

For each decided ballot, weighted agent scores produce a causal share. Boule
takes the median causal share across the panel and applies the precommitted
collaboration floor.

The result is `INCONCLUSIVE` when:

- valid reveals are below quorum;
- fewer than two ballots provide a decision;
- the maximum spread of decided causal shares exceeds the case threshold;
- referenced evidence is absent or outside the sealed root.

Objective verifier errors are rerun, not voted upon.

## Appeal and settlement

The code stops at `PROVISIONAL_DECISION`. A production system must provide one
appeal, limited to pre-cutoff evidence omission, verifier error, undisclosed
conflict, or procedural violation. A fresh panel should replace the original
decision only through the same sealed process.

Settlement is a distinct adapter after the appeal window. Mining emissions,
treasury holdings, spot valuation, reserved payout assets, a payout instruction,
and finalized recipient receipts are separate facts. v0.1 moves no value.

## Threats not solved in v0.1

- clerk censorship, roster manipulation, or dishonest receipt times;
- undeclared common control and sophisticated Sybil identities;
- off-protocol reviewer collusion;
- unavailable committee-private evidence;
- malicious untrusted code execution;
- hidden external sources or incomplete provenance;
- model-provider identity and inference provenance;
- bribery, legal disputes, taxes, sanctions, and payout recovery.

The path toward stronger openness is incremental: public clerk receipts,
independent mirrors, real calibration cases, bonded challenges, multiple
clerks, isolated compute, TEE-backed execution receipts, and only then a
settlement contract.
