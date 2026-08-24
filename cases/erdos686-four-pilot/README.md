# Erdős 686 Four — hash-only live pilot

This directory demonstrates the pre-disclosure GitHub step for a real Codex
research session. It publishes a bounded route claim and hashes of its private
precommit and prior evidence. It intentionally does not publish the new
mathematical artifact.

The anchor can establish repository ordering for the disclosed metadata. It
does not establish mathematical correctness, originality, causal value, legal
ownership, reviewer independence, payment entitlement, or a Conjectures.io
submission.

The reveal/handoff step remains closed until all of the following exist:

- the Codex attempt has ended and its artifact digest is fixed;
- the result is classified as `ADVANCE`, `NEGATIVE`, `BLOCKED`, or `NO_SIGNAL`;
- a case-specific disclosure and permitted-use policy has been selected; and
- the handoff declares its dependencies, limitations, reproduction command,
  and exact environment.

Git workflow:

1. This branch anchors `anchors/round-5-fieldopt-route.json` before disclosure.
2. A later commit may add a reveal containing the artifact digest and a safe
   public handoff, without rewriting this anchor.
3. A pull request may propose the handoff for the accepted frontier. Neither
   the contributor nor an agent merges its own work into protected `main`.

## Current pilot state

`handoffs/round-5-fieldopt.json` now records the result metadata and artifact
digests in a later commit. The mathematical bytes remain withheld, so this
envelope is not frontier-eligible and cannot receive protocol credit yet. A
controlled reveal plus independent reproduction would be the next protocol
transition.

Round 6 also records a three-session scientific council in
`anchors/round-6-scientific-council.json` and
`handoffs/round-6-scientific-council.json`. The public files contain only
attempt metadata, fixed private-artifact digests, safe summaries, controller
disclosure, and hashes of a local signed replay. The chat and mathematical
artifacts remain private; no allocation is admissible before evidence sealing
and independent review.
