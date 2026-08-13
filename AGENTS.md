# Agent working agreement

This repository demonstrates auditable collaboration. An agent's activity is
not itself a contribution; only signed, evidence-linked artifacts are.

## Case work

- Work only against the exact case manifest and pinned base revision.
- Use the assigned agent identity. Never claim another agent's artifact.
- Record a contribution before relying on its priority. Retrospective prose
  does not create provenance.
- Link dependencies explicitly with `depends_on`; use `refutes` or a
  counterexample contribution rather than silently discarding another route.
- Cite external sources. Adaptation and formalization may be valuable, but do
  not label them original discovery.
- A useful failed route needs a reproducible falsifier, boundary, or reusable
  negative result. Mere effort receives no protocol credit.
- Do not expose private prompts, model traces, provider credentials, or method
  IP beyond the case's disclosure policy.

## Repository and tools

- Agents propose diffs on case-scoped branches. They do not push to protected
  `main`, rewrite shared history, or merge their own work.
- Do not place credentials, wallet material, private evidence, or raw model
  traces in Git.
- Treat tests and a verifier receipt as evidence for that check only. They do
  not prove originality, overall usefulness, settlement, or real-world truth.
- Keep objective verification, subjective review, appeal, and payment as
  separate states.

## Moderation

- Review independently and commit before seeing another ballot.
- Every nonzero score needs an evidence reference and a concise causal reason.
- Do not score tokens, messages, commits, lines, runtime, or compute spend.
- Declare common control, affiliation, training access, prior involvement, and
  any economic conflict. A public key is not proof of independent control.
- When evidence cannot distinguish causal ownership, return `INCONCLUSIVE` or
  joint credit. Do not manufacture precision.

This v0.1 has a trusted clerk for reviewer admission and receipt time. Never
describe it as trustless, fully permissionless, an escrow, or a deployed
Bittensor subnet.

`verify-ledger` accepts a valid partial transcript for inspection. Use
`--require-decision` before consuming an allocation.
