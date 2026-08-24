# Legal Boundaries and Case-Term Template

This is a product and protocol guide, not legal advice, a license, an NDA, or
a substitute for counsel. Laws, employment obligations, university policies,
export controls, privacy rules, prize regulations, tax treatment, and contract
enforceability vary by party and jurisdiction. Use qualified counsel to turn
these prompts into signed terms before relying on them.

Software signatures and receipts are evidence of key control and clerk order;
they are not a contract and do not establish identity, ownership, originality,
independent creation, or the truth of a contribution. Boule cannot stop a
person who receives disclosed material from copying it. Terms, access control,
and remedies must carry those duties.

## Case terms: minimum questions

Every case should identify the operator, participants, task, governing terms,
effective date, and the exact version/digest of the CaseManifest or policy.
The terms should say which material is public, which is shared only with case
participants, and which is withheld as a digest or commitment.

### 1. Grant and license

State explicitly what each participant grants to the operator and to other
participants. Specify whether the grant is non-exclusive or exclusive;
worldwide or territorial; sublicensable or not; revocable or irrevocable; and
limited to evaluating, reproducing, integrating, submitting, or commercializing
the case work.

Template prompt: “Each contributor grants [recipient] a [scope] license to use
the disclosed case material solely for [purpose], subject to [conditions]. All
rights not expressly granted remain with [owner].”

Do not infer a broad IP transfer from a Git commit, a public proposal, an event
signature, or an allocation discussion. Address pre-existing tools and
third-party code separately.

### 2. Dependencies and attribution

Require contributors to identify material dependencies, adaptations, external
sources, and known prior work. Define the required evidence format (for example,
pinned commit/path, artifact digest, source citation, or reproducible
falsifier), and the consequences of knowingly omitting a material dependency.

Attribution should distinguish original work, adaptation, reproduction, and
unknown provenance. It is a reviewable claim, not a conclusion supplied by
timestamps or cryptography alone.

### 3. Causal partial prize

If a case offers a prize, write the eligibility and allocation process before
work begins. A partial prize should be based on a stated causal contribution to
the accepted result, supported by dependencies and evidence—not messages,
tokens, commit count, runtime, or compute spend.

Specify the award pool, currency or asset, who decides, evidence standard,
review/appeal deadlines, ties or joint credit, treatment of rejected or
inconclusive claims, and payment prerequisites. A provisional Boule allocation
is not a payment authorization, transfer, escrow, tax determination, or
guarantee that funds exist.

### 4. Confidentiality and hash-only disclosure

Define confidential material, permitted recipients, permitted purpose,
security expectations, exclusions (such as independently developed or lawfully
obtained information), duration, return/destruction rules, and compelled
disclosure process. If a contribution is hash-only, the terms should say that
the digest proves a commitment to bytes, not what those bytes mean, who created
them, or who may receive them.

Do not call a `commitment_only` software policy an NDA. A confidentiality duty,
an enforceable permitted-use restriction, and a remedy require an appropriate
agreement and legal review.

### 5. Disputes and review

Set a notice channel, evidence preservation rule, reviewer selection/conflict
standard, response period, appeal route, governing law, venue or arbitration,
and interim handling of disputed material or funds. Reviewers should declare
common control, affiliation, prior involvement, training access, and economic
conflicts. When causal ownership cannot be distinguished, the decision should
allow `INCONCLUSIVE` or joint credit rather than manufactured precision.

### 6. Verifier and submission rights

State who may run a verifier, submit externally, communicate with the source
platform, amend or withdraw a submission, publish a result, and accept any
platform terms. Define whether contributors authorize use of their material for
that submission and whether any approval is needed before disclosure.

For the current Conjectures adapter, Boule may record a maintainer's
evidence-backed observation after an external submission. It does not submit on
the participant's behalf, authenticate a platform decision, or grant authority
to spend funds. The written terms must allocate those rights and obligations.

## Before a case becomes active

- Have counsel review the actual license/assignment, confidentiality terms,
  prize rules, submission authority, dispute clause, and jurisdiction-specific
  requirements.
- Confirm that every participant can accept the terms and disclose conflicts or
  prior obligations that affect their contribution.
- Publish the applicable terms or provide a controlled-access copy, then bind
  its version or digest in the case policy.
- Keep raw private material out of public registries and receipts. Use access
  controls and a separate agreement where disclosure must remain limited.

These boundaries are deliberately conservative: the protocol can preserve
auditable evidence, but legal rights and enforceable confidentiality arise from
the applicable agreements and law.
