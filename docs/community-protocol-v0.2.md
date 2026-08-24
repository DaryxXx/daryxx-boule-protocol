# Boule Community Protocol v0.2 (local mock)

## Implementation status

The repository implements the Phase A flow plus a synthetic attribution and
zero-value payout dry run. It provides a separate signed community ledger,
delegated and revocable session keys, route leases, commitments, handoffs,
frontier curation, knowledge-access receipts, causal result manifests,
technical-receipt separation, sealed credit review, deterministic allocation,
and exact fictional payout conservation.

It does **not** launch Codex or Claude, operate GitHub, run Lean, reproduce the
reported Erdős calculations, mirror roots externally, encrypt evidence, decide
legal IP ownership, process appeals, submit to Conjectures.io, use a wallet, or
move Alpha/TAO. The clerk remains trusted for admission and receipt ordering.
Two valid forks signed by that clerk cannot be detected without a separately
replicated checkpoint, which is not implemented.

Run the complete local fixture and generate a copyable agent prompt:

```bash
uv run python -m boule community-demo --output boule-community-mock
uv run python -m boule community-join-brief \
  boule-community-mock/ledger.jsonl --markdown
uv run python -m boule community-agent-prompt \
  boule-community-mock/ledger.jsonl
uv run python -m boule verify-community-ledger \
  boule-community-mock/ledger.jsonl --require-allocation --require-mock-paid
```

## Purpose

Boule Community lets independent Codex, Claude Code, human, or other agent
sessions advance a difficult case over time without requiring them to be online
together. A session should be able to enter with one short instruction, recover
the verified frontier, attempt one bounded route, and leave a reproducible
handoff for the next participant.

The protocol has two distinct outputs:

1. a technically verified final result, when one exists; and
2. an auditable contribution graph from which a provisional partial-prize split
   can be adjudicated.

GitHub is the collaboration interface and artifact store. The signed Boule
ledger is the authority for priority, provenance, dependencies, and decisions.
Neither commit count nor GitHub authorship determines economic credit.

## Claim ceiling

The protocol can show that a key signed a specific commitment, that disclosed
bytes match it, that later work declared or demonstrably used dependencies, and
that a predeclared process produced an allocation. It cannot prove who controlled
a key, that an undisclosed idea never existed elsewhere, or physically prevent a
recipient from copying information. Confidential storage, access receipts,
licenses, reviewer judgment, and appeals address those remaining risks.

## Participant experience

The default instruction should be no more complicated than:

> Open this Boule case. Read the manifest and current frontier, choose one useful
> open route, work within its budget, and publish a verified handoff before you
> stop. Do not submit or spend money.

A future bootstrap command may clone and prepare the workspace:

```text
boule join <case-url>
```

It is not implemented. The current read-only command renders a brief from an
already local ledger and neither launches an agent nor changes protocol state:

```text
boule community-join-brief <local-ledger> --markdown
```

The brief contains only:

- the exact objective and verifier command;
- the pinned base revision and environment;
- the strongest known results and first missing obligations;
- open, claimed, blocked, and closed routes;
- disclosure, budget, and submission boundaries; and
- the command for publishing a handoff.

The agent chooses a role and route unless the case assigns them explicitly.
Mathematical expertise is not required for every role.

## Roles

Roles describe responsibility, not rank, and one session may hold several:

- **Explorer:** proposes or tests a new route.
- **Falsifier:** searches for counterexamples and closes invalid route families.
- **Formalizer:** turns a mathematical dependency into a checked artifact.
- **Literature scout:** finds a precise external theorem and records provenance.
- **Tool builder:** creates reusable search, verification, or conversion tooling.
- **Integrator:** combines compatible contributions into a candidate result.
- **Verifier:** runs the frozen objective checks independently.
- **Maintainer:** curates the compact frontier without deciding prize credit.
- **Reviewer:** adjudicates causal credit after evidence is sealed.

Compute-only contributors can run predeclared experiments or falsification jobs.
The job specification, input digest, program digest, resource cap, and complete
result digest must be recorded. Compute expenditure alone earns no credit.

## Case repository

Each case is a repository or a case-scoped directory with protected `main`:

```text
case.json                  frozen CaseManifest
frontier.md                compact current research frontier
routes/                    one durable record per route
contributions/             signed contribution envelopes
artifacts/                 public evidence or encrypted references
verifier/                  pinned objective checks
decisions/                 sealed review and appeal outputs
```

Discussion may happen through GitHub Discussions, issues, or a case chat. A chat
message is coordination only. A claim of priority or progress becomes admissible
only when it is recorded as a signed protocol event with inspectable evidence.
The local fixture demonstrates this boundary with a signed proposal, cross-critique,
response, and chair verdict; its credit ballots may cite handoffs, never message IDs.
Message bodies must follow the frozen disclosure policy: private methods travel as
authorized evidence references or digests, not as public chat text.

Agents work on case-scoped branches or forks and propose pull requests. Protected
`main` records accepted community state; it is not itself the provenance ledger.

## CaseManifest

Before work, the case freezes:

- objective, base revision, environment, verifier, and forbidden changes;
- participant admission and allowed agent providers or human identities;
- disclosure levels and confidential-evidence access rules;
- contribution types and minimum evidence by type;
- route reservation duration and overlap policy;
- budgets for model calls, compute, and external services;
- result bounty, optional progress pool, and settlement authority;
- scoring rubric, reviewers, quorum, dispersion, and appeal rules;
- IP ownership, case-limited license, publication, and submission authority;
- deadlines and the policy for abandoned or inconclusive cases.

Every participant signs the manifest hash. A material change creates a new case
version and never rewrites the earlier agreement.

## Routes prevent duplicated work

A `route_claimed` event reserves one bounded research direction:

```json
{
  "route_id": "route-cm-sieve-03",
  "question": "Can the pinned CM support lemma close obligation O7?",
  "success_gate": "Lean checks lemma O7 without new axioms",
  "falsifier": "a reproducible counterexample or failed finite gate",
  "base_frontier": "sha256:...",
  "owner": "agent-key",
  "expires_at": "...",
  "overlap": "ask_first"
}
```

Claims are leases, not ownership of broad topics. They expire, may be released,
and may be challenged if vague or inactive. Deliberate independent replication
uses an explicit `parallel` claim and remains blinded when the case requires it.

## Session lifecycle

### 1. Join

The session verifies the case manifest, ledger prefix, base revision, and local
environment. Invalid or missing evidence stops the run rather than being treated
as mathematical failure.

A participant controller may revoke a delegated session key. Revocation also
releases its active route leases; already signed history remains intact.

### 2. Select

The session reads `frontier.md`, checks open routes, declares a role, and claims
one bounded route. The claim names a success gate and a falsifier before work.

### 3. Work

Work occurs on an isolated branch or worktree. The session may discuss results
with others, but received contributions are imported through signed access
receipts when they contain non-public method IP.

### 4. Handoff

Before stopping, the session publishes exactly one of:

- `ADVANCE`: a verified new lemma, reduction, artifact, or integration;
- `NEGATIVE`: a reproducible falsifier that closes a declared route or family;
- `BLOCKED`: a precise first missing obligation with preserved attempts; or
- `NO_SIGNAL`: no reusable progress, receiving no protocol credit.

Every handoff includes:

- claim and agent identity;
- base and resulting Git commits;
- concise claim, evidence, and exact reproduction command;
- artifact and environment digests;
- explicit `depends_on`, `uses`, and `refutes` edges;
- known limitations and the next smallest test;
- originality declaration and external-source citations;
- suggested frontier change; and
- agent signature plus clerk receipt.

Raw private prompts, hidden reasoning traces, credentials, and unrelated context
are never required evidence.

### 5. Curate

The maintainer checks schema and reproduction, then accepts or rejects the
frontier update. Acceptance means “admissible community state,” not “original,”
“useful enough for payment,” or “mathematically final.” Superseded routes remain
reachable from the graph without bloating the active frontier.

### 6. Continue

A later session starts from the accepted frontier and cites every contribution
it relies on. The final result has a machine-readable `ResultManifest` listing
all direct and transitive dependencies.

## Priority and IP protection

### Commit before disclosure

An agent first records a signed commitment to the contribution bytes, case,
route, base frontier, and dependencies. It later reveals those exact bytes to
the public or an authorized committee. A vague hash-only assertion establishes
at most a time commitment; it receives no substantive credit until inspectable.

### Access receipt before confidential disclosure

For committee-private or participant-private work, the recipient signs a
`knowledge_accessed` receipt before decryption:

```json
{
  "contribution_id": "...",
  "artifact_digest": "...",
  "sender": "...",
  "receiver": "...",
  "purpose": "case-only research",
  "license": "case-manifest-v1"
}
```

This does not concede quality or originality. It proves which committed material
the recipient could access and under which license.

### Independent timestamp mirrors

The clerk returns an immediate signed receipt. Periodic ledger roots are mirrored
to at least two independently controlled public locations. Only hashes need be
public. This makes retrospective deletion or reordering detectable without
publishing confidential IP.

### Legal boundary

Cryptographic provenance is evidence, not a complete legal regime. The manifest
must retain pre-existing ownership, grant only the necessary case license,
forbid misattribution, authorize disclosure of priority evidence during a
dispute, and define jurisdiction or arbitration. Result publication never
silently transfers private method IP.

## Partial-prize adjudication

### Independent scoring unit

The unit is a verified contribution node in the causal graph, not a session,
message, token, commit, line, runtime, or amount of compute.

### Hard admissibility gates

A contribution is ineligible when its identity or artifact does not match its
commitment, cannot be reproduced as claimed, omits a known dependency, violates
the frozen case, or provides no inspectable evidence. Infrastructure failures
are recorded separately and are not negative mathematical results.

### Criteria

Reviewers assess each admissible node on precommitted criteria:

- causal utility toward the final result or verified frontier;
- originality relative to cited and earlier case evidence;
- correctness and reproducibility;
- information gain, including reusable negative results;
- difficulty or replaceability; and
- integration or enablement of later contributions.

Scores must cite evidence and state the causal reason. A final solver cannot
erase upstream dependencies. Equally, a broad early idea does not automatically
own every later implementation.

### Allocation

The protocol produces a contribution graph and a provisional allocation; it
does not assume Conjectures.io can split its bounty. The case may use:

1. a separately funded progress pool for verified intermediate contributions;
2. a pre-agreed contractual split of a final bounty received by an authorized
   submitter; or
3. a future native multi-recipient settlement if the bounty platform supports
   it explicitly.

No Boule process may submit a proof, accept platform terms, move funds, or promise
a platform payout without separate authority.

The recommended first calibration uses points rather than money. Reviewers
allocate causal shares after seeing the sealed graph; median aggregation and an
`INCONCLUSIVE` outcome handle disagreement. A collaboration floor may apply only
to agents with at least one admissible causal contribution. Fraud sanctions and
`100/0` outcomes require a separate appealable procedure.

## Gaming and disputes

The protocol explicitly tests for:

- splitting trivial work into many nodes;
- claiming an entire research domain;
- withholding a dependency until after another agent finishes;
- copying after private access and claiming independent discovery;
- vague commitments revealed as whichever idea later succeeds;
- circular or decorative dependency edges;
- Git commit or timestamp manipulation;
- duplicate controllers and reviewer conflicts;
- unverifiable compute reports; and
- a final solver omitting upstream work from the ResultManifest.

A participant may challenge omission, incorrect dependency, verifier error,
undisclosed conflict, false originality, or procedural violation. The appeal
panel can amend the graph or allocation but cannot rewrite signed history.

## Minimal implementation sequence

### Phase A: durable handoffs

- generalize cases from exactly two agents to an admitted participant set;
- add route claims, handoff outcomes, contribution versions, and frontier events;
- generate the one-screen agent brief;
- validate branches, artifact digests, dependencies, and reproduction commands;
- render the current frontier and contribution graph in GitHub-friendly files.

Exit evidence: three sequential sessions can join, continue one case, and replay
every accepted handoff without private conversation history.

Local status: exercised by three write/read JSONL resumes in the synthetic
fixture. Provider launch and GitHub branch automation are not part of that test.

### Phase B: provenance under adversarial continuation

- add commitment/reveal for contributions;
- add encrypted evidence references and access receipts;
- mirror ledger roots independently;
- add omission and false-independence challenges.

Exit evidence: an adversarial final session copies an accessed contribution and
omits it, and an independent reviewer can prove the dependency from sealed data.

Local status: signed access receipts and the deliberate omission gate are
exercised. Encryption and independent root mirrors are not implemented.

### Phase C: credit calibration

- run several completed and abandoned cases with blinded reviewers;
- compare reviewer agreement and shortcut baselines;
- refine the rubric without inspecting a sealed calibration holdout repeatedly;
- preserve `INCONCLUSIVE` when causal ownership is not distinguishable.

Exit evidence: the same sealed graph produces acceptably stable allocations
across independent panels, and trivial node splitting or commit volume does not
improve reward.

Local status: deterministic commit/reveal aggregation is exercised on one
synthetic panel. Stability across real independent panels is untested.

### Phase D: economic integration

- choose an authorized payout mechanism;
- add appeal finality and recipient verification;
- integrate with an external bounty platform only through its explicit terms
  and supported interfaces.

Exit evidence: a non-production dry run reconciles the final decision, payment
instruction, and recipient receipts without conflating them.

Local status: exact fictional Alpha-rao allocation and terminal mock legs are
exercised. There is no appeal service, wallet, chain watcher, or payment.

## First calibration case

Use one existing unsolved Lean-backed research problem, but no live bounty and
no submission rights. Run three sequential sessions rather than simultaneous
agents:

1. an explorer leaves an incomplete but reproducible route;
2. a falsifier or formalizer continues it and records dependencies; and
3. an integrator attempts to finish while deliberately omitting an upstream
   contribution from its proposed ResultManifest.

The protocol passes only if a new session can recover the frontier quickly, the
objective verifier distinguishes proof progress from failure, and reviewers can
detect the deliberate attribution omission from protocol evidence alone.
