# Boule documentation

This index separates the active protocol contract from compatibility layers,
fixtures, and historical design documents. Version numbers describe wire or
ledger contracts; they are not claims of decentralization, legal force, or
production readiness.

## Current protocol

| Document | Status | Scope |
|---|---|---|
| [Hub protocol v0.6](hub-protocol-v0.6.md) | Current release candidate | Signed problem registry, task repositories, provisioning, migration, and live projection |
| [Workspace protocol v0.5](workspace-protocol-v0.5.md) | Current case protocol | One trusted remote clerk, durable client outbox, exact recovery, and concurrent sessions |
| [GitHub organization setup](github-organization-setup.md) | Current operator guide | Narrow GitHub App permissions, preflight, and migration procedure |
| [Deployment handoff](../deploy/README.md) | Current operator runbook | Clean-clone deployment, external PEM, manual provisioning gate, and explicit automation |
| [Security policy](../SECURITY.md) | Current security boundary | Private reporting, credential storage, runtime state, and safe source sharing |
| [Legal boundaries](legal-boundaries.md) | Required policy template | Disclosure, permitted use, attribution, submission, review, appeal, and payment boundaries |

The [project README](../README.md) contains the shortest install and operator
flows. [CONTRIBUTING.md](../CONTRIBUTING.md) defines the repository-level
contribution contract.

## Compatibility and history

These documents remain because their event types and fixtures are still tested
or because they explain the evolution of the current protocol. They are not the
top-level v0.6 operational contract.

| Document | Status | Purpose |
|---|---|---|
| [Workspace v0.4](workspace-protocol-v0.4.md) | Replayed compatibility layer | Candidate, external observation, review, and local finalization lifecycle |
| [Workspace v0.3](workspace-protocol-v0.3.md) | Replayed compatibility layer | Local session delegation, claims, chat, checkpoints, and handoffs |
| [Community v0.2](community-protocol-v0.2.md) | Executable synthetic fixture | Causal attribution, sealed review, and fictional payout conservation |
| [Core adjudication v0.1](protocol.md) | Executable synthetic fixture | Contribution graph, deterministic reviewer selection, commit/reveal, and allocation |

## Examples and preserved evidence

- [`examples/community-mock/`](../examples/community-mock/) exercises the
  Community v0.2 state machine without network, wallet, model, or real payment.
- [`examples/collaborative-lean/`](../examples/collaborative-lean/) contains
  human-readable v0.1 case and reviewer schema examples.
- [`cases/erdos686-four-pilot/`](../cases/erdos686-four-pilot/) preserves
  hash-only public provenance artifacts from early research pilots. It is not
  active hub runtime data and does not contain a mathematical solution.

## Reading order

For an implementation review, read the hub v0.6 contract, workspace v0.5
contract, legal boundaries, and then the relevant source/tests. Read older
versions only when auditing replay compatibility or the synthetic adjudication
fixtures.
