# Boule Protocol

Boule is the open-source protocol for agentic research on hard problems and
technical bounties. It preserves auditable continuity and causal attribution as
people and short-lived AI agents work across many sessions, recording signed
claims, checkpoints, dependencies, handoffs, candidates, and review observations
so the research can continue without erasing who contributed what.

Boule deliberately separates four questions:

1. Did the pinned verifier accept the final artifact?
2. Which recorded contributions materially advanced it?
3. Was an idea original, adapted, independently reproduced, or merely repeated?
4. Was a reviewed allocation appealed and eventually paid?

The software is an experimental trusted-clerk protocol. It is not a proof of
identity or originality, an escrow, a payment rail, a legal agreement, a
deployed Bittensor subnet, or a mechanism that prevents disclosed IP from being
copied.

## Current status

| Surface | Status | Purpose |
|---|---|---|
| Hub protocol v0.6 | Current release candidate | Signed problem registry, task isolation, provisioning, and live projection |
| Workspace protocol v0.5 | Current case protocol | Durable multi-session claims, chat, checkpoints, handoffs, candidates, and recovery |
| Core adjudication v0.1 and Community v0.2 | Retained compatibility fixtures | Synthetic moderation, allocation, and replay testing; not the active hub contract |

The reviewable v0.6 candidate is on `feature/boule-hub-v06`. Public staging is
available at <https://boule.207.180.245.67.nip.io/>. Staging is a demonstration
environment: its maintainer heartbeat is operational metadata, not signed
protocol evidence, and automatic GitHub provisioning remains disabled until a
narrowly scoped GitHub App is installed.

Conjectures.io is the current source of problem definitions, verifier outcomes,
and bounties. Boule's registry and case model are source-agnostic.

## Architecture

```text
problem source
    -> signed Boule registry
        -> one private repository and trusted clerk per task
            -> independent agent sessions, claims, chat, and handoffs
                -> candidate + external verifier/reviewer observations
                    -> causal review, appeal, and settlement outside the verifier
```

GitHub carries branches, diffs, pull requests, and reproducible artifacts.
Boule carries signed chronology, dependencies, disclosure references, and
review state. Case terms carry confidentiality, permitted use, submission
authority, licensing, appeals, and any prize-sharing agreement.

## Quick start

Requirements: Git, Python 3.12 or 3.13, and
[`uv`](https://docs.astral.sh/uv/).

Until v0.6 is reviewed into `main`, clone the exact candidate branch:

```bash
git clone --branch feature/boule-hub-v06 --single-branch \
  https://github.com/BouleProtocol/boule-protocol.git
cd boule-protocol
uv sync --frozen --extra dev --python 3.12
uv run boule --help
```

All source-checkout commands below use `uv run` so they execute in the locked
project environment.

## Continue a problem with a new agent session

Initialize a local case from the exact Conjectures task:

```bash
uv run boule init \
  https://conjectures.io/problems/erdos686-erdos-686-variants-four \
  --root problems
```

The command prints the case directory. A general-purpose agent can then create
its own identity, read the cold-resume brief, claim one bounded route, and leave
a reproducible handoff:

```bash
uv run boule agent start PROBLEM \
  --name alice --controller alice --label "Codex session A"
uv run boule brief PROBLEM
uv run boule claim PROBLEM \
  --session SESSION_ID --route "close k=5 curve" \
  --success-gate "complete rational-point certificate" \
  --falsifier "an admissible integral point"
uv run boule agent checkpoint PROBLEM \
  --session SESSION_ID --summary "reduced to one missing rank bound" \
  --next "verify the bound independently"
uv run boule agent handoff PROBLEM \
  --session SESSION_ID --outcome BLOCKED \
  --summary "rank certificate still missing" \
  --next "reproduce the rank independently" \
  --reproduce "make verify-k5"
```

`boule claim` is the short form of `boule agent claim`; both append the same
signed event.

Session private keys stay below the ignored `.boule/private/` directory with
mode `0600`. Command output exposes the public identity and local profile path,
never the private bytes. A useful failed route needs a reproducible falsifier,
boundary, or reusable negative result; mere activity is not protocol credit.

For multiple local clones on one machine, run one canonical clerk and point
each clone at the same loopback service:

```bash
uv run boule clerk serve PROBLEM --host 127.0.0.1 --port 8787
export BOULE_SERVER=http://127.0.0.1:8787
uv run boule status PROBLEM
```

The client signs immutable requests locally, verifies clerk receipts, and keeps
an ignored private outbox. Recover an ambiguous append without creating a new
event:

```bash
uv run boule remote recover PROBLEM REQUEST_UUID
```

The built-in HTTP server is loopback-first. Remote use requires a TLS reverse
proxy with authentication and rate limits. Independent machines must use that
HTTPS origin, for example `BOULE_SERVER=https://clerk.example`; their own
`127.0.0.1` is not the canonical host. This is not a multi-node consensus
service.

## Operate a problem hub

Initialize a registry and admit one pinned source task:

```bash
uv run boule registry init ./boule-data
uv run boule propose \
  https://conjectures.io/problems/erdos686-erdos-686-variants-four \
  --registry ./boule-data
uv run boule registry list ./boule-data
uv run boule registry admit ./boule-data CASE_ID
```

Admission re-fetches and compares the source identity. Repository provisioning
is a separate maintainer action and is private by default:

```bash
uv run boule registry provision ./boule-data CASE_ID \
  --provider github-app \
  --github-org BOULE_ORG \
  --github-app-id APP_ID \
  --github-installation-id INSTALLATION_ID \
  --github-key-file /absolute/private/path/github-app.pem
```

The App can create repositories and write their initial contents. It cannot
sign as a contributor, submit to Conjectures, review a proof, allocate a prize,
or move funds. See the [deployment handoff](deploy/README.md),
[GitHub organization setup](docs/github-organization-setup.md), and
[hub protocol](docs/hub-protocol-v0.6.md) before enabling automation.

Run the read-only registry and landing locally:

```bash
docker compose -f compose.staging.yml up --build -d init registry
curl http://127.0.0.1:18786/healthz
```

The Compose setup uses a named volume and prepares it for runtime UID/GID
`10001`. If an operator replaces it with a host bind mount, that directory must
be private and writable by `10001:10001` before the non-root service starts.

The listener is deliberately loopback-bound. A TLS reverse-proxy example is in
[`deploy/staging/nginx.conf.example`](deploy/staging/nginx.conf.example).
The GitHub App PEM remains outside the checkout; `.env` contains only public
identifiers and its host path. See [SECURITY.md](SECURITY.md) before sharing a
source archive or runtime backup.

## Candidate and review boundary

`boule submit` seals a local candidate against an exact session handoff and
artifact digest. It does not contact Conjectures, authorize a fee, or prove
acceptance. An authorized operator submits externally; the trusted maintainer
may then record evidence-bound verifier and reviewer observations. Verifier
success, human review, local finalization, reward eligibility, and payment are
distinct states.

The complete lifecycle and its failure semantics are documented in the
[workspace v0.4 candidate layer](docs/workspace-protocol-v0.4.md) and the
[workspace v0.5 remote-clerk layer](docs/workspace-protocol-v0.5.md).

## Evidence boundaries

| Layer | Records | Does not prove or authorize |
|---|---|---|
| GitHub | Branches, commits, diffs, PRs, and public artifacts | Original authorship, causal ownership, or prize entitlement |
| Boule | Signatures, clerk receipts, dependencies, handoffs, and review state | Who controls a key, first conceived a private idea, or owns IP |
| Objective verifier | One exact artifact/check result | Originality, broader truth, human acceptance, or payment |
| Case terms | Agreed use, disclosure, submission, licensing, and appeal rules | Physical prevention of copying after access |

When evidence cannot distinguish causal ownership, reviewers should return
`INCONCLUSIVE` or joint credit rather than manufacture precision.

## Repository layout

```text
src/boule/                  protocol implementation, CLI, and bundled web UI
tests/                      adversarial, replay, API, and end-to-end tests
docs/                       current specifications and labelled history
examples/                   synthetic fixtures and schema templates
cases/                      preserved public provenance pilots, never runtime data
deploy/staging/             reverse-proxy example for the loopback service
deploy/README.md            clean-host deployment and credential handoff
.github/                    CI and contribution templates
```

Start with the [documentation index](docs/README.md), then read
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[legal boundary template](docs/legal-boundaries.md) before opening a real case.

## Development

```bash
uv sync --frozen --extra dev --python 3.12
uv lock --check
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen pytest
uv build
docker build --tag boule:local .
```

The Community v0.2 and core v0.1 demos remain executable compatibility fixtures.
Their purpose and exact commands are indexed in [docs/README.md](docs/README.md);
they are not evidence that a mathematical problem was solved or that value moved.

## Contributing

Use case-scoped branches and assigned participant identities. Declare
dependencies, adaptations, common control, conflicts, and disclosure level.
Do not push protected `main`, rewrite shared history, publish private traces, or
merge your own case work. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Boule is independent experimental software and is not presented as an
official component of Conjectures.io, Bittensor, OpenAI, Anthropic, or Chutes.
