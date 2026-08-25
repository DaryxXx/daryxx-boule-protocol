# GitHub Organization and Provisioner Setup

This is the one-time owner setup for real GitHub provisioning. Boule can run
locally without it; the staging `local` provider exists for deterministic
tests.

## 1. Create the organization

Create a GitHub organization owned by the intended human/operator account and
enable organization members to create repositories only if that is part of the
governance policy. The public `Boule` account name is already occupied, so pick
an unambiguous available organization name such as `BouleProtocol` and verify
the final choice before configuring clients.

GitHub.com exposes ordinary organization creation through its owner web flow,
not the normal REST API. This is therefore an explicit human-owner action, not
an authority granted to the Boule watcher.

## 2. Register the private GitHub App

Register a private GitHub App owned by that organization. It needs no webhook
or OAuth user authorization for v0.6. Request only:

- repository `Administration: read and write`, needed by GitHub's organization
  repository-creation endpoint;
- repository `Contents: read and write`, needed for the signed marker and
  public scaffold; and
- repository `Metadata: read`, the baseline read permission.

Install it only on the Boule organization. The organization policy and App
installation must allow the App to create and then access the new repositories.
Generate a private key once and deliver it to the maintainer host through its
secret manager or authenticated SSH; keep the directory `0700` and file `0600`.
Never commit the PEM or paste it into chat, an issue, Compose YAML, or `.env`.
With the supplied container, make the file readable only by runtime UID `10001`
(for example ownership `10001:10001` and mode `0600`).

Record the non-secret organization, App ID, and installation ID in the runtime
environment. Mount the private key read-only at the path named by
`BOULE_GITHUB_APP_KEY_FILE`.

## 3. Verify before enabling the watcher

Run one explicit private provisioning first:

```bash
boule registry provision /data CASE_ID \
  --provider github-app \
  --github-org BouleProtocol \
  --github-app-id APP_ID \
  --github-installation-id INSTALLATION_ID \
  --github-key-file /run/secrets/boule-github-app.pem \
  --visibility private
```

Require the returned repository to match the requested owner, deterministic
name, private visibility, and `main` default branch. Boule then verifies every
scaffold file at the immutable commit recorded in the registry and records the
GitHub repository id/node id bound by its signed case marker. A same-name
replacement is rejected during provisioning; a pre-existing empty repository
is rejected rather than silently claimed.

Only after this succeeds should the deterministic watcher receive
`--auto-provision`. A language model may advise on operational state, but it is
not given the App key and cannot widen the watcher's authority.

## 4. Main repository transfer

The protocol repository was transferred to
`BouleProtocol/daryxx-boule-protocol` on 2026-08-25 while preserving GitHub
repository id `1332560675`, branches, and pull requests. Re-check branch
protection and App access after any organization policy change. A successful
Git authentication is not itself authorization to transfer another repository.

## 5. Migrate an existing staging-local case

The migration command does not create a repository or push Git data. First
freeze automated writers, back up the hub and source bare repository, create an
empty private repository with the case's deterministic name, and mirror-push
the complete source refs through the authorized owner account. Keep the local
source bare repository intact.

From a host that has read access to the hub, authenticated `gh` access, and SSH
read access to the destination, record the transition with the registry head
observed immediately before the operation:

```bash
boule registry migrate-repository /data CASE_ID \
  --expected-registry-head REGISTRY_HEAD \
  --github-org BouleProtocol \
  --github-account EXPECTED_GITHUB_LOGIN \
  --visibility private
```

This command performs lookup-only GitHub metadata inspection, clones the
destination afresh, checks Git integrity and exact branch/tag parity, verifies
the original marker bytes and signature at the pinned commit, advances the
verified case-clerk anchor, and finally appends one clerk-signed migration
event under a registry-head compare-and-swap. The exact ref manifest remains as
`0600` hub-private evidence; only its schema, count, `main`, and digest enter
the public registry. It fails without changing the registry if the destination
is missing, empty, public, renamed, owned by the
wrong organization, has a non-`main` default branch, has any moved/missing/extra
ref, or does not preserve the original marker.

Afterwards, verify the signed public registry projection, clone the private
GitHub repository independently, run `git fsck --strict`, and compare its
canonical refs again. Do not delete the original staging repository: it is the
rollback and provenance source for this one-shot v0.6 transition. A future
rollback needs another explicit signed protocol transition; editing the JSONL
or repointing a URL is not a rollback.
