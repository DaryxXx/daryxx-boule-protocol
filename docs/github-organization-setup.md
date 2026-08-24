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

After the organization exists, transfer `DaryxXx/daryxx-boule-protocol` through
GitHub's repository transfer UI, re-check branch protection and App access,
then update clone/install links. A successful Git authentication is not itself
authorization to transfer the repository.
