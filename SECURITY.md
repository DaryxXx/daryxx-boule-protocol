# Security policy

Boule is experimental trusted-clerk software. Please report a suspected
vulnerability through a private GitHub security advisory for this repository.
If private reporting is unavailable, contact an organization owner privately.
Do not put credentials, exploit details, private case evidence, or participant
data in a public issue.

## Credential boundary

The current hub integration needs one GitHub App credential. The App ID,
installation ID, organization name, and host file path are configuration, not
secrets. The App PEM is a secret and must remain outside the checkout in a
mode-`0700` directory as a mode-`0600` regular file readable by runtime UID
`10001`. Compose mounts it read-only; its contents never belong in `.env`.

Do not store personal access tokens, OAuth tokens, provider keys, passwords,
wallet files, wallet passwords, private prompts, or case evidence in this
repository. Boule does not currently require a Conjectures.io credential or
wallet credential, and adding either to `.env` does not enable submission or
payment.

The `boule-data` runtime volume contains the trusted clerk signing key, signed
registry, case workspaces, and private evidence. Treat the volume and its
backups as sensitive operational state. Never expose the built-in plaintext
listener directly to the internet; use an authenticated TLS reverse proxy.

## Safe sharing

Share a clean clone or a `git archive` of a reviewed commit. Never zip the
working directory: ignored `.env`, `.boule`, `demo-output`, `knowledge`, and
runtime directories may contain private keys or method evidence. The committed
secret-detection baseline contains only detector hashes for reviewed synthetic
fixtures and public integrity digests; it contains no raw values.

Before release, require the locked CI checks, inspect outgoing paths, verify
that only `.env.example` is tracked, and run the deployment preflight described
in [`deploy/README.md`](deploy/README.md). Enable GitHub secret scanning and
push protection at the organization or repository level where available; the
repository CI scan remains mandatory.
