# Deployment handoff

This runbook deploys the unified Boule API, landing page, case ledgers, and
trusted maintainer from a clean clone. It does not issue TLS certificates,
submit to Conjectures.io, or move funds.

The supplied credential-mount and UID checks target a Linux host with rootful
Docker Engine and Docker Compose v2. A rootless Docker or Podman deployment
needs an explicit user-namespace ownership design and is not covered by this
runbook.

If Compose fails before creating containers because its negotiated Docker API
is below the daemon's minimum, pin the daemon-supported API for that invocation
(the staging host currently requires `DOCKER_API_VERSION=1.44`). Confirm the
server API with `docker version` first; do not use this override to hide an
otherwise unsupported Docker installation.

## 1. Start the credential-free service

Use a reviewed commit or release, not an untracked copy of another operator's
workspace:

```bash
git clone --branch main --single-branch \
  https://github.com/BouleProtocol/boule-protocol.git
cd boule-protocol
git checkout --detach <REVIEWED_COMMIT_OR_TAG>
docker compose -f compose.staging.yml config --quiet
docker compose -f compose.staging.yml up --build -d init api
curl --fail http://127.0.0.1:18786/healthz
```

Port `18786` is loopback-only. Put it behind authenticated TLS and appropriate
rate limits before remote access; adapt
[`staging/nginx.conf.example`](staging/nginx.conf.example) inside an existing
TLS server block.

## 2. Configure the GitHub App

Create and install the narrowly scoped App described in
[`../docs/github-organization-setup.md`](../docs/github-organization-setup.md).
On the deployment host, store its PEM outside the checkout:

```bash
sudo install -d -o 10001 -g 10001 -m 0700 /etc/boule/secrets
sudo install -o 10001 -g 10001 -m 0600 \
  /path/from/your/secret-manager/github-app.pem \
  /etc/boule/secrets/github-app.pem
install -m 0600 .env.example .env
```

Edit `.env` and fill the canonical HTTPS `BOULE_PUBLIC_ORIGIN`, organization,
App ID, installation ID, and external PEM path. The origin and IDs are public;
the final value is only a path. Never paste the PEM, a token, a password, or
wallet material into `.env`.

Validate file permissions, RSA key shape, and both Compose overlays without
printing credential values:

```bash
sudo ./deploy/preflight.sh .env
```

Direct `boule` commands do not read `.env`; it is passed explicitly to Docker
Compose.

## 3. Provision one private repository manually

Propose and admit a disposable source task first. Then exercise the App through
the credentialed CLI overlay, replacing `CASE_ID`:

```bash
docker compose --env-file .env \
  -f compose.staging.yml -f compose.github.yml \
  --profile tools run --rm cli \
  registry provision /data CASE_ID \
  --provider github-app --visibility private --json
```

Verify the returned owner, immutable repository identity, private visibility,
`main` branch, and signed scaffold. A same-name repository, public repository,
or mismatched identity must fail closed.

## 4. Enable automation deliberately

The normal GitHub overlay supplies credentials but leaves the maintainer
passive. Only after the manual provisioning gate succeeds, add the explicit
automation overlay:

```bash
docker compose --env-file .env \
  -f compose.staging.yml -f compose.github-auto.yml \
  --profile maintainer up --build -d init api maintainer
curl --fail http://127.0.0.1:18786/healthz
curl --fail http://127.0.0.1:18786/v1/maintainer
```

The automation overlay repeats its required credential boundary, so using it
without the credential overlay still fails closed when configuration is
missing. Never run passive and automated maintainers from different Compose
projects against the same volume.

The maintainer's credential-free provider-status observer is enabled by
default whenever that watcher runs. It only polls already recorded submissions
and appends newly reached verifier/reviewer decisions; it neither submits nor
pays. Add `--no-provider-sync` to the watcher command if deployment policy
forbids outbound public reads, and record official feedback manually.

## 5. Production boundaries

Each provisioned case is served by the shared API at
`https://<PUBLIC_ORIGIN>/cases/<case_id>`. Its workspace, signing key, ledger,
receipts, and policy remain isolated inside the shared data volume. The API may
serve the signed state while a case is `PROVISIONING` so the maintainer can
verify and activate it, but participant appends fail closed until it is `LIVE`.
Adding a case does not require another container, port, or TLS hostname.

The `boule-data` volume contains clerk signing keys, ledgers, case workspaces,
and private evidence. Before production, configure encrypted off-host backups
and test restore while writers are stopped. Before any upgrade, back up that
volume, pin the new image or Git commit, run the full checks, recreate the
services, and verify `/healthz`, the signed registry snapshot, maintainer state,
TLS, and case-clerk reachability.

To hand source to another team, give them the Git URL and reviewed commit. If an
archive is required, create it with `git archive`; never archive the working
directory or `.git`, because ignored local state can contain private keys.
