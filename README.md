# artifacts-keyring-nofuss

[![CI](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml)

> **⚠️ This is an unsupported Microsoft sample.** Unlike
> [`artifacts-keyring`](https://pypi.org/project/artifacts-keyring/), this
> project is a best-effort alternative focused on convenience
> (more auth auto-detection, reuse of existing `az` CLI logins) and
> debuggability (pure Python — no opaque .NET binary). It is not covered by
> any Microsoft support program — use at your own risk.

Minimal, pure-Python keyring backend for Azure DevOps Artifacts feeds.

Replaces the official `artifacts-keyring` (which wraps a ~100 MB .NET binary) with a
no-fuss, pure-Python implementation — no .NET required.

## Install

### Recommended: standalone tool

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

Or with pipx:

```bash
pipx install keyring
pipx inject keyring artifacts-keyring-nofuss
```

Both install the package in an isolated environment. The `keyring` CLI is
placed on your PATH and works automatically with both pip
(`--keyring-provider=subprocess`) and uv (`keyring-provider = "subprocess"`).

#### Verified installs (pinned + hash-checked)

The package ships a `requirements-lock.txt` with SHA-256 hashes for all
runtime dependencies — covered by the package's own
[PyPI attestation](https://docs.pypi.org/attestations/). To install with
hash-verified, pinned dependencies:

```bash
# Extract the lockfile from the attested package on PyPI
pip download --no-deps --only-binary=:all: artifacts-keyring-nofuss -d /tmp/aknf
unzip -p /tmp/aknf/artifacts_keyring_nofuss-*.whl \
    artifacts_keyring_nofuss/requirements-lock.txt > /tmp/requirements-lock.txt

# Install with pinned + hash-checked deps
uv tool install keyring --with artifacts-keyring-nofuss \
    --with-requirements /tmp/requirements-lock.txt
```

The lockfile is maintained by Dependabot and regenerated on each release.

### Into project environment (no isolation)

```bash
pip install artifacts-keyring-nofuss
```

### For development

```bash
pip install -e ".[dev]"
```

## How it works

When pip, uv, twine, etc. query the keyring for credentials to an Azure DevOps
Artifacts feed, this backend:

1. **Discovers** the Azure AD tenant by making an unauthenticated request to the feed
   URL and parsing the `WWW-Authenticate` header.
2. **Obtains a bearer token** using one of the supported auth flows (see below).
3. For **user tokens** (Azure CLI): **exchanges** the bearer token for a narrower
   `VssSessionToken` scoped to `vso.packaging`.
4. For **service principal tokens** (managed identity, SP, WIF): returns the Entra
   bearer token directly as Basic auth credentials.
5. **Returns** the credentials to the caller.

## Auth flows (priority order)

| # | Flow | How it works |
|---|------|-------------|
| 1 | **Environment variable** | Reads a bearer token from `ARTIFACTS_KEYRING_NOFUSS_TOKEN` (or `VSS_NUGET_ACCESSTOKEN` as fallback). Also supports `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` pointing to a file, and auto-detects Docker BuildKit secrets at `/run/secrets/`. Best for CI and Docker builds. |
| 2 | **Azure CLI** | Runs `az account get-access-token`. Most common for local dev. |
| 3 | **ADO auth helper** | Calls `~/ado-auth-helper` (created by the `ado-codespaces-auth` VS Code extension). Enables seamless auth in GitHub Codespaces. |
| 4 | **Workload Identity** | Exchanges a federated OIDC assertion via `AZURE_CLIENT_ID` (+ optional `AZURE_TENANT_ID`). The assertion comes from `AZURE_FEDERATED_TOKEN_FILE` when set, or — on GitHub Actions jobs with `permissions: id-token: write` — is fetched directly from the GitHub OIDC endpoint (no `az`, no token file needed). Best for GitHub Actions. |
| 5 | **Azure Identity** | Uses `DefaultAzureCredential` from `azure-identity`. Handles managed identities (system + user-assigned), service principals (secret/cert), workload identity federation, and more. |

## Configuration

### Select a specific flow

By default, providers are tried in the order above. To force a specific one:

```bash
# Environment variable
export ARTIFACTS_KEYRING_NOFUSS_PROVIDER=azure_cli  # or: env_var, ado_auth_helper, workload_identity, azure_identity
```

Or in `~/.config/python_keyring/keyringrc.cfg`:

```ini
[artifacts_keyring_nofuss]
provider = azure_cli
```

### User-assigned managed identity

Set `AZURE_CLIENT_ID` to the client ID of the user-assigned managed identity:

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

When unset, system-assigned managed identity is used.

### Service principal with secret

Set the standard Azure Identity environment variables:

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=your-secret
```

This requires the `azure-identity` package (included as a dependency). The service principal must have
permissions on the Azure DevOps feed (e.g. Feed Reader).

### Bearer token via environment variable

For CI pipelines and Docker builds, pass a pre-minted bearer token:

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN=<bearer-token>
```

For backward compatibility with existing `artifacts-keyring` CI configs,
`VSS_NUGET_ACCESSTOKEN` is also accepted as a fallback.

#### Reading tokens from files (`_FILE` convention)

Set `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` to a path containing the bearer token.
This follows the Docker `_FILE` convention used by official images (postgres, mysql, etc.):

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE=/run/secrets/my_token
```

#### Docker BuildKit secrets (zero config)

When building Docker images with BuildKit, secrets are mounted as files under
`/run/secrets/` only for the duration of the build step — they are never persisted
in image layers.

The env_var provider automatically checks these well-known BuildKit secret paths:

- `/run/secrets/ARTIFACTS_KEYRING_NOFUSS_TOKEN`
- `/run/secrets/ado_token`

This means you can use BuildKit secrets with **no extra env vars inside the container**:

```dockerfile
# Dockerfile
RUN pip install artifacts-keyring-nofuss

RUN --mount=type=secret,id=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    PIP_KEYRING_PROVIDER=import pip install \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-private-package
```

Build with:

```bash
# Mint a short-lived ADO bearer token and pass it as a BuildKit secret
export ADO_TOKEN=$(az account get-access-token \
  --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv)

DOCKER_BUILDKIT=1 docker buildx build \
  --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ADO_TOKEN \
  -t my-image .
```

The token is available at `/run/secrets/ARTIFACTS_KEYRING_NOFUSS_TOKEN` only during
that `RUN` step and is never baked into the image.

**Priority order**: `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` → `ARTIFACTS_KEYRING_NOFUSS_TOKEN` →
`VSS_NUGET_ACCESSTOKEN` → BuildKit secret paths.

### Workload Identity Federation (GitHub Actions OIDC)

On a GitHub Actions job with `permissions: id-token: write`, the workload
identity provider mints a bearer token directly from the GitHub OIDC endpoint —
no Azure CLI and no federated token file required. It only needs `AZURE_CLIENT_ID`
(and `AZURE_TENANT_ID`, or the tenant discovered from the feed URL). This works
whether or not `azure/login@v2` ran.

If an `AZURE_FEDERATED_TOKEN_FILE` is present (the AKS workload-identity
convention), the provider reads the assertion from that file instead. The OIDC
audience defaults to `api://AzureADTokenExchange` and can be overridden via
`AZURE_FEDERATED_TOKEN_AUDIENCE` for sovereign clouds.

> Note: `azure/login@v2` on GitHub-hosted runners authenticates the Azure CLI
> but does **not** write an `AZURE_FEDERATED_TOKEN_FILE`; the GitHub OIDC path
> above is what makes az-free minting work on those runners.

### Minting a token without `az` (CI / Docker builds)

Inside `docker buildx build`, this backend can't perform Workload Identity
Federation itself: the OIDC material (`AZURE_CLIENT_ID`,
`AZURE_FEDERATED_TOKEN_FILE`) lives on the CI runner, not inside the isolated
build. The standard workaround is to **mint a feed token on the runner** and
inject it into the build as a BuildKit secret, where the env_var provider
consumes it.

That minting is often done with `az account get-access-token`, which is
heavyweight and can hang. This package ships a hang-proof, pure-Python
alternative — the `ak-nofuss mint-token` command — that reuses the same
federated-token exchange with a bounded timeout and retry/backoff. It needs
`AZURE_CLIENT_ID` (and `AZURE_TENANT_ID`, or `--tenant`), and obtains the OIDC
assertion either from `AZURE_FEDERATED_TOKEN_FILE` or, on a GitHub Actions job
with `permissions: id-token: write`, directly from the GitHub OIDC endpoint. It
prints the bearer token to stdout. Because it can fetch the OIDC token itself,
it does not require `az` or `azure/login` on the runner.

#### Installing the CLI

The executable is named `ak-nofuss` (distinct from the `artifacts-keyring-nofuss`
package name), so how you run it depends on your environment:

- **Interactive / long-lived runner** — install `keyring` as a
  [`uv` tool](https://docs.astral.sh/uv/) and expose *our* executable on `PATH`
  alongside it:

  ```bash
  uv tool install keyring --with-executables-from artifacts-keyring-nofuss
  ```

  `--with-executables-from` (not `--with`) is what puts `ak-nofuss` on `PATH`;
  `--with` would install the package into the tool environment but would not
  expose its console script. After this, `keyring` and `ak-nofuss` are both
  available directly.

- **Ephemeral CI (no install, nothing added to `PATH`)** — run it on demand
  with `uvx`. The `--from` is required because the executable name differs from
  the package name:

  ```bash
  uvx --from artifacts-keyring-nofuss ak-nofuss mint-token
  ```

- **Using pipx instead of uv** — inject the package into a `keyring` install and
  expose *our* executable with `--include-apps` (pipx's equivalent of uv's
  `--with-executables-from`):

  ```bash
  pipx inject --include-apps keyring artifacts-keyring-nofuss
  ```

  Plain `pipx inject keyring artifacts-keyring-nofuss` installs the package but
  does **not** put `ak-nofuss` on `PATH` — `--include-apps` is required.
  Alternatively, `pipx install artifacts-keyring-nofuss` installs `ak-nofuss`
  standalone.

You can also use plain `pip install artifacts-keyring-nofuss`, which places
`ak-nofuss` on `PATH` in the active environment.

#### GitHub Actions (composite action — most convenient)

This repository ships a composite action that mints the token via the ephemeral
`uvx` form, masks it, and exposes it as both a step output and the
`ARTIFACTS_KEYRING_NOFUSS_TOKEN` environment variable for later steps:

```yaml
# .github/workflows/build.yml
jobs:
  build:
    permissions:
      id-token: write   # required for OIDC
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6

      - name: Mint feed token
        uses: microsoft/artifacts-keyring-nofuss@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant: ${{ secrets.AZURE_TENANT_ID }}
        # resource is optional (defaults to the Azure DevOps resource)

      - name: Build image
        run: |
          DOCKER_BUILDKIT=1 docker buildx build \
            --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
            -t myorg/my-image .
```

The action fetches the GitHub OIDC token itself, so `azure/login` is not
required — you only need `id-token: write` plus the federated identity's
`client-id` and `tenant`. Add `azure/login` only if other steps need an
authenticated `az`; when it runs first, its exported `AZURE_CLIENT_ID` /
`AZURE_TENANT_ID` are picked up automatically and the `with:` inputs can be
omitted.

#### GitHub Actions (manual step)

If you'd rather mint the token inline:

```yaml
      - uses: astral-sh/setup-uv@v6

      - name: Mint feed token
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: |
          TOKEN=$(uvx --from artifacts-keyring-nofuss ak-nofuss mint-token)
          echo "::add-mask::$TOKEN"
          echo "ARTIFACTS_KEYRING_NOFUSS_TOKEN=$TOKEN" >> "$GITHUB_ENV"
```

Always run `::add-mask::` on the minted token so it is redacted from logs (the
composite action does this for you).

The Dockerfile consumes the secret exactly as in the BuildKit example above:

```dockerfile
RUN --mount=type=secret,id=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    PIP_KEYRING_PROVIDER=import pip install \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/<feed>/pypi/simple/ \
    my-private-package
```

Prefer keeping the token out of your shell environment? Use the `exec` form,
which mints the token, sets `ARTIFACTS_KEYRING_NOFUSS_TOKEN` in the child
environment, and runs the wrapped command:

```bash
ak-nofuss exec -- \
  docker buildx build \
    --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    -t myorg/my-image .
```

You can also write the token straight to a file (created with `0600`
permissions) with `--output-file PATH`, and override the tenant or target
resource with `--tenant` / `--resource`. The same command works via
`python -m artifacts_keyring_nofuss mint-token`.

### GitHub Codespaces

Add the [`artifacts-helper`](https://github.com/microsoft/codespace-features)
devcontainer feature to your `.devcontainer/devcontainer.json`:

```json
{
  "features": {
    "ghcr.io/microsoft/codespace-features/artifacts-helper:3": {}
  }
}
```

This installs the `ado-codespaces-auth` VS Code extension, which creates
`~/ado-auth-helper`. The `ado_auth_helper` provider calls it automatically —
no `az login` needed. Sign in via the "Click to authenticate" prompt in the
VS Code status bar on first use.


## Usage with pip

When installed as a standalone tool (recommended), configure pip to use the
subprocess keyring provider:

```bash
# Global config (recommended — add to ~/.config/pip/pip.conf):
# [global]
# keyring-provider = subprocess

# Or per-command:
pip install --keyring-provider=subprocess \
    --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-package
```

When installed in the same environment as pip, no extra flags are needed — the
backend is discovered automatically via entry points.

## Usage with uv

1. Install as a standalone tool (if not done already):

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

2. Configure uv to use keyring for authentication. Either add it to your
   project config:

```toml
# pyproject.toml or uv.toml
[tool.uv]
keyring-provider = "subprocess"
```

Or set the environment variable:

```bash
export UV_KEYRING_PROVIDER=subprocess
```

3. Use uv as normal with your private feed. A username in the URL (e.g.
   `__token__@`) is required to trigger keyring lookup:

```bash
uv pip install my-package --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/
```

This also works with legacy subdomain-prefixed feed URLs:

```bash
uv pip install my-package --index-url https://__token__@myorg.pkgs.visualstudio.com/_packaging/{feed}/pypi/simple/
```

For `pyproject.toml` index configuration:

```toml
[[tool.uv.index]]
url = "https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/"
name = "my-feed"
```


## Supported feed URLs

Any URL whose host matches one of (including subdomain-prefixed variants):

- `pkgs.dev.azure.com` (e.g. `https://pkgs.dev.azure.com/myorg/…`)
- `pkgs.visualstudio.com` (e.g. `https://myorg.pkgs.visualstudio.com/…`)
- `pkgs.codedev.ms`
- `pkgs.vsts.me`

URLs with userinfo (e.g. `https://__token__@host/…`) and bare hostnames without
a scheme are also handled correctly.

## Troubleshooting

Enable verbose debug output to see the full authentication flow:

```bash
ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 pip install --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ my-package
```

This prints the provider chain, token exchange steps, and any errors to stderr.

### Transient network failures / flaky CI

Outbound calls to Azure DevOps (tenant discovery and the session-token exchange)
are automatically retried with exponential backoff when they hit a transient
failure — a dropped connection, timeout, or a `429`/`5xx` response. This smooths
over the occasional blip that previously surfaced as a spurious `401`/"could not
find a version" error that only a re-run would fix.

The retry budget defaults to **3 attempts** per request. Override it with:

```bash
export ARTIFACTS_KEYRING_NOFUSS_RETRIES=5  # total attempts per request (1–10)
```

Set it to `1` to disable retries entirely.

## Security model

This package handles authentication tokens. Key security properties:

- **Endpoint validation**: Discovery responses are validated against allowlists.
  The `authorization_uri` and VSTS authority must point to known hosts over HTTPS,
  with no non-default ports, userinfo, or deep paths. The authority must be a clean
  origin (`https://host` or `https://host/`). This prevents bearer token
  exfiltration via DNS hijacking or rogue proxy responses.
- **Short-lived tokens**: Bearer tokens are not persisted to disk. In-memory caching
  has a 50-minute TTL (tokens typically live 60–75 minutes).
- **Narrow scope**: User tokens (Azure CLI) are exchanged for session tokens scoped to
  `vso.packaging` (read-only). Service principal tokens (MI/SP/WIF) are returned
  directly — scope is determined by the identity's Azure DevOps permissions.
- **No CWD config**: Provider configuration is read only from `~/.config/` or
  environment variables, never from the working directory.
