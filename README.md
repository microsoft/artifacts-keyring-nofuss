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
| 4 | **Workload Identity** | Exchanges a federated token via `AZURE_CLIENT_ID` + `AZURE_FEDERATED_TOKEN_FILE` + `AZURE_TENANT_ID`. Best for GitHub Actions with `azure/login@v2`. |
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

When using `azure/login@v2` in GitHub Actions, the action automatically sets
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE`.
The workload identity provider detects these and exchanges the federated token
for a bearer — no extra configuration needed.

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
