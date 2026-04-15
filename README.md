# artifacts-keyring-nofuss

Minimal, pure-Python keyring backend for Azure DevOps Artifacts feeds.

Replaces the official `artifacts-keyring` (which wraps a ~100 MB .NET binary) with a
no-fuss implementation that covers the most common Linux auth scenarios using raw
HTTP — no `msal`, no `azure-identity`, no .NET.

## Install

```bash
pip install artifacts-keyring-nofuss
```

Or for development:

```bash
pip install -e .
```

## How it works

When pip, uv, twine, etc. query the keyring for credentials to an Azure DevOps
Artifacts feed, this backend:

1. **Discovers** the Azure AD tenant by making an unauthenticated request to the feed
   URL and parsing the `WWW-Authenticate` header.
2. **Obtains a bearer token** using one of the supported auth flows (see below).
3. **Exchanges** the bearer token for a narrower `VssSessionToken` scoped to
   `vso.packaging`.
4. **Returns** the session token to the caller as Basic auth credentials.

## Auth flows (priority order)

| # | Flow | How it works |
|---|------|-------------|
| 1 | **Azure CLI** | Runs `az account get-access-token`. Most common for local dev. |
| 2 | **Managed Identity** | Queries the Azure IMDS endpoint. For VMs/containers on Azure. |

## Configuration

### Select a specific flow

By default, providers are tried in the order above. To force a specific one:

```bash
# Environment variable
export ARTIFACTS_KEYRING_NOFUSS_PROVIDER=azure_cli  # or: managed_identity
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

## Usage with pip

```bash
pip install --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ my-package
```

The keyring backend is automatically discovered by pip. No extra flags needed.

## Usage with uv

1. Install keyring with this backend:

```bash
pip install keyring artifacts-keyring-nofuss
# or
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

## Security model

This package handles authentication tokens. Key security properties:

- **Endpoint validation**: Discovery responses are validated against allowlists.
  The `authorization_uri` and VSTS authority must point to known hosts over HTTPS,
  with no non-default ports, userinfo, or deep paths. The authority must be a clean
  origin (`https://host` or `https://host/`). This prevents bearer token
  exfiltration via DNS hijacking or rogue proxy responses.
- **Short-lived tokens**: Bearer tokens are not persisted to disk. In-memory caching
  has a 50-minute TTL (tokens typically live 60–75 minutes).
- **Narrow scope**: Session tokens are scoped to `vso.packaging` (read-only,
  org-scoped).
- **No CWD config**: Provider configuration is read only from `~/.config/` or
  environment variables, never from the working directory.
- **Minimal dependencies**: Only `keyring` and `requests` — no large frameworks with
  broad attack surface.
