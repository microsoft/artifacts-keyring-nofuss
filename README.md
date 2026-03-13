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

When pip (or twine, etc.) queries the keyring for credentials to an Azure DevOps
Artifacts feed, this backend:

1. **Discovers** the Azure AD tenant by making an unauthenticated request to the feed
   URL and parsing the `WWW-Authenticate` header.
2. **Obtains a bearer token** using one of the supported auth flows (see below).
3. **Exchanges** the bearer token for an org-scoped, **read-only** Azure DevOps session
   token (`vso.packaging` scope) — the narrowest viable scope.
4. **Returns** the session token to pip as Basic auth credentials.

## Auth flows (priority order)

| # | Flow | How it works |
|---|------|-------------|
| 1 | **Azure CLI** | Runs `az account get-access-token`. Most common for local dev. |
| 2 | **Managed Identity** | Queries the Azure IMDS endpoint. For VMs/containers on Azure. |
| 3 | **Browser** | Opens system browser for OAuth2 login (authorization code + PKCE). |

## Configuration

### Select a specific flow

By default, providers are tried in the order above. To force a specific one:

```bash
# Environment variable
export ARTIFACTS_KEYRING_NOFUSS_PROVIDER=azure_cli  # or: managed_identity, browser
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

## Supported feed URLs

Any URL whose host matches one of:

- `pkgs.dev.azure.com`
- `pkgs.visualstudio.com`
- `pkgs.codedev.ms`
- `pkgs.vsts.me`
