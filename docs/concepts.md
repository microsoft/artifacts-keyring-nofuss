# How it works

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

By default, providers are tried in the order above. To force a specific one,
see [Selecting a specific flow](configuration.md#select-a-specific-flow).

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
