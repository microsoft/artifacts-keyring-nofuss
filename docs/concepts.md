# How it works

When pip, uv, or twine asks the keyring for credentials to an Azure DevOps
Artifacts feed, this backend:

1. **Discovers** the Azure AD tenant with an unauthenticated request to the feed
   URL, reading the `WWW-Authenticate` header.
2. **Obtains a bearer token** from the first auth flow that succeeds (below).
3. For **user tokens** (Azure CLI): **exchanges** it for a narrower
   `VssSessionToken` scoped to `vso.packaging` (read-only).
   For **service-principal tokens** (managed identity, SP, WIF): returns the
   Entra token directly.
4. **Returns** the credentials to the caller.

## Auth flows (priority order)

| # | Flow | How it works |
|---|------|-------------|
| 1 | **Environment variable** | Bearer token from `ARTIFACTS_KEYRING_NOFUSS_TOKEN` (or `VSS_NUGET_ACCESSTOKEN`), `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE`, or a Docker BuildKit secret under `/run/secrets/`. See [Pre-minted tokens](ci-token.md). |
| 2 | **Azure CLI** | Runs `az account get-access-token`. Best for [local dev](local-dev.md). |
| 3 | **ADO auth helper** | Calls `~/ado-auth-helper` from the `ado-codespaces-auth` extension. See [Codespaces](codespaces.md). |
| 4 | **Workload Identity** | Federated OIDC exchange via `AZURE_CLIENT_ID`; assertion from `AZURE_FEDERATED_TOKEN_FILE` or the GitHub OIDC endpoint. See [GitHub Actions](github-actions.md). |
| 5 | **Azure Identity** | `DefaultAzureCredential` — [managed identities and service principals](identity.md). |

Providers are tried in this order. To force one, see
[Selecting a flow](reference.md#selecting-a-specific-flow).

## Security model

- **Endpoint validation** — discovery responses are checked against allowlists.
  The `authorization_uri` and VSTS authority must be known hosts over HTTPS with
  no non-default ports, userinfo, or deep paths. This blocks token exfiltration
  via DNS hijacking or a rogue proxy.
- **Short-lived, never persisted** — tokens are fetched per request and are not
  written to disk or cached across runs.
- **Narrow scope** — user tokens (Azure CLI) are exchanged for `vso.packaging`
  (read-only) session tokens. Service-principal tokens are returned directly;
  their scope is the identity's Azure DevOps permissions.
- **No CWD config** — provider config is read only from `~/.config/` or
  environment variables, never the working directory.
