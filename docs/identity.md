# Managed identity &amp; service principals

**When:** an unattended host (Azure VM, AKS, App Service, self-hosted runner)
authenticates as an Azure identity instead of a signed-in user. These flow
through `DefaultAzureCredential`, so set the standard `AZURE_*` env vars and the
backend does the rest.

## System-assigned managed identity

Nothing to configure — leave `AZURE_CLIENT_ID` unset and the system-assigned
identity is used.

## User-assigned managed identity

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

??? note "The same with official `artifacts-keyring`"
    Declare the identity per endpoint (`clientId` is the user-assigned client ID,
    or `"system"` for system-assigned):

    ```bash
    export ARTIFACTS_CREDENTIALPROVIDER_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","clientId":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}]}'
    ```

## Service principal with secret

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=your-secret
```

The service principal needs a role on the feed (e.g. Feed Reader). Certificate
auth works too — set `AZURE_CLIENT_CERTIFICATE_PATH` instead of the secret.

??? note "The same with official `artifacts-keyring`"
    Acquire the token yourself, then inject it as per-endpoint JSON:

    ```bash
    TOKEN=$(curl -s -X POST \
      "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" \
      -d "client_id={client-id}" -d "client_secret={secret}" \
      -d "grant_type=client_credentials" \
      -d "scope=499b84ac-1321-427f-aa17-267ca6975798/.default" \
      | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"'"$TOKEN"'"}]}'
    ```

## Workload Identity Federation (OIDC)

On a GitHub Actions job with `permissions: id-token: write`, the backend mints a
token directly from the GitHub OIDC endpoint — no Azure CLI, no token file. It
needs `AZURE_CLIENT_ID` (and `AZURE_TENANT_ID`, or the tenant discovered from the
feed URL), and works whether or not `azure/login@v2` ran. See
[GitHub Actions](github-actions.md) for the full workflow.

If `AZURE_FEDERATED_TOKEN_FILE` is set (the AKS workload-identity convention),
the assertion is read from that file instead. The OIDC audience defaults to
`api://AzureADTokenExchange`; override it with `AZURE_FEDERATED_TOKEN_AUDIENCE`
for sovereign clouds.

!!! note
    `azure/login@v2` on GitHub-hosted runners authenticates the Azure CLI but
    does **not** write an `AZURE_FEDERATED_TOKEN_FILE`; the GitHub OIDC path is
    what makes az-free minting work on those runners.
