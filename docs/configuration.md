# Configuration

## Select a specific flow

By default, providers are tried in [priority order](concepts.md#auth-flows-priority-order).
To force a specific one:

```bash
# Environment variable
export ARTIFACTS_KEYRING_NOFUSS_PROVIDER=azure_cli  # or: env_var, ado_auth_helper, workload_identity, azure_identity
```

Or in `~/.config/python_keyring/keyringrc.cfg`:

```ini
[artifacts_keyring_nofuss]
provider = azure_cli
```

## User-assigned managed identity

Set `AZURE_CLIENT_ID` to the client ID of the user-assigned managed identity:

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

When unset, system-assigned managed identity is used.

??? note "The same with official `artifacts-keyring`"
    There's no managed-identity path, so you fetch a token from the instance
    metadata endpoint yourself and hand it over as per-endpoint JSON:

    ```bash
    TOKEN=$(curl -s -H Metadata:true \
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=499b84ac-1321-427f-aa17-267ca6975798" \
      | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"'"$TOKEN"'"}]}'
    ```

## Service principal with secret

Set the standard Azure Identity environment variables:

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=your-secret
```

This requires the `azure-identity` package (included as a dependency). The service principal must have
permissions on the Azure DevOps feed (e.g. Feed Reader).

??? note "The same with official `artifacts-keyring`"
    Acquire a token for the service principal yourself, then inject it as
    per-endpoint JSON:

    ```bash
    TOKEN=$(curl -s -X POST \
      "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" \
      -d "client_id={client-id}" \
      -d "client_secret={secret}" \
      -d "grant_type=client_credentials" \
      -d "scope=499b84ac-1321-427f-aa17-267ca6975798/.default" \
      | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"'"$TOKEN"'"}]}'
    ```

## Bearer token via environment variable

For CI pipelines and Docker builds, pass a pre-minted bearer token:

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN=<bearer-token>
```

For backward compatibility with existing `artifacts-keyring` CI configs,
`VSS_NUGET_ACCESSTOKEN` is also accepted as a fallback.

??? note "The same with official `artifacts-keyring`"
    The token goes into a per-endpoint JSON document, repeated for every feed
    you use:

    ```bash
    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"<bearer-token>"}]}'
    ```

### Reading tokens from files (`_FILE` convention)

Set `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` to a path containing the bearer token.
This follows the Docker `_FILE` convention used by official images (postgres, mysql, etc.):

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE=/run/secrets/my_token
```

!!! tip "Docker builds"
    Inside a container build, the env_var provider also auto-detects BuildKit
    secrets mounted under `/run/secrets/`. See [Docker](docker.md) for the
    zero-config workflow.

**Priority order**: `ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` → `ARTIFACTS_KEYRING_NOFUSS_TOKEN` →
`VSS_NUGET_ACCESSTOKEN` → BuildKit secret paths.

## Workload Identity Federation (GitHub Actions OIDC)

When using `azure/login@v2` in GitHub Actions, the action automatically sets
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE`.
The workload identity provider detects these and exchanges the federated token
for a bearer — no extra configuration needed.

See [GitHub Actions](github-actions.md) for full CI examples, including the
composite action.
