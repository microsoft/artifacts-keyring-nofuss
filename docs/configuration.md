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

??? note "What this simplifies vs. official `artifacts-keyring`"
    The official package has **no managed-identity flow** — the credential
    provider is built around interactive/PAT auth, so on a VM or container you'd
    typically mint a token yourself and hand it over via
    `VSS_NUGET_EXTERNAL_FEED_ENDPOINTS`. Here, a managed identity is picked up
    automatically through `azure-identity`; no token wrangling required.

## Service principal with secret

Set the standard Azure Identity environment variables:

```bash
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=your-secret
```

This requires the `azure-identity` package (included as a dependency). The service principal must have
permissions on the Azure DevOps feed (e.g. Feed Reader).

??? note "What this simplifies vs. official `artifacts-keyring`"
    With the official package you'd acquire a token for the service principal
    out-of-band and inject it as a per-endpoint JSON blob
    (`VSS_NUGET_EXTERNAL_FEED_ENDPOINTS`). Here the standard
    `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` trio is
    consumed directly — the same variables you already use elsewhere in Azure
    tooling, with no feed-specific JSON.

## Bearer token via environment variable

For CI pipelines and Docker builds, pass a pre-minted bearer token:

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN=<bearer-token>
```

For backward compatibility with existing `artifacts-keyring` CI configs,
`VSS_NUGET_ACCESSTOKEN` is also accepted as a fallback.

??? note "What this simplifies vs. official `artifacts-keyring`"
    The official package expects `VSS_NUGET_EXTERNAL_FEED_ENDPOINTS` — a JSON
    document that maps **each feed endpoint** to a username and
    password/token:

    ```json
    {"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/ORG/_packaging/FEED/pypi/simple/","username":"AzureDevOps","password":"<token>"}]}
    ```

    Here a single `ARTIFACTS_KEYRING_NOFUSS_TOKEN` (or its `_FILE` variant)
    covers any supported feed — no JSON, no per-endpoint entries to keep in
    sync. The legacy `VSS_NUGET_ACCESSTOKEN` bearer value is still honored as a
    fallback.

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
