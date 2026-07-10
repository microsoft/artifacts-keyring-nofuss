# Pre-minted tokens (CI)

**When:** you already have a bearer token (from `az`, a pipeline, or another
step) and just want the backend to use it.

## From an environment variable

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN=<bearer-token>
```

`VSS_NUGET_ACCESSTOKEN` is also accepted as a fallback for existing
`artifacts-keyring` CI configs.

## From a file (`_FILE` convention)

Point at a file containing the token — the Docker `_FILE` convention used by
official images:

```bash
export ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE=/run/secrets/my_token
```

## Inside a Docker build

The env-var provider also auto-detects BuildKit secrets mounted under
`/run/secrets/` — no env var needed inside the container. See
[Docker builds](docker.md).

## Priority order

`ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE` → `ARTIFACTS_KEYRING_NOFUSS_TOKEN` →
`VSS_NUGET_ACCESSTOKEN` → BuildKit secret paths
(`/run/secrets/ARTIFACTS_KEYRING_NOFUSS_TOKEN`, `/run/secrets/ado_token`).

??? note "The same with official `artifacts-keyring`"
    The token goes into a per-endpoint JSON document, repeated for every feed:

    ```bash
    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"<bearer-token>"}]}'
    ```
