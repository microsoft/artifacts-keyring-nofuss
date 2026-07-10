# Docker

## BuildKit secrets (zero config)

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

??? note "The same with official `artifacts-keyring`"
    The build stage needs the .NET runtime plus the credential provider, and the
    token supplied as per-endpoint JSON — for example:

    ```dockerfile
    RUN apt-get update && apt-get install -y dotnet-runtime-8.0 \
        && pip install artifacts-keyring

    RUN --mount=type=secret,id=VSS_NUGET_EXTERNAL_FEED_ENDPOINTS \
        VSS_NUGET_EXTERNAL_FEED_ENDPOINTS="$(cat /run/secrets/VSS_NUGET_EXTERNAL_FEED_ENDPOINTS)" \
        pip install \
        --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
        my-private-package
    ```

See [Reading tokens from files](configuration.md#reading-tokens-from-files-_file-convention)
for the full `_FILE`/BuildKit priority order.

## Minting a token without `az` (CI / Docker builds)

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

??? note "The same with official `artifacts-keyring`"
    There's no minting helper, so you shell out to the Azure CLI on the runner
    (which needs `az` installed and can hang) and build the JSON yourself:

    ```bash
    TOKEN=$(az account get-access-token \
      --resource 499b84ac-1321-427f-aa17-267ca6975798 \
      --query accessToken -o tsv)

    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS='{"endpointCredentials":[{"endpoint":"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/","username":"AzureDevOps","password":"'"$TOKEN"'"}]}'
    ```

### Installing the CLI

The executable is named `ak-nofuss` (distinct from the `artifacts-keyring-nofuss`
package name), so how you run it depends on your environment:

=== "uv tool (long-lived runner)"

    Install `keyring` as a [`uv` tool](https://docs.astral.sh/uv/) and expose
    *our* executable on `PATH` alongside it:

    ```bash
    uv tool install keyring --with-executables-from artifacts-keyring-nofuss
    ```

    `--with-executables-from` (not `--with`) is what puts `ak-nofuss` on `PATH`;
    `--with` would install the package into the tool environment but would not
    expose its console script. After this, `keyring` and `ak-nofuss` are both
    available directly.

=== "uvx (ephemeral CI)"

    Run it on demand with `uvx` — nothing added to `PATH`. The `--from` is
    required because the executable name differs from the package name:

    ```bash
    uvx --from artifacts-keyring-nofuss ak-nofuss mint-token
    ```

=== "pipx"

    Inject the package into a `keyring` install and expose *our* executable with
    `--include-apps` (pipx's equivalent of uv's `--with-executables-from`):

    ```bash
    pipx inject --include-apps keyring artifacts-keyring-nofuss
    ```

    Plain `pipx inject keyring artifacts-keyring-nofuss` installs the package but
    does **not** put `ak-nofuss` on `PATH` — `--include-apps` is required.
    Alternatively, `pipx install artifacts-keyring-nofuss` installs `ak-nofuss`
    standalone.

You can also use plain `pip install artifacts-keyring-nofuss`, which places
`ak-nofuss` on `PATH` in the active environment.

### `exec`: keep the token out of your shell

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

For wiring this into CI, see [GitHub Actions](github-actions.md).
