# Docker builds

**When:** a `docker buildx` build installs private packages. Pass a bearer token
in as a BuildKit secret — it is mounted only for the build step and never baked
into a layer.

## 1. The Dockerfile (zero config)

The env-var provider auto-detects BuildKit secrets at
`/run/secrets/ARTIFACTS_KEYRING_NOFUSS_TOKEN` (and `/run/secrets/ado_token`), so
nothing extra is needed inside the container:

```dockerfile
RUN pip install artifacts-keyring-nofuss

RUN --mount=type=secret,id=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    PIP_KEYRING_PROVIDER=import pip install \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-private-package
```

## 2. Mint a token and build

=== "Local (you have `az`)"

    ```bash
    export ARTIFACTS_KEYRING_NOFUSS_TOKEN=$(az account get-access-token \
      --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv)

    DOCKER_BUILDKIT=1 docker buildx build \
      --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
      -t my-image .
    ```

=== "CI without `az` (hang-proof)"

    `az account get-access-token` is heavyweight and can hang. Mint the token
    with the pure-Python CLI instead — it needs `AZURE_CLIENT_ID`
    (+ `AZURE_TENANT_ID`, or `--tenant`) and gets the OIDC assertion from
    `AZURE_FEDERATED_TOKEN_FILE` or, on a GitHub Actions job with
    `id-token: write`, directly from the GitHub OIDC endpoint:

    ```bash
    export ARTIFACTS_KEYRING_NOFUSS_TOKEN=$(uvx --from artifacts-keyring-nofuss ak-nofuss mint-token)

    DOCKER_BUILDKIT=1 docker buildx build \
      --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
      -t my-image .
    ```

    On GitHub Actions, prefer the [composite action](github-actions.md#build-a-docker-image-in-a-job),
    which mints, masks, and hands you a ready-to-splice `secret-arg`.

=== "Keep the token out of your shell"

    `ak-nofuss exec` mints the token, sets it in the child environment, and runs
    the command — the value never touches your shell:

    ```bash
    ak-nofuss exec -- \
      docker buildx build \
        --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
        -t myorg/my-image .
    ```

See [Reference](reference.md#the-ak-nofuss-cli) for CLI install/flags, and
[Pre-minted tokens](ci-token.md) for the full `_FILE`/BuildKit priority order.

??? note "The same with official `artifacts-keyring`"
    The build stage runs the self-contained credential provider (a native
    ~110 MB download, no separate .NET install) and needs the token as
    per-endpoint JSON:

    ```dockerfile
    RUN pip install artifacts-keyring

    RUN --mount=type=secret,id=VSS_NUGET_EXTERNAL_FEED_ENDPOINTS \
        VSS_NUGET_EXTERNAL_FEED_ENDPOINTS="$(cat /run/secrets/VSS_NUGET_EXTERNAL_FEED_ENDPOINTS)" \
        pip install \
        --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
        my-private-package
    ```
