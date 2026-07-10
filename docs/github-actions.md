# GitHub Actions

## Install private packages in a job

**When:** a workflow step runs `pip`/`uv install` from your feed.

Use OIDC — no `az`, no token marshalling. Give the job `id-token: write` and set
`AZURE_CLIENT_ID` (+ `AZURE_TENANT_ID`) for the federated identity:

```yaml
jobs:
  build:
    permissions:
      id-token: write    # required for OIDC
      contents: read
    runs-on: ubuntu-latest
    env:
      AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
      AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6

      - run: uv tool install keyring --with artifacts-keyring-nofuss

      - name: Install private package
        run: |
          uv pip install my-package \
            --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/
```

The workload-identity flow mints the token straight from the GitHub OIDC
endpoint — it works whether or not `azure/login` ran.

??? note "The same with official `artifacts-keyring`"
    There's no OIDC path, so after `azure/login@v2` you mint a token and marshal
    it into per-endpoint JSON yourself:

    ```yaml
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          allow-no-subscriptions: true
      - run: |
          TOKEN=$(az account get-access-token \
            --resource 499b84ac-1321-427f-aa17-267ca6975798 \
            --query accessToken -o tsv)
          echo "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS={\"endpointCredentials\":[{\"endpoint\":\"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/\",\"username\":\"AzureDevOps\",\"password\":\"$TOKEN\"}]}" >> "$GITHUB_ENV"
    ```

## Build a Docker image in a job

**When:** a workflow builds an image that pulls private packages. The OIDC
material lives on the runner and can't reach the isolated build, so mint a token
on the runner and pass it in as a BuildKit secret.

Use the bundled composite action — pure-Python, no `uv` and no Azure CLI. It
masks the token and exposes it as step outputs (`token` and a ready-to-splice
`secret-arg`); the token is **not** written to `$GITHUB_ENV`, so it stays scoped
to the build step:

```yaml
jobs:
  build:
    permissions:
      id-token: write
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Mint feed token
        id: mint
        uses: microsoft/artifacts-keyring-nofuss@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant: ${{ secrets.AZURE_TENANT_ID }}

      - name: Build image
        env:
          ARTIFACTS_KEYRING_NOFUSS_TOKEN: ${{ steps.mint.outputs.token }}
        run: |
          DOCKER_BUILDKIT=1 docker buildx build \
            ${{ steps.mint.outputs.secret-arg }} \
            -t myorg/my-image .
```

See [Docker builds](docker.md) for the matching `Dockerfile`. The action fetches
the OIDC token itself, so `azure/login` is not required — add it only if other
steps need an authenticated `az` (its exported `AZURE_CLIENT_ID` /
`AZURE_TENANT_ID` are then picked up and the `with:` inputs can be omitted).

### Action inputs &amp; outputs

| Input | Required | Description |
|-------|----------|-------------|
| `client-id` | No | Federated identity's client ID. Defaults to `AZURE_CLIENT_ID`. |
| `tenant` | No | Azure AD tenant ID. Defaults to `AZURE_TENANT_ID`. |
| `resource` | No | Resource to scope the token to. Defaults to the Azure DevOps resource. |

| Output | Description |
|--------|-------------|
| `token` | The minted bearer token (masked in logs). |
| `secret-arg` | A ready-to-splice `--secret id=…,env=…` argument for `docker buildx build`. |

### Prefer to mint inline?

If you'd rather not use the action (needs `uv` on the runner):

```yaml
      - uses: astral-sh/setup-uv@v6
      - name: Mint feed token
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: |
          TOKEN=$(uvx --from artifacts-keyring-nofuss ak-nofuss mint-token)
          echo "::add-mask::$TOKEN"
          {
            echo "ARTIFACTS_KEYRING_NOFUSS_TOKEN<<EOF"
            echo "$TOKEN"
            echo "EOF"
          } >> "$GITHUB_ENV"
```

Always `::add-mask::` the token (the action does this for you). This form writes
`$GITHUB_ENV`, exposing the token to every later step in the job — prefer the
action's scoped `env:` pattern unless you need the job-wide value.
