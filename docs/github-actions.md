# GitHub Actions

## Workload Identity Federation (OIDC)

On a GitHub Actions job with `permissions: id-token: write`, the workload
identity provider mints a bearer token directly from the GitHub OIDC endpoint —
no Azure CLI and no federated token file required. It only needs `AZURE_CLIENT_ID`
(and `AZURE_TENANT_ID`, or the tenant discovered from the feed URL), so it works
whether or not `azure/login@v2` ran.

!!! note
    `azure/login@v2` on GitHub-hosted runners authenticates the Azure CLI but
    does **not** write an `AZURE_FEDERATED_TOKEN_FILE`; the GitHub OIDC path
    above is what makes az-free minting work on those runners.

??? note "The same with official `artifacts-keyring`"
    There's no OIDC path, so after `azure/login@v2` you mint a token and marshal
    it into the JSON yourself:

    ```yaml
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          allow-no-subscriptions: true

      - name: Configure feed credentials
        run: |
          TOKEN=$(az account get-access-token \
            --resource 499b84ac-1321-427f-aa17-267ca6975798 \
            --query accessToken -o tsv)
          echo "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS={\"endpointCredentials\":[{\"endpoint\":\"https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/\",\"username\":\"AzureDevOps\",\"password\":\"$TOKEN\"}]}" >> "$GITHUB_ENV"
    ```

For Docker builds, the OIDC material lives on the runner and can't reach the
isolated build, so you mint a feed token on the runner and pass it in as a
BuildKit secret. The approaches below do exactly that; see
[Minting a token without `az`](docker.md#minting-a-token-without-az-ci-docker-builds)
for the background.

## Composite action (most convenient)

This repository ships a composite action that mints the token (pure-Python, no
`uv` and no Azure CLI required), masks it, and exposes it as step outputs: the
`token` and a ready-to-use `secret-arg` for `docker buildx build`. The token is
**not** written to `$GITHUB_ENV`, so it stays scoped to the build step that
references it:

```yaml
# .github/workflows/build.yml
jobs:
  build:
    permissions:
      id-token: write   # required for OIDC
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
        # resource is optional (defaults to the Azure DevOps resource)

      - name: Build image
        env:
          # scope the token to this step only (not the whole job)
          ARTIFACTS_KEYRING_NOFUSS_TOKEN: ${{ steps.mint.outputs.token }}
        run: |
          DOCKER_BUILDKIT=1 docker buildx build \
            ${{ steps.mint.outputs.secret-arg }} \
            -t myorg/my-image .
```

The action fetches the GitHub OIDC token itself, so `azure/login` is not
required — you only need `id-token: write` plus the federated identity's
`client-id` and `tenant`. It installs its own checked-out copy of the package,
so the CLI version always matches the action ref (no `setup-uv`, no PyPI or
branch pinning). Add `azure/login` only if other steps need an authenticated
`az`; when it runs first, its exported `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` are
picked up automatically and the `with:` inputs can be omitted.

### Inputs and outputs

| Input | Required | Description |
|-------|----------|-------------|
| `client-id` | No | Federated identity's client ID. Defaults to `AZURE_CLIENT_ID`. |
| `tenant` | No | Azure AD tenant ID. Defaults to `AZURE_TENANT_ID`. |
| `resource` | No | Resource to scope the token to. Defaults to the Azure DevOps resource. |

| Output | Description |
|--------|-------------|
| `token` | The minted bearer token (masked in logs). |
| `secret-arg` | A ready-to-splice `--secret id=…,env=…` argument for `docker buildx build`. |

## Manual step

If you'd rather mint the token inline (this form uses `uvx`, so it needs `uv` on
the runner):

```yaml
      - uses: astral-sh/setup-uv@v6

      - name: Mint feed token
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: |
          TOKEN=$(uvx --from artifacts-keyring-nofuss ak-nofuss mint-token)
          echo "::add-mask::$TOKEN"
          # Heredoc form so an unexpected character in the value can't inject
          # extra environment entries.
          {
            echo "ARTIFACTS_KEYRING_NOFUSS_TOKEN<<EOF"
            echo "$TOKEN"
            echo "EOF"
          } >> "$GITHUB_ENV"
```

Always run `::add-mask::` on the minted token so it is redacted from logs (the
composite action does this for you). Note the composite action above is
output-only and does **not** write `$GITHUB_ENV`; this manual form does, which
exposes the token to every later step in the job — prefer the composite action's
scoped `env:` pattern unless you specifically need the job-wide value.

The Dockerfile consumes the secret exactly as in the
[BuildKit example](docker.md#buildkit-secrets-zero-config):

```dockerfile
RUN --mount=type=secret,id=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    PIP_KEYRING_PROVIDER=import pip install \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/<feed>/pypi/simple/ \
    my-private-package
```
