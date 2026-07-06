# GitHub Actions

## Workload Identity Federation (OIDC)

When using `azure/login@v2` in GitHub Actions, the action automatically sets
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE`.
The workload identity provider detects these and exchanges the federated token
for a bearer — no extra configuration needed for direct installs.

??? note "What this simplifies vs. official `artifacts-keyring`"
    The official package has no Workload Identity Federation flow, so the usual
    pattern is an extra step that mints a token and marshals it into the
    `VSS_NUGET_EXTERNAL_FEED_ENDPOINTS` JSON. Here, a direct install "just
    works" straight after `azure/login@v2` — the OIDC env vars are detected and
    exchanged automatically, with nothing feed-specific to assemble.

For Docker builds, the OIDC material lives on the runner and can't reach the
isolated build, so you mint a feed token on the runner and pass it in as a
BuildKit secret. The two approaches below do exactly that; see
[Minting a token without `az`](docker.md#minting-a-token-without-az-ci-docker-builds)
for the background.

## Composite action (most convenient)

This repository ships a composite action that mints the token via the ephemeral
`uvx` form, masks it, and exposes it as both a step output and the
`ARTIFACTS_KEYRING_NOFUSS_TOKEN` environment variable for later steps:

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

      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - uses: astral-sh/setup-uv@v6

      - name: Mint feed token
        uses: microsoft/artifacts-keyring-nofuss@v1
        # inputs (both optional):
        #   tenant:   Azure AD tenant ID (defaults to AZURE_TENANT_ID)
        #   resource: resource ID to scope the token to

      - name: Build image
        run: |
          DOCKER_BUILDKIT=1 docker buildx build \
            --secret id=ARTIFACTS_KEYRING_NOFUSS_TOKEN,env=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
            -t myorg/my-image .
```

The action exposes the minted bearer token as the `token` output (masked in
logs) in addition to the `ARTIFACTS_KEYRING_NOFUSS_TOKEN` environment variable.

## Manual step

If you'd rather mint the token inline:

```yaml
      - uses: astral-sh/setup-uv@v6

      - name: Mint feed token
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
composite action does this for you).

The Dockerfile consumes the secret exactly as in the
[BuildKit example](docker.md#buildkit-secrets-zero-config):

```dockerfile
RUN --mount=type=secret,id=ARTIFACTS_KEYRING_NOFUSS_TOKEN \
    PIP_KEYRING_PROVIDER=import pip install \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/<feed>/pypi/simple/ \
    my-private-package
```
