# Local development

**When:** you develop on your laptop and are already signed in with `az login`.

1. Install `keyring` plus this backend as an isolated tool:

    ```bash
    uv tool install keyring --with artifacts-keyring-nofuss
    ```

2. Install from your feed — the backend reuses your `az` login, discovers the
   tenant, and fetches a read-only token automatically:

    === "pip"

        ```bash
        pip install --keyring-provider=subprocess \
            --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
            my-package
        ```

    === "uv"

        ```bash
        uv pip install my-package \
            --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/
        ```

That's it. To make the `--keyring-provider` flag permanent, see
[pip &amp; uv setup](pip-uv.md).

!!! tip "Not signed in?"
    Run `az login` first. No Azure CLI at all? Use a
    [managed identity or service principal](identity.md), or supply a
    [pre-minted token](ci-token.md).

??? note "The same first run with official `artifacts-keyring`"
    ```bash
    pip install artifacts-keyring
    pip install \
        --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
        my-package
    ```

    On the first request `artifacts-keyring` downloads the Azure Artifacts
    Credential Provider — a self-contained, architecture-specific native binary
    (~45 MB compressed, ~110 MB on disk, bundling the .NET runtime) — and opens
    an **interactive browser / device-code sign-in**. Unattended environments
    instead need a token supplied ahead of time via
    `VSS_NUGET_EXTERNAL_FEED_ENDPOINTS`.
