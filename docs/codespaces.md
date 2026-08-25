# Dev containers &amp; GitHub Codespaces

**When:** you develop inside a dev container and want pip or uv to authenticate
to an Azure Artifacts feed.

The backend works normally in a dev container. Install it in the container and
give it an identity using either the Azure CLI or the Codespaces auth helper.

## Local dev containers

This complete example uses the standard Python dev-container image, installs the
Azure CLI with its official feature, and installs the backend as an isolated
`pipx` tool:

```json
{
  "image": "mcr.microsoft.com/devcontainers/python:3.12-bookworm",
  "features": {
    "ghcr.io/devcontainers/features/azure-cli:1": {}
  },
  "postCreateCommand": "pipx install keyring && pipx inject keyring artifacts-keyring-nofuss"
}
```

After creating the container, sign in from its terminal:

```bash
az login
```

Then pip and uv work exactly as they do on the host:

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

If the image already contains Python and `pipx`, keep your existing `image` and
add only the feature and `postCreateCommand`. If it does not, add the
[`python` feature](https://github.com/devcontainers/features/tree/main/src/python)
as well. If `keyring` and `artifacts-keyring-nofuss` are already installed in
the image, omit `postCreateCommand` too.

!!! tip "Avoid signing in after every rebuild"
    Mounting the host's `~/.azure` directory into a personal, local Linux
    container can reuse the host login, but it also gives the container access
    to all of those developer credentials and can cause permission or
    cross-platform token-cache problems. Signing in inside the container is the
    safer, portable default. For unattended containers, use a
    [service principal](identity.md) instead.

## GitHub Codespaces

Codespaces can authenticate without a separate `az login`. Add the
[`artifacts-helper`](https://github.com/microsoft/codespace-features) feature
and install this backend (or omit `postCreateCommand` when the image already
contains it):

```json
{
  "image": "mcr.microsoft.com/devcontainers/python:3.12-bookworm",
  "features": {
    "ghcr.io/microsoft/codespace-features/artifacts-helper:3": {}
  },
  "postCreateCommand": "pipx install keyring && pipx inject keyring artifacts-keyring-nofuss"
}
```

This installs the `ado-codespaces-auth` VS Code extension, which creates
`~/ado-auth-helper`. The backend's `ado_auth_helper` provider calls it
automatically — sign in via the **"Click to authenticate"** prompt in the VS
Code status bar on first use, then use pip or uv as shown above.

!!! note
    The helper requires the Codespaces runtime and user interaction. For a dev
    container running locally, use the Azure CLI setup above.

??? note "The same with official `artifacts-keyring`"
    You'd still install `artifacts-keyring` (which downloads the self-contained
    native credential provider) and complete its own interactive sign-in on
    first package restore, separate from the Codespaces auth helper.
