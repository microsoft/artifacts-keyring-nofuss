# GitHub Codespaces

**When:** you develop in a Codespace and want feed auth without `az login`.

Add the [`artifacts-helper`](https://github.com/microsoft/codespace-features)
devcontainer feature to `.devcontainer/devcontainer.json`:

```json
{
  "features": {
    "ghcr.io/microsoft/codespace-features/artifacts-helper:3": {}
  }
}
```

This installs the `ado-codespaces-auth` VS Code extension, which creates
`~/ado-auth-helper`. The backend's `ado_auth_helper` provider calls it
automatically — sign in via the **"Click to authenticate"** prompt in the VS
Code status bar on first use, then install as usual:

```bash
pip install --keyring-provider=subprocess \
    --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-package
```

??? note "The same with official `artifacts-keyring`"
    You'd still install `artifacts-keyring` (which downloads the self-contained
    native credential provider) and complete its own interactive sign-in on
    first package restore, separate from the Codespaces auth helper.
