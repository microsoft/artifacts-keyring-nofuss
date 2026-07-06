# Tool integration

## Usage with pip

When installed as a standalone tool (recommended), configure pip to use the
subprocess keyring provider:

```bash
# Global config (recommended — add to ~/.config/pip/pip.conf):
# [global]
# keyring-provider = subprocess

# Or per-command:
pip install --keyring-provider=subprocess \
    --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-package
```

When installed in the same environment as pip, no extra flags are needed — the
backend is discovered automatically via entry points.

??? note "What this simplifies vs. official `artifacts-keyring`"
    Both packages plug into keyring the same way, so the pip invocation is
    identical. The difference is what happens on a cache miss: the official
    backend may trigger the .NET credential provider (and, locally, an
    interactive sign-in), whereas this backend resolves credentials
    non-interactively from your existing environment (`az` login, managed
    identity, OIDC, or a token env var).

## Usage with uv

1. Install as a standalone tool (if not done already):

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

2. Configure uv to use keyring for authentication. Either add it to your
   project config:

```toml
# pyproject.toml or uv.toml
[tool.uv]
keyring-provider = "subprocess"
```

Or set the environment variable:

```bash
export UV_KEYRING_PROVIDER=subprocess
```

3. Use uv as normal with your private feed. A username in the URL (e.g.
   `__token__@`) is required to trigger keyring lookup:

```bash
uv pip install my-package --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/
```

This also works with legacy subdomain-prefixed feed URLs:

```bash
uv pip install my-package --index-url https://__token__@myorg.pkgs.visualstudio.com/_packaging/{feed}/pypi/simple/
```

For `pyproject.toml` index configuration:

```toml
[[tool.uv.index]]
url = "https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/"
name = "my-feed"
```

## GitHub Codespaces

Add the [`artifacts-helper`](https://github.com/microsoft/codespace-features)
devcontainer feature to your `.devcontainer/devcontainer.json`:

```json
{
  "features": {
    "ghcr.io/microsoft/codespace-features/artifacts-helper:3": {}
  }
}
```

This installs the `ado-codespaces-auth` VS Code extension, which creates
`~/ado-auth-helper`. The `ado_auth_helper` provider calls it automatically —
no `az login` needed. Sign in via the "Click to authenticate" prompt in the
VS Code status bar on first use.

??? note "What this simplifies vs. official `artifacts-keyring`"
    In a Codespace the official package would still pull in the .NET credential
    provider and its own sign-in. Here the `ado_auth_helper` provider reuses the
    `~/ado-auth-helper` created by the Codespaces auth feature, so a single
    status-bar sign-in covers package restores with no .NET and no separate
    credential-provider login.
