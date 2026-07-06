# artifacts-keyring-nofuss

[![CI](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml)

!!! warning "This is an unsupported Microsoft sample."
    Unlike [`artifacts-keyring`](https://pypi.org/project/artifacts-keyring/),
    this project is a best-effort alternative focused on convenience (more auth
    auto-detection, reuse of existing `az` CLI logins) and debuggability (pure
    Python — no opaque .NET binary). It is not covered by any Microsoft support
    program — use at your own risk.

Minimal, pure-Python keyring backend for Azure DevOps Artifacts feeds.

Replaces the official `artifacts-keyring` (which wraps a ~100 MB .NET binary)
with a no-fuss, pure-Python implementation — no .NET required.

## Why this

It focuses on the cases the official package makes awkward:

- **No .NET runtime** — pure Python, auditable, nothing extra to pull into a
  build image.
- **Reuses an existing `az login`** — no separate interactive sign-in for local
  development.
- **GitHub Actions OIDC / Workload Identity Federation** handled in-process — no
  token-marshalling step.
- **Built for CI** — a single token environment variable, bounded
  retry/backoff for flaky networks, and a hang-proof `ak-nofuss mint-token`
  helper for containers without `az`.

For interactive sign-in, personal access tokens, and managed identity, the
official `artifacts-keyring` already handles those natively; this project is a
best-effort convenience alternative, not a replacement for supported tooling.

## Install

### Recommended: standalone tool

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

Or with pipx:

```bash
pipx install keyring
pipx inject keyring artifacts-keyring-nofuss
```

Both install the package in an isolated environment. The `keyring` CLI is
placed on your PATH and works automatically with both pip
(`--keyring-provider=subprocess`) and uv (`keyring-provider = "subprocess"`).

#### Verified installs (pinned + hash-checked)

The package ships a `requirements-lock.txt` with SHA-256 hashes for all
runtime dependencies — covered by the package's own
[PyPI attestation](https://docs.pypi.org/attestations/). To install with
hash-verified, pinned dependencies:

```bash
# Extract the lockfile from the attested package on PyPI
pip download --no-deps --only-binary=:all: artifacts-keyring-nofuss -d /tmp/aknf
unzip -p /tmp/aknf/artifacts_keyring_nofuss-*.whl \
    artifacts_keyring_nofuss/requirements-lock.txt > /tmp/requirements-lock.txt

# Install with pinned + hash-checked deps
uv tool install keyring --with artifacts-keyring-nofuss \
    --with-requirements /tmp/requirements-lock.txt
```

The lockfile is maintained by Dependabot and regenerated on each release.

### Into project environment (no isolation)

```bash
pip install artifacts-keyring-nofuss
```

### For development

```bash
pip install -e ".[dev]"
```

## First run

Once installed as a standalone tool, point your package manager at your private
feed and let the backend do the rest:

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

No token to paste, no `pip.conf` secrets — the backend discovers the tenant and
obtains credentials automatically. See [Tool integration](tool-integration.md)
for the full pip/uv setup.

## How it works (in a nutshell)

When pip, uv, or twine queries the keyring for a feed, this backend discovers
the Azure AD tenant, obtains a bearer token via one of several auth flows
(environment variable, Azure CLI, Codespaces helper, Workload Identity, or
`DefaultAzureCredential`), and returns short-lived credentials — exchanging user
tokens for a narrowly scoped, read-only session token along the way. Read the
full walkthrough in [How it works](concepts.md).

## Explore the docs

| Page | What's inside |
|------|---------------|
| [How it works](concepts.md) | Auth flows, priority order, and the security model. |
| [Configuration](configuration.md) | Selecting a flow, managed identity, service principals, and token env vars/files. |
| [Docker](docker.md) | BuildKit secrets and minting a token without `az`. |
| [GitHub Actions](github-actions.md) | Workload Identity Federation and the composite action. |
| [Tool integration](tool-integration.md) | pip, uv, and GitHub Codespaces. |
| [Reference](reference.md) | Supported feed URLs and troubleshooting. |
