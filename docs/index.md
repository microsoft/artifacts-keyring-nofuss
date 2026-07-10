# artifacts-keyring-nofuss

[![CI](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml)

!!! warning "This is an unsupported Microsoft sample."
    Unlike [`artifacts-keyring`](https://pypi.org/project/artifacts-keyring/),
    this project is a best-effort alternative focused on convenience and
    debuggability (pure Python — no opaque native binary). It is not covered by
    any Microsoft support program — use at your own risk.

A minimal, pure-Python [keyring](https://pypi.org/project/keyring/) backend that
authenticates pip, uv, and twine against Azure DevOps Artifacts feeds. No .NET,
no interactive sign-in, no token to paste.

## Install

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

<small>Prefer pipx or a plain `pip install`? See [Install options](reference.md#install-options).</small>

## Pick your scenario

| I want to… | Recipe |
|------------|--------|
| Install private packages on my laptop (I use `az login`) | [Local development](local-dev.md) |
| Point pip or uv at the feed | [pip &amp; uv setup](pip-uv.md) |
| Install private packages in a GitHub Actions job | [GitHub Actions](github-actions.md) |
| Build a Docker image that pulls private packages | [Docker builds](docker.md) |
| Work in a GitHub Codespace | [Codespaces](codespaces.md) |
| Authenticate as a managed identity or service principal | [Managed identity &amp; service principals](identity.md) |
| Use a bearer token I already have (CI) | [Pre-minted tokens](ci-token.md) |

New here? Skim [How it works](concepts.md) for the auth-flow priority order and
security model, or jump to the [Reference](reference.md) for feed URLs, the CLI,
env vars, and troubleshooting.
