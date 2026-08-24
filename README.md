# artifacts-keyring-nofuss

[![CI](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/artifacts-keyring-nofuss/actions/workflows/ci.yml)

> **⚠️ This is an unsupported Microsoft sample.** Unlike
> [`artifacts-keyring`](https://pypi.org/project/artifacts-keyring/), this
> project is a best-effort alternative focused on convenience
> (more auth auto-detection, reuse of existing `az` CLI logins) and
> debuggability (pure Python — no opaque .NET binary). It is not covered by
> any Microsoft support program — use at your own risk.

Minimal, pure-Python keyring backend for Azure DevOps Artifacts feeds. Replaces
the official `artifacts-keyring` (which wraps a ~100 MB .NET binary) with a
no-fuss, pure-Python implementation — no .NET required.

## 📖 Documentation

**Full docs: <https://microsoft.github.io/artifacts-keyring-nofuss/>**

| Page | What's inside |
|------|---------------|
| [Home](https://microsoft.github.io/artifacts-keyring-nofuss/) | Install and a scenario picker. |
| [Local development](https://microsoft.github.io/artifacts-keyring-nofuss/local-dev/) | Install packages locally with an `az login`. |
| [pip &amp; uv setup](https://microsoft.github.io/artifacts-keyring-nofuss/pip-uv/) | Turn on the keyring provider once. |
| [pixi setup](https://microsoft.github.io/artifacts-keyring-nofuss/pixi/) | Install from a feed with pixi's uv-based resolver. |
| [GitHub Actions](https://microsoft.github.io/artifacts-keyring-nofuss/github-actions/) | OIDC installs and the Docker composite action. |
| [Docker builds](https://microsoft.github.io/artifacts-keyring-nofuss/docker/) | BuildKit secrets and minting a token without `az`. |
| [GitHub Codespaces](https://microsoft.github.io/artifacts-keyring-nofuss/codespaces/) | The `artifacts-helper` devcontainer feature. |
| [Managed identity &amp; service principals](https://microsoft.github.io/artifacts-keyring-nofuss/identity/) | MI, service principals, and workload identity. |
| [Pre-minted tokens](https://microsoft.github.io/artifacts-keyring-nofuss/ci-token/) | Supply a bearer token via env var or file. |
| [How it works](https://microsoft.github.io/artifacts-keyring-nofuss/concepts/) | Auth flows, priority order, security model. |
| [Reference](https://microsoft.github.io/artifacts-keyring-nofuss/reference/) | Install options, CLI, env vars, feed URLs, troubleshooting. |

## Quickstart

Install `keyring` plus this backend as an isolated standalone tool:

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

Then point your package manager at your private feed — the backend discovers the
tenant and obtains credentials automatically:

```bash
# pip
pip install --keyring-provider=subprocess \
    --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ \
    my-package

# uv
uv pip install my-package \
    --index-url https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/
```

See the [documentation site](https://microsoft.github.io/artifacts-keyring-nofuss/)
for CI, Docker, service principal, and Codespaces setups.

## Development

```bash
pip install -e ".[dev]"
```

## License

Licensed under the [MIT License](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for how to report security issues.
