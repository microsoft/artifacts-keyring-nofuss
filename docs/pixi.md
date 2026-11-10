# pixi setup

**When:** you use [pixi](https://pixi.sh) for a project and want its PyPI
dependencies to install from an Azure Artifacts feed.

pixi resolves PyPI packages with [uv](https://github.com/astral-sh/uv), so it
reuses the same *subprocess* keyring provider. Turn the provider on, install the
backend where pixi can find it, and point pixi at the feed as an index.

## 1. Make the backend discoverable

pixi resolves PyPI packages in an isolated environment, so `keyring` and this
backend must be installed on a tool that is on your `PATH` — not just inside the
project environment. Installing `keyring` as a global tool with the backend
alongside it works well:

```bash
uv tool install keyring --with artifacts-keyring-nofuss
```

Alternatively, install it as a pixi global tool:

```bash
pixi global install keyring --with artifacts-keyring-nofuss
```

## 2. Enable the subprocess provider

Add `keyring-provider = "subprocess"` under `[pypi-options]` in `pixi.toml` (or
the `[tool.pixi.pypi-options]` table in `pyproject.toml`):

```toml
[pypi-options]
keyring-provider = "subprocess"
```

## 3. Configure the feed as an index

uv (and therefore pixi) only calls keyring when the index URL carries a
username, so include `__token__@`. Configure the feed as an index and depend on
packages **by name**:

```toml
# pixi.toml — use [tool.pixi.pypi-options] / [tool.pixi.pypi-dependencies] in pyproject.toml
[pypi-options]
keyring-provider = "subprocess"
# Use index-url when the feed has public PyPI configured as an upstream source;
# otherwise use extra-index-urls to keep the public PyPI index as well.
index-url = "https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/"

[pypi-dependencies]
my-package = "==1.2.3"
```

Legacy subdomain feed URLs work too:
`https://__token__@myorg.pkgs.visualstudio.com/_packaging/{feed}/pypi/simple/`.

!!! tip "`pixi install --locked` works with index URLs"
    Index URLs are stored verbatim in `pixi.lock`, so they round-trip and keep
    `pixi install --locked` passing. Prefer configuring private packages through
    an index and depending on them by name (as above) rather than pinning them
    by a credentialed direct URL (e.g.
    `my-package = { url = "https://__token__@.../my_package-1.2.3-py3-none-any.whl" }`).

    Older pixi versions could fail `--locked` on a credentialed direct URL,
    because the lock file redacted the token to `****` while the manifest kept
    the literal `__token__`. Current pixi releases handle that redaction, but the
    index-based pattern above stays the recommended setup.

!!! tip
    See [Reference](reference.md#supported-feed-urls) for every supported feed
    host, and [How it works](concepts.md) for which auth flow supplies the
    credentials.
