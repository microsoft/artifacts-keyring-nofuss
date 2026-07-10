# pip &amp; uv setup

**When:** you want pip or uv to use this backend without repeating flags.

Both package managers call `keyring` through the *subprocess* provider. Turn it
on once, then use pip/uv as normal.

## pip

Add to `~/.config/pip/pip.conf` (or `%APPDATA%\pip\pip.ini` on Windows):

```ini
[global]
keyring-provider = subprocess
```

Or pass `--keyring-provider=subprocess` per command. When the package is
installed in the *same* environment as pip, no flag is needed — it is discovered
via entry points.

## uv

Enable the provider in project config:

```toml
# pyproject.toml or uv.toml
[tool.uv]
keyring-provider = "subprocess"
```

Or set `UV_KEYRING_PROVIDER=subprocess`.

uv only calls keyring when the index URL contains a username, so include
`__token__@`:

```toml
[[tool.uv.index]]
name = "my-feed"
url = "https://__token__@pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/"
```

Legacy subdomain feed URLs work too:
`https://__token__@myorg.pkgs.visualstudio.com/_packaging/{feed}/pypi/simple/`.

!!! tip
    See [Reference](reference.md#supported-feed-urls) for every supported feed
    host, and [How it works](concepts.md) for which auth flow supplies the
    credentials.
