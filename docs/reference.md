# Reference

## Install options

=== "uv (recommended)"

    ```bash
    uv tool install keyring --with artifacts-keyring-nofuss
    ```

=== "pipx"

    ```bash
    pipx install keyring
    pipx inject keyring artifacts-keyring-nofuss
    ```

=== "pip (no isolation)"

    ```bash
    pip install artifacts-keyring-nofuss
    ```

=== "development"

    ```bash
    pip install -e ".[dev]"
    ```

### Verified installs (pinned + hash-checked)

The package ships a `requirements-lock.txt` with SHA-256 hashes for all runtime
dependencies, covered by the package's own
[PyPI attestation](https://docs.pypi.org/attestations/):

```bash
pip download --no-deps --only-binary=:all: artifacts-keyring-nofuss -d /tmp/aknf
unzip -p /tmp/aknf/artifacts_keyring_nofuss-*.whl \
    artifacts_keyring_nofuss/requirements-lock.txt > /tmp/requirements-lock.txt

uv tool install keyring --with artifacts-keyring-nofuss \
    --with-requirements /tmp/requirements-lock.txt
```

The lockfile is maintained by Dependabot and regenerated on each release.

## The `ak-nofuss` CLI

Mints a feed token without the Azure CLI — pure Python, bounded timeout, retry/
backoff. Used in [Docker builds](docker.md) and CI.

```bash
ak-nofuss mint-token                 # print a bearer token to stdout
ak-nofuss mint-token --output-file t # write it to a 0600 file instead
ak-nofuss exec -- <command>          # run <command> with the token in its env
```

Also available as `python -m artifacts_keyring_nofuss`. Flags: `--tenant`,
`--client-id`, `--resource` (and `--output-file` for `mint-token`); all fall
back to the matching `AZURE_*` env vars.

### Installing the CLI

The executable is named `ak-nofuss`, distinct from the
`artifacts-keyring-nofuss` package, so how you expose it depends on the tool:

=== "uv tool (long-lived)"

    ```bash
    uv tool install keyring --with-executables-from artifacts-keyring-nofuss
    ```

    `--with-executables-from` (not `--with`) is what puts `ak-nofuss` on `PATH`.

=== "uvx (ephemeral)"

    ```bash
    uvx --from artifacts-keyring-nofuss ak-nofuss mint-token
    ```

    `--from` is required because the executable name differs from the package.

=== "pipx"

    ```bash
    pipx inject --include-apps keyring artifacts-keyring-nofuss
    ```

    `--include-apps` is required; plain `pipx inject` won't expose the script.

Plain `pip install artifacts-keyring-nofuss` also places `ak-nofuss` on `PATH`.

## Selecting a specific flow

By default providers are tried in [priority order](concepts.md#auth-flows-priority-order).
Force one with an env var:

```bash
export ARTIFACTS_KEYRING_NOFUSS_PROVIDER=azure_cli
# env_var | azure_cli | ado_auth_helper | workload_identity | azure_identity
```

Or in `~/.config/python_keyring/keyringrc.cfg`:

```ini
[artifacts_keyring_nofuss]
provider = azure_cli
```

## Supported feed URLs

Any URL whose host matches one of (including subdomain-prefixed variants):

- `pkgs.dev.azure.com` (e.g. `https://pkgs.dev.azure.com/myorg/…`)
- `pkgs.visualstudio.com` (e.g. `https://myorg.pkgs.visualstudio.com/…`)
- `pkgs.codedev.ms`
- `pkgs.vsts.me`

URLs with userinfo (`https://__token__@host/…`) and bare hostnames without a
scheme are handled correctly.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `ARTIFACTS_KEYRING_NOFUSS_TOKEN` / `_TOKEN_FILE` | Supply a pre-minted bearer token (or a file path). |
| `VSS_NUGET_ACCESSTOKEN` | Fallback token, for compatibility with `artifacts-keyring`. |
| `ARTIFACTS_KEYRING_NOFUSS_PROVIDER` | Force a single auth flow. |
| `ARTIFACTS_KEYRING_NOFUSS_RETRIES` | Attempts per outbound request (1–10, default 3). |
| `ARTIFACTS_KEYRING_NOFUSS_DEBUG` | Set to `1` for verbose flow logging on stderr. |
| `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_CERTIFICATE_PATH` | Identity for managed identity / service principal / WIF. |
| `AZURE_FEDERATED_TOKEN_FILE` / `AZURE_FEDERATED_TOKEN_AUDIENCE` | Workload-identity assertion file and OIDC audience override. |

## Troubleshooting

Enable verbose output to see the full flow (provider chain, token exchange,
errors) on stderr:

```bash
ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 pip install \
  --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ my-package
```

### Transient network failures / flaky CI

Outbound calls (including GitHub Actions OIDC acquisition and Entra bearer-token
minting) are retried with jittered exponential backoff on a dropped connection,
timeout, or HTTP `429`, `500`, `502`, `503`, or `504` — smoothing
over blips that previously surfaced as a spurious `401` / "could not find a
version" error. Default **3 attempts**; override with:

```bash
export ARTIFACTS_KEYRING_NOFUSS_RETRIES=5   # 1 disables retries
```

The budget applies per HTTP request, is clamped to 1–10 total attempts, and
includes the initial attempt. Delays are chosen uniformly between zero and
an exponentially increasing ceiling: 0.5 seconds, 1 second, 2 seconds, up to
8 seconds. Each token request has a 30-second timeout.

GitHub OIDC and Entra token responses with malformed JSON or a missing, empty,
non-string, or whitespace-only token are also retried within that same budget.
Authorization failures (such as HTTP `400`, `401`, or `403`) and TLS errors
are not retried. After exhaustion, token minting fails closed: `mint-token`
exits nonzero without emitting a token or writing its output file, and `exec`
does not launch the wrapped command. An existing output file is left unchanged;
consumers must check the exit status rather than reuse a stale token file.
