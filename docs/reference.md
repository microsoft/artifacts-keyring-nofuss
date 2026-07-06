# Reference

## Supported feed URLs

Any URL whose host matches one of (including subdomain-prefixed variants):

- `pkgs.dev.azure.com` (e.g. `https://pkgs.dev.azure.com/myorg/…`)
- `pkgs.visualstudio.com` (e.g. `https://myorg.pkgs.visualstudio.com/…`)
- `pkgs.codedev.ms`
- `pkgs.vsts.me`

URLs with userinfo (e.g. `https://__token__@host/…`) and bare hostnames without
a scheme are also handled correctly.

## Troubleshooting

Enable verbose debug output to see the full authentication flow:

```bash
ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 pip install --index-url https://pkgs.dev.azure.com/{org}/_packaging/{feed}/pypi/simple/ my-package
```

This prints the provider chain, token exchange steps, and any errors to stderr.

### Transient network failures / flaky CI

Outbound calls to Azure DevOps (tenant discovery and the session-token exchange)
are automatically retried with exponential backoff when they hit a transient
failure — a dropped connection, timeout, or a `429`/`5xx` response. This smooths
over the occasional blip that previously surfaced as a spurious `401`/"could not
find a version" error that only a re-run would fix.

The retry budget defaults to **3 attempts** per request. Override it with:

```bash
export ARTIFACTS_KEYRING_NOFUSS_RETRIES=5  # total attempts per request (1–10)
```

Set it to `1` to disable retries entirely.
