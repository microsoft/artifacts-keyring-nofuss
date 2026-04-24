"""Keyring backend for Azure DevOps Artifacts feeds."""

from __future__ import annotations

import base64
import configparser
import json
import logging
import time
import urllib.parse
from pathlib import Path

import keyring.backend
import keyring.credentials
import requests

from . import _constants as C
from . import _provider, _session_token
from ._azure_cli import AzureCliProvider
from ._azure_identity import AzureIdentityProvider
from ._env_var import EnvVarProvider
from ._workload_identity import WorkloadIdentityProvider

log = logging.getLogger(__name__)

# Cached credentials expire after 50 minutes (tokens typically live 60-75 min)
_CACHE_TTL_SECONDS = 50 * 60

PROVIDERS: dict[str, type[_provider.TokenProvider]] = {
    "env_var": EnvVarProvider,
    "azure_cli": AzureCliProvider,
    "workload_identity": WorkloadIdentityProvider,
    "azure_identity": AzureIdentityProvider,
}

DEFAULT_CHAIN = ["env_var", "azure_cli", "workload_identity", "azure_identity"]


def _decode_jwt_claims(bearer: str) -> dict[str, str]:
    """Decode the payload of a JWT without validation. Returns {} on failure."""
    try:
        payload = bearer.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))  # type: ignore[no-any-return]
    except Exception:
        return {}


def _account_from_token(bearer: str) -> str | None:
    """Extract the user principal name from a JWT bearer token (no validation)."""
    claims = _decode_jwt_claims(bearer)
    return claims.get("upn") or claims.get("unique_name") or claims.get("oid")


def _is_service_principal_token(bearer: str) -> bool:  # noqa: PLR0911
    """Detect whether a bearer token belongs to a service principal.

    Inspects JWT claims in priority order to decide whether the token can be
    exchanged for a VssSessionToken (user) or must be returned directly (SP).
    """
    claims = _decode_jwt_claims(bearer)
    if not claims:
        return False  # fail safe: treat as user

    # 1. Authoritative when present
    idtyp = claims.get("idtyp")
    if idtyp == "app":
        return True
    if idtyp == "user":
        return False

    # 2. Strong behavioral signal
    if "scp" in claims:
        return False  # delegated user token
    if "roles" in claims:
        return True  # app-only token

    # 3. Weak fallback (best-effort only)
    if "preferred_username" in claims or "upn" in claims:
        return False

    # Unknown → assume user (safe default: exchange will fail gracefully)
    return False


def _ensure_scheme(url: str) -> str:
    """Prepend ``https://`` when *url* has no scheme (e.g. bare hostnames from uv)."""
    if url.lower().startswith(("http://", "https://")):
        return url
    return f"https://{url}"


def _strip_userinfo(url: str) -> str:
    """Return *url* with any ``user:pass@`` or ``user@`` removed."""
    parsed = urllib.parse.urlparse(_ensure_scheme(url))
    if parsed.username or parsed.password:
        # Rebuild without userinfo
        netloc = parsed.hostname or ""
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    return _ensure_scheme(url)


def _parse_hostname(service: str) -> str:
    """Extract the lowercase hostname from *service*, normalising the URL first."""
    try:
        return (urllib.parse.urlparse(_ensure_scheme(service)).hostname or "").lower()
    except ValueError:
        return ""


def _hostname_matches(hostname: str) -> bool:
    """Return True if *hostname* matches a known Azure DevOps Artifacts netloc.

    Accepts both exact matches (``pkgs.dev.azure.com``) and subdomain-prefixed
    matches (``myorg.pkgs.visualstudio.com``) while rejecting spoofed domains
    like ``evil-pkgs.dev.azure.com``.
    """
    return _host_in_allowed(hostname, C.SUPPORTED_NETLOCS)


def _is_supported(service: str) -> bool:
    """Return True if *service* looks like an Azure DevOps Artifacts feed URL."""
    hostname = _parse_hostname(service)
    if not hostname:
        return False
    return _hostname_matches(hostname)


def _host_in_allowed(hostname: str, allowed_hosts: frozenset[str]) -> bool:
    """Return True if *hostname* matches any entry in *allowed_hosts*.

    Supports both exact matches and subdomain-prefixed matches
    (e.g. ``myorg.vssps.visualstudio.com`` matches ``vssps.visualstudio.com``).
    """
    return any(
        hostname == allowed or hostname.endswith(f".{allowed}")
        for allowed in allowed_hosts
    )


def _is_safe_origin(
    parsed: urllib.parse.ParseResult, allowed_hosts: frozenset[str]
) -> bool:
    """Return True if *parsed* is a clean HTTPS origin on an allowed host.

    Rejects HTTP, explicit non-default ports, userinfo, and non-root paths.
    """
    if parsed.scheme != "https":
        return False
    if not _host_in_allowed((parsed.hostname or "").lower(), allowed_hosts):
        return False
    if parsed.port is not None and parsed.port != 443:
        return False
    return not (parsed.username or parsed.password)


def _validate_auth_uri(uri: str) -> bool:
    """Return True if *uri* points to a known Azure AD login endpoint over HTTPS."""
    try:
        parsed = urllib.parse.urlparse(uri)
    except Exception:
        return False
    return _is_safe_origin(parsed, C.ALLOWED_AUTH_HOSTS)


def _validate_vsts_authority(url: str) -> bool:
    """Return True if *url* is a clean HTTPS origin on a known Azure DevOps host.

    The authority URL typically includes an org-name path segment
    (e.g. ``https://vssps.dev.azure.com/my-org/``).  We allow a single
    path segment but reject deeper paths to prevent path-traversal tricks.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if not _is_safe_origin(parsed, C.ALLOWED_VSTS_AUTHORITY_HOSTS):
        return False
    # Allow root or a single path segment (the org name): "/org" or "/org/"
    path = parsed.path.strip("/")
    return "/" not in path


def _discover(service: str) -> tuple[str, str] | None:
    """GET the feed URL unauthenticated to discover tenant and authority.

    Returns ``(tenant_id, vsts_authority)`` or ``None``.
    """
    # Strip userinfo (e.g. __token__@) so the request is truly unauthenticated
    clean_url = _strip_userinfo(service)
    try:
        resp = requests.get(clean_url, allow_redirects=False, timeout=10)
    except requests.RequestException:
        log.debug(
            "discovery request failed for %s (network error or timeout)",
            clean_url,
            exc_info=True,
        )
        return None

    www_auth = resp.headers.get("WWW-Authenticate", "")
    vsts_authority = resp.headers.get("X-VSS-AuthorizationEndpoint", "")

    # Parse tenant from: Bearer authorization_uri=https://login.microsoftonline.com/{tenant}
    tenant_id = ""
    for raw_part in www_auth.split(","):
        part = raw_part.strip()
        if "authorization_uri=" in part:
            uri = part.split("authorization_uri=", 1)[1].strip().strip('"')
            if not _validate_auth_uri(uri):
                log.warning("discovery returned untrusted authorization_uri: %s", uri)
                return None
            # URI is like https://login.microsoftonline.com/{tenant_id}
            tenant_id = uri.rstrip("/").rsplit("/", 1)[-1]
            break

    if not tenant_id or not vsts_authority:
        log.debug(
            "discovery incomplete: tenant=%r authority=%r",
            tenant_id,
            vsts_authority,
        )
        return None

    if not _validate_vsts_authority(vsts_authority):
        log.warning(
            "discovery returned untrusted authority endpoint: %s", vsts_authority
        )
        return None

    return tenant_id, vsts_authority


def _configured_provider() -> str | None:
    """Read provider override from env var or keyring config."""
    import os  # noqa: PLC0415

    env = os.environ.get("ARTIFACTS_KEYRING_NOFUSS_PROVIDER", "").strip()
    if env:
        return env

    # Try keyring config file (user home only — CWD is not trusted)
    path = Path("~/.config/python_keyring/keyringrc.cfg").expanduser()
    if path.is_file():
        cfg = configparser.ConfigParser()
        cfg.read(path)
        val = cfg.get("artifacts_keyring_nofuss", "provider", fallback="").strip()
        if val:
            return val

    return None


class ArtifactsKeyringBackend(keyring.backend.KeyringBackend):
    priority = 9.9  # keyring expects numeric

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self._cache: dict[str, tuple[keyring.credentials.SimpleCredential, float]] = {}

    def get_credential(  # noqa: PLR0911, PLR0912, C901
        self,
        service: str,
        username: str | None,  # noqa: ARG002
    ) -> keyring.credentials.SimpleCredential | None:
        if not _is_supported(service):
            return None

        # Validate provider config early so typos are surfaced before
        # any network calls.
        chosen = _configured_provider()
        if chosen and chosen not in PROVIDERS:
            log.warning("unknown provider %r, valid: %s", chosen, ", ".join(PROVIDERS))
            return None

        cached = self._cache.get(service)
        if cached is not None:
            cred, ts = cached
            if time.monotonic() - ts < _CACHE_TTL_SECONDS:
                return cred
            del self._cache[service]

        # Discover tenant + authority
        info = _discover(service)
        if info is None:
            log.warning(
                "could not discover Azure AD tenant for %s "
                "(is this an Azure DevOps Artifacts URL?). "
                "Check network/VPN connectivity. "
                "Set ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 for details.",
                _strip_userinfo(service),
            )
            return None
        tenant_id, vsts_authority = info

        # Build provider list
        if chosen:
            chain: list[_provider.TokenProvider] = [PROVIDERS[chosen]()]
        else:
            chain = [PROVIDERS[name]() for name in DEFAULT_CHAIN]

        # Get bearer token
        result = _provider.run_chain(chain, tenant_id)
        if result is None:
            log.warning(
                "all auth providers failed for %s "
                "(tried: %s). "
                "For local dev, try: az login --tenant %s  "
                "For CI, set ARTIFACTS_KEYRING_NOFUSS_TOKEN. "
                "Set ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 for details.",
                _strip_userinfo(service),
                ", ".join(p.__class__.__name__ for p in chain),
                tenant_id,
            )
            return None

        bearer = result
        account = _account_from_token(bearer)

        if _is_service_principal_token(bearer):
            # MI / SP / WIF tokens cannot be exchanged for a VssSessionToken.
            # Return the Entra bearer token directly as Basic auth password.
            if account:
                log.debug(
                    "authenticated to %s as %s (service principal)",
                    _strip_userinfo(service),
                    account,
                )
            cred = keyring.credentials.SimpleCredential("bearer", bearer)
        else:
            # User tokens (e.g. Azure CLI) are exchanged for a narrower
            # VssSessionToken scoped to vso.packaging.
            session_tok = _session_token.exchange(bearer, vsts_authority)
            if session_tok is None:
                if account:
                    log.warning(
                        "session token exchange failed for %s (authenticated as %s). "
                        "Check that the account has Packaging Read permissions. "
                        "Set ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 for details.",
                        _strip_userinfo(service),
                        account,
                    )
                else:
                    log.warning(
                        "session token exchange failed for %s. "
                        "Set ARTIFACTS_KEYRING_NOFUSS_DEBUG=1 for details.",
                        _strip_userinfo(service),
                    )
                return None

            if account:
                log.debug(
                    "authenticated to %s as %s",
                    _strip_userinfo(service),
                    account,
                )
            cred = keyring.credentials.SimpleCredential("VssSessionToken", session_tok)
        self._cache[service] = (cred, time.monotonic())
        return cred

    def get_password(self, service: str, username: str | None) -> str | None:
        cred = self.get_credential(service, username)
        return cred.password if cred else None

    def set_password(self, service: str, username: str, password: str) -> None:
        msg = "read-only backend"
        raise NotImplementedError(msg)

    def delete_password(self, service: str, username: str) -> None:
        msg = "read-only backend"
        raise NotImplementedError(msg)
