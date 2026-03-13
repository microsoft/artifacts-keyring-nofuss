"""Keyring backend for Azure DevOps Artifacts feeds."""

from __future__ import annotations

import configparser
import logging
import os
import urllib.parse

import keyring.backend
import keyring.credentials
import requests

from . import _constants as C
from . import _provider, _session_token
from ._azure_cli import AzureCliProvider
from ._browser import BrowserProvider
from ._managed_identity import ManagedIdentityProvider

log = logging.getLogger(__name__)

PROVIDERS = {
    "azure_cli": AzureCliProvider,
    "managed_identity": ManagedIdentityProvider,
    "browser": BrowserProvider,
}

DEFAULT_CHAIN = ["azure_cli", "managed_identity", "browser"]


def _is_supported(service: str) -> bool:
    """Return True if *service* looks like an Azure DevOps Artifacts feed URL."""
    try:
        netloc = urllib.parse.urlparse(service).hostname or ""
    except Exception:
        return False
    return netloc in C.SUPPORTED_NETLOCS


def _discover(service: str) -> tuple[str, str] | None:
    """GET the feed URL unauthenticated to discover tenant and authority.

    Returns ``(tenant_id, vsts_authority)`` or ``None``.
    """
    try:
        resp = requests.get(service, allow_redirects=False, timeout=10)
    except requests.RequestException:
        log.debug("discovery request failed for %s", service, exc_info=True)
        return None

    www_auth = resp.headers.get("WWW-Authenticate", "")
    vsts_authority = resp.headers.get("X-VSS-AuthorizationEndpoint", "")

    # Parse tenant from: Bearer authorization_uri=https://login.microsoftonline.com/{tenant}
    tenant_id = ""
    for part in www_auth.split(","):
        part = part.strip()
        if "authorization_uri=" in part:
            uri = part.split("authorization_uri=", 1)[1].strip().strip('"')
            # URI is like https://login.microsoftonline.com/{tenant_id}
            tenant_id = uri.rstrip("/").rsplit("/", 1)[-1]
            break

    if not tenant_id or not vsts_authority:
        log.debug("discovery incomplete: tenant=%r authority=%r", tenant_id, vsts_authority)
        return None

    return tenant_id, vsts_authority


def _configured_provider() -> str | None:
    """Read provider override from env var or keyring config."""
    env = os.environ.get("ARTIFACTS_KEYRING_NOFUSS_PROVIDER", "").strip()
    if env:
        return env

    # Try keyring config file
    for path in [
        os.path.join(os.getcwd(), "keyringrc.cfg"),
        os.path.expanduser("~/.config/python_keyring/keyringrc.cfg"),
    ]:
        if os.path.isfile(path):
            cfg = configparser.ConfigParser()
            cfg.read(path)
            val = cfg.get("artifacts_keyring_nofuss", "provider", fallback="").strip()
            if val:
                return val

    return None


class ArtifactsKeyringBackend(keyring.backend.KeyringBackend):
    priority = 9.9  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, keyring.credentials.SimpleCredential] = {}

    def get_credential(
        self, service: str, username: str | None
    ) -> keyring.credentials.SimpleCredential | None:
        if not _is_supported(service):
            return None

        # Validate provider config early so typos are surfaced before
        # any network calls.
        chosen = _configured_provider()
        if chosen and chosen not in PROVIDERS:
            log.warning("unknown provider %r, valid: %s", chosen, ", ".join(PROVIDERS))
            return None

        if service in self._cache:
            return self._cache[service]

        # Discover tenant + authority
        info = _discover(service)
        if info is None:
            log.warning("could not discover tenant for %s", service)
            return None
        tenant_id, vsts_authority = info

        # Build provider list
        if chosen:
            providers = [PROVIDERS[chosen]()]
        else:
            providers = [PROVIDERS[name]() for name in DEFAULT_CHAIN]

        # Get bearer token
        bearer = _provider.run_chain(providers, tenant_id)
        if bearer is None:
            log.warning("all providers failed for %s", service)
            return None

        # Exchange for session token
        session_tok = _session_token.exchange(bearer, vsts_authority)
        if session_tok is None:
            log.warning("session token exchange failed for %s", service)
            return None

        cred = keyring.credentials.SimpleCredential("VssSessionToken", session_tok)
        self._cache[service] = cred
        return cred

    def get_password(self, service: str, username: str | None) -> str | None:
        cred = self.get_credential(service, username)
        return cred.password if cred else None

    def set_password(self, service: str, username: str, password: str) -> None:
        raise NotImplementedError("read-only backend")

    def delete_password(self, service: str, username: str) -> None:
        raise NotImplementedError("read-only backend")
