"""Provider protocol and chain logic."""

from __future__ import annotations

import logging
from typing import Protocol

log = logging.getLogger(__name__)


class TokenProvider(Protocol):
    """A provider that can obtain a bearer token for Azure DevOps."""

    name: str

    def get_token(self, tenant_id: str) -> str | None:
        """Return a bearer token, or None if this provider cannot authenticate.

        *tenant_id* is the Azure AD tenant discovered from the feed URL.
        Providers that don't need it (e.g. Azure CLI) may ignore it.
        """
        ...


def run_chain(providers: list[TokenProvider], tenant_id: str) -> str | None:
    """Try each provider in order; return the first successful bearer token."""
    for provider in providers:
        log.debug("trying provider: %s", provider.name)
        try:
            token = provider.get_token(tenant_id)
        except Exception:
            log.debug("provider %s failed", provider.name, exc_info=True)
            continue
        if token is not None:
            log.debug("provider %s succeeded", provider.name)
            return token
    return None
