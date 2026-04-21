"""Provider protocol and chain logic."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TokenResult:
    """Bearer token plus metadata about how it was obtained.

    *is_service_principal* signals that the token came from a non-user identity
    (managed identity, service principal, workload identity federation).
    Service-principal tokens cannot be exchanged for a VssSessionToken — the
    bearer must be returned directly to the package manager.
    """

    access_token: str
    is_service_principal: bool = False


class TokenProvider(Protocol):
    """A provider that can obtain a bearer token for Azure DevOps."""

    name: str

    def get_token(self, tenant_id: str) -> TokenResult | None:
        """Return a bearer token, or None if this provider cannot authenticate.

        *tenant_id* is the Azure AD tenant discovered from the feed URL.
        Providers that don't need it (e.g. Azure CLI) may ignore it.
        """
        ...


def run_chain(providers: list[TokenProvider], tenant_id: str) -> TokenResult | None:
    """Try each provider in order; return the first successful bearer token."""
    for provider in providers:
        log.debug("trying provider: %s", provider.name)
        try:
            result = provider.get_token(tenant_id)
        except Exception:
            log.debug("provider %s failed", provider.name, exc_info=True)
            continue
        if result is not None:
            log.debug("provider %s succeeded", provider.name)
            return result
    return None
