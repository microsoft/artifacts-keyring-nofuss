"""Provider protocol and chain logic."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

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


def iter_tokens(
    providers: Iterable[TokenProvider], tenant_id: str
) -> Iterator[tuple[TokenProvider, str]]:
    """Yield ``(provider, bearer_token)`` for each provider that succeeds.

    Failures and ``None`` returns are logged and skipped automatically.
    Callers can iterate and decide whether to consume the next token
    (e.g. after a session-token exchange rejection).
    """
    for provider in providers:
        log.debug("trying provider: %s", provider.name)
        try:
            token = provider.get_token(tenant_id)
        except Exception:
            log.debug("provider %s failed", provider.name, exc_info=True)
            continue
        if token is not None:
            log.debug("provider %s succeeded", provider.name)
            yield provider, token


def run_chain(providers: Iterable[TokenProvider], tenant_id: str) -> str | None:
    """Try each provider in order; return the first successful bearer token."""
    return next((token for _, token in iter_tokens(providers, tenant_id)), None)
