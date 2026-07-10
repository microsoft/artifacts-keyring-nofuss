"""Fetch a GitHub Actions OIDC ID token for federated credential exchange.

When a workflow grants ``permissions: id-token: write``, the runner exposes
``ACTIONS_ID_TOKEN_REQUEST_URL`` and ``ACTIONS_ID_TOKEN_REQUEST_TOKEN``.  These
let a step request a signed OIDC JWT for an arbitrary audience, which Azure AD
accepts as the ``client_assertion`` in a workload-identity-federation exchange.

This lets the CLI mint a bearer token on a GitHub runner *without* the Azure CLI
and *without* an ``AZURE_FEDERATED_TOKEN_FILE``.  The latter matters because
``azure/login@v2`` on GitHub-hosted runners does not create a federated token
file (that file is an AKS workload-identity convention), so relying on it alone
means ``ak-nofuss mint-token`` cannot mint on a plain GitHub runner.
"""

from __future__ import annotations

import logging
import os

import requests

from . import _http

log = logging.getLogger(__name__)

# Audience Azure AD expects for a GitHub-federated identity credential.
DEFAULT_AUDIENCE = "api://AzureADTokenExchange"

_REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL"
_REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"  # noqa: S105


def available() -> bool:
    """Return True if the GitHub Actions OIDC token endpoint is reachable.

    Both env vars are only present when the job (or workflow) has been granted
    the ``id-token: write`` permission.
    """
    return bool(
        os.environ.get(_REQUEST_URL_ENV, "").strip()
        and os.environ.get(_REQUEST_TOKEN_ENV, "").strip()
    )


def fetch_assertion(audience: str = DEFAULT_AUDIENCE) -> str | None:
    """Request a GitHub Actions OIDC ID token for *audience*.

    Returns the signed JWT on success, or ``None`` on any failure.  Never
    raises.  Requires the ``id-token: write`` workflow permission (which
    populates the ``ACTIONS_ID_TOKEN_REQUEST_*`` env vars).
    """
    request_url = os.environ.get(_REQUEST_URL_ENV, "").strip()
    request_token = os.environ.get(_REQUEST_TOKEN_ENV, "").strip()
    if not request_url or not request_token:
        log.debug("github oidc: request URL or token env var not set")
        return None

    try:
        resp = _http.request(
            "GET",
            request_url,
            params={"audience": audience},
            headers={
                "Authorization": f"Bearer {request_token}",
                "Accept": "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException:
        log.debug("github oidc: token request failed", exc_info=True)
        return None

    try:
        payload = resp.json()
    except ValueError:
        log.debug("github oidc: response was not valid JSON", exc_info=True)
        return None

    value = payload.get("value") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and value else None
