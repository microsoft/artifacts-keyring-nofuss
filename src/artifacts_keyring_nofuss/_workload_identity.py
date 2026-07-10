"""Auth flow: Workload Identity Federation (e.g. GitHub Actions OIDC).

Exchanges a federated token for an Azure AD bearer token using the OAuth2
client-credentials grant with
``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``.

The federated assertion is sourced from ``AZURE_FEDERATED_TOKEN_FILE`` when set
(the AKS workload-identity convention).  When it is absent but the job runs in
GitHub Actions with ``permissions: id-token: write``, the assertion is fetched
directly from the GitHub Actions OIDC endpoint — this covers plain GitHub
runners where ``azure/login`` does not write a token file.

Required env vars:
- ``AZURE_CLIENT_ID``
- ``AZURE_FEDERATED_TOKEN_FILE`` *or* the GitHub Actions OIDC env vars
  (``ACTIONS_ID_TOKEN_REQUEST_URL`` + ``ACTIONS_ID_TOKEN_REQUEST_TOKEN``)

Optional env var:
- ``AZURE_TENANT_ID`` (preferred when set; otherwise the discovered
  ``tenant_id`` from the feed URL is used)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import requests

from . import _constants as C
from . import _github_oidc, _http

log = logging.getLogger(__name__)

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"  # noqa: S105


def mint_bearer(
    client_id: str,
    assertion: str,
    tenant_id: str,
    resource: str = C.RESOURCE_ID,
) -> str | None:
    """Exchange a federated OIDC assertion for an Azure AD bearer token.

    Performs the OAuth2 client-credentials grant with a JWT client assertion
    against ``login.microsoftonline.com``.  Returns the ``access_token`` on
    success, or ``None`` on any failure.  Never raises.
    """
    url = _TOKEN_URL.format(tenant=tenant_id)

    try:
        resp = _http.request(
            "POST",
            url,
            data={
                "client_id": client_id,
                "client_assertion": assertion,
                "client_assertion_type": (
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
                "grant_type": "client_credentials",
                "scope": f"{resource}/.default",
            },
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException:
        log.debug("workload identity: token request failed", exc_info=True)
        return None

    try:
        payload = resp.json()
    except ValueError:
        log.debug("workload identity: token response was not valid JSON", exc_info=True)
        return None

    token = payload.get("access_token") if isinstance(payload, dict) else None
    return token if isinstance(token, str) and token else None


def _read_assertion() -> str | None:
    """Resolve a federated OIDC assertion for the client-credentials grant.

    Prefers ``AZURE_FEDERATED_TOKEN_FILE`` when set; otherwise falls back to the
    GitHub Actions OIDC endpoint (available when the job has ``id-token: write``).
    Returns ``None`` when no assertion source is available or usable.
    """
    token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
    if token_file:
        try:
            assertion = Path(token_file).read_text().strip()
        except OSError:
            log.debug("workload identity: cannot read %s", token_file, exc_info=True)
            return None
        if not assertion:
            log.debug("workload identity: token file is empty")
            return None
        return assertion

    if _github_oidc.available():
        # The audience for Entra ID workload-identity federation is a fixed
        # value; only override it for non-public clouds via the env var.
        audience = (
            os.environ.get("AZURE_FEDERATED_TOKEN_AUDIENCE", "").strip()
            or _github_oidc.DEFAULT_AUDIENCE
        )
        oidc_assertion = _github_oidc.fetch_assertion(audience)
        if not oidc_assertion:
            log.debug("workload identity: GitHub Actions OIDC token unavailable")
            return None
        return oidc_assertion

    log.debug(
        "workload identity: no AZURE_FEDERATED_TOKEN_FILE and no GitHub "
        "Actions OIDC env vars"
    )
    return None


class WorkloadIdentityProvider:
    name = "workload_identity"

    def get_token(self, tenant_id: str) -> str | None:
        client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
        # Prefer AZURE_TENANT_ID (set by azure/login) over discovered tenant
        env_tenant = os.environ.get("AZURE_TENANT_ID", "").strip()

        if not client_id:
            log.debug("workload identity: AZURE_CLIENT_ID not set")
            return None

        assertion = _read_assertion()
        if assertion is None:
            return None

        tid = env_tenant or tenant_id
        return mint_bearer(client_id, assertion, tid)
