"""Auth flow: Workload Identity Federation (e.g. GitHub Actions OIDC).

Exchanges a federated token (from ``AZURE_FEDERATED_TOKEN_FILE``) for an
Azure AD bearer token using the OAuth2 client-credentials grant with
``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``.

Required env vars (typically set by ``azure/login@v2``):
- ``AZURE_CLIENT_ID``
- ``AZURE_FEDERATED_TOKEN_FILE``

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

log = logging.getLogger(__name__)

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"  # noqa: S105


class WorkloadIdentityProvider:
    name = "workload_identity"

    def get_token(self, tenant_id: str) -> str | None:
        client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
        token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
        # Prefer AZURE_TENANT_ID (set by azure/login) over discovered tenant
        env_tenant = os.environ.get("AZURE_TENANT_ID", "").strip()

        if not client_id or not token_file:
            log.debug(
                "workload identity: AZURE_CLIENT_ID or "
                "AZURE_FEDERATED_TOKEN_FILE not set"
            )
            return None

        try:
            assertion = Path(token_file).read_text().strip()
        except OSError:
            log.debug("workload identity: cannot read %s", token_file, exc_info=True)
            return None

        if not assertion:
            log.debug("workload identity: token file is empty")
            return None

        tid = env_tenant or tenant_id
        url = _TOKEN_URL.format(tenant=tid)

        try:
            resp = requests.post(
                url,
                data={
                    "client_id": client_id,
                    "client_assertion": assertion,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "grant_type": "client_credentials",
                    "scope": f"{C.RESOURCE_ID}/.default",
                },
                timeout=30,
            )
            resp.raise_for_status()
        except requests.RequestException:
            log.debug("workload identity: token request failed", exc_info=True)
            return None

        return resp.json().get("access_token") or None
