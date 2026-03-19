"""Auth flow: Azure Managed Identity via the IMDS endpoint."""

from __future__ import annotations

import logging
import os

import requests

from . import _constants as C

log = logging.getLogger(__name__)

IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
IMDS_TIMEOUT = 2  # fail fast on non-Azure machines


class ManagedIdentityProvider:
    name = "managed_identity"

    def get_token(self, tenant_id: str) -> str | None:  # noqa: ARG002
        params: dict[str, str] = {
            "resource": C.RESOURCE_ID,
            "api-version": "2018-02-01",
        }

        # User-assigned managed identity
        client_id = os.environ.get("AZURE_CLIENT_ID")
        if client_id:
            params["client_id"] = client_id

        try:
            resp = requests.get(
                IMDS_URL,
                params=params,
                headers={"Metadata": "true"},
                timeout=IMDS_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException:
            log.debug("IMDS request failed", exc_info=True)
            return None

        return resp.json().get("access_token") or None
