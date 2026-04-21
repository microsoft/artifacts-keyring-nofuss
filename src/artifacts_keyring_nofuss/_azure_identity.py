"""Auth flow: azure-identity library (MI, SP, WIF, and more).

Uses ``DefaultAzureCredential`` which automatically handles managed
identities (system + user-assigned), service principals with secrets or
certificates, workload identity federation, and several other credential
types.
"""

from __future__ import annotations

import logging
import os

from azure.identity import DefaultAzureCredential, ManagedIdentityCredential

from . import _constants as C
from ._provider import TokenResult

log = logging.getLogger(__name__)


class AzureIdentityProvider:
    name = "azure_identity"

    def get_token(self, tenant_id: str) -> TokenResult | None:  # noqa: ARG002
        client_id = os.environ.get("AZURE_CLIENT_ID")

        # If AZURE_CLIENT_ID is set but no AZURE_TENANT_ID, this is likely a
        # user-assigned managed identity scenario — use ManagedIdentityCredential
        # directly so DefaultAzureCredential doesn't mis-interpret it as an
        # EnvironmentCredential (which requires AZURE_TENANT_ID + a secret).
        credential: ManagedIdentityCredential | DefaultAzureCredential
        tenant_id_env = os.environ.get("AZURE_TENANT_ID")
        if client_id and not tenant_id_env:
            log.debug(
                "AZURE_CLIENT_ID set without AZURE_TENANT_ID — "
                "using ManagedIdentityCredential for user-assigned MI"
            )
            credential = ManagedIdentityCredential(client_id=client_id)
        else:
            # DefaultAzureCredential tries (in order):
            #   EnvironmentCredential, WorkloadIdentityCredential,
            #   ManagedIdentityCredential, AzureCliCredential, ...
            # We exclude AzureCliCredential since we have our own provider
            # for that, and it avoids double-prompting.
            credential = DefaultAzureCredential(
                exclude_cli_credential=True,
                managed_identity_client_id=client_id,
            )

        try:
            token = credential.get_token(C.RESOURCE_ID)
        except Exception:
            log.debug("azure-identity auth failed", exc_info=True)
            return None

        if not token.token:
            return None
        return TokenResult(token.token, is_service_principal=True)
