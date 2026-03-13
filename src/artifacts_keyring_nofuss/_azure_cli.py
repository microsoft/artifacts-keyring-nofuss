"""Auth flow: Azure CLI — runs `az account get-access-token`."""

from __future__ import annotations

import json
import logging
import subprocess

from . import _constants as C

log = logging.getLogger(__name__)


class AzureCliProvider:
    name = "azure_cli"

    def get_token(self, tenant_id: str) -> str | None:
        try:
            result = subprocess.run(
                [
                    "az", "account", "get-access-token",
                    "--resource", C.RESOURCE_ID,
                    "--tenant", tenant_id,
                    "--query", "accessToken",
                    "--output", "json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            log.debug("az CLI not found on PATH")
            return None
        except subprocess.TimeoutExpired:
            log.debug("az CLI timed out")
            return None

        if result.returncode != 0:
            log.debug("az CLI failed (rc=%d): %s", result.returncode, result.stderr.strip())
            return None

        try:
            token = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            log.debug("failed to parse az CLI output")
            return None

        if isinstance(token, str) and token:
            return token
        return None
