"""Auth flow: Azure CLI — runs `az account get-access-token`."""

from __future__ import annotations

import json
import logging
import subprocess

from . import _constants as C
from ._provider import TokenResult

log = logging.getLogger(__name__)


def _current_account() -> str | None:
    """Return the UPN or app ID of the currently logged-in az CLI account."""
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "user.name", "--output", "tsv"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    return None


class AzureCliProvider:
    name = "azure_cli"

    def get_token(self, tenant_id: str) -> TokenResult | None:
        try:
            result = subprocess.run(
                [
                    "az",
                    "account",
                    "get-access-token",
                    "--resource",
                    C.RESOURCE_ID,
                    "--tenant",
                    tenant_id,
                    "--query",
                    "accessToken",
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            log.debug("az CLI not found on PATH")
            return None
        except subprocess.TimeoutExpired:
            log.debug("az CLI timed out")
            return None

        if result.returncode != 0:
            account = _current_account()
            stderr = result.stderr.strip()
            if account:
                log.warning(
                    "az CLI auth failed for account %r (tenant %s): %s",
                    account,
                    tenant_id,
                    stderr,
                )
            else:
                log.warning("az CLI auth failed (not logged in?): %s", stderr)
            return None

        try:
            token = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            log.debug("failed to parse az CLI output")
            return None

        if isinstance(token, str) and token:
            return TokenResult(token, is_service_principal=False)
        return None
