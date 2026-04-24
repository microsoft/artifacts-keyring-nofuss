"""Auth flow: ADO auth helper (VS Code Codespaces extension).

The ``ms-codespaces-tools.ado-codespaces-auth`` VS Code extension creates
``~/ado-auth-helper`` — a Node.js credential helper that obtains Azure AD
tokens via VS Code's built-in Microsoft authentication provider.

This provider calls that helper directly, so ``__token__@`` URLs in
``pyproject.toml`` work in Codespaces without any special-casing.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_HELPER_PATH = Path.home() / "ado-auth-helper"


class AdoAuthHelperProvider:
    name = "ado_auth_helper"

    def get_token(self, tenant_id: str) -> str | None:  # noqa: ARG002
        if not _HELPER_PATH.is_file():
            log.debug("ado-auth-helper not found at %s", _HELPER_PATH)
            return None

        try:
            result = subprocess.run(
                [str(_HELPER_PATH), "get-access-token"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.debug("ado-auth-helper could not be executed: %s", exc)
            return None

        if result.returncode != 0:
            log.debug(
                "ado-auth-helper failed (rc=%d): %s",
                result.returncode,
                result.stderr.strip(),
            )
            return None

        token = result.stdout.strip()
        if token:
            return token
        log.debug("ado-auth-helper returned empty output")
        return None
