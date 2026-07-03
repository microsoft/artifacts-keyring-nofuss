"""Exchange a bearer token for an org-scoped, read-only Azure DevOps session token."""

from __future__ import annotations

import contextlib
import logging

import requests

from . import _http

log = logging.getLogger(__name__)


class TokenRejectedError(Exception):
    """Raised when the session token exchange returns 401 (bearer was rejected)."""


def exchange(bearer_token: str, vsts_authority: str) -> str | None:
    """Exchange *bearer_token* for a session token scoped to ``vso.packaging``.

    *vsts_authority* is the Azure DevOps authority URL extracted from the
    ``X-VSS-AuthorizationEndpoint`` response header (e.g.
    ``https://app.vssps.visualstudio.com``).
    """
    url = (
        f"{vsts_authority.rstrip('/')}/"
        "_apis/Token/SessionTokens"
        "?api-version=5.0-preview.1"
    )

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        # Prevent Azure DevOps from returning 302 redirects to the
        # sign-in page; surface a proper 401 instead so we can
        # report errors and retry.
        "X-TFS-FedAuthRedirect": "Suppress",
    }

    try:
        resp = _http.request(
            "POST",
            url,
            json={
                "scope": "vso.packaging",
                "displayName": "artifacts-keyring-nofuss",
            },
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.HTTPError:
        detail = ""
        with contextlib.suppress(Exception):
            detail = resp.json().get("message", "")
        if resp.status_code == 401:
            log.debug(
                "session token exchange returned 401 — bearer token was "
                "rejected by Azure DevOps. %s",
                detail,
            )
            raise TokenRejectedError(detail) from None
        log.debug(
            "session token exchange failed (HTTP %s): %s",
            resp.status_code,
            detail,
            exc_info=True,
        )
        return None
    except requests.RequestException:
        log.debug("session token exchange failed", exc_info=True)
        return None

    try:
        token = resp.json().get("token")
    except (ValueError, AttributeError):
        log.debug("session token response was not valid JSON")
        return None
    return token or None
