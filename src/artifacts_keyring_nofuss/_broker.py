"""Auth flow: MSAL broker — uses WAM (Windows) or Identity Broker (Linux)."""

from __future__ import annotations

import logging
import os
import sys

from . import _constants as C

log = logging.getLogger(__name__)

_CACHE_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
    "artifacts-keyring-nofuss",
)
_CACHE_FILE = os.path.join(_CACHE_DIR, "msal_broker_cache.json")


def _load_cache():
    """Load persistent MSAL token cache from disk."""
    import msal

    cache = msal.SerializableTokenCache()
    if os.path.isfile(_CACHE_FILE):
        try:
            with open(_CACHE_FILE) as f:
                cache.deserialize(f.read())
        except Exception:
            log.debug("failed to load MSAL cache from %s", _CACHE_FILE)
    return cache


def _save_cache(cache) -> None:
    """Save MSAL token cache to disk if state changed."""
    if not cache.has_state_changed:
        return
    try:
        os.makedirs(_CACHE_DIR, mode=0o700, exist_ok=True)
        with open(_CACHE_FILE, "w") as f:
            f.write(cache.serialize())
    except Exception:
        log.debug("failed to save MSAL cache to %s", _CACHE_FILE)


class BrokerProvider:
    name = "broker"

    def get_token(self, tenant_id: str) -> str | None:
        try:
            import msal
        except ImportError:
            log.debug("msal not installed, skipping broker provider")
            return None

        cache = _load_cache()
        authority = f"https://login.microsoftonline.com/{tenant_id}"

        # Try native broker for silent SSO (cached device credentials).
        try:
            app = msal.PublicClientApplication(
                client_id=C.CLIENT_ID,
                authority=authority,
                token_cache=cache,
                enable_broker_on_windows=sys.platform == "win32",
                enable_broker_on_linux=sys.platform.startswith("linux"),
            )
            log.debug("broker: trying native broker silent auth")
            accounts = app.get_accounts()
            if accounts:
                log.debug("broker: found account %s", accounts[0].get("username", "?"))
                result = app.acquire_token_silent(C.SCOPE, account=accounts[0])
                if result and "access_token" in result:
                    log.debug("broker: got token from native broker cache")
                    _save_cache(cache)
                    return result["access_token"]
        except Exception:
            log.debug("native broker unavailable", exc_info=True)

        # Fall back to plain MSAL (no broker) for both silent and interactive.
        # The first-party client ID only has http://localhost registered,
        # which the native broker's interactive flow does not use.
        try:
            app = msal.PublicClientApplication(
                client_id=C.CLIENT_ID,
                authority=authority,
                token_cache=cache,
            )
        except Exception:
            log.debug("failed to create MSAL app", exc_info=True)
            _save_cache(cache)
            return None

        log.debug("broker: using MSAL (no native broker)")

        # Silent from MSAL's own cache
        accounts = app.get_accounts()
        if accounts:
            log.debug("broker: found cached account %s", accounts[0].get("username", "?"))
            result = app.acquire_token_silent(C.SCOPE, account=accounts[0])
            if result and "access_token" in result:
                log.debug("broker: got token from MSAL cache/refresh")
                _save_cache(cache)
                return result["access_token"]

        # Interactive browser flow (uses http://localhost redirect)
        try:
            result = app.acquire_token_interactive(
                C.SCOPE,
                prompt="select_account",
            )
        except Exception:
            log.debug("broker: interactive auth failed", exc_info=True)
            _save_cache(cache)
            return None

        _save_cache(cache)

        if not result or "access_token" not in result:
            error = result.get("error", "") if result else ""
            desc = result.get("error_description", "") if result else ""
            log.debug("broker: token acquisition failed: %s %s", error, desc)
            return None

        return result["access_token"]
