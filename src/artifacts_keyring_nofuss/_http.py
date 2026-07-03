"""Shared HTTP helper that retries transient network failures with backoff.

Azure DevOps feeds occasionally drop connections or return transient 5xx/429
responses.  A single failed request makes the whole auth flow fail, which then
surfaces to pip/twine as a 401.  Retrying the outbound requests here turns those
transient blips into a brief delay instead of a hard failure that only a manual
re-run would recover from.
"""

from __future__ import annotations

import logging
import os
import random
import time

import requests

log = logging.getLogger(__name__)

# Total attempts (including the first) for a single outbound request.
DEFAULT_MAX_ATTEMPTS = 3
_MIN_ATTEMPTS = 1
_MAX_ATTEMPTS = 10

# Exponential backoff bounds (seconds).
_BASE_DELAY = 0.5
_MAX_DELAY = 8.0

# Status codes worth retrying: rate limiting and transient server errors.
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Exception types worth retrying: dropped connections and timeouts. Other
# RequestException subclasses (invalid URL, TLS/SSL misconfiguration, too many
# redirects, ...) are not transient — retrying only adds delay and hides the
# real error, so we let them propagate immediately.
_RETRYABLE_EXCEPTIONS = (requests.ConnectionError, requests.Timeout)

_MAX_ATTEMPTS_ENV = "ARTIFACTS_KEYRING_NOFUSS_RETRIES"


def _is_retryable_exception(exc: requests.RequestException) -> bool:
    """Return True if *exc* is a transient network failure worth retrying."""
    # SSLError subclasses ConnectionError but almost always signals a
    # misconfiguration (bad cert, protocol mismatch) rather than a blip.
    if isinstance(exc, requests.exceptions.SSLError):
        return False
    return isinstance(exc, _RETRYABLE_EXCEPTIONS)


def _configured_attempts() -> int:
    """Resolve the retry budget, honouring an env-var override when valid."""
    raw = os.environ.get(_MAX_ATTEMPTS_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_ATTEMPTS
    try:
        value = int(raw)
    except ValueError:
        log.debug("ignoring invalid %s=%r", _MAX_ATTEMPTS_ENV, raw)
        return DEFAULT_MAX_ATTEMPTS
    return max(_MIN_ATTEMPTS, min(_MAX_ATTEMPTS, value))


def _backoff_delay(attempt: int) -> float:
    """Return a jittered exponential backoff delay for a 1-based *attempt*."""
    delay = min(_MAX_DELAY, _BASE_DELAY * (2 ** (attempt - 1)))
    # Full jitter avoids synchronised retries across parallel pip workers.
    return random.uniform(0, delay)  # noqa: S311 (not used for security)


def request(
    method: str,
    url: str,
    *,
    max_attempts: int | None = None,
    **kwargs: object,
) -> requests.Response:
    """Perform an HTTP request, retrying transient failures with backoff.

    Retries on transient connection errors, timeouts, and retryable status
    codes (:data:`RETRYABLE_STATUS`).  Non-transient failures (invalid URL,
    TLS/SSL misconfiguration, ...) propagate immediately.  The final response is
    returned as-is so the caller can inspect non-retryable statuses (e.g. a
    ``401`` carrying a ``WWW-Authenticate`` header, or a rejected bearer token).

    Raises the last :class:`requests.RequestException` if every attempt fails
    at the network level.
    """
    attempts = max_attempts if max_attempts is not None else _configured_attempts()
    attempts = max(_MIN_ATTEMPTS, min(_MAX_ATTEMPTS, attempts))

    for attempt in range(1, attempts + 1):
        try:
            # Timeout is always supplied by callers via **kwargs.
            resp = requests.request(method, url, **kwargs)  # type: ignore[arg-type]  # noqa: S113
        except requests.RequestException as exc:
            if not _is_retryable_exception(exc) or attempt >= attempts:
                raise
            delay = _backoff_delay(attempt)
            log.debug(
                "request %s %s failed (attempt %d/%d), retrying in %.2fs",
                method,
                url,
                attempt,
                attempts,
                delay,
                exc_info=True,
            )
            time.sleep(delay)
            continue

        if resp.status_code in RETRYABLE_STATUS and attempt < attempts:
            delay = _backoff_delay(attempt)
            log.debug(
                "request %s %s returned HTTP %d (attempt %d/%d), retrying in %.2fs",
                method,
                url,
                resp.status_code,
                attempt,
                attempts,
                delay,
            )
            time.sleep(delay)
            continue

        return resp

    # Unreachable: the loop always returns a response or raises.
    msg = "retry loop exited without returning or raising"  # pragma: no cover
    raise AssertionError(msg)  # pragma: no cover
