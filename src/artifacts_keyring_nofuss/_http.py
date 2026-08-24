"""Shared HTTP helper that retries transient network failures with backoff.

Azure DevOps feeds occasionally drop connections or return transient 5xx/429
responses.  A single failed request makes the whole auth flow fail, which then
surfaces to pip/twine as a 401.  Retrying the outbound requests here turns those
transient blips into a brief delay instead of a hard failure that only a manual
re-run would recover from.
"""

from __future__ import annotations

import importlib.metadata
import logging
import os
import random
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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


def _user_agent() -> str:
    """Build a package-specific user agent string."""
    try:
        package_version = importlib.metadata.version("artifacts-keyring-nofuss")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"
    return f"artifacts-keyring-nofuss/{package_version}"


def _build_retry(attempts: int) -> Retry:
    retries = max(_MIN_ATTEMPTS, min(_MAX_ATTEMPTS, attempts)) - 1
    return Retry(
        total=retries,
        # Keep connect/read retries in the manual loop so we can explicitly avoid
        # retrying SSLError while still using urllib3 Retry for status retries.
        connect=0,
        read=0,
        status=retries,
        backoff_factor=_BASE_DELAY,
        allowed_methods=None,
        status_forcelist=RETRYABLE_STATUS,
        raise_on_status=False,
    )


def _build_session(attempts: int) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": _user_agent()})
    adapter = HTTPAdapter(max_retries=_build_retry(attempts))
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


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


_SESSION_ATTEMPTS = _configured_attempts()
_SESSION = _build_session(_SESSION_ATTEMPTS)


def _session_for_attempts(attempts: int) -> requests.Session:
    if attempts == _SESSION_ATTEMPTS:
        return _SESSION
    return _build_session(attempts)


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
    """Perform an HTTP request, retrying transient failures.

    Retries transient connection errors and timeouts with jittered backoff.
    Retryable status codes (:data:`RETRYABLE_STATUS`) are handled by the
    session's configured :class:`urllib3.util.retry.Retry`. Non-transient
    failures (invalid URL,
    TLS/SSL misconfiguration, ...) propagate immediately.  The final response is
    returned as-is so the caller can inspect non-retryable statuses (e.g. a
    ``401`` carrying a ``WWW-Authenticate`` header, or a rejected bearer token).

    Raises the last :class:`requests.RequestException` if every attempt fails
    at the network level.
    """
    attempts = max_attempts if max_attempts is not None else _configured_attempts()
    attempts = max(_MIN_ATTEMPTS, min(_MAX_ATTEMPTS, attempts))

    session = _session_for_attempts(attempts)

    for attempt in range(1, attempts + 1):
        try:
            # Timeout is always supplied by callers via **kwargs.
            resp = session.request(method, url, **kwargs)  # type: ignore[arg-type]
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

        return resp

    # Unreachable: the loop always returns a response or raises.
    msg = "retry loop exited without returning or raising"  # pragma: no cover
    raise AssertionError(msg)  # pragma: no cover
