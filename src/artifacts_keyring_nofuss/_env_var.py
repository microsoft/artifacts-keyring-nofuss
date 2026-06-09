"""Auth flow: bearer token from an environment variable or file.

Supports the Docker ``_FILE`` convention: if ``ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE``
is set, the token is read from that path (e.g. a BuildKit secret mounted at
``/run/secrets/…``).  When neither env var is set, well-known BuildKit secret
paths are checked automatically.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

ENV_VAR = "ARTIFACTS_KEYRING_NOFUSS_TOKEN"
ENV_VAR_FILE = "ARTIFACTS_KEYRING_NOFUSS_TOKEN_FILE"
FALLBACK_ENV_VAR = "VSS_NUGET_ACCESSTOKEN"

# Well-known BuildKit secret paths checked when no env var is set.
_BUILDKIT_SECRET_PATHS: tuple[Path, ...] = (
    Path("/run/secrets/ARTIFACTS_KEYRING_NOFUSS_TOKEN"),
    Path("/run/secrets/ado_token"),
)


def _read_token_file(path: str | os.PathLike[str]) -> str | None:
    """Read and return stripped token from *path*, or None on failure."""
    try:
        token = Path(path).read_text().strip()
        if token:
            return token
    except (OSError, ValueError):
        pass
    return None


class EnvVarProvider:
    name = "env_var"

    def get_token(self, tenant_id: str) -> str | None:  # noqa: ARG002
        # 1. Explicit _FILE env var (Docker convention)
        file_path = os.environ.get(ENV_VAR_FILE, "").strip()
        if file_path:
            token = _read_token_file(file_path)
            if token:
                log.debug(
                    "using bearer token from file %s (%s)", file_path, ENV_VAR_FILE
                )
                return token
            log.debug(
                "%s points to %s but file is empty or unreadable",
                ENV_VAR_FILE,
                file_path,
            )

        # 2. Direct env vars
        for var in (ENV_VAR, FALLBACK_ENV_VAR):
            token = os.environ.get(var, "").strip()
            if token:
                log.debug("using bearer token from %s", var)
                return token

        # 3. Well-known BuildKit secret paths
        for secret_path in _BUILDKIT_SECRET_PATHS:
            token = _read_token_file(secret_path)
            if token:
                log.debug("using bearer token from BuildKit secret %s", secret_path)
                return token

        log.debug(
            "%s / %s / %s not set; no BuildKit secret found",
            ENV_VAR,
            ENV_VAR_FILE,
            FALLBACK_ENV_VAR,
        )
        return None
