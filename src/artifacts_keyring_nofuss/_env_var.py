"""Auth flow: bearer token from an environment variable."""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

ENV_VAR = "ARTIFACTS_KEYRING_NOFUSS_TOKEN"
FALLBACK_ENV_VAR = "VSS_NUGET_ACCESSTOKEN"


class EnvVarProvider:
    name = "env_var"

    def get_token(self, tenant_id: str) -> str | None:  # noqa: ARG002
        for var in (ENV_VAR, FALLBACK_ENV_VAR):
            token = os.environ.get(var, "").strip()
            if token:
                log.debug("using bearer token from %s", var)
                return token
        log.debug("%s / %s not set or empty", ENV_VAR, FALLBACK_ENV_VAR)
        return None
