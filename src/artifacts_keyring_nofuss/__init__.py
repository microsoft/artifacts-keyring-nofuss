"""No-fuss, pure-Python keyring backend for Azure DevOps Artifacts feeds."""

import logging
import os
import sys
from importlib.metadata import version

__version__ = version(__name__)


def _configure_logging() -> None:
    if not os.environ.get("ARTIFACTS_KEYRING_NOFUSS_DEBUG"):
        return
    pkg_logger = logging.getLogger(__name__)
    pkg_logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    pkg_logger.addHandler(handler)
    pkg_logger.propagate = False


_configure_logging()

from ._backend import ArtifactsKeyringBackend

__all__ = ["ArtifactsKeyringBackend"]
