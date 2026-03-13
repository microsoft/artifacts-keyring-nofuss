"""No-fuss, pure-Python keyring backend for Azure DevOps Artifacts feeds."""

__version__ = "0.1.0"

from ._backend import ArtifactsKeyringBackend

__all__ = ["ArtifactsKeyringBackend"]
