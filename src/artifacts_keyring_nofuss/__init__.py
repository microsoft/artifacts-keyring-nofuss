"""No-fuss, pure-Python keyring backend for Azure DevOps Artifacts feeds."""

from importlib.metadata import version

__version__ = version(__name__)

from ._backend import ArtifactsKeyringBackend

__all__ = ["ArtifactsKeyringBackend"]
