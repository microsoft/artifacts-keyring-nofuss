"""Entry point for ``python -m artifacts_keyring_nofuss``."""

from __future__ import annotations

import sys

from ._cli import main

if __name__ == "__main__":
    sys.exit(main())
