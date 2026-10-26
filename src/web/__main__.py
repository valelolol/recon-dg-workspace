"""CLI entry point for ``python -m src.web``."""

from __future__ import annotations

import sys

from src.web.server import main

if __name__ == "__main__":
    sys.exit(main())
