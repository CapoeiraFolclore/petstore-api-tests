"""HTTP request/response logging configuration."""

from __future__ import annotations

import logging
from typing import Optional


def setup_logging(level: Optional[str] = None) -> None:
    """Configure root logging for API test runs."""
    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
