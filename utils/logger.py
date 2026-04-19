"""
Application-wide logger factory.
"""

import logging
import sys
from config import LOG_FILE

_configured: set[str] = set()

def get_logger(name: str = "scanner") -> logging.Logger:
    logger = logging.getLogger(name)

    if name in _configured:
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # File handler
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console handler (useful during development / container stdout)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    # Prevent propagation to root logger to avoid duplicate output
    logger.propagate = False

    _configured.add(name)
    return logger
