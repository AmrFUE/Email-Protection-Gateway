"""
logger.py — Centralized logging setup.
All pipeline modules call get_logger() to get a consistent logger.
"""

import logging
import sys


def get_logger(name: str = "phishing_pipeline") -> logging.Logger:
    """
    Returns a named logger with a formatted console handler.
    Calling this multiple times with the same name returns the same logger
    (Python's logging module caches by name).
    """
    logger = logging.getLogger(name)

    # Only add handler once (idempotent)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger
