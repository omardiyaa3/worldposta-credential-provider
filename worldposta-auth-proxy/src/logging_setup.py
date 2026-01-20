"""
WorldPosta Authentication Proxy - Logging Setup
"""

import os
import logging
import logging.handlers
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    debug: bool = False
):
    """
    Configure logging for the authentication proxy

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Path to log file (None for stdout only)
        debug: Enable debug mode with verbose output
    """

    if debug:
        log_level = "DEBUG"

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if log_file specified)
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # Use rotating file handler (max 10MB, keep 5 backups)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized (level={log_level}, file={log_file})")

    return root_logger
