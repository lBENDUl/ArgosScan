"""
ArgosScan - Logger
"""

import logging
import sys
from pathlib import Path


def setup_logger(log_file: str = None, level: int = logging.WARNING) -> logging.Logger:
    """
    Setup application logger.
    
    Args:
        log_file: Optional path to write logs to file.
        level: Logging level (default: WARNING to keep CLI output clean).
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("argosScan")
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Only add console handler once
    has_console = any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
                      for h in logger.handlers)
    if not has_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Add file handler if requested (always, even if logger already has handlers)
    if log_file:
        # Avoid duplicate file handlers for the same path
        existing_files = [h.baseFilename for h in logger.handlers
                          if isinstance(h, logging.FileHandler)]
        if str(Path(log_file).resolve()) not in existing_files:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.setLevel(logging.DEBUG)

    return logger
