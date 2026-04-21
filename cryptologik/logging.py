from __future__ import annotations

import logging
import sys
from typing import Optional

_LOGGER_NAME = "cryptologik"


def _build_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


_logger = _build_logger()


def set_level(level: int) -> None:
    _logger.setLevel(level)


def info(message: str, *args: object, exc_info: Optional[BaseException] = None) -> None:
    _logger.info(message, *args, exc_info=exc_info)


def warning(message: str, *args: object, exc_info: Optional[BaseException] = None) -> None:
    _logger.warning(message, *args, exc_info=exc_info)


def error(message: str, *args: object, exc_info: Optional[BaseException] = None) -> None:
    _logger.error(message, *args, exc_info=exc_info)
