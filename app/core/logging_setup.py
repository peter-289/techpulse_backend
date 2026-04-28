from __future__ import annotations

import copy
import logging
import logging.config
from pathlib import Path

from uvicorn.config import LOGGING_CONFIG as UVICORN_LOGGING_CONFIG
from app.core.config import settings


def configure_logging() -> None:
    """Configure logging for FastAPI + Uvicorn."""

    log_level = (settings.LOG_LEVEL or "INFO").upper()
    log_file = Path(settings.LOG_FILE_PATH)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging_config = copy.deepcopy(UVICORN_LOGGING_CONFIG)
    logging_config["disable_existing_loggers"] = False

    # === Formatters ===
    logging_config["formatters"]["default"]["fmt"] = (
        "%(asctime)s | %(levelprefix)s | %(name)s | %(message)s"
    )
    logging_config["formatters"]["default"]["datefmt"] = "%Y-%m-%d %H:%M:%S"

    logging_config["formatters"]["access"]["fmt"] = (
        '%(asctime)s | %(levelprefix)s | %(client_addr)s - "%(request_line)s" %(status_code)s'
    )
    logging_config["formatters"]["access"]["datefmt"] = "%Y-%m-%d %H:%M:%S"

    # === Handlers ===

    # Console handlers (keep them for local/dev visibility)
    # Make sure they still exist
    if "default" not in logging_config["handlers"]:
        logging_config["handlers"]["default"] = {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "stream": "ext://sys.stderr",
        }
    logging_config["handlers"]["default"]["level"] = log_level

    if "access" not in logging_config["handlers"]:
        logging_config["handlers"]["access"] = {
            "class": "logging.StreamHandler",
            "formatter": "access",
            "stream": "ext://sys.stdout",
        }
    logging_config["handlers"]["access"]["level"] = log_level

    # File handlers — use SEPARATE files to avoid RotatingFileHandler conflicts
    log_file_default = log_file.with_suffix(".app.log")      # or .error.log
    log_file_access = log_file.with_suffix(".access.log")

    logging_config["handlers"]["file_default"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "default",
        "filename": str(log_file_default),
        "maxBytes": settings.LOG_MAX_BYTES,
        "backupCount": settings.LOG_BACKUP_COUNT,
        "encoding": "utf-8",
        "level": log_level,
    }

    logging_config["handlers"]["file_access"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "access",
        "filename": str(log_file_access),
        "maxBytes": settings.LOG_MAX_BYTES,
        "backupCount": settings.LOG_BACKUP_COUNT,
        "encoding": "utf-8",
        "level": log_level,
    }

    # === Loggers ===

    # uvicorn.error → handles startup messages + full exception tracebacks
    logging_config["loggers"]["uvicorn.error"] = {
        "handlers": ["default", "file_default"],
        "level": log_level,
        "propagate": False,
    }

    # uvicorn.access → HTTP request logs
    logging_config["loggers"]["uvicorn.access"] = {
        "handlers": ["access", "file_access"],
        "level": log_level,
        "propagate": False,
    }

    # Your application logger
    logging_config["loggers"]["app"] = {
        "handlers": ["default", "file_default"],
        "level": log_level,
        "propagate": False,
    }

    # Root logger (catch-all)
    logging_config["root"] = {
        "handlers": ["default", "file_default"],
        "level": log_level,
    }

    logging.config.dictConfig(logging_config)

    logging.getLogger("app").info(
        "Logging configured | level=%s | app_log=%s | access_log=%s",
        log_level, log_file_default, log_file_access
    )