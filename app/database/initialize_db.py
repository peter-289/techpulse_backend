from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

from app.models import (  # noqa: F401
    audit_event,
    chat_message,
    project,
    resource,
    security_alert,
    session,
    user,
)

logger = logging.getLogger(__name__)

def init_db():
    try:
        backend_root = Path(__file__).resolve().parents[2]
        alembic_ini_path = backend_root / "alembic.ini"
        config = Config(str(alembic_ini_path))
        config.set_main_option("script_location", str(backend_root / "alembic"))
        command.upgrade(config, "head")
    except Exception as exc:
        logger.exception("[-] Failed to apply database migrations: %s", exc)
        raise
