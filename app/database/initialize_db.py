from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config

from app.models.enums import AppState
# from app.services.app_cycle_manger import LifecycleManager
from app.core.config import settings
from app.models import (  # noqa: F401
    audit_event,
    chat_message,
    payment,
    project,
    resource,
    security_alert,
    session,
    software,
    user,
)

logger = logging.getLogger(__name__)

def run_migrations_blocking(lifecycle=None):
    """
    Fully blocking, deterministic migration runner.
    Safe for startup orchestration.
    """
    try:
        # Log migrations start and app state
        logger.info("[+] Starting database migrations...")
        if lifecycle:
            lifecycle.set_state(AppState.DB_MIGRATIONS_RUNNING)

        # Resolve root
        backend_root = Path(__file__).resolve().parents[2]

        alembic_ini_path = backend_root / "alembic.ini"
        if not alembic_ini_path.exists():
           raise FileNotFoundError(f"Alembic config file not found: {alembic_ini_path}")
        
        config = Config(str(alembic_ini_path))

        # Explicitly set script location
        config.set_main_option("script_location", str(backend_root / "alembic"))

        # Inject DB URL dynamically
        db_url = settings.DATABASE_URL
        if not db_url:
            raise RuntimeError("DATABASE_URL not set.")
        config.set_main_option("sqlalchemy.url", db_url)

        # Log
        logger.info("[+] Running database migrations... ")

        # Run command
        command.upgrade(config, "head")
        
        
        # Log
        logger.info("[+] Database migrations completed successfully")
        if lifecycle:
            lifecycle.mark_db_ready()

    except Exception as exc:
        logger.exception("[-] Failed to apply database migrations: %s", exc)
        if lifecycle:
            lifecycle.set_state(AppState.FAILED)
        raise
