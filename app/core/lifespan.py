from contextlib import asynccontextmanager
from fastapi import FastAPI
import logging

from app.core.app_cycle_manger import LifecycleManager
from app.core.config import settings
from app.infrastructure.database.db_setup import SessionLocal
from app.infrastructure.email.email_service.verification_recovery import (
    run_verification_recovery_loop,
)
from app.infrastructure.redis.client import redis_manager
from app.infrastructure.scripts.superuser_seeder import seed_superuser
from app.modules.shared.enums import AppState

logger = logging.getLogger(__name__)


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    lifecycle = LifecycleManager()
    app.state.lifecycle = lifecycle
    app.state.email_recovery_task = None

    try:
        logger.info("[lifespan] Starting application...")

        lifecycle.set_state(AppState.BOOTING)
        lifecycle.set_state(AppState.CONFIG_VALIDATED)
        settings.validate_security()

        lifecycle.set_state(AppState.SEEDING_STARTED)
        logger.info("[lifespan] Seeding superuser...")
        async with SessionLocal() as db:
            await seed_superuser(db)
        logger.info("[lifespan] Seeding completed successfully")
        lifecycle.set_state(AppState.SEEDING_COMPLETE)
        lifecycle.mark_db_ready()

        # Redis is optional; the client falls back to in-memory behavior.
        await redis_manager.connect()

        if settings.EMAIL_RECOVERY_ENABLED:
            logger.info("[lifespan] Starting email recovery loop...")
            app.state.email_recovery_task = lifecycle.create_task(
                run_verification_recovery_loop(
                    lifecycle.shutdown_event,
                    lifecycle.db_ready,
                ),
                name="email_recovery_loop",
            )

        lifecycle.set_state(AppState.SERVICES_READY)
        lifecycle.set_state(AppState.RUNNING)
        logger.info("[lifespan] Application startup complete. Ready to accept requests.")
        yield

    except Exception:
        logger.exception("[lifespan] Startup failed")
        lifecycle.set_state(AppState.FAILED)
        raise
    finally:
        logger.info("[lifespan] Shutting down...")
        await redis_manager.disconnect()
        await lifecycle.shutdown()
