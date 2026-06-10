from contextlib import asynccontextmanager
from fastapi import FastAPI
import logging

# from app.infrastructure.database.initialize_db import run_migrations_blocking
from app.infrastructure.scripts.superuser_seeder import seed_superuser
from app.infrastructure.database.db_setup import SessionLocal
from app.core.app_cycle_manger import LifecycleManager
from app.infrastructure.email.email_service.verification_recovery import run_verification_recovery_loop
from app.infrastructure.database.models.enums import AppState
from .config import settings

logger = logging.getLogger(__name__)

@asynccontextmanager
async def app_lifespan(app: FastAPI):
    lifecycle = LifecycleManager()
    app.state.lifecycle = lifecycle   # Make it accessible if needed

    try:
        logger.info("[lifespan] Starting application...")

        lifecycle.set_state(AppState.CONFIG_VALIDATED)
        settings.validate_security()


        # Moved migrations to cli
        # === Migrations ===
        if settings.STARTUP_RUN_MIGRATIONS:
            # logger.info("[lifespan] Running database migrations...")
            # run_migrations_blocking(lifecycle=lifecycle)   # Still blocking but now clearer
            pass
        else:
            logger.warning("[lifespan] Migrations skipped")

        # === Seeding ===
        lifecycle.set_state(AppState.SEEDING_STARTED)
        
        try:
            logger.info("[lifespan] Seeding superuser...")
            async with SessionLocal() as db:
                  await seed_superuser(db)
            logger.info("[lifespan] Seeding completed successfully")
        finally:
           await db.close()

        lifecycle.set_state(AppState.SEEDING_COMPLETE)
       
        # === Background services ===
        logger.info("[Background] Email service started.")
        if settings.EMAIL_RECOVERY_ENABLED:
            app.state.email_recovery_task = lifecycle.create_task(
                run_verification_recovery_loop(
                    lifecycle.shutdown_event,
                    lifecycle.db_ready,
                ),
                name="email_recovery_loop"
            )

        lifecycle.set_state(AppState.RUNNING)
        logger.info("[lifespan] Application startup complete. Ready to accept requests.")

        yield   # ← Server runs here

    except Exception as exc:
        logger.exception("[lifespan] Startup failed")
        lifecycle.set_state(AppState.FAILED)
        raise
    finally:
        logger.info("[lifespan] Shutting down...")
        await lifecycle.shutdown()