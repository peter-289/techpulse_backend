from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import asyncio
import logging

from app.exceptions.handlers import register_exception_handlers
from app.core.config import settings
from app.core.audit_middleware import AuditMiddleware
from app.core.logging_setup import configure_logging
from app.database.db_setup import SessionLocal
from app.database.initialize_db import init_db
from app.services.superuser_seeder import seed_superuser
from app.services.email_service.verification_recovery import run_verification_recovery_loop

from app.api.v1.users import router as user_router
from app.api.v1.auth import router as auth_router
from app.api.v1.support_chat import router as support_chat_router
from app.api.v1.projects import router as project_router
from app.api.v1.resources import router as resource_router
from app.api.v1.software_packages import router as software_package_router
from app.api.v1.admin import router as admin_router
from app.api.v1.analytics import router as analytics_router

configure_logging()
logger = logging.getLogger(__name__)

# Initialize app
app = FastAPI(
    title="Web Application Backend",
    description="This is a backend service for Tech pulse web application.",
    version="1.0.0"
)

# Exception handlers
register_exception_handlers(app)


# CORS configuration
def _normalize_origins(raw_origins: str) -> list[str]:
    normalized: list[str] = []
    for origin in raw_origins.split(","):
        clean = origin.strip().rstrip("/")
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized


origins = _normalize_origins(settings.FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditMiddleware)


# Ensure crucial services are on on startup.
@app.on_event("startup")
async def startup():
      logger.info("[startup] Effective CORS origins: %s", origins or ["http://localhost:3000"])
      settings.validate_security()
      init_db()
      db = SessionLocal()
      try:
          seed_superuser(db)
      finally:
          db.close()
      if settings.EMAIL_RECOVERY_ENABLED:
          app.state.email_recovery_stop_event = asyncio.Event()
          app.state.email_recovery_task = asyncio.create_task(
              run_verification_recovery_loop(app.state.email_recovery_stop_event)
          )
          logging.info("[startup] Verification email recovery loop started.")


@app.on_event("shutdown")
async def shutdown():
    stop_event = getattr(app.state, "email_recovery_stop_event", None)
    recovery_task = getattr(app.state, "email_recovery_task", None)
    if stop_event and recovery_task:
        stop_event.set()
        await recovery_task
        logging.info("[shutdown] Verification email recovery loop stopped.")
     


@app.get("/")
async def read_root():
    return {
        "message": "Welcome to Tech Pulse web API",
        "status": "Running",
        "documentation": "/docs",
    }

# Check if the backend is on
@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# Register router
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(support_chat_router)
app.include_router(project_router)
app.include_router(resource_router)
app.include_router(software_package_router)
app.include_router(admin_router)
app.include_router(analytics_router)

# Serve frontend build in production if present
frontend_build = Path(__file__).resolve().parents[2] / "frontend" / "build"
if frontend_build.exists():
    app.mount("/", StaticFiles(directory=frontend_build, html=True), name="frontend")
