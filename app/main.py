import logging
from app.core.logging_setup import configure_logging

# Configure logging
configure_logging()
logger = logging.getLogger(__name__)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path


from app.core.config import settings
from app.exceptions.handlers import register_exception_handlers
from app.modules.security.audit_middleware import AuditMiddleware


from app.modules.user.api.router.user_router import router as user_router
from app.modules.authentication.auth_router import router as auth_router
from app.modules.user.api.router.support_chat_router import router as support_chat_router

from app.modules.resource.api.routers.resources_router import router as resource_router
from app.modules.security.api.router.admin_router import router as admin_router
from app.modules.user.api.router.admin_user_router import router as admin_user_router
from app.modules.software_management.api.routers.software_admin_router import router as software_admin_router
from app.modules.security.api.router.security_router import router as security_router
from app.modules.analytics.analytics_router import router as analytics_router
from app.modules.software_management.api.routers.software_router import router as software_management_router
from app.modules.software_management.api.routers.category_router import router as category_router

from app.core.lifespan import app_lifespan


class IterableFastAPI(FastAPI):
    def __iter__(self):
        return iter(self.routes)


# Initialize app
# No `proxy_headers=` argument here on purpose. FastAPI does not accept it:
# it falls into **extra and is silently discarded (Starlette has no such
# parameter), so passing it only looks like it configures trust without doing
# anything. Whether X-Forwarded-For is believed is decided at the uvicorn
# layer, and docker-entrypoint.sh derives uvicorn's flag from
# settings.TRUST_PROXY_HEADERS so there is exactly one switch. See
# app/modules/security/abuse_protection.py::get_client_ip for the
# application-side half of that decision.
app = IterableFastAPI(
    title="TechPulse Backend",
    description="This is a backend service for Tech pulse web application.",
    version="1.0.0",
    lifespan=app_lifespan,
    # Publishing these exposes the whole route surface, which is a map of the
    # application for anyone who can reach it. Off in production; set
    # SERVE_API_DOCS to override explicitly either way.
    docs_url="/docs" if settings.api_docs_enabled else None,
    redoc_url="/redoc" if settings.api_docs_enabled else None,
    openapi_url="/openapi.json" if settings.api_docs_enabled else None,
)


# Exception handlers
register_exception_handlers(app)


# ---------------------------CORS configuration---------------------------------------------------
# ------------------------------------------------------------------------------------------------
def _normalize_origins(raw_origins: str) -> list[str]:
    normalized: list[str] = []
    for origin in raw_origins.split(","):
        clean = origin.strip().rstrip("/")
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized

# Origins
origins = _normalize_origins(settings.FRONTEND_URL)
# The loopback fallbacks are a development convenience. In production they are
# not added: allow_credentials=True means any origin on this list can make
# authenticated cross-origin calls, and leaving localhost enabled would keep
# a working credentialed channel open to any page a developer happens to have
# open. A production deployment must name its real frontend.
if not settings.is_production:
    for fallback_origin in (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ):
        if fallback_origin not in origins:
            origins.append(fallback_origin)

# Middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditMiddleware, )


# ===========================================================================================
# -------------------- ROUTES ---------------------------------------------------------------
# Root 
@app.get("/")
async def read_root():
    return {
        "message": "Welcome to Tech Pulse web API",
        "status": "Running",
        "documentation": "/docs",
    }

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# Register router
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(support_chat_router)
app.include_router(resource_router)
app.include_router(admin_router)
app.include_router(admin_user_router)
app.include_router(software_admin_router)
app.include_router(security_router)
app.include_router(analytics_router)
app.include_router(software_management_router)
app.include_router(category_router)

# Serve frontend build in production if present
frontend_build = Path(__file__).resolve().parents[2] / "frontend" / "build"
if frontend_build.exists():
    app.mount("/", StaticFiles(directory=frontend_build, html=True), name="frontend")
