import logging
from app.core.logging_setup import configure_logging

# Configure logging
configure_logging()
logger = logging.getLogger(__name__)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path


from app.exceptions.handlers import register_exception_handlers
from app.core.config import settings
from app.modules.security.audit_middleware import AuditMiddleware


from app.modules.user.user_router import router as user_router
from app.modules.authentication.auth_router import router as auth_router
from app.modules.user.support_chat_router import router as support_chat_router
from app.modules.projects.projects_router import router as project_router
from app.modules.resource.resources_router import router as resource_router
from app.modules.user.admin_router import router as admin_router
from app.modules.analytics.analytics_router import router as analytics_router
from app.modules.software_management.software_router import router as software_management_router
from app.modules.software_management.category.api.category_router import router as category_router
from app.modules.billing.api.purchase_router import router as purchase_router
from app.modules.billing.api.payment_router import router as payment_router

from app.core.lifespan import app_lifespan


# Initialize app
app = FastAPI(
    title="TechPulse Backend",
    description="This is a backend service for Tech pulse web application.",
    version="1.0.0",
    lifespan=app_lifespan,
    proxy_headers=True
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
# origins = _normalize_origins(settings.FRONTEND_URL)
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000"
]

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
app.include_router(project_router)
app.include_router(resource_router)
app.include_router(admin_router)
app.include_router(analytics_router)
app.include_router(software_management_router)
app.include_router(category_router)
app.include_router(purchase_router)
app.include_router(payment_router)

# Serve frontend build in production if present
frontend_build = Path(__file__).resolve().parents[2] / "frontend" / "build"
if frontend_build.exists():
    app.mount("/", StaticFiles(directory=frontend_build, html=True), name="frontend")
