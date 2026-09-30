from __future__ import annotations

import logging
import time
import uuid
from functools import partial
import asyncio

import anyio
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


from app.core.config import settings
from app.modules.shared.dependencies import get_redis
from app.modules.security.dependencies import (
    _get_abuse_protection,
    alert_thresholds,
    resolve_optional_user,
)
from app.modules.security.application.services.audit_service import AuditService
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.infrastructure.database.db_setup import SessionLocal

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    _SKIP_PREFIXES = ("/docs", "/openapi", "/redoc", "/favicon.ico")

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        started_at = time.perf_counter()
        status_code = 500
        request_exception: Exception | None = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as exc:
            request_exception = exc
            status_code = 500
            raise
        finally:
        
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            # Resolve the client IP once, through the same helper the rate
            # limiters use, so audit records show the address that was actually
            # enforced against rather than the proxy's.
            client_ip = _get_abuse_protection(get_redis()).get_client_ip(request) or "-"
            path_with_query = request.url.path
            if request.url.query:
                path_with_query = f"{path_with_query}?{request.url.query}"

            # Keep request details available for deep debugging without duplicating access logs.
            logger.debug(
                "http_request method=%s path=%s status=%s duration_ms=%d client_ip=%s request_id=%s",
                request.method,
                path_with_query,
                status_code,
                duration_ms,
                client_ip,
                request_id,
            )

            # Log server errors with full traceback.
            if status_code >= 500 and request_exception is not None:
                logger.exception(
                    "Unhandled server error on %s %s [request_id=%s]",
                    request.method,
                    request.url.path,
                    request_id,
                    exc_info=request_exception,
                )

            # Audit DB logging is separate; skip non-API paths.
            if settings.AUDIT_ENABLED and not self._should_skip(request.url.path):
                actor_user_id = getattr(request.state, "audit_actor_user_id", None)
                if actor_user_id is None:
                    try:
                        async with SessionLocal() as audit_session:
                            maybe_user = await resolve_optional_user(
                                request, UnitOfWork(session=audit_session)
                            )
                        actor_user_id = str(maybe_user.user_id) if maybe_user else None
                    except Exception as exc:
                        # Attribution is best-effort; never fail a request over it.
                        logger.debug("Audit actor resolution failed: %s", exc)
                        actor_user_id = None

                event_type = self._classify_event_type(request.url.path, status_code)
                ip_address = client_ip
                user_agent = request.headers.get("user-agent")

            

                try:
                    # Log event in a background task
                    asyncio.create_task(self._log_audit_event(
                             event_type=event_type,
                             actor_user_id=actor_user_id,
                             method=request.method,
                             path=request.url.path[:255],
                             status_code=status_code,
                             ip_address=ip_address,
                             user_agent=user_agent,
                             request_id=request_id,
                             metadata={"duration_ms": duration_ms},
                    ))
                
                except Exception as exc:
                    logger.exception("Audit middleware failed to log event: %s", exc)

    def _should_skip(self, path: str) -> bool:
        if not path.startswith("/api/"):
            return True
        return path.startswith(self._SKIP_PREFIXES)

    async def _log_audit_event(self, **event_data) -> None:
        db =  SessionLocal()
        try:
            # Thresholds come from the composition root, as they do on the
            # request path. This task builds its service by hand because it owns
            # its own session and outlives the request that spawned it.
            service = AuditService(
                uow=UnitOfWork(session=db),
                thresholds=alert_thresholds,
            )
            await service.log_audit_event(**event_data)
        finally:
            await db.close()

    def _classify_event_type(self, path: str, status_code: int) -> str:
        if path == "/api/v1/auth/login":
            return "auth.login.failed" if status_code >= 400 else "auth.login.success"
        if status_code == 403:
            return "auth.access.denied"
        return "http.request"
