from pathlib import Path
import json
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.services.auth_service import AuthService
from app.core.unit_of_work import UnitOfWork
from app.schemas.user import ProfileResponse
from app.database.db_setup import get_db
from app.core.config import settings
from app.core.abuse_protection import abuse_protection

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]

)
logger = logging.getLogger(__name__)

# Get auth service
def get_service(session: Session = Depends(get_db))->AuthService:
    uow = UnitOfWork(session=session)
    return AuthService(uow)

# Rate limiting functionality
def _enforce_rate_limit(
    *,
    request: Request,
    scope: str,
    limit: int,
    window_seconds: int,
    identifier: str | None = None,
) -> None:
    ip_address = request.client.host if request and request.client else "unknown"
    key = f"{ip_address}:{(identifier or '').strip().lower()}"
    limited, retry_after = abuse_protection.hit_rate_limit(
        scope=scope,
        key=key,
        limit=limit,
        window_seconds=window_seconds,
    )
    if limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    access_max_age = settings.LOGIN_TOKEN_EXPIRE_MINUTES * 60
    refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

    response.set_cookie(
        key=settings.ACCESS_COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=access_max_age,
        path=settings.ACCESS_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=refresh_max_age,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )

def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(
        key=settings.ACCESS_COOKIE_NAME,
        path=settings.ACCESS_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )

# Login route
@router.post("/login", response_model=ProfileResponse, status_code=200)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(get_service),
      ):
    username = (form_data.username or "").strip()
    password = form_data.password
    _enforce_rate_limit(
        request=request,
        scope="auth_login",
        limit=settings.AUTH_LOGIN_RATE_LIMIT,
        window_seconds=settings.AUTH_LOGIN_WINDOW_SECONDS,
        identifier=username,
    )

    user, access_token = service.authenticate_user(username, password)
    user_agent = request.headers.get("user-agent") if request else None
    ip_address = request.client.host if request and request.client else None
    refresh_token, _session = service.create_session(
        user_id=user.id,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    request.state.audit_actor_user_id = user.id
    # Set cookies
    _set_auth_cookies(response, access_token, refresh_token)
    logger.info(
        "[auth.login] user_id=%s origin=%s set_cookies=%s secure=%s samesite=%s domain=%s refresh_path=%s",
        user.id,
        request.headers.get("origin"),
        [settings.ACCESS_COOKIE_NAME, settings.REFRESH_COOKIE_NAME],
        settings.COOKIE_SECURE,
        settings.COOKIE_SAMESITE,
        settings.COOKIE_DOMAIN,
        settings.REFRESH_COOKIE_PATH,
    )
    payload = {
        "user_id": user.id,
        "token_type": "bearer",
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
    }
    if settings.EXPOSE_ACCESS_TOKEN_IN_BODY:
        payload["access_token"] = access_token
    return payload

# Logout route
@router.post("/refresh", response_model=ProfileResponse, status_code=200)
def refresh_session(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
):
    _enforce_rate_limit(
        request=request,
        scope="auth_refresh",
        limit=settings.AUTH_REFRESH_RATE_LIMIT,
        window_seconds=settings.AUTH_REFRESH_WINDOW_SECONDS,
    )
    # Get refresh token from cookie
    has_access_cookie = bool(request.cookies.get(settings.ACCESS_COOKIE_NAME)) if request else False
    refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME) if request else None
    logger.info(
        "[auth.refresh] origin=%s has_access_cookie=%s has_refresh_cookie=%s",
        request.headers.get("origin"),
        has_access_cookie,
        bool(refresh_token),
    )
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    user_agent = request.headers.get("user-agent") if request else None
    ip_address = request.client.host if request and request.client else None
    user, access_token, new_refresh = service.rotate_session(
        refresh_token=refresh_token,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    _set_auth_cookies(response, access_token, new_refresh)
    logger.info(
        "[auth.refresh] user_id=%s rotated_refresh_cookie=true",
        user.id,
    )
    payload = {
        "user_id": user.id,
        "token_type": "bearer",
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
    }
    if settings.EXPOSE_ACCESS_TOKEN_IN_BODY:
        payload["access_token"] = access_token
    return payload


# Logout route
@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
):
    refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME) if request else None
    if refresh_token:
        service.revoke_session(refresh_token=refresh_token)
    _clear_auth_cookies(response)
    return None

# Verify route
@router.get("/verify", status_code=200)
def verify_email(
    token: str,
    service: AuthService = Depends(get_service),
):
    service.verify_user_account(token=token)
    return {"message": "Account verified"}


# Email verification page
@router.get("/verify-page", response_class=HTMLResponse, status_code=200)
def verify_page():
    template_path = (
        Path(__file__).resolve().parents[2]
        / "services"
        / "email_service"
        / "templates"
        / "verification_page.html"
    )
    html = template_path.read_text(encoding="utf-8")
    frontend_origins = [origin.strip() for origin in settings.FRONTEND_URL.split(",") if origin.strip()]
    login_base_url = (frontend_origins[0] if frontend_origins else "http://localhost:3000").rstrip("/")
    login_url = f"{login_base_url}/?page=login"
    html = html.replace("__LOGIN_URL_JSON__", json.dumps(login_url))
    return HTMLResponse(content=html)

# Password reset routes
@router.post("/password-reset/requests", status_code=200)
def request_password_reset(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Form(...),
    service: AuthService = Depends(get_service),
):
    # Enforce rate limiting
    _enforce_rate_limit(
        request=request,
        scope="auth_password_reset_request",
        limit=settings.AUTH_PASSWORD_RESET_REQUEST_RATE_LIMIT,
        window_seconds=settings.AUTH_PASSWORD_RESET_REQUEST_WINDOW_SECONDS,
        identifier=email,
    )
    detail = service.request_password_reset(email=email, background_tasks=background_tasks)
    return {"detail": detail}

# Password reset confirmation route
@router.post("/password-reset/confirm", status_code=200)
def confirm_password_reset(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    service: AuthService = Depends(get_service),
):
    _enforce_rate_limit(
        request=request,
        scope="auth_password_reset_confirm",
        limit=settings.AUTH_PASSWORD_RESET_CONFIRM_RATE_LIMIT,
        window_seconds=settings.AUTH_PASSWORD_RESET_CONFIRM_WINDOW_SECONDS,
    )
    service.reset_password(
        token=token,
        new_password=new_password,
        confirm_password=confirm_password,
    )
    return {"detail": "Password reset successful"}

# Password reset page
@router.get("/password-reset/page", response_class=HTMLResponse, status_code=200)
def password_reset_page(token: str):
    template_path = (
        Path(__file__).resolve().parents[2]
        / "services"
        / "email_service"
        / "templates"
        / "password_reset_page.html"
    )
    html = template_path.read_text(encoding="utf-8")
    frontend_origins = [origin.strip() for origin in settings.FRONTEND_URL.split(",") if origin.strip()]
    login_base_url = (frontend_origins[0] if frontend_origins else "http://localhost:3000").rstrip("/")
    login_url = f"{login_base_url}/?page=login"
    html = html.replace("__TOKEN_JSON__", json.dumps(token)).replace(
        "__LOGIN_URL_JSON__", json.dumps(login_url)
    )
    return HTMLResponse(content=html)
