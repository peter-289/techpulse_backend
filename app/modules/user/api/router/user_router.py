from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from typing import Optional
from uuid import UUID

from ...schema.user_schema import UserCreate, UserResponse, UserRead
from ...application.services.user_service import UserService
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.authentication.auth_service import AuthService
from app.modules.shared.dependencies import get_db
from app.modules.security.dependencies import (
    CurrentUser,
    get_abuse_protection,
    get_current_user,
    require_role,
)
from app.modules.shared.enums import RoleEnum
from app.modules.security.abuse_protection import AbuseProtection

from app.exceptions.exceptions import DomainError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["Users"]
)


# Get User Service
def get_service(
        db: AsyncSession = Depends(get_db), 
        abuse_protection: AbuseProtection = Depends(get_abuse_protection)
        )->UserService:
    uow = UnitOfWork(session=db)
    return UserService(uow=uow, abuse_protection=abuse_protection)

def get_auth_service(
        db: AsyncSession=Depends(get_db),
        abuse_protection: AbuseProtection = Depends(get_abuse_protection)
        )->AuthService:
    uow = UnitOfWork(session=db)
    return AuthService(uow=uow, abuse_protection=abuse_protection)

# Registration route
@router.post("/users", response_model=UserResponse, status_code=201)
async def register_user(
    request: Request,
    payload: UserCreate,
    background_tasks: BackgroundTasks,
    service: UserService = Depends(get_service),
    auth_service: AuthService = Depends(get_auth_service),
    abuse_protection: AbuseProtection = Depends(get_abuse_protection),
):
    # The client IP is read here, at the transport edge. The service used to take
    # the whole ``Request`` and call ``get_client_ip`` itself, which is what
    # pulled FastAPI into the application layer.
    user = await service.create_user(
        full_name=payload.full_name,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        gender=payload.gender,
        client_ip=abuse_protection.get_client_ip(request),
    )
    try:
        auth_service.enqueue_verification_email(background_tasks, payload=user)
        logger.info("User registered successfully", extra={"user_id": user.id, "email": user.email})
        #logger.warning("Email verification is currently disabled, skipping email queueing", extra={"user_id": user.id})
    except DomainError as exc:
        logger.warning("Failed to queue verification email", extra={"user_id": user.id, "error": str(exc)})
    return user


# Get my profile 
@router.get("/users/me", response_model=UserRead, status_code=200)
async def get_my_profile(
    service: UserService = Depends(get_service),
    current_user: CurrentUser = Depends(get_current_user),
):
    user_id = current_user.user_id
    user = await service.get_user_by_id(user_id=user_id)
    return user


# List users
@router.get("/users", response_model=Optional[list[UserRead]], status_code=200)
async def list_users(
    limit: int = Query(100, ge=1, le=200),
    before_id: str | None = Query(
        None,
        description="Keyset cursor: the user id to page before. Use the last id of the previous page.",
    ),
    service: UserService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    return await service.list_users(limit=limit, before_id=before_id)

# Get user by id
@router.get("/users/{user_id}", response_model=UserRead, status_code=200)
async def get_user(
    user_id: UUID,
    service: UserService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    user = await service.get_user_by_id(user_id=user_id)
    return user
