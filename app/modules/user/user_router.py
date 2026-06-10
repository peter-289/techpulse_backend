from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from .user_schema import UserCreate, UserResponse, UserRead
from .user_service import UserService
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.authentication.auth_service import AuthService
from app.modules.shared.dependencies import require_role, get_current_user, get_db

from app.exceptions.exceptions import DomainError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["Users"]
)


# Get User Service
def get_service(db: AsyncSession = Depends(get_db))->UserService:
    uow = UnitOfWork(session=db)
    return UserService(uow=uow)

def get_auth_service(db: AsyncSession=Depends(get_db))->AuthService:
    uow = UnitOfWork(session=db)
    return AuthService(uow)

# Registration route
@router.post("/users", response_model=UserResponse, status_code=201)
async def register_user(
    payload: UserCreate,
    background_tasks: BackgroundTasks,
    service: UserService = Depends(get_service),
    auth_service: AuthService = Depends(get_auth_service)
    ):
 
    user = await service.create_user(payload)
    try:
        auth_service.enqueue_verification_email(background_tasks, payload=user)
        logger.info("User registered successfully", extra={"user_id": user.id, "email": user.email})
        logger.warning("Email verification is currently disabled, skipping email queueing", extra={"user_id": user.id})
    except DomainError as exc:
        logger.warning("Failed to queue verification email", extra={"user_id": user.id, "error": str(exc)})
    return user


# Get my profile 
@router.get("/users/me", response_model=UserRead, status_code=200)
async def get_my_profile(
    service: UserService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]
    user = await service.get_user_by_id(user_id=user_id)
    return user


# List users
@router.get("/users", response_model=list[UserRead], status_code=200)
async def list_users(
    cursor: int | None = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=200),
    service: UserService = Depends(get_service),
    _admin: dict = Depends(require_role("ADMIN")),
):
    users = await service.list_users(cursor=cursor, limit=limit)
    return users

# Get user by id
@router.get("/users/{user_id}", response_model=UserRead, status_code=200)
async def get_user(
    user_id: int,
    service: UserService = Depends(get_service),
    _admin: dict = Depends(require_role("ADMIN")),
):
    user = await service.get_user_by_id(user_id=user_id)
    return user
