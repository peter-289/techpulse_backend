from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.orm import Session
import logging

from app.schemas.user import UserCreate, UserResponse, UserRead
from app.services.user_service import UserService
from app.core.unit_of_work import UnitOfWork
from app.database.db_setup import get_db
from app.services.auth_service import AuthService
from app.core.security import admin_access, get_current_user

from app.exceptions.exceptions import DomainError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["Users"]
)


# Get User Service
def get_service(db: Session = Depends(get_db))->UserService:
    uow = UnitOfWork(session=db)
    return UserService(uow=uow)

def get_auth_service(db: Session=Depends(get_db))->AuthService:
    uow = UnitOfWork(session=db)
    return AuthService(uow)

# Registration route
@router.post("/users", response_model=UserResponse, status_code=201)
def register_user(
    payload: UserCreate,
    background_tasks: BackgroundTasks,
    service: UserService = Depends(get_service),
    auth_service: AuthService = Depends(get_auth_service)
    ):
    user = service.create_user(payload)
    try:
        # auth_service.enqueue_verification_email(background_tasks, payload=user)
        pass
        logger.info("User registered successfully", extra={"user_id": user.id, "email": user.email})
        logger.warning("Email verification is currently disabled, skipping email queueing", extra={"user_id": user.id})
    except DomainError as exc:
        logger.warning("Failed to queue verification email", extra={"user_id": user.id, "error": str(exc)})
    return user


# Get my profile 
@router.get("/users/me", response_model=UserRead, status_code=200)
def get_my_profile(
    service: UserService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]
    return service.get_user_by_id(user_id=user_id)


# List users
@router.get("/users", response_model=list[UserRead], status_code=200)
def list_users(
    cursor: int | None = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=200),
    service: UserService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    return service.list_users(cursor=cursor, limit=limit)

# Get user by id
@router.get("/users/{user_id}", response_model=UserRead, status_code=200)
def get_user(
    user_id: int,
    service: UserService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    return service.get_user_by_id(user_id=user_id)

