from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.modules.security.dependencies import CurrentUser, require_role
from app.modules.shared.enums import RoleEnum
from app.modules.user.api.router.user_router import get_service
from app.modules.user.application.services.user_service import UserService
from app.modules.user.schema.user_schema import UserRead


router = APIRouter(prefix="/api/v1/admin/users", tags=["Admin - Users"])


@router.get("", response_model=Optional[list[UserRead]])
async def list_users(
    limit: int = Query(100, ge=1, le=200),
    before_id: str | None = Query(None),
    service: UserService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    return await service.list_users(limit=limit, before_id=before_id)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: UUID,
    service: UserService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    return await service.get_user_by_id(user_id=user_id)
