from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.shared.dependencies import (
    CurrentUser,
    get_current_user,
    get_db,
    require_role,
)
from app.modules.shared.enums import RoleEnum
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.resource.resource_schema import ResourceCreate, ResourceRead
from app.modules.resource.resource_service import ResourceService

router = APIRouter(prefix="/api/v1/resources", tags=["Resources"])


def get_service(db: AsyncSession = Depends(get_db)) -> ResourceService:
    return ResourceService(UnitOfWork(session=db))


@router.get("", response_model=list[ResourceRead], status_code=200)
async def list_resources(
    type: str | None = Query(None),
    service: ResourceService = Depends(get_service),
    _user: CurrentUser = Depends(get_current_user),
):
    return await service.list_resources(type_filter=type)


@router.get("/{slug}", response_model=ResourceRead, status_code=200)
async def get_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _user: CurrentUser = Depends(get_current_user),
):
    return await service.get_by_slug(slug=slug)


@router.post("", response_model=ResourceRead, status_code=201)
async def create_resource(
    payload: ResourceCreate,
    service: ResourceService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    return await service.create_resource(payload)


@router.delete("/{slug}", status_code=204)
async def delete_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    await service.delete_resource(slug=slug)
    return None
