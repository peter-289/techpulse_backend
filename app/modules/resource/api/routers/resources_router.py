from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.resource.api.presenters import resource_read
from app.modules.resource.application.services.resource_service import ResourceService
from app.modules.resource.schema.resource_schema import ResourceCreate, ResourceRead
from app.modules.shared.dependencies import (
    CurrentUser,
    get_current_user,
    get_db,
    require_role,
)
from app.modules.shared.enums import RoleEnum

router = APIRouter(prefix="/api/v1/resources", tags=["Resources"])


def get_unit_of_work(session: AsyncSession = Depends(get_db)) -> UnitOfWork:
    """Provide a UnitOfWork for the request scope.

    The composition root for this context. It is the only place that names the
    concrete adapter; the service below is typed against
    ``ResourceUnitOfWork`` and never sees it.
    """
    return UnitOfWork(session=session)


def get_service(uow: UnitOfWork = Depends(get_unit_of_work)) -> ResourceService:
    return ResourceService(uow)


@router.get("", response_model=list[ResourceRead], status_code=200)
async def list_resources(
    type: str | None = Query(None),
    service: ResourceService = Depends(get_service),
    _user: CurrentUser = Depends(get_current_user),
):
    return [resource_read(r) for r in await service.list_resources(type_filter=type)]


@router.get("/{slug}", response_model=ResourceRead, status_code=200)
async def get_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _user: CurrentUser = Depends(get_current_user),
):
    return resource_read(await service.get_by_slug(slug=slug))


@router.post("", response_model=ResourceRead, status_code=201)
async def create_resource(
    payload: ResourceCreate,
    service: ResourceService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    return resource_read(
        await service.create_resource(
            title=payload.title,
            slug=payload.slug,
            resource_type=payload.type,
            description=payload.description,
            url=payload.url,
        )
    )


@router.delete("/{slug}", status_code=204)
async def delete_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
):
    await service.delete_resource(slug=slug)
    return None
