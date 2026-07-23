from __future__ import annotations

from uuid import UUID

import logging
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.shared.dependencies import (
    CurrentUser,
    get_current_user,
    get_db,
    require_role,
)
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.software_management.schema.category_schema import (
    CategoryCreate,
    CategoryPage,
    CategoryResponse,
    CategoryUpdate,
)
from app.modules.software_management.application.services.category_service import (
    CategoryService,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/categories", tags=["categories"])


def get_unit_of_work(session: AsyncSession = Depends(get_db)) -> UnitOfWork:
    """Provide a UnitOfWork for the request scope."""
    uow = UnitOfWork(session=session)
    return uow


def get_category_service(uow: UnitOfWork = Depends(get_unit_of_work)) -> CategoryService:
    """Construct the category application service."""
    return CategoryService(unit_of_work=uow)


@router.post("", response_model=CategoryResponse, status_code=status.HTTP_201_CREATED)
async def create_category(
    payload: CategoryCreate,
    service: CategoryService = Depends(get_category_service),
    admin: CurrentUser = Depends(require_role("ADMIN")),
) -> CategoryResponse:
    """Create a category. Admins only."""
    logger.info("Category create requested by admin=%s", admin.user_id)
    category = await service.create(name=payload.name, description=payload.description)
    logger.info("Category created: id=%s admin=%s", category.id, admin.user_id)
    return CategoryResponse.from_domain(category)


@router.get("", response_model=CategoryPage[CategoryResponse])
async def list_categories(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_deleted: bool = Query(False, description="Include soft-deleted categories."),
    service: CategoryService = Depends(get_category_service),
    _current_user: CurrentUser = Depends(get_current_user),
) -> CategoryPage[CategoryResponse]:
    """List categories with offset pagination."""
    items, total = await service.list_categories(
        limit=limit,
        offset=offset,
        include_deleted=include_deleted,
    )
    responses = [CategoryResponse.from_domain(item) for item in items]
    has_next = offset + limit < total
    has_prev = offset > 0
    return CategoryPage(
        items=responses,
        total=total,
        limit=limit,
        offset=offset,
        has_next=has_next,
        has_prev=has_prev,
    )


@router.get("/{category_id}", response_model=CategoryResponse)
async def get_category(
    category_id: UUID,
    service: CategoryService = Depends(get_category_service),
    _current_user: CurrentUser = Depends(get_current_user),
) -> CategoryResponse:
    """Return a single category by id."""
    category = await service.get(category_id)
    return CategoryResponse.from_domain(category)


@router.patch("/{category_id}", response_model=CategoryResponse)
async def update_category(
    category_id: UUID,
    payload: CategoryUpdate,
    service: CategoryService = Depends(get_category_service),
    admin: CurrentUser = Depends(require_role("ADMIN")),
) -> CategoryResponse:
    """Rename and/or update a category description. Admins only."""
    logger.info("Category update requested: id=%s admin=%s", category_id, admin.user_id)
    if payload.name is not None and payload.description is None:
        category = await service.rename(category_id=category_id, name=payload.name)
    else:
        # Description-only or combined update.
        if payload.name is not None:
            await service.rename(category_id=category_id, name=payload.name)
        category = await service.update_description(
            category_id=category_id, description=payload.description
        )
    logger.info("Category updated: id=%s admin=%s", category_id, admin.user_id)
    return CategoryResponse.from_domain(category)


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_category(
    category_id: UUID,
    service: CategoryService = Depends(get_category_service),
    admin: CurrentUser = Depends(require_role("ADMIN")),
) -> Response:
    """Soft-delete a category. Admins only. Blocked while software is assigned."""
    logger.info("Category delete requested: id=%s admin=%s", category_id, admin.user_id)
    await service.delete(category_id)
    logger.info("Category deleted: id=%s admin=%s", category_id, admin.user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{category_id}/restore", response_model=CategoryResponse)
async def restore_category(
    category_id: UUID,
    service: CategoryService = Depends(get_category_service),
    admin: CurrentUser = Depends(require_role("ADMIN")),
) -> CategoryResponse:
    """Restore a previously soft-deleted category. Admins only."""
    logger.info("Category restore requested: id=%s admin=%s", category_id, admin.user_id)
    category = await service.restore(category_id)
    logger.info("Category restored: id=%s admin=%s", category_id, admin.user_id)
    return CategoryResponse.from_domain(category)
