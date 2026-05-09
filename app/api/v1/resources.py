from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.security import admin_access, get_current_user
from app.core.unit_of_work import UnitOfWork
from app.database.db_setup import get_db
from app.schemas.resource import ResourceCreate, ResourceRead
from app.services.resource_service import ResourceService

router = APIRouter(prefix="/api/v1/resources", tags=["Resources"])


def get_service(db: Session = Depends(get_db)) -> ResourceService:
    return ResourceService(UnitOfWork(session=db))


@router.get("", response_model=list[ResourceRead], status_code=200)
def list_resources(
    type: str | None = Query(None),
    service: ResourceService = Depends(get_service),
    _user: dict = Depends(get_current_user),
):
    return service.list_resources(type_filter=type)


@router.get("/{slug}", response_model=ResourceRead, status_code=200)
def get_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _user: dict = Depends(get_current_user),
): 
    return service.get_by_slug(slug=slug)


@router.post("", response_model=ResourceRead, status_code=201)
def create_resource(
    payload: ResourceCreate,
    service: ResourceService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    return service.create_resource(payload)


@router.delete("/{slug}", status_code=204)
def delete_resource(
    slug: str,
    service: ResourceService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    service.delete_resource(slug=slug)
    return None

