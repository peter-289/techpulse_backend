from fastapi import APIRouter, Depends, Query

from app.modules.security.dependencies import CurrentUser, require_role
from app.modules.shared.enums import RoleEnum
from app.modules.software_management.api.presenters import software_item
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.dependencies import get_software_service
from app.modules.software_management.schema.software_schema import SoftwareRead, SoftwareSummary


router = APIRouter(prefix="/api/v1/admin/software", tags=["Admin - Software"])


@router.get("/packages", response_model=list[SoftwareRead])
async def admin_packages(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_software_service),
    admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
) -> list[SoftwareRead]:
    items = await service.list_all(limit=limit)
    return [
        software_item(item, viewer_user_id=admin.user_id).model_copy(update={"viewer_has_access": True})
        for item in items
    ]


@router.get("/summary", response_model=SoftwareSummary)
async def admin_summary(
    service: SoftwareService = Depends(get_software_service),
    _admin: CurrentUser = Depends(require_role(RoleEnum.ADMIN)),
) -> SoftwareSummary:
    items = await service.list_all(limit=200)
    versions = [version for software in items for version in software.versions]
    return SoftwareSummary(
        total_packages=len(items),
        total_versions=len(versions),
        published_versions=sum(1 for version in versions if version.status.value == "published"),
        total_downloads=sum(version.download_count for version in versions),
    )
