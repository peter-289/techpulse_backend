from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.shared.dependencies import require_role, get_current_user, get_db
from app.modules.software_management.software import Software, Version
from app.modules.software_management.software.exceptions import SoftwareAccessDeniedError, SoftwareDomainError, SoftwareNotFoundError
from app.modules.software_management.software_schema import (
    SoftwareCheckoutRead,
    SoftwarePricingUpdate,
    SoftwareRead,
    SoftwareSummary,
    SoftwareUploadResponse,
    SoftwareVersionRead,
)
from .software.software import _payment_item, _software_item, _version_item, _error
from app.modules.software_management.software_service import SoftwareService
from app.modules.software_management.search_service import SearchService
from app.infrastructure.database.models.category import CategoryModel
from sqlalchemy import select, func

router = APIRouter(prefix="/api/v1/software-management", tags=["software-management"])


def get_service(db: AsyncSession = Depends(get_db)) -> SoftwareService:
    return SoftwareService(db)



# List softwares for a user
@router.get("", response_model=list[SoftwareRead])
async def list_software(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> list[SoftwareRead]:
    user_id = int(current_user["user_id"])
    items = await service.list_visible(user_id=user_id, limit=limit)
    return [
        _software_item(
            item,
            viewer_user_id=user_id,
        ).model_copy(update={"viewer_has_access": item.price_cents == 0 or item.owner_id == SoftwareService.actor_uuid(user_id) or service.has_purchase(software_id=item.id, user_id=user_id)})
        for item in items
    ]


@router.post("/upload", response_model=SoftwareUploadResponse, status_code=status.HTTP_201_CREATED)
# Upload software package
async def upload_software_package(
    software_name: str = Form(...),
    software_description: str = Form(...),
    version: str = Form("1.0.0"),
    is_public: bool = Form(True),
    price_cents: int = Form(0),
    currency: str = Form("KSH"),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareUploadResponse:
    
    uploaded = await service.spool_file(file.file, file.filename or "package.bin")
    try:
        software, created_version = service.upload_package(
            user_id=int(current_user["user_id"]),
            name=software_name,
            description=software_description,
            version_number=version,
            is_public=is_public,
            price_cents=price_cents,
            currency=currency,
            uploaded=uploaded,
            content_type=file.content_type,
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    finally:
        uploaded.temp_path.unlink(missing_ok=True)

    artifact = created_version.artifact
    return SoftwareUploadResponse(
        id=str(software.id),
        software_id=str(software.id),
        version_id=str(created_version.id),
        version=str(created_version.number),
        size_bytes=artifact.size_bytes if artifact else uploaded.size_bytes,
        sha256=artifact.sha256 if artifact else uploaded.sha256,
    )


@router.patch("/{software_id}/pricing", response_model=SoftwareRead)
async def update_pricing(
    software_id: UUID,
    payload: SoftwarePricingUpdate,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareRead:
    user_id = int(current_user["user_id"])
    try:
        raise NotImplementedError("Method not implemented.")
        """
        software = await service.update_pricing(
            software_id=software_id,
            user_id=user_id,
            price_cents=payload.price_cents,
            currency=payload.currency,
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
        """
        
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _software_item(software, viewer_user_id=user_id).model_copy(update={"viewer_has_access": True})

# NOT YET IMPLEMENTED
@router.post("/{software_id}/checkout", response_model=SoftwareCheckoutRead, status_code=status.HTTP_201_CREATED)
async def create_checkout(
    software_id: UUID,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareCheckoutRead:
    try:
        raise NotImplementedError("Method not implemented.")
        #payment = await service.create_checkout(software_id=software_id, user_id=int(current_user["user_id"]))
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _payment_item(payment)


@router.post("/payments/{payment_id}/confirm", response_model=SoftwareCheckoutRead)
async def confirm_checkout(
    payment_id: UUID,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareCheckoutRead:
    try:
        payment = await service.confirm_checkout(payment_id=payment_id, user_id=int(current_user["user_id"]))
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _payment_item(payment)


@router.get("/{software_id}/versions", response_model=list[SoftwareVersionRead])
# List versions
async def list_versions(
    software_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    service: SoftwareService = Depends(get_service),
    _current_user: dict = Depends(get_current_user),
) -> list[SoftwareVersionRead]:
    try:
        software = await service.get(software_id)
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return [_version_item(item) for item in software.versions[:limit]]


@router.post("/{software_id}/versions/upload", response_model=SoftwareVersionRead, status_code=status.HTTP_201_CREATED)
async def upload_version(
    software_id: UUID,
    version: str = Form(...),
    release_notes: str = Form(""),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareVersionRead:
    uploaded = await service.spool_file(file.file, file.filename or "package.bin")
    try:
        created_version = service.upload_version(
            software_id=software_id,
            user_id=int(current_user["user_id"]),
            version_number=version,
            release_notes=release_notes,
            uploaded=uploaded,
            content_type=file.content_type,
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    finally:
        uploaded.temp_path.unlink(missing_ok=True)
    return _version_item(created_version)

# Deprecate a software version
@router.post("/{software_id}/versions/{version}/deprecate", status_code=status.HTTP_202_ACCEPTED)
async def deprecate_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    try:
        await service.deprecate_version(
            software_id=software_id,
            version_number=version,
            user_id=int(current_user["user_id"]),
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return {"status": "deprecated", "version": version}

# Revoke a version
@router.post("/{software_id}/versions/{version}/revoke", status_code=status.HTTP_202_ACCEPTED)
async def revoke_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    try:
        await service.revoke_version(
            software_id=software_id,
            version_number=version,
            user_id=int(current_user["user_id"]),
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return {"status": "revoked", "version": version}


@router.get("/{software_id}/versions/{version}/download")
async def download_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> RedirectResponse:
    try:
        url = await service.download_url(
            software_id=software_id,
            version_number=version,
            user_id=int(current_user["user_id"]),
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)



# Search endpoint
@router.get("/search")
async def search(
    q: str | None = Query(None, alias="q"),
    category: str | None = Query(None, alias="category"),
    tags: str | None = Query(None, alias="tags"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    service: SoftwareService = Depends(get_service),
) -> dict:
    """Search packages with optional category slug and comma-separated tags.

    Returns items (software read dicts), scores, total, limit, offset.
    """
    # parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    # resolve category slug to id
    category_id = None
    if category:
        stmt = select(CategoryModel.id).where(func.lower(CategoryModel.slug) == category.lower())
        cid = await service.session.scalar(stmt)
        if cid:
            category_id = cid

    search_service = SearchService(repository=service.repository)
    try:
        results, total = await search_service.search(q, category_id=category_id, tags=tag_list, limit=limit, offset=offset)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    items = [
        _software_item(r.software, viewer_user_id=int((service.actor_int(r.software.owner_id))))
        .model_copy(update={"viewer_has_access": r.software.price_cents == 0 or r.software.owner_id == service.actor_uuid(0)})
        for r in results
    ]
    scores = [r.score for r in results]

    return {"items": [item.model_dump() for item in items], "scores": scores, "total": total, "limit": limit, "offset": offset}


@router.get("/admin/packages", response_model=list[SoftwareRead])
async def admin_packages(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_service),
    admin: dict = Depends(require_role("ADMIN")),
) -> list[SoftwareRead]:
    user_id = int(admin["user_id"])
    items = await service.list_visible(user_id=user_id, limit=limit)
    return [_software_item(item, viewer_user_id=user_id).model_copy(update={"viewer_has_access": True}) for item in items]


@router.get("/admin/summary", response_model=SoftwareSummary)
async def admin_summary(
    service: SoftwareService = Depends(get_service),
    admin: dict = Depends(require_role("ADMIN")),
) -> SoftwareSummary:
    items = await service.list_visible(user_id=int(admin["user_id"]), limit=200)
    versions = [version for software in items for version in software.versions]
    return SoftwareSummary(
        total_packages=len(items),
        total_versions=len(versions),
        published_versions=sum(1 for version in versions if version.status.value == "published"),
        total_downloads=sum(version.download_count for version in versions),
    )

# Download from local storage.
@router.get("/storage/download/{storage_key:path}")
async def internal_storage_download(
    storage_key: str,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    service: SoftwareService = Depends(get_service),
) -> Response:
    if not service.storage.verify_signed_request(storage_key=storage_key, expires=expires, token=token, method="GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired storage signature.")
    try:
        content, content_type = await service.storage.read(storage_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored artifact not found.") from exc
    filename = Path(storage_key).name or "artifact.bin"
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
