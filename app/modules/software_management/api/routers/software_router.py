from pathlib import Path
from uuid import UUID

from fastapi.concurrency import run_in_threadpool
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import RedirectResponse, StreamingResponse

from app.modules.shared.dependencies import (
    CurrentUser,
    get_category_service,
    get_current_user,
    get_download_service,
    get_signer,
    get_software_service,
    get_storage,
    require_role,
)
from app.modules.software_management.domain.exceptions import SoftwareDomainError
from app.modules.shared.enums import SoftwareVisibility
from app.modules.software_management.schema.software_schema import (
    SoftwareRead,
    SoftwareSummary,
    SoftwareUploadResponse,
    SoftwareVersionRead,
)
from app.modules.software_management.domain.value_objects import OwnedSoftwareCard 
from app.modules.shared.mappers import _software_item, _version_item, _error
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.application.services.search_service import SearchService
from app.infrastructure.storage.local_storage import DownloadUrlSigner, Storage, StorageFileNotFoundError, StorageSecurityError, StorageUnavailableError

router = APIRouter(prefix="/api/v1/software-management", tags=["software-management"])



# List softwares for a user
@router.get("", response_model=tuple[list[OwnedSoftwareCard], int])
async def list_software(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> tuple[list[OwnedSoftwareCard], int]:
    user_id = current_user.user_id
    items, _ = await service.list_visible(user_id=user_id, limit=limit)
     
    return items, _


@router.post("/upload", response_model=SoftwareUploadResponse, status_code=status.HTTP_201_CREATED)
# Upload software package
async def upload_software_package(
    category_id: UUID = Form(...),
    software_name: str = Form(...),
    software_description: str = Form(...),
    version: str = Form("1.0.0"),
    visibility: SoftwareVisibility = Form(SoftwareVisibility.PUBLIC),
    price_cents: int = Form(0),
    currency: str = Form("KES"),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareUploadResponse:
    
    uploaded = await service.spool_file(file.file, file.filename or "package.bin")
    try:
        software, created_version = await service.upload_package(
            user_id=current_user.user_id,
            category_id=category_id,
            name=software_name,
            description=software_description,
            version_number=version,
            visibility=SoftwareVisibility(visibility),
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




@router.get("/{software_id}/versions")
# List versions
async def list_versions(
    software_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    service: SoftwareService = Depends(get_software_service),
    _current_user: CurrentUser = Depends(get_current_user),
):
    try:
        software = await service.list_versions(
            software_id=software_id, 
            user_id=_current_user.user_id,
            limit=limit,
            )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return software


@router.post("/{software_id}/versions/upload", response_model=SoftwareVersionRead, status_code=status.HTTP_201_CREATED)
async def upload_version(
    software_id: UUID,
    version: str = Form(...),
    release_notes: str = Form(""),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareVersionRead:
    uploaded = await service.spool_file(file.file, file.filename or "package.bin")
    try:
        created_version = await service.upload_version(
            software_id=software_id,
            user_id=current_user.user_id,
            version_number=version,
            release_notes=release_notes,
            uploaded=uploaded,
            content_type=file.content_type,
            is_admin=str(current_user.role).upper() == "ADMIN",
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
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    try:
        await service.deprecate_version(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
            is_admin=str(current_user.role).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return {"status": "deprecated", "version": version}

# Revoke a version
@router.post("/{software_id}/versions/{version}/revoke", status_code=status.HTTP_202_ACCEPTED)
async def revoke_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    try:
        await service.revoke_version(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
            is_admin=str(current_user.role).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return {"status": "revoked", "version": version}


@router.get("/{software_id}/versions/{version}/download")
async def download_version(
    software_id: UUID,
    version: str,
    service: DownloadService = Depends(get_download_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> RedirectResponse:
    try:
        url = await service.create_download_url(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return RedirectResponse(url=url.url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)



# Search endpoint
@router.get("/search")
async def search(
    q: str | None = Query(None, alias="q"),
    category: str | None = Query(None, alias="category"),
    tags: str | None = Query(None, alias="tags"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    service: SoftwareService = Depends(get_software_service),
    category_service = Depends(get_category_service),
) -> dict:
    """Search packages with optional category slug and comma-separated tags.

    Returns items (software read dicts), scores, total, limit, offset.
    """
    # parse tags
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    # resolve category name to id
    category_id = None
    if category:
        try:
            category_obj = await category_service.find_by_name(category)
        except Exception:
            category_obj = None
        if category_obj:
            category_id = category_obj.id

    search_service = SearchService(repository=service.repository)
    try:
        results, total = await search_service.search(q, category_id=category_id, tags=tag_list, limit=limit, offset=offset)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    items = [
        _software_item(r.software, viewer_user_id=r.software.owner_id)
        .model_copy(update={"viewer_has_access": r.software.is_public() or r.software.price.amount_cents == 0})
        for r in results
    ]
    scores = [r.score for r in results]

    return {"items": [item.model_dump() for item in items], "scores": scores, "total": total, "limit": limit, "offset": offset}


@router.get("/admin/packages", response_model=list[SoftwareRead])
async def admin_packages(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_software_service),
    admin:CurrentUser = Depends(require_role("ADMIN")),
) -> list[SoftwareRead]:
    user_id = admin.user_id
    items, _ = await service.list_visible(user_id=user_id, limit=limit)
    return [_software_item(item, viewer_user_id=user_id).model_copy(update={"viewer_has_access": True}) for item in items]


@router.get("/admin/summary", response_model=SoftwareSummary)
async def admin_summary(
    service: SoftwareService = Depends(get_software_service),
    admin: CurrentUser = Depends(require_role("ADMIN")),
) -> SoftwareSummary:
    items, _ = await service.list_visible(user_id=admin.user_id, limit=200)
    versions = [version for software in items for version in software.versions]
    return SoftwareSummary(
        total_packages=len(items),
        total_versions=len(versions),
        published_versions=sum(1 for version in versions if version.status.value == "published"),
        total_downloads=sum(version.download_count for version in versions),
    )

@router.get("/storage/download/{storage_key:path}")
async def internal_storage_download(
    storage_key: str,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    download_service: DownloadService = Depends(get_download_service)
) -> StreamingResponse:
    """Stream artifact download with signed URL verification."""
    await download_service.verify_token(
        storage_key=storage_key,
        expires=expires,
        token=token,
        method="GET",
        )
    file_handle = await download_service.read_file(storage_key=storage_key)
    
    # Stream response — FastAPI handles chunking
    filename = Path(storage_key).name or "artifact.bin"
    
    return StreamingResponse(
        content=file_handle,           # BinaryIO — FastAPI reads chunks
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
