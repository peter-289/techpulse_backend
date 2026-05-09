from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.security import admin_access, get_current_user
from app.database.db_setup import get_db
from app.domain.software import Software, Version
from app.domain.software.exceptions import SoftwareAccessDeniedError, SoftwareDomainError, SoftwareNotFoundError
from app.schemas.software import (
    SoftwareCheckoutRead,
    SoftwarePricingUpdate,
    SoftwareRead,
    SoftwareSummary,
    SoftwareUploadResponse,
    SoftwareVersionRead,
)
from app.services.software_service import SoftwareService

router = APIRouter(prefix="/api/v1/software-management", tags=["software-management"])


def get_service(db: Session = Depends(get_db)) -> SoftwareService:
    return SoftwareService(db)


def _category(description: str) -> str:
    for line in (description or "").splitlines():
        if line.lower().startswith("category:"):
            return line.split(":", 1)[1].strip().lower() or "others"
    return "others"


def _software_item(software: Software, *, viewer_user_id: int) -> SoftwareRead:
    latest = software.latest_downloadable()
    viewer = SoftwareService.actor_uuid(viewer_user_id)
    return SoftwareRead(
        id=str(software.id),
        name=software.name,
        description=software.description,
        owner_id=SoftwareService.actor_int(software.owner_id),
        is_public=software.visibility.value == "public",
        price_cents=software.price_cents,
        currency=software.currency,
        viewer_has_access=software.owner_id == viewer or software.price_cents == 0,
        category=_category(software.description),
        latest_version=str(latest.number) if latest else None,
        download_count=sum(version.download_count for version in software.versions),
        created_at=software.created_at.isoformat(),
        updated_at=software.updated_at.isoformat(),
    )


def _version_item(version: Version) -> SoftwareVersionRead:
    artifact = version.artifact
    return SoftwareVersionRead(
        id=str(version.id),
        software_id=str(version.software_id),
        version=str(version.number),
        is_published=version.status.value in {"published", "deprecated"},
        status=version.status.value,
        download_count=version.download_count,
        release_notes=version.release_notes,
        created_at=version.created_at.isoformat(),
        published_at=version.published_at.isoformat() if version.published_at else None,
        file_hash=artifact.sha256 if artifact else None,
        size_bytes=artifact.size_bytes if artifact else None,
        content_type=artifact.mime_type if artifact else None,
        file_name=artifact.filename if artifact else None,
        artifact_status=artifact.status.value if artifact else None,
        quarantine_reason=artifact.quarantine_reason if artifact else None,
    )


def _payment_item(payment) -> SoftwareCheckoutRead:
    return SoftwareCheckoutRead(
        id=payment.id,
        software_id=payment.software_id,
        buyer_id=SoftwareService.actor_int(UUID(payment.buyer_id)),
        owner_id=SoftwareService.actor_int(UUID(payment.owner_id)),
        amount_cents=payment.amount_cents,
        currency=payment.currency,
        status=payment.status,
        provider=payment.provider,
        provider_reference=payment.provider_reference,
        created_at=payment.created_at.isoformat(),
        completed_at=payment.completed_at.isoformat() if payment.completed_at else None,
    )


def _error(exc: SoftwareDomainError) -> HTTPException:
    if isinstance(exc, SoftwareAccessDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, SoftwareNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

# List softwares for a user
@router.get("", response_model=list[SoftwareRead])
def list_software(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> list[SoftwareRead]:
    user_id = int(current_user["user_id"])
    items = service.list_visible(user_id=user_id, limit=limit)
    return [
        _software_item(
            item,
            viewer_user_id=user_id,
        ).model_copy(update={"viewer_has_access": item.price_cents == 0 or item.owner_id == SoftwareService.actor_uuid(user_id) or service.has_purchase(software_id=item.id, user_id=user_id)})
        for item in items
    ]


@router.post("/upload", response_model=SoftwareUploadResponse, status_code=status.HTTP_201_CREATED)
# Upload software package
def upload_software_package(
    software_name: str = Form(...),
    software_description: str = Form(...),
    version: str = Form("1.0.0"),
    is_public: bool = Form(True),
    price_cents: int = Form(0),
    currency: str = Form("USD"),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareUploadResponse:
    
    uploaded = service.spool_file(file.file, file.filename or "package.bin")
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
def update_pricing(
    software_id: UUID,
    payload: SoftwarePricingUpdate,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareRead:
    user_id = int(current_user["user_id"])
    try:
        software = service.update_pricing(
            software_id=software_id,
            user_id=user_id,
            price_cents=payload.price_cents,
            currency=payload.currency,
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _software_item(software, viewer_user_id=user_id).model_copy(update={"viewer_has_access": True})


@router.post("/{software_id}/checkout", response_model=SoftwareCheckoutRead, status_code=status.HTTP_201_CREATED)
def create_checkout(
    software_id: UUID,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareCheckoutRead:
    try:
        payment = service.create_checkout(software_id=software_id, user_id=int(current_user["user_id"]))
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _payment_item(payment)


@router.post("/payments/{payment_id}/confirm", response_model=SoftwareCheckoutRead)
def confirm_checkout(
    payment_id: UUID,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareCheckoutRead:
    try:
        payment = service.confirm_checkout(payment_id=payment_id, user_id=int(current_user["user_id"]))
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return _payment_item(payment)


@router.get("/{software_id}/versions", response_model=list[SoftwareVersionRead])
# List versions
def list_versions(
    software_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    service: SoftwareService = Depends(get_service),
    _current_user: dict = Depends(get_current_user),
) -> list[SoftwareVersionRead]:
    try:
        software = service.get(software_id)
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return [_version_item(item) for item in software.versions[:limit]]


@router.post("/{software_id}/versions/upload", response_model=SoftwareVersionRead, status_code=status.HTTP_201_CREATED)
def upload_version(
    software_id: UUID,
    version: str = Form(...),
    release_notes: str = Form(""),
    file: UploadFile = File(...),
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> SoftwareVersionRead:
    uploaded = service.spool_file(file.file, file.filename or "package.bin")
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
def deprecate_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    try:
        service.deprecate_version(
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
def revoke_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> dict[str, str]:
    try:
        service.revoke_version(
            software_id=software_id,
            version_number=version,
            user_id=int(current_user["user_id"]),
            is_admin=str(current_user.get("role", "")).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return {"status": "revoked", "version": version}


@router.get("/{software_id}/versions/{version}/download")
def download_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
) -> RedirectResponse:
    try:
        url = service.download_url(
            software_id=software_id,
            version_number=version,
            user_id=int(current_user["user_id"]),
        )
    except SoftwareDomainError as exc:
        raise _error(exc) from exc
    return RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/admin/packages", response_model=list[SoftwareRead])
def admin_packages(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_service),
    admin: dict = Depends(admin_access),
) -> list[SoftwareRead]:
    user_id = int(admin["user_id"])
    items = service.list_visible(user_id=user_id, limit=limit)
    return [_software_item(item, viewer_user_id=user_id).model_copy(update={"viewer_has_access": True}) for item in items]


@router.get("/admin/summary", response_model=SoftwareSummary)
def admin_summary(
    service: SoftwareService = Depends(get_service),
    admin: dict = Depends(admin_access),
) -> SoftwareSummary:
    items = service.list_visible(user_id=int(admin["user_id"]), limit=200)
    versions = [version for software in items for version in software.versions]
    return SoftwareSummary(
        total_packages=len(items),
        total_versions=len(versions),
        published_versions=sum(1 for version in versions if version.status.value == "published"),
        total_downloads=sum(version.download_count for version in versions),
    )


@router.get("/storage/download/{storage_key:path}")
def internal_storage_download(
    storage_key: str,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    service: SoftwareService = Depends(get_service),
) -> Response:
    if not service.storage.verify_signed_request(storage_key=storage_key, expires=expires, token=token, method="GET"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired storage signature.")
    try:
        content, content_type = service.storage.read(storage_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored artifact not found.") from exc
    filename = Path(storage_key).name or "artifact.bin"
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
