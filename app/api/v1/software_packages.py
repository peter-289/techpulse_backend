from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import AsyncIterator

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import admin_access, get_current_user
from app.core.unit_of_work import UnitOfWork
from app.database.db_setup import get_db
from app.infrastructure.storage.local_fs import LocalFileSystemStorage
from app.infrastructure.storage.object_storage import ObjectStorageBackend
from app.schemas.software_package import (
    SoftwarePackageAdminItemRead,
    SoftwarePackageAdminSummaryRead,
    FileVersionRead,
    SoftwarePackageRead,
    UploadAppendResponse,
    UploadCompleteResponse,
    UploadSessionInitRequest,
    UploadSessionInitResponse,
)
from app.services.software_package_service import SoftwarePackageService

router = APIRouter(prefix="/api/v1/software-packages", tags=["Software Packages"])


def _build_storage_backend():
    if settings.PACKAGE_STORAGE_BACKEND == "local":
        return LocalFileSystemStorage(Path(settings.UPLOAD_ROOT) / "software_packages")
    if settings.PACKAGE_STORAGE_BACKEND == "object":
        return ObjectStorageBackend()
    raise RuntimeError(f"Unsupported PACKAGE_STORAGE_BACKEND: {settings.PACKAGE_STORAGE_BACKEND}")


def get_service(db: Session = Depends(get_db)) -> SoftwarePackageService:
    return SoftwarePackageService(
        uow=UnitOfWork(session=db),
        storage=_build_storage_backend(),
    )


def _parse_range(range_header: str | None, total_size: int) -> tuple[int, int] | None:
    if not range_header:
        return None
    if not range_header.startswith("bytes="):
        raise ValueError("Invalid Range header")
    raw = range_header.removeprefix("bytes=").strip()
    if "," in raw:
        raise ValueError("Multiple byte ranges are not supported")
    start_s, sep, end_s = raw.partition("-")
    if sep != "-":
        raise ValueError("Invalid Range header")
    if not start_s and not end_s:
        raise ValueError("Invalid Range header")
    try:
        if start_s:
            start = int(start_s)
            end = int(end_s) if end_s else total_size - 1
        else:
            tail = int(end_s)
            if tail <= 0:
                raise ValueError("Invalid Range suffix")
            start = max(0, total_size - tail)
            end = total_size - 1
    except ValueError as exc:
        raise ValueError("Invalid Range header") from exc
    if start < 0 or end < start or start >= total_size:
        raise ValueError("Requested range is not satisfiable")
    end = min(end, total_size - 1)
    return start, end


async def _upload_file_chunk_stream(upload_file: UploadFile) -> AsyncIterator[bytes]:
    while True:
        chunk = await upload_file.read(settings.PACKAGE_UPLOAD_CHUNK_SIZE_BYTES)
        if not chunk:
            break
        yield chunk


@router.post("", response_model=UploadCompleteResponse, status_code=201)
async def upload_package(
    name: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    language: str = Form(...),
    version: str | None = Form(None),
    is_public: bool = Form(True),
    file: UploadFile = File(...),
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    started = time.perf_counter()
    resolved_version = (version or "").strip() or "v1.0.0"
    upload_id, version_id = await service.upload_single_request(
        user_id=int(current_user["user_id"]),
        package_name=name,
        package_description=description,
        package_category=category,
        package_language=language,
        package_version=resolved_version,
        is_public=is_public,
        file_name=file.filename or "package.bin",
        content_type=file.content_type,
        chunk_stream=_upload_file_chunk_stream(file),
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    logging.info(
        "[software_package_upload] user_id=%s version_id=%s elapsed_ms=%s",
        current_user["user_id"],
        version_id,
        elapsed_ms,
    )
    return UploadCompleteResponse(upload_id=upload_id, file_version_id=version_id)


@router.post("/uploads/init", response_model=UploadSessionInitResponse, status_code=201)
async def init_upload_session(
    payload: UploadSessionInitRequest,
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    initialized = service.init_upload_session(
        user_id=int(current_user["user_id"]),
        package_name=payload.package_name,
        package_description=payload.package_description,
        package_category=payload.package_category,
        package_language=payload.package_language,
        package_version=payload.package_version,
        is_public=payload.is_public,
        file_name=payload.file_name,
        content_type=payload.content_type,
        max_size_bytes=payload.max_size_bytes,
    )
    try:
        await service.storage.init_upload(initialized.upload_id)
    except Exception as exc:
        service.fail_upload_session(
            upload_id=initialized.upload_id,
            user_id=int(current_user["user_id"]),
            error_message="Upload initialization failed",
        )
        raise HTTPException(status_code=500, detail="Unable to initialize upload session") from exc
    return UploadSessionInitResponse(
        upload_id=initialized.upload_id,
        offset=initialized.offset,
        max_size_bytes=initialized.max_size_bytes,
    )


@router.patch("/uploads/{upload_id}", response_model=UploadAppendResponse, status_code=200)
async def append_upload_session_chunk(
    upload_id: str,
    request: Request,
    x_upload_offset: int = Header(..., alias="X-Upload-Offset"),
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    async def _body_stream() -> AsyncIterator[bytes]:
        async for chunk in request.stream():
            if chunk:
                yield chunk

    result = await service.append_upload_stream(
        upload_id=upload_id,
        user_id=int(current_user["user_id"]),
        expected_offset=x_upload_offset,
        chunk_stream=_body_stream(),
    )
    return UploadAppendResponse(upload_id=result.upload_id, offset=result.offset, status=result.status)


@router.post("/uploads/{upload_id}/complete", response_model=UploadCompleteResponse, status_code=200)
async def complete_upload_session(
    upload_id: str,
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    version_id = await service.complete_upload(upload_id=upload_id, user_id=int(current_user["user_id"]))
    return UploadCompleteResponse(upload_id=upload_id, file_version_id=version_id)


@router.delete("/uploads/{upload_id}", status_code=204)
async def cancel_upload_session(
    upload_id: str,
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    await service.cancel_upload(upload_id=upload_id, user_id=int(current_user["user_id"]))
    return None


@router.delete("/{package_id}", status_code=204)
async def delete_software_package(
    package_id: int,
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    await service.delete_package_for_owner(package_id=package_id, user_id=int(current_user["user_id"]))
    return None


@router.get("", response_model=list[SoftwarePackageRead], status_code=200)
def list_software_packages(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    language: str | None = Query(None),
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    return service.list_packages(
        user_id=int(current_user["user_id"]),
        offset=offset,
        limit=limit,
        language=language,
    )


@router.get("/{package_id}/versions", response_model=list[FileVersionRead], status_code=200)
def list_software_package_versions(
    package_id: int,
    limit: int = Query(20, ge=1, le=200),
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    return service.list_package_versions(
        user_id=int(current_user["user_id"]),
        package_id=package_id,
        limit=limit,
    )


@router.get("/admin/summary", response_model=SoftwarePackageAdminSummaryRead, status_code=200)
def software_package_admin_summary(
    service: SoftwarePackageService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    return service.get_admin_summary()


@router.get("/admin/packages", response_model=list[SoftwarePackageAdminItemRead], status_code=200)
def software_package_admin_list(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=300),
    owner_query: str | None = Query(None),
    only_private: bool = Query(False),
    service: SoftwarePackageService = Depends(get_service),
    _admin: dict = Depends(admin_access),
):
    return service.list_packages_admin(
        offset=offset,
        limit=limit,
        owner_query=owner_query,
        only_private=only_private,
    )


@router.get("/{package_id}/versions/{version_id}/download", status_code=200)
async def download_software_package(
    package_id: int,
    version_id: int,
    range_header: str | None = Header(default=None, alias="Range"),
    service: SoftwarePackageService = Depends(get_service),
    current_user: dict = Depends(get_current_user),
):
    started = time.perf_counter()
    ticket = service.get_download_ticket(
        user_id=int(current_user["user_id"]),
        package_id=package_id,
        version_id=version_id,
    )
    size = ticket.file_size_bytes
    try:
        byte_range = _parse_range(range_header, size)
    except ValueError as exc:
        raise HTTPException(status_code=416, detail=str(exc)) from exc
    if byte_range is None:
        start = 0
        end = size - 1
        status_code = 200
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Length": str(size),
            "ETag": ticket.checksum_sha256,
        }
    else:
        start, end = byte_range
        status_code = 206
        content_length = end - start + 1
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Content-Length": str(content_length),
            "ETag": ticket.checksum_sha256,
        }

    async def _stream():
        async for chunk in service.storage.stream_object(
            ticket.storage_key,
            start=start,
            end=end,
            chunk_size=settings.PACKAGE_UPLOAD_CHUNK_SIZE_BYTES,
        ):
            yield chunk
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        logging.info(
            "[software_package_download] user_id=%s package_id=%s version_id=%s elapsed_ms=%s range=%s",
            current_user["user_id"],
            package_id,
            version_id,
            elapsed_ms,
            range_header or "full",
        )

    media_type = ticket.content_type or "application/octet-stream"
    response = StreamingResponse(_stream(), status_code=status_code, media_type=media_type, headers=headers)
    response.headers["Content-Disposition"] = f'attachment; filename="{ticket.file_name}"'
    return response
