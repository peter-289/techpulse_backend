from __future__ import annotations

import threading
import time
from typing import Any, AsyncIterator, Callable
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from software_management.application.dtos import (
    DeleteSoftwareInput,
    DeprecateVersionInput,
    DownloadSoftwareInput,
    ListAdminSoftwareInput,
    ListSoftwareInput,
    ListVersionsInput,
    PublishVersionInput,
    RevokeVersionInput,
    UploadSoftwareInput,
)
from software_management.application.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from software_management.application.use_cases import (
    DeleteSoftware,
    DeprecateVersion,
    DownloadSoftware,
    GetAdminSummary,
    ListAdminSoftware,
    ListSoftware,
    ListVersions,
    PublishVersion,
    RevokeVersion,
    UploadSoftware,
)

from .schemas import (
    AdminSoftwareResponse,
    AdminSummaryResponse,
    DeleteSoftwareResponse,
    DeprecateVersionResponse,
    PublishVersionResponse,
    RevokeVersionResponse,
    SoftwareListResponse,
    UploadSoftwareResponse,
    VersionListResponse,
)


def _raise_http_error(exc: Exception) -> None:
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, ValidationError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    if isinstance(exc, ConflictError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, ForbiddenError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, NotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="internal server error")


def _assert_admin(current_actor: dict) -> None:
    if str(current_actor.get("role", "")).upper() != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin access required")


def create_router(
    *,
    upload_software: UploadSoftware,
    publish_version: PublishVersion,
    deprecate_version: DeprecateVersion,
    revoke_version: RevokeVersion,
    download_software: DownloadSoftware,
    delete_software: DeleteSoftware,
    list_software: ListSoftware,
    list_versions: ListVersions,
    get_admin_summary: GetAdminSummary,
    list_admin_software: ListAdminSoftware,
    current_actor_dependency: Callable[..., Any],
    upload_chunk_size: int,
    upload_max_size_bytes: int | None,
    upload_rate_limit: int,
    upload_rate_window_seconds: int,
    download_rate_limit: int,
    download_rate_window_seconds: int,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/software-management", tags=["Software Management"])
    rate_buckets: dict[str, tuple[int, int]] = {}
    rate_lock = threading.Lock()

    def _enforce_rate_limit(
        *,
        request: Request,
        scope: str,
        actor_id: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        if limit <= 0 or window_seconds <= 0:
            return
        ip_address = request.client.host if request and request.client else "unknown"
        bucket = f"{scope}:{ip_address}:{actor_id}"
        now = int(time.time())
        with rate_lock:
            count, reset_at = rate_buckets.get(bucket, (0, now + window_seconds))
            if now >= reset_at:
                count = 0
                reset_at = now + window_seconds
            count += 1
            rate_buckets[bucket] = (count, reset_at)
            retry_after = max(1, reset_at - now)
        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    async def _upload_stream(file: UploadFile) -> AsyncIterator[bytes]:
        total_read = 0
        while True:
            chunk = await file.read(upload_chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            if upload_max_size_bytes is not None and total_read > upload_max_size_bytes:
                raise ValidationError("upload exceeds maximum allowed size")
            yield chunk

    @router.post("/upload", response_model=UploadSoftwareResponse, status_code=status.HTTP_201_CREATED)
    async def upload_endpoint(
        request: Request,
        software_name: str = Form(..., min_length=1, max_length=150),
        software_description: str = Form("", max_length=5000),
        version: str = Form(..., min_length=1, max_length=64),
        is_public: bool = Form(True),
        publish_now: bool = Form(False),
        software_id: UUID | None = Form(default=None),
        file: UploadFile = File(...),
        if_match_row_version: int | None = Header(default=None, alias="If-Match-Row-Version"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        artifact_hash: str | None = Header(default=None, alias="X-Artifact-Hash"),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> UploadSoftwareResponse:
        try:
            actor_id = str(current_actor["user_id"])
            _enforce_rate_limit(
                request=request,
                scope="sms_upload",
                actor_id=actor_id,
                limit=upload_rate_limit,
                window_seconds=upload_rate_window_seconds,
            )
            output = await upload_software.execute(
                UploadSoftwareInput(
                    actor_id=actor_id,
                    software_name=software_name.strip(),
                    software_description=software_description.strip(),
                    version=version.strip(),
                    file_name=file.filename or "artifact.bin",
                    content_type=file.content_type or "application/octet-stream",
                    stream=_upload_stream(file),
                    is_public=is_public,
                    software_id=software_id,
                    publish_now=publish_now,
                    expected_software_row_version=if_match_row_version,
                    idempotency_key=idempotency_key,
                    expected_file_hash=artifact_hash,
                )
            )
            return UploadSoftwareResponse.model_validate(output)
        except Exception as exc:
            _raise_http_error(exc)

    @router.get("", response_model=list[SoftwareListResponse], status_code=status.HTTP_200_OK)
    async def list_software_endpoint(
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=300),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> list[SoftwareListResponse]:
        try:
            items = await list_software.execute(
                ListSoftwareInput(
                    actor_id=str(current_actor["user_id"]),
                    offset=offset,
                    limit=limit,
                )
            )
            return [SoftwareListResponse.model_validate(item) for item in items]
        except Exception as exc:
            _raise_http_error(exc)

    @router.get("/{software_id}/versions", response_model=list[VersionListResponse], status_code=status.HTTP_200_OK)
    async def list_versions_endpoint(
        software_id: UUID,
        limit: int = Query(20, ge=1, le=100),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> list[VersionListResponse]:
        try:
            items = await list_versions.execute(
                ListVersionsInput(
                    actor_id=str(current_actor["user_id"]),
                    software_id=software_id,
                    limit=limit,
                )
            )
            return [VersionListResponse.model_validate(item) for item in items]
        except Exception as exc:
            _raise_http_error(exc)

    @router.post(
        "/{software_id}/versions/{version}/publish",
        response_model=PublishVersionResponse,
        status_code=status.HTTP_200_OK,
    )
    async def publish_endpoint(
        software_id: UUID,
        version: str,
        if_match_row_version: int | None = Header(default=None, alias="If-Match-Row-Version"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> PublishVersionResponse:
        try:
            output = await publish_version.execute(
                PublishVersionInput(
                    actor_id=str(current_actor["user_id"]),
                    software_id=software_id,
                    version=version.strip(),
                    expected_software_row_version=if_match_row_version,
                    idempotency_key=idempotency_key,
                )
            )
            return PublishVersionResponse.model_validate(output)
        except Exception as exc:
            _raise_http_error(exc)

    @router.post(
        "/{software_id}/versions/{version}/deprecate",
        response_model=DeprecateVersionResponse,
        status_code=status.HTTP_200_OK,
    )
    async def deprecate_endpoint(
        software_id: UUID,
        version: str,
        if_match_row_version: int | None = Header(default=None, alias="If-Match-Row-Version"),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> DeprecateVersionResponse:
        try:
            output = await deprecate_version.execute(
                DeprecateVersionInput(
                    actor_id=str(current_actor["user_id"]),
                    software_id=software_id,
                    version=version.strip(),
                    expected_software_row_version=if_match_row_version,
                )
            )
            return DeprecateVersionResponse.model_validate(output)
        except Exception as exc:
            _raise_http_error(exc)

    @router.post(
        "/{software_id}/versions/{version}/revoke",
        response_model=RevokeVersionResponse,
        status_code=status.HTTP_200_OK,
    )
    async def revoke_endpoint(
        software_id: UUID,
        version: str,
        if_match_row_version: int | None = Header(default=None, alias="If-Match-Row-Version"),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> RevokeVersionResponse:
        try:
            output = await revoke_version.execute(
                RevokeVersionInput(
                    actor_id=str(current_actor["user_id"]),
                    software_id=software_id,
                    version=version.strip(),
                    expected_software_row_version=if_match_row_version,
                    idempotency_key=idempotency_key,
                )
            )
            return RevokeVersionResponse.model_validate(output)
        except Exception as exc:
            _raise_http_error(exc)

    @router.get("/{software_id}/versions/{version}/download", status_code=status.HTTP_200_OK)
    async def download_endpoint(
        request: Request,
        software_id: UUID,
        version: str,
        current_actor: dict = Depends(current_actor_dependency),
    ) -> StreamingResponse:
        try:
            actor_id = str(current_actor["user_id"])
            _enforce_rate_limit(
                request=request,
                scope="sms_download",
                actor_id=actor_id,
                limit=download_rate_limit,
                window_seconds=download_rate_window_seconds,
            )
            output = await download_software.execute(
                DownloadSoftwareInput(
                    actor_id=actor_id,
                    software_id=software_id,
                    version=version.strip(),
                )
            )
            response = StreamingResponse(output.stream, media_type=output.content_type)
            response.headers["Content-Length"] = str(output.size_bytes)
            response.headers["ETag"] = output.file_hash
            response.headers["Content-Disposition"] = f'attachment; filename="{output.file_name}"'
            return response
        except Exception as exc:
            _raise_http_error(exc)

    @router.delete(
        "/{software_id}",
        response_model=DeleteSoftwareResponse,
        status_code=status.HTTP_200_OK,
    )
    async def delete_endpoint(
        software_id: UUID,
        if_match_row_version: int | None = Header(default=None, alias="If-Match-Row-Version"),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> DeleteSoftwareResponse:
        try:
            output = await delete_software.execute(
                DeleteSoftwareInput(
                    actor_id=str(current_actor["user_id"]),
                    software_id=software_id,
                    expected_software_row_version=if_match_row_version,
                )
            )
            return DeleteSoftwareResponse.model_validate(output)
        except Exception as exc:
            _raise_http_error(exc)

    @router.get("/admin/summary", response_model=AdminSummaryResponse, status_code=status.HTTP_200_OK)
    async def admin_summary_endpoint(
        current_actor: dict = Depends(current_actor_dependency),
    ) -> AdminSummaryResponse:
        _assert_admin(current_actor)
        output = await get_admin_summary.execute()
        return AdminSummaryResponse.model_validate(output)

    @router.get("/admin/packages", response_model=list[AdminSoftwareResponse], status_code=status.HTTP_200_OK)
    async def admin_packages_endpoint(
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=300),
        current_actor: dict = Depends(current_actor_dependency),
    ) -> list[AdminSoftwareResponse]:
        _assert_admin(current_actor)
        items = await list_admin_software.execute(ListAdminSoftwareInput(offset=offset, limit=limit))
        return [AdminSoftwareResponse.model_validate(item) for item in items]

    return router
