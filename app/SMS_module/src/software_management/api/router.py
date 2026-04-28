from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status

from ..application.commands import (
    AddVersionCommand,
    CreateSoftwareCommand,
    GenerateDownloadLinkQuery,
    ProcessMalwareScanFailedCommand,
    ProcessMalwareScanSuccessCommand,
    PublishVersionCommand,
    RequestArtifactUploadCommand,
)
from ..application.services import DownloadService, SoftwareCommandService
from ..domain.exceptions import (
    AccessDeniedError,
    ConcurrencyError,
    DomainError,
    MalwareScanPendingError,
    NotFoundError,
)
from .dependencies import (
    gatekeeper,
    get_command_service,
    get_current_user_id,
    get_download_service,
    get_internal_storage_test_gateway,
)
from .schemas import (
    AddVersionRequest,
    ArtifactUploadResponse,
    CreateSoftwareRequest,
    DownloadLinkResponse,
    MalwareScanFailedRequest,
    RequestArtifactUploadRequest,
    SoftwareResponse,
    VersionResponse,
)

router = APIRouter(prefix="/software", tags=["software-management"])


def _authorize_internal_storage_access(
    *,
    storage_key: str,
    expires: int,
    token: str,
    method: str,
    gateway,
) -> None:
    if not gateway.verify_signature(
        storage_key=storage_key,
        expires=expires,
        token=token,
        method=method,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired storage signature.",
        )


@router.post("", response_model=SoftwareResponse, status_code=status.HTTP_201_CREATED)
async def create_software(
    payload: CreateSoftwareRequest,
    user_id: UUID = Depends(get_current_user_id),
    service: SoftwareCommandService = Depends(get_command_service),
) -> SoftwareResponse:
    software = await service.create_software(
        CreateSoftwareCommand(
            name=payload.name,
            description=payload.description,
            owner_id=user_id,
            visibility=payload.visibility,
        )
    )
    return SoftwareResponse(software_id=str(software.id))


@router.post("/{software_id}/versions", response_model=VersionResponse)
async def add_version(
    software_id: UUID,
    payload: AddVersionRequest,
    service: SoftwareCommandService = Depends(get_command_service),
) -> VersionResponse:
    version = await service.add_version(
        AddVersionCommand(
            software_id=software_id,
            number=payload.number,
            release_notes=payload.release_notes,
        )
    )
    return VersionResponse(version_id=str(version.id), lock_version=version.lock_version)


@router.post("/{software_id}/versions/{version_id}/artifact", response_model=ArtifactUploadResponse)
async def request_artifact_upload(
    software_id: UUID,
    version_id: UUID,
    payload: RequestArtifactUploadRequest,
    background_tasks: BackgroundTasks,
    service: SoftwareCommandService = Depends(get_command_service),
) -> ArtifactUploadResponse:
    result = await service.request_artifact_upload(
        RequestArtifactUploadCommand(
            software_id=software_id,
            version_id=version_id,
            filename=payload.filename,
            content_type=payload.content_type,
            sha256=payload.sha256,
            size_bytes=payload.size_bytes,
        )
    )

    # No-op task demonstrates non-blocking extension point for telemetry/auditing.
    background_tasks.add_task(lambda: None)

    return ArtifactUploadResponse(
        artifact_id=str(result.artifact_id),
        storage_key=result.storage_key,
        upload_url=result.upload.url,
        upload_fields=result.upload.fields,
        expires_in_seconds=result.upload.expires_in_seconds,
    )


@router.post("/{software_id}/versions/{version_id}/malware/success", status_code=status.HTTP_202_ACCEPTED)
async def malware_success(
    software_id: UUID,
    version_id: UUID,
    artifact_id: UUID = Query(...),
    service: SoftwareCommandService = Depends(get_command_service),
) -> dict[str, str]:
    await service.process_malware_scan_success(
        ProcessMalwareScanSuccessCommand(
            software_id=software_id,
            version_id=version_id,
            artifact_id=artifact_id,
        )
    )
    return {"status": "accepted"}


@router.post("/{software_id}/versions/{version_id}/malware/failed", status_code=status.HTTP_202_ACCEPTED)
async def malware_failed(
    software_id: UUID,
    version_id: UUID,
    payload: MalwareScanFailedRequest,
    artifact_id: UUID = Query(...),
    service: SoftwareCommandService = Depends(get_command_service),
) -> dict[str, str]:
    await service.process_malware_scan_failed(
        ProcessMalwareScanFailedCommand(
            software_id=software_id,
            version_id=version_id,
            artifact_id=artifact_id,
            reason=payload.reason,
        )
    )
    return {"status": "accepted"}


@router.post("/{software_id}/versions/{version_id}/publish", status_code=status.HTTP_202_ACCEPTED)
async def publish_version(
    software_id: UUID,
    version_id: UUID,
    service: SoftwareCommandService = Depends(get_command_service),
) -> dict[str, str]:
    await service.publish_version(PublishVersionCommand(software_id=software_id, version_id=version_id))
    return {"status": "published"}


@router.get("/{software_id}/download", response_model=DownloadLinkResponse)
async def get_download_link(
    software_id: UUID,
    version_id: UUID | None = Query(default=None),
    user_id: UUID = Depends(gatekeeper),
    service: DownloadService = Depends(get_download_service),
) -> DownloadLinkResponse:
    try:
        url = await service.generate_download_url(
            GenerateDownloadLinkQuery(
                user_id=user_id,
                software_id=software_id,
                version_id=version_id,
            )
        )
    except AccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except MalwareScanPendingError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ConcurrencyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return DownloadLinkResponse(url=url)


@router.put("/storage/upload/{storage_key:path}", status_code=status.HTTP_201_CREATED)
async def internal_storage_upload(
    storage_key: str,
    request: Request,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    gateway=Depends(get_internal_storage_test_gateway),
) -> dict[str, str | int]:
    _authorize_internal_storage_access(
        storage_key=storage_key,
        expires=expires,
        token=token,
        method="PUT",
        gateway=gateway,
    )

    body = await request.body()
    if not body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload body is empty.",
        )

    await gateway.upload(storage_key, body, request.headers.get("content-type"))
    return {
        "status": "uploaded",
        "storage_key": storage_key,
        "size_bytes": len(body),
    }


@router.get("/storage/download/{storage_key:path}")
async def internal_storage_download(
    storage_key: str,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    gateway=Depends(get_internal_storage_test_gateway),
) -> Response:
    _authorize_internal_storage_access(
        storage_key=storage_key,
        expires=expires,
        token=token,
        method="GET",
        gateway=gateway,
    )

    try:
        content, content_type = await gateway.download(storage_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored artifact not found.") from exc

    filename = os.path.basename(storage_key) or "artifact.bin"
    return Response(
        content=content,
        media_type=content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/storage/delete/{storage_key:path}", status_code=status.HTTP_200_OK)
async def internal_storage_delete(
    storage_key: str,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=16),
    gateway=Depends(get_internal_storage_test_gateway),
) -> dict[str, str]:
    _authorize_internal_storage_access(
        storage_key=storage_key,
        expires=expires,
        token=token,
        method="DELETE",
        gateway=gateway,
    )
    try:
        await gateway.delete(storage_key)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored artifact not found.") from exc
    return {"status": "deleted", "storage_key": storage_key}
