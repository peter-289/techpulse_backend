from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import BinaryIO
from urllib.parse import quote
from uuid import UUID


from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from starlette.background import BackgroundTask
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.software_management.domain.ports.download_signer import (
    SIGNED_DOWNLOAD_ROUTE,
)
from app.modules.security.dependencies import (
    CurrentUser,
    get_abuse_protection,
    get_current_user,
)
from app.modules.software_management.dependencies import (
    get_artifact_stager,
    get_category_service,
    get_download_service,
    get_software_service,
    upload_limits,
)

from app.modules.software_management.domain.exceptions import SoftwareAccessDeniedError, SoftwareDomainError
from app.modules.shared.enums import SoftwareVisibility
from app.modules.shared.dependencies import get_db
from app.infrastructure.database.models.software import SoftwareArtifactModel, SoftwareModel, SoftwareVersionModel
from app.modules.software_management.schema.software_schema import (
    ArtifactResponse,
    SoftwareRead,
    SoftwarePricingUpdate,
    SoftwareSummary,
    SoftwareUploadResponse,
    SoftwareVersionRead,
    ArtifactBrowserResponse,
)
from app.modules.software_management.domain.ports.artifact_stager import ArtifactStager
from app.modules.software_management.domain.value_objects import OwnedSoftwareCard, SemVer
from app.modules.software_management.api.presenters import software_item, version_item
from app.modules.software_management.api.errors import http_error
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.application.services.search_service import SearchService
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.application.services.scan_report_service import record_upload_scan_reports

router = APIRouter(prefix="/api/v1/software-management", tags=["software-management"])


# List softwares for a user
@router.get("", response_model=tuple[list[OwnedSoftwareCard], int])
async def list_software(
    limit: int = Query(100, ge=1, le=200),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> tuple[list[OwnedSoftwareCard], int]:
   # print("CURRENT USER:", current_user)
    user_id = current_user.user_id
    items, _ = await service.list_visible(user_id=user_id, limit=limit)

    return items, _


@router.get("/artifacts", response_model=list[ArtifactBrowserResponse])
async def list_artifacts(
    limit: int = Query(50, ge=1, le=200),
    software_id: UUID | None = Query(None),
    version_id: UUID | None = Query(None),
    status: str | None = Query(None, max_length=32),
    search: str | None = Query(None, max_length=120),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[ArtifactBrowserResponse]:
    statement = (
        select(SoftwareArtifactModel, SoftwareVersionModel, SoftwareModel)
        .join(SoftwareVersionModel, SoftwareVersionModel.id == SoftwareArtifactModel.version_id)
        .join(SoftwareModel, SoftwareModel.id == SoftwareVersionModel.software_id)
        .where(
            SoftwareArtifactModel.status != "DELETED",
            or_(
                SoftwareModel.owner_id == str(current_user.user_id),
                SoftwareModel.visibility == SoftwareVisibility.PUBLIC,
            ),
        )
        .order_by(SoftwareArtifactModel.created_at.desc())
        .limit(limit)
    )
    if software_id is not None:
        statement = statement.where(SoftwareModel.id == str(software_id))
    if version_id is not None:
        statement = statement.where(SoftwareVersionModel.id == str(version_id))
    if status:
        statement = statement.where(SoftwareArtifactModel.status == status.upper())
    if search:
        pattern = f"%{search.strip()}%"
        statement = statement.where(
            or_(
                SoftwareArtifactModel.file_name.ilike(pattern),
                SoftwareModel.name.ilike(pattern),
            )
        )

    result = await session.execute(statement)
    return [
        ArtifactBrowserResponse(
            id=artifact.id,
            artifact_id=artifact.id,
            software_id=software.id,
            software_name=software.name,
            version_id=version.id,
            version=version.version,
            filename=artifact.file_name,
            file_name=artifact.file_name,
            size_bytes=artifact.size_bytes,
            sha256=artifact.file_hash,
            content_type=artifact.content_type,
            status=artifact.status.lower(),
            scan_status="completed" if artifact.status.upper() in {"ACTIVE", "QUARANTINED"} else "queued",
            quarantine_reason=artifact.quarantine_reason,
            created_at=artifact.created_at,
            updated_at=artifact.updated_at,
        )
        for artifact, version, software in result.all()
    ]


@router.get("/summary", response_model=SoftwareSummary)
async def software_summary(
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareSummary:
    """Return workspace metrics for the authenticated user's software."""
    total_packages, total_versions, published_versions, total_downloads = await service.summary_for_user(
        current_user.user_id
    )
    return SoftwareSummary(
        total_packages=total_packages,
        total_versions=total_versions,
        published_versions=published_versions,
        total_downloads=total_downloads,
    )


@router.get("/{software_id}", response_model=SoftwareRead)
async def get_software(
    software_id: UUID,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareRead:
    try:
        software = await service.get(software_id)
        if not software.is_owned_by(current_user.user_id) and not software.is_public():
            raise SoftwareAccessDeniedError("You do not have access to this software.")
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return software_item(software, viewer_user_id=current_user.user_id)


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
    release_notes: str = Form(""),
    files: list[UploadFile] = File(...),
    stager: ArtifactStager = Depends(get_artifact_stager),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SoftwareUploadResponse:
    uploads = [
        stager.stage(file.file, file.filename or "package.bin", content_type=file.content_type, limits=upload_limits)
        for file in files
    ]
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
            release_notes=release_notes,
            artifacts=uploads,
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    finally:
        for uploaded in uploads:
            stager.discard(uploaded)

    await record_upload_scan_reports(
        session,
        software_id=software.id,
        version_id=created_version.id,
        artifacts=list(created_version.artifacts),
    )

    return SoftwareUploadResponse(
        software_id=str(software.id),
        version_id=str(created_version.id),
        version=str(created_version.number),
        artifacts=[
            ArtifactResponse(
                id=artifact.id,
                filename=artifact.filename,
                size_bytes=artifact.size_bytes,
                sha256=artifact.sha256,
                content_type=artifact.mime_type,
                status=artifact.status.value,
            )
            for artifact in created_version.artifacts
        ],
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
        versions = await service.list_versions(
            software_id=software_id,
            user_id=_current_user.user_id,
            limit=limit,
            )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return [version_item(version) for version in versions]


@router.post("/{software_id}/versions/upload", response_model=SoftwareVersionRead, status_code=status.HTTP_201_CREATED)
async def upload_version(
    software_id: UUID,
    version: str = Form(...),
    release_notes: str = Form(""),
    files: list[UploadFile] = File(...),
    stager: ArtifactStager = Depends(get_artifact_stager),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> SoftwareVersionRead:
    uploads = [
        stager.stage(file.file, file.filename or "package.bin", content_type=file.content_type, limits=upload_limits)
        for file in files
    ]
    try:
        created_version = await service.upload_version(
            software_id=software_id,
            user_id=current_user.user_id,
            version_number=version,
            release_notes=release_notes,
            artifacts=uploads,
            is_admin=str(current_user.role).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    finally:
        for uploaded in uploads:
            stager.discard(uploaded)
    await record_upload_scan_reports(
        session,
        software_id=created_version.software_id,
        version_id=created_version.id,
        artifacts=list(created_version.artifacts),
    )
    return version_item(created_version)


@router.get("/{software_id}/versions/{version}", response_model=SoftwareVersionRead)
async def get_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareVersionRead:
    try:
        item = await service.get_version(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return version_item(item)


@router.patch("/{software_id}/pricing", response_model=SoftwareRead)
async def update_pricing(
    software_id: UUID,
    payload: SoftwarePricingUpdate,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> SoftwareRead:
    try:
        software = await service.update_pricing(
            software_id=software_id,
            user_id=current_user.user_id,
            price_cents=payload.price_cents,
            currency=payload.currency,
            is_admin=str(current_user.role).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return software_item(software, viewer_user_id=current_user.user_id)



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
        raise http_error(exc) from exc
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
        raise http_error(exc) from exc
    return {"status": "revoked", "version": version}


@router.post("/{software_id}/versions/{version}/archive", status_code=status.HTTP_202_ACCEPTED)
async def archive_version(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    try:
        await service.archive_version(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
            is_admin=str(current_user.role).upper() == "ADMIN",
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return {"status": "archived", "version": version}


@router.get("/{software_id}/versions/{version}/artifacts", response_model=list[ArtifactResponse])
async def list_version_artifacts(
    software_id: UUID,
    version: str,
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[ArtifactResponse]:
    """List the artifacts attached to one version.

    The authorization check lives inline here rather than in the service because
    listing is not downloading: it exposes filenames, sizes and hashes, so it
    carries the same private/paid gate without touching the download rules.
    """
    try:
        software = await service.get(software_id)
        target_version = software.get_version_by_semver(SemVer.parse(version))
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc

    if not software.is_public() and not software.is_owned_by(current_user.user_id) and not await service.has_purchase(
        software_id=software_id,
        user_id=current_user.user_id,
    ):
        raise http_error(SoftwareDomainError("A purchase is required to view artifacts."))

    return [
        ArtifactResponse(
            id=artifact.id,
            filename=artifact.filename,
            size_bytes=artifact.size_bytes,
            sha256=artifact.sha256,
            content_type=artifact.mime_type,
            status=artifact.status.value,
        )
        for artifact in target_version.artifacts
    ]


@router.get("/{software_id}/versions/{version}/artifacts/{artifact_id}/download")
async def download_artifact(
    software_id: UUID,
    version: str,
    artifact_id: UUID,
    request: Request,
    abuse_protection: AbuseProtection = Depends(get_abuse_protection),
    service: SoftwareService = Depends(get_software_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> RedirectResponse:
    try:
        # Get client ip
        ip = abuse_protection.get_client_ip(request=request)

        await abuse_protection.guard_download(ip=ip)
        artifactURL = await service.download_artifact_url(
            software_id=software_id,
            version_number=version,
            artifact_id=artifact_id,
            user_id=current_user.user_id,
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
    return RedirectResponse(url=artifactURL.url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/{software_id}/versions/{version}/download")
async def download_version(
    software_id: UUID,
    version: str,
    request: Request,
    abuse_protection: AbuseProtection = Depends(get_abuse_protection),
    service: DownloadService = Depends(get_download_service),
    current_user: CurrentUser = Depends(get_current_user),
) -> RedirectResponse:
    try:
        # Get client ip
        ip = abuse_protection.get_client_ip(request=request)

        await abuse_protection.guard_download(ip=ip)
        url = await service.create_download_url(
            software_id=software_id,
            version_number=version,
            user_id=current_user.user_id,
        )
    except SoftwareDomainError as exc:
        raise http_error(exc) from exc
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

    Unauthenticated by design: it is the public catalogue. The repository
    restricts candidates to PUBLIC and not-deleted rows, so nothing private is
    reachable through it. ``total`` is the number of ranked candidates and is
    capped by ``SearchService.CANDIDATE_LIMIT`` -- it is not a table count.
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
        software_item(r.software, viewer_user_id=r.software.owner_id)
        .model_copy(update={"viewer_has_access": r.software.is_public() or r.software.price.amount_cents == 0})
        for r in results
    ]
    scores = [r.score for r in results]

    return {"items": [item.model_dump() for item in items], "scores": scores, "total": total, "limit": limit, "offset": offset}


#: Bytes read per iteration while streaming an artifact out of storage. Fixed
#: rather than "iterate the file object": ``iter()`` on a binary file splits on
#: newline, so an artifact with no newlines in it -- a PDF, an image, a zip --
#: arrives as one chunk the size of the whole file. That is the difference
#: between streaming and buffering the entire artifact in memory.
STREAM_CHUNK_SIZE = 1024 * 1024

#: This router's path for the signed artifact-serving endpoint, relative to
#: :data:`SOFTWARE_ROUTER_PREFIX`.
#:
#: Spelled out as a literal rather than sliced out of ``SIGNED_DOWNLOAD_ROUTE``
#: inside the decorator. Slicing looked equivalent and was not: inside an
#: f-string, ``f"{route[len(prefix)]}"`` resolves the format-spec mini-language
#: rather than the slice, and yields ``"/"``. The route then registered as
#: ``/api/v1/software-management//{storage_key:path}`` -- which is the same
#: double-slash defect as the signed URL, one layer down, and just as fatal.
SIGNED_DOWNLOAD_ROUTE_SUFFIX = "/storage/download"

#: The two descriptions of the serving route must agree or every signed URL
#: 404s, and nothing else in the codebase would notice. Checked at import so a
#: change to either one fails here rather than in a client's browser. Read from
#: the router so the check covers the prefix FastAPI actually mounts under.
assert (
    f"{router.prefix}{SIGNED_DOWNLOAD_ROUTE_SUFFIX}" == SIGNED_DOWNLOAD_ROUTE
), (
    "the signed artifact route declared by this router and the one the signer "
    f"builds URLs from disagree: router "
    f"{router.prefix + SIGNED_DOWNLOAD_ROUTE_SUFFIX!r} != signer {SIGNED_DOWNLOAD_ROUTE!r}"
)


@router.get(f"{SIGNED_DOWNLOAD_ROUTE_SUFFIX}/{{storage_key:path}}")
async def stream_signed_artifact(
    storage_key: str,
    request: Request,
    expires: int = Query(..., ge=1),
    token: str = Query(..., min_length=1, max_length=128),
    download_service: DownloadService = Depends(get_download_service),
) -> StreamingResponse:
    """Serve an artifact named by a signed URL.

    This is the *second* half of a download, not the authorized half. It has no
    session dependency on purpose: the HMAC token is the credential, it is
    short-lived, and it is bound to this key, this verb and its own expiry, so it
    cannot be redirected at another artifact. ``download_artifact`` above is what
    authenticates the caller and decides whether they may have the file at all.

    The response streams. Nothing here touches the filesystem: the key goes
    through the service to the ``Storage`` port, which is the only thing that
    knows that ``/app/storage`` is where artifacts live.
    """
    await download_service.verify_token(
        storage_key=storage_key,
        expires=expires,
        token=token,
        # The real verb, not a hardcoded "GET", so the signature is checked
        # against the request that was actually made.
        method=request.method,
    )

    file_handle = await download_service.read_file(storage_key=storage_key)

    return StreamingResponse(
        content=_iter_chunks(file_handle, chunk_size=STREAM_CHUNK_SIZE),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": _content_disposition(storage_key),
            # Short-lived bearer credential in the query string: never let it be
            # cached or written to a referrer.
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
        # Runs once the body has been sent, including when the client hangs up
        # mid-stream, so an abandoned download still releases its descriptor.
        background=BackgroundTask(file_handle.close),
    )


def _iter_chunks(file_handle: BinaryIO, *, chunk_size: int) -> Iterator[bytes]:
    """Yield ``chunk_size`` blocks until the handle is exhausted.

    A generator rather than the handle itself, so Starlette's ``iterate_in_threadpool``
    pulls fixed-size blocks off disk instead of reading until newline.
    """
    try:
        while chunk := file_handle.read(chunk_size):
            yield chunk
    finally:
        file_handle.close()


def _content_disposition(storage_key: str) -> str:
    """Build a ``Content-Disposition`` header for the artifact's filename.

    Only the final segment of the key is a filename; the rest is internal layout
    and is not echoed to the client. Both the quoted and the RFC 5987 forms are
    emitted because the quoted one cannot carry a non-ASCII name.
    """
    filename = PurePosixPath(storage_key).name or "artifact.bin"
    # A quote or a newline in the filename would break out of the header value.
    escaped = filename.replace('"', "").replace("\\", "").replace("\r", "").replace("\n", "")
    ascii_fallback = escaped.encode("ascii", "replace").decode("ascii").replace("?", "_")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(escaped, safe='')}"
