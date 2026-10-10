"""Authenticated security views for the workspace."""

from __future__ import annotations

import asyncio
import inspect
import os
import tempfile
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.software import (
    SoftwareArtifactModel,
    SoftwareModel,
    SoftwareVersionModel,
)
from app.infrastructure.database.models.security_scan_report import SecurityScanReportModel
from app.modules.security.application.services.scan_report_service import record_rescan_report
from app.modules.security.dependencies import CurrentUser, get_current_user
from app.modules.shared.dependencies import get_db
from app.modules.shared.enums import SoftwareVisibility
from app.modules.software_management.dependencies import get_scanner, get_storage
from app.modules.software_management.domain.ports.malware_scanner import MalwareScanner
from app.modules.software_management.domain.ports.storage import Storage

router = APIRouter(prefix="/api/v1/security", tags=["Security"])


class ScanRequest(BaseModel):
    artifact_id: UUID


def _scan_status(status: str | None) -> tuple[str, str]:
    value = (status or "").lower()
    if value == "active":
        return "completed", "clean"
    if value == "quarantined":
        return "completed", "malicious"
    if value == "deleted":
        return "completed", "unknown"
    return "queued", "unknown"


async def _visible_artifacts(
    session: AsyncSession,
    current_user: CurrentUser,
    *,
    limit: int,
    software_id: UUID | None = None,
    version_id: UUID | None = None,
    artifact_id: UUID | None = None,
) -> list[tuple[SoftwareArtifactModel, SoftwareVersionModel, SoftwareModel]]:
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
    if artifact_id is not None:
        statement = statement.where(SoftwareArtifactModel.id == str(artifact_id))
    result = await session.execute(statement)
    return list(result.all())


def _artifact_item(
    artifact: SoftwareArtifactModel,
    version: SoftwareVersionModel,
    software: SoftwareModel,
    report: SecurityScanReportModel | None = None,
) -> dict:
    scan_status, verdict = _scan_status(artifact.status)
    if report is not None:
        scan_status = report.status
        verdict = report.verdict
    return {
        "id": report.id if report is not None else artifact.id,
        "artifact_id": artifact.id,
        "software_id": software.id,
        "software_name": software.name,
        "version_id": version.id,
        "version": version.version,
        "file_name": artifact.file_name,
        "filename": artifact.file_name,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.file_hash,
        "content_type": artifact.content_type,
        "scan_status": scan_status,
        "status": artifact.status.lower(),
        "verdict": verdict,
        "quarantine_reason": report.reason if report is not None and report.reason else artifact.quarantine_reason,
        "provider": report.provider if report is not None else None,
        "reference": report.reference if report is not None else None,
        "report_status": report.status if report is not None else scan_status,
        "requested_at": report.requested_at if report is not None else artifact.updated_at,
        "completed_at": report.completed_at if report is not None else artifact.updated_at,
        "created_at": artifact.created_at,
        "updated_at": artifact.updated_at,
    }


async def _latest_reports(
    session: AsyncSession,
    artifact_ids: list[str],
) -> dict[str, SecurityScanReportModel]:
    if not artifact_ids:
        return {}
    result = await session.execute(
        select(SecurityScanReportModel)
        .where(SecurityScanReportModel.artifact_id.in_(artifact_ids))
        .order_by(SecurityScanReportModel.requested_at.desc())
    )
    latest: dict[str, SecurityScanReportModel] = {}
    for report in result.scalars():
        latest.setdefault(report.artifact_id, report)
    return latest


@router.get("/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    software_id: UUID | None = Query(None),
    version_id: UUID | None = Query(None),
    artifact_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[dict]:
    rows = await _visible_artifacts(
        session, current_user, limit=limit, software_id=software_id,
        version_id=version_id, artifact_id=artifact_id,
    )
    reports = await _latest_reports(session, [artifact.id for artifact, _, _ in rows])
    return [_artifact_item(artifact, version, software, reports.get(artifact.id)) for artifact, version, software in rows]


@router.get("/scan-reports")
async def list_scan_reports(
    limit: int = Query(50, ge=1, le=200),
    software_id: UUID | None = Query(None),
    version_id: UUID | None = Query(None),
    artifact_id: UUID | None = Query(None),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> list[dict]:
    statement = (
        select(SecurityScanReportModel, SoftwareArtifactModel, SoftwareVersionModel, SoftwareModel)
        .join(SoftwareArtifactModel, SoftwareArtifactModel.id == SecurityScanReportModel.artifact_id)
        .join(SoftwareVersionModel, SoftwareVersionModel.id == SecurityScanReportModel.version_id)
        .join(SoftwareModel, SoftwareModel.id == SecurityScanReportModel.software_id)
        .where(
            SoftwareArtifactModel.status != "DELETED",
            or_(
                SoftwareModel.owner_id == str(current_user.user_id),
                SoftwareModel.visibility == SoftwareVisibility.PUBLIC,
            ),
        )
        .order_by(SecurityScanReportModel.requested_at.desc())
        .limit(limit)
    )
    if software_id is not None:
        statement = statement.where(SecurityScanReportModel.software_id == str(software_id))
    if version_id is not None:
        statement = statement.where(SecurityScanReportModel.version_id == str(version_id))
    if artifact_id is not None:
        statement = statement.where(SecurityScanReportModel.artifact_id == str(artifact_id))

    result = await session.execute(statement)
    return [
        _artifact_item(artifact, version, software, report)
        for report, artifact, version, software in result.all()
    ]


@router.get("/scan-reports/{scan_id}")
async def get_scan_report(
    scan_id: UUID,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    report_result = await session.execute(
        select(SecurityScanReportModel).where(SecurityScanReportModel.id == str(scan_id))
    )
    report = report_result.scalar_one_or_none()
    if report is not None:
        rows = await _visible_artifacts(session, current_user, limit=1, artifact_id=UUID(report.artifact_id))
        if rows:
            artifact, version, software = rows[0]
            return _artifact_item(artifact, version, software, report)

    rows = await _visible_artifacts(session, current_user, limit=1, artifact_id=scan_id)
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan report not found")
    artifact, version, software = rows[0]
    reports = await _latest_reports(session, [artifact.id])
    return _artifact_item(artifact, version, software, reports.get(artifact.id))


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def rescan_artifact(
    payload: ScanRequest,
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
    scanner: MalwareScanner = Depends(get_scanner),
    storage: Storage = Depends(get_storage),
) -> dict:
    rows = await _visible_artifacts(session, current_user, limit=1, artifact_id=payload.artifact_id)
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    artifact, version, software = rows[0]

    temporary_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="techpulse-scan-", suffix=".bin", delete=False) as temporary:
            temporary_path = temporary.name
            with storage.open(storage_key=artifact.storage_key) as source:
                while chunk := source.read(1024 * 1024):
                    temporary.write(chunk)
        try:
            scan_method = scanner.scan_file
            arguments = {
                "file_path": temporary_path,
                "filename": artifact.file_name,
                "sha256": artifact.file_hash,
                "content_type": artifact.content_type,
            }
            if inspect.iscoroutinefunction(scan_method):
                result = await scan_method(**arguments)
            else:
                result = await asyncio.to_thread(scan_method, **arguments)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Security scanner unavailable") from exc
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

    artifact.status = "ACTIVE" if result.is_clean else "QUARANTINED"
    artifact.quarantine_reason = None if result.is_clean else result.reason
    await session.commit()
    await session.refresh(artifact)
    report = await record_rescan_report(
        session,
        artifact_id=artifact.id,
        software_id=software.id,
        version_id=version.id,
        provider=result.provider,
        reference=result.reference,
        is_clean=result.is_clean,
        reason=result.reason,
    )
    return _artifact_item(artifact, version, software, report)


@router.get("/summary")
async def security_summary(
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, int | object | None]:
    rows = await _visible_artifacts(session, current_user, limit=limit)
    reports = await _latest_reports(session, [artifact.id for artifact, _, _ in rows])
    items = [_artifact_item(artifact, version, software, reports.get(artifact.id)) for artifact, version, software in rows]
    return {
        "total_scans": len(items),
        "clean": sum(item["verdict"] == "clean" for item in items),
        "threats": sum(item["verdict"] == "malicious" for item in items),
        "pending": sum(item["scan_status"] in {"queued", "running"} for item in items),
        "inconclusive": sum(item["verdict"] == "unknown" for item in items),
        "last_scan_at": max((item["updated_at"] for item in items), default=None),
    }
