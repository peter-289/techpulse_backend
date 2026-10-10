from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models.security_scan_report import SecurityScanReportModel
from app.modules.software_management.domain.entities.artifact import Artifact


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def record_upload_scan_reports(
    session: AsyncSession,
    *,
    software_id: UUID,
    version_id: UUID,
    artifacts: list[Artifact],
) -> None:
    """Persist the successful scans performed before an upload was committed."""
    requested_at = _now()
    session.add_all(
        SecurityScanReportModel(
            id=str(uuid4()),
            artifact_id=str(artifact.id),
            software_id=str(software_id),
            version_id=str(version_id),
            provider=artifact.scan_provider or "unknown",
            reference=artifact.scan_reference,
            status="completed",
            verdict="clean",
            requested_at=requested_at,
            started_at=requested_at,
            completed_at=artifact.scan_completed_at or requested_at,
        )
        for artifact in artifacts
    )
    await session.commit()


async def record_rescan_report(
    session: AsyncSession,
    *,
    artifact_id: str,
    software_id: str,
    version_id: str,
    provider: str,
    reference: str | None,
    is_clean: bool,
    reason: str | None,
) -> SecurityScanReportModel:
    completed_at = _now()
    report = SecurityScanReportModel(
        id=str(uuid4()),
        artifact_id=artifact_id,
        software_id=software_id,
        version_id=version_id,
        provider=provider,
        reference=reference,
        status="completed",
        verdict="clean" if is_clean else "malicious",
        reason=reason,
        requested_at=completed_at,
        started_at=completed_at,
        completed_at=completed_at,
    )
    session.add(report)
    await session.commit()
    await session.refresh(report)
    return report
