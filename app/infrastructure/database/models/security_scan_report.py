from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.database.db_setup import Base

if TYPE_CHECKING:
    from app.infrastructure.database.models.software import SoftwareArtifactModel


class SecurityScanReportModel(Base):
    """Immutable record of one artifact security scan attempt."""

    __tablename__ = "security_scan_reports"
    __table_args__ = (
        Index("ix_security_scan_reports_artifact_requested", "artifact_id", "requested_at"),
        Index("ix_security_scan_reports_software_requested", "software_id", "requested_at"),
        Index("ix_security_scan_reports_status_verdict", "status", "verdict"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(
        ForeignKey("sms_artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    software_id: Mapped[str] = mapped_column(
        ForeignKey("sms_softwares.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_id: Mapped[str] = mapped_column(
        ForeignKey("sms_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    artifact: Mapped["SoftwareArtifactModel"] = relationship(back_populates="scan_reports")
