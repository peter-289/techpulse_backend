from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.db_setup import Base


class SoftwareModel(Base):
    __tablename__ = "sms_softwares"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_sms_software_owner_name"),
        Index("ix_sms_softwares_owner_id", "owner_id"),
        Index("ix_sms_softwares_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    versions: Mapped[list["SoftwareVersionModel"]] = relationship(
        back_populates="software",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="SoftwareVersionModel.created_at.desc()",
    )


class SoftwareArtifactModel(Base):
    __tablename__ = "sms_artifacts"
    __table_args__ = (
        UniqueConstraint("storage_key"),
        Index("ix_sms_artifacts_file_hash", "file_hash"),
        Index("ix_sms_artifacts_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SoftwareVersionModel(Base):
    __tablename__ = "sms_versions"
    __table_args__ = (
        UniqueConstraint("artifact_id"),
        UniqueConstraint("software_id", "version", name="uq_sms_versions_software_version"),
        Index("ix_sms_versions_software_id", "software_id"),
        Index("ix_sms_versions_created_at", "created_at"),
        Index("ix_sms_versions_software_id_version", "software_id", "version"),
        Index("ix_sms_versions_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    software_id: Mapped[str] = mapped_column(
        ForeignKey("sms_softwares.id", ondelete="CASCADE"),
        nullable=False,
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("sms_artifacts.id", ondelete="SET NULL"),
        nullable=True,
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    release_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT")
    lock_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    software: Mapped[SoftwareModel] = relationship(back_populates="versions")
    artifact: Mapped[SoftwareArtifactModel | None] = relationship(lazy="selectin")
