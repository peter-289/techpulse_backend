from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SMSBase(DeclarativeBase):
    pass


class SoftwareModel(SMSBase):
    __tablename__ = "sms_softwares"
    __table_args__ = (
        UniqueConstraint("owner_id", "name", name="uq_sms_software_owner_name"),
        Index("ix_sms_softwares_created_at", "created_at"),
        Index("ix_sms_softwares_current_version_id", "current_version_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_version_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sms_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)

    versions: Mapped[list["VersionModel"]] = relationship(
        back_populates="software",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="VersionModel.software_id",
    )


class ArtifactModel(SMSBase):
    __tablename__ = "sms_artifacts"
    __table_args__ = (
        Index("ix_sms_artifacts_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False, default="application/octet-stream")
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)

    version: Mapped["VersionModel"] = relationship(back_populates="artifact", uselist=False)


class VersionModel(SMSBase):
    __tablename__ = "sms_versions"
    __table_args__ = (
        UniqueConstraint("software_id", "version", name="uq_sms_versions_software_version"),
        Index("ix_sms_versions_created_at", "created_at"),
        Index("ix_sms_versions_software_id_version", "software_id", "version"),
        Index("ix_sms_versions_status", "status"),
        CheckConstraint(
            "status IN ('DRAFT', 'PUBLISHED', 'DEPRECATED', 'REVOKED')",
            name="ck_sms_versions_status",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    software_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sms_softwares.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    artifact_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("sms_artifacts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    is_published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT")
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    software: Mapped[SoftwareModel] = relationship(
        back_populates="versions",
        foreign_keys="VersionModel.software_id",
    )
    artifact: Mapped[ArtifactModel] = relationship(back_populates="version")


class IdempotencyKeyModel(SMSBase):
    __tablename__ = "sms_idempotency_keys"
    __table_args__ = (
        UniqueConstraint("scope", "actor_id", "key", name="uq_sms_idempotency_scope_actor_key"),
        Index("ix_sms_idempotency_scope_actor", "scope", "actor_id"),
        Index("ix_sms_idempotency_created_at", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
