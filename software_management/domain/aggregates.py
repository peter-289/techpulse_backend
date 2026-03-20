from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from .entities import Artifact, Version
from .events import SoftwareUploaded, VersionPublished
from .value_objects import VersionNumber, VersionStatus


@dataclass(slots=True)
class Software:
    id: UUID
    owner_id: str
    name: str
    description: str
    row_version: int
    created_at: datetime
    updated_at: datetime
    versions: dict[str, Version] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.owner_id.strip():
            raise ValueError("owner id is required")
        if not self.name.strip():
            raise ValueError("software name is required")
        if self.row_version < 1:
            raise ValueError("row_version must be >= 1")

    def add_version(self, version: Version, artifact: Artifact) -> SoftwareUploaded:
        if version.software_id != self.id:
            raise ValueError("version does not belong to software")
        key = version.number.value
        if key in self.versions:
            raise ValueError("version already exists")
        if version.artifact_id != artifact.id:
            raise ValueError("version artifact mismatch")
        self.versions[key] = version
        self.row_version += 1
        self.updated_at = datetime.now(datetime.timezone.utc)
        return SoftwareUploaded(
            software_id=self.id,
            version_id=version.id,
            artifact_id=artifact.id,
            occurred_at=self.updated_at,
        )

    def publish_version(self, version_number: VersionNumber) -> VersionPublished:
        version = self.versions.get(version_number.value)
        if version is None:
            raise ValueError("version not found")
        if version.status != VersionStatus.DRAFT:
            raise ValueError("version is already published")
        now = datetime.now(datetime.timezone.utc)
        self.versions[version_number.value] = Version(
            id=version.id,
            software_id=version.software_id,
            artifact_id=version.artifact_id,
            number=version.number,
            status=VersionStatus.PUBLISHED,
            created_at=version.created_at,
            published_at=now,
        )
        self.row_version += 1
        self.updated_at = now
        return VersionPublished(
            software_id=self.id,
            version_id=version.id,
            version=version_number,
            occurred_at=now,
        )

    def deprecate_version(self, version_number: VersionNumber) -> None:
        version = self.versions.get(version_number.value)
        if version is None:
            raise ValueError("version not found")
        if version.status != VersionStatus.PUBLISHED:
            raise ValueError("version must be published before deprecating")
        self.versions[version_number.value] = Version(
            id=version.id,
            software_id=version.software_id,
            artifact_id=version.artifact_id,
            number=version.number,
            status=VersionStatus.DEPRECATED,
            created_at=version.created_at,
            published_at=version.published_at,
        )

    def revoke_version(self, version_number: VersionNumber) -> None:
        version = self.versions.get(version_number.value)
        if version is None:
            raise ValueError("version not found")
        if version.status != VersionStatus.DEPRECATED:
            raise ValueError("version must be deprecated before revoking")
        self.versions[version_number.value] = Version(
            id=version.id,
            software_id=version.software_id,
            artifact_id=version.artifact_id,
            number=version.number,
            status=VersionStatus.REVOKED,
            created_at=version.created_at,
            published_at=version.published_at,
        )
