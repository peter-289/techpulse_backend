from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .value_objects import FileHash, VersionNumber, VersionStatus


@dataclass(frozen=True, slots=True)
class Artifact:
    id: UUID
    storage_key: str
    file_name: str
    content_type: str
    size_bytes: int
    file_hash: FileHash
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.storage_key.strip():
            raise ValueError("storage key is required")
        if not self.file_name.strip():
            raise ValueError("file name is required")
        if self.size_bytes <= 0:
            raise ValueError("artifact size must be positive")


@dataclass(frozen=True, slots=True)
class Version:
    id: UUID
    software_id: UUID
    artifact_id: UUID
    number: VersionNumber
    status: VersionStatus
    created_at: datetime
    published_at: datetime | None

    @property
    def is_published(self) -> bool:
        return self.status.is_public
