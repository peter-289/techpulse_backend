from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UploadSoftwareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_id: UUID
    version_id: UUID
    artifact_id: UUID
    version: str
    file_hash: str
    size_bytes: int
    software_row_version: int
    published: bool


class PublishVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_id: UUID
    version_id: UUID
    version: str
    published_at: datetime
    software_row_version: int


class DeprecateVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_id: UUID
    version_id: UUID
    version: str
    deprecated_at: datetime
    software_row_version: int


class RevokeVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_id: UUID
    version_id: UUID
    version: str
    revoked_at: datetime
    software_row_version: int


class DeleteSoftwareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    software_id: UUID
    deleted_versions: int
    deleted_artifacts: int


class SoftwareListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    owner_id: str
    name: str
    description: str
    is_public: bool
    latest_version: str | None
    latest_version_id: UUID | None
    download_count: int
    created_at: datetime
    updated_at: datetime


class VersionListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    software_id: UUID
    version: str
    is_published: bool
    download_count: int
    file_name: str
    content_type: str
    size_bytes: int
    file_hash: str
    created_at: datetime
    published_at: datetime | None


class AdminSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_packages: int
    private_packages: int
    public_packages: int
    total_versions: int
    total_downloads: int


class AdminSoftwareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    package_id: UUID
    name: str
    owner_id: str
    is_public: bool
    latest_version: str | None
    download_count: int
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    detail: str = Field(..., min_length=1)
