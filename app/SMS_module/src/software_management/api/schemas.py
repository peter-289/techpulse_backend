from __future__ import annotations

from pydantic import BaseModel, Field


class CreateSoftwareRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    visibility: str = Field(default="public")


class AddVersionRequest(BaseModel):
    number: str = Field(min_length=5, max_length=32)
    release_notes: str = Field(default="")


class RequestArtifactUploadRequest(BaseModel):
    filename: str
    content_type: str
    sha256: str = Field(min_length=64, max_length=64)
    size_bytes: int = Field(gt=0)


class MalwareScanFailedRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class SoftwareResponse(BaseModel):
    software_id: str


class VersionResponse(BaseModel):
    version_id: str
    lock_version: int


class ArtifactUploadResponse(BaseModel):
    artifact_id: str
    storage_key: str
    upload_url: str
    upload_fields: dict[str, str]
    expires_in_seconds: int


class DownloadLinkResponse(BaseModel):
    url: str
