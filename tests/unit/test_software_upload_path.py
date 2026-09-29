"""The artifact upload path, end to end through the service.

``SoftwareService._process_artifact`` -- filename sanitising, scanning, writing to
storage, constructing the artifact -- had no test at all. Phase 3 rewrote most
of the surrounding code and a missing ``pathlib`` import inside it survived
untested: ``_sanitize_filename`` would have raised ``NameError`` on the first
real upload. These tests exercise the path so that class of break is caught.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.infrastructure.storage.local_artifact_stager import LocalArtifactStager
from app.modules.shared.enums import SoftwareVisibility, VersionStatus
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.events.events import (
    ArtifactAddedToVersion,
    VersionAddedEvent,
    VersionPublishedEvent,
)
from app.modules.software_management.domain.exceptions import SoftwareDomainError
from app.modules.software_management.domain.ports.artifact_stager import UploadLimits
from app.modules.software_management.domain.value_objects import SemVer


class _FakeRepo:
    def __init__(self, software: Software | None) -> None:
        self.software = software
        self.saved: list[Software] = []

    async def get(self, software_id: UUID) -> Software | None:
        return self.software

    async def save(self, software: Software) -> Software:
        self.saved.append(software)
        return software


class _FakeUow:
    def __init__(self, repo: _FakeRepo) -> None:
        self.software_repo = repo

    def read_only(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False


class _FakeStorage:
    def __init__(self) -> None:
        self.saved: dict[str, bytes] = {}
        self.deleted: list[str] = []

    def save(self, *, storage_key: str, source_path: Path) -> None:
        self.saved[storage_key] = source_path.read_bytes()

    def delete(self, *, storage_key: str) -> None:
        self.saved.pop(storage_key, None)
        self.deleted.append(storage_key)


class _RecordingPublisher:
    def __init__(self) -> None:
        self.published: list = []

    async def publish(self, events) -> None:
        self.published.extend(events)


def _software() -> Software:
    return Software.create(
        name="Pkg",
        description="desc",
        owner_id=uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
    )


async def _upload(service: SoftwareService, stager: LocalArtifactStager, **kwargs):
    content = kwargs.pop("content", b"abcd")
    upload = stager.stage(
        BytesIO(content),
        kwargs.pop("filename", "package.zip"),
        content_type="application/zip",
        limits=UploadLimits(max_size_bytes=1024),
    )
    try:
        return await service.upload_version(artifacts=[upload], **kwargs)
    finally:
        stager.discard(upload)


@pytest.fixture
def stager() -> LocalArtifactStager:
    return LocalArtifactStager()


async def test_upload_version_attaches_the_artifact_and_publishes(stager) -> None:
    software = _software()
    repo = _FakeRepo(software)
    publisher = _RecordingPublisher()
    service = SoftwareService(
        storage=_FakeStorage(),
        unit_of_work=_FakeUow(repo),
        event_publisher=publisher,
    )

    version = await _upload(
        service,
        stager,
        software_id=software.id,
        user_id=software.owner_id,
        version_number="1.0.0",
        release_notes="first",
    )

    assert version.status is VersionStatus.PUBLISHED
    assert [a.filename for a in version.artifacts] == ["package.zip"]
    assert repo.saved == [software]
    assert len(list(service._storage.saved)) == 1

    kinds = [type(e) for e in publisher.published]
    assert ArtifactAddedToVersion in kinds
    assert VersionAddedEvent in kinds
    assert VersionPublishedEvent in kinds
    # dispatch drains the aggregate
    assert software.pull_events() == []


async def test_traversal_filename_is_reduced_to_its_basename(stager) -> None:
    software = _software()
    service = SoftwareService(
        storage=_FakeStorage(),
        unit_of_work=_FakeUow(_FakeRepo(software)),
    )

    version = await _upload(
        service,
        stager,
        software_id=software.id,
        user_id=software.owner_id,
        version_number="2.0.0",
        release_notes="",
        filename="../../etc/passwd",
    )

    assert [a.filename for a in version.artifacts] == ["passwd"]


async def test_empty_upload_is_rejected(stager) -> None:
    software = _software()
    service = SoftwareService(
        storage=_FakeStorage(),
        unit_of_work=_FakeUow(_FakeRepo(software)),
    )

    with pytest.raises(SoftwareDomainError, match="empty"):
        await _upload(
            service,
            stager,
            software_id=software.id,
            user_id=software.owner_id,
            version_number="3.0.0",
            release_notes="",
            content=b"",
        )


async def test_download_dispatch_failure_does_not_fail_the_upload(stager) -> None:
    """The transaction already committed; a logging failure is not a 500."""

    class _Exploding:
        async def publish(self, events) -> None:
            raise RuntimeError("broker down")

    software = _software()
    service = SoftwareService(
        storage=_FakeStorage(),
        unit_of_work=_FakeUow(_FakeRepo(software)),
        event_publisher=_Exploding(),
    )

    version = await _upload(
        service,
        stager,
        software_id=software.id,
        user_id=software.owner_id,
        version_number="4.0.0",
        release_notes="",
    )

    assert version.status is VersionStatus.PUBLISHED
    assert SemVer.parse("4.0.0") == version.number
