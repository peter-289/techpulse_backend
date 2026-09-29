"""Aggregate behaviour added in Phase 3.

Two things used to be done by application services that are aggregate
responsibilities: bumping a version's download counter (plus its lock) and
attaching an artifact to a version. Both are now methods on the aggregate, and
both are where the corresponding domain event is recorded, so the state change
and the event cannot come apart.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.modules.shared.enums import ArtifactStatus, SoftwareVisibility, VersionStatus
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.events.events import ArtifactAddedToVersion
from app.modules.software_management.domain.exceptions import InvalidStateTransitionError
from app.modules.software_management.domain.value_objects import SemVer


def _software() -> Software:
    return Software.create(
        name="Pkg",
        description="desc",
        owner_id=uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
    )


def _version(software: Software) -> Version:
    return Version(
        id=uuid4(),
        software_id=software.id,
        number=SemVer.parse("1.0.0"),
        release_notes="",
        status=VersionStatus.DRAFT,
        lock_version=0,
    )


def _artifact(version: Version, *, status: ArtifactStatus = ArtifactStatus.ACTIVE) -> Artifact:
    now = datetime.now(timezone.utc)
    return Artifact(
        id=uuid4(),
        version_id=version.id,
        storage_key="software/x/versions/y/1/pkg.zip",
        sha256="a" * 64,
        size_bytes=10,
        mime_type="application/zip",
        filename="pkg.zip",
        status=status,
        created_at=now,
        updated_at=now,
    )


def test_record_download_increments_the_counter_and_the_lock() -> None:
    software = _software()
    version = _version(software)

    version.record_download()

    assert version.download_count == 1
    assert version.lock_version == 1


def test_attaching_an_artifact_records_an_event() -> None:
    software = _software()
    version = _version(software)
    artifact = _artifact(version)

    software.add_artifact_to_version(version=version, artifact=artifact)

    assert version.artifacts == (artifact,)
    events = software.pull_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ArtifactAddedToVersion)
    assert event.artifact_id == artifact.id
    assert event.version_id == version.id
    assert event.software_id == software.id


def test_attaching_an_unscanned_artifact_is_rejected() -> None:
    software = _software()
    version = _version(software)
    artifact = _artifact(version, status=ArtifactStatus.QUARANTINED)

    with pytest.raises(InvalidStateTransitionError):
        software.add_artifact_to_version(version=version, artifact=artifact)

    assert version.artifacts == ()
    assert software.pull_events() == []


def test_pull_events_drains_the_queue() -> None:
    software = _software()
    version = _version(software)

    software.add_artifact_to_version(version=version, artifact=_artifact(version))

    assert len(software.pull_events()) == 1
    assert software.pull_events() == []
