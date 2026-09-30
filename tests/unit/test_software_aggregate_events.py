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

from app.modules.shared.enums import (
    AccessType,
    ArtifactStatus,
    SoftwareVisibility,
    VersionStatus,
)
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


def _version(software: Software, semver: str = "1.0.0") -> Version:
    return Version(
        id=uuid4(),
        software_id=software.id,
        number=SemVer.parse(semver),
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


def _exercise(command: str) -> tuple[Software, tuple[object, ...]]:
    """Run one state-changing command and return the software with its events.

    Prerequisite commands (``publish_version`` before ``deprecate_version``,
    an artifact before publishing a version) run first; their own events are
    drained so the assertions see only what the command under test recorded.
    """
    software = _software()
    version = _version(software)
    software.add_version(version)
    software.pull_events()

    def prereq() -> None:
        """Put the version in a state the command under test can act on."""
        software.add_artifact_to_version(version=version, artifact=_artifact(version))
        software.publish_version(version.id)
        software.pull_events()

    def has_artifact() -> None:
        """Everything ``publish_version`` needs except the publish itself."""
        software.add_artifact_to_version(version=version, artifact=_artifact(version))
        software.pull_events()

    match command:
        case "update_pricing":
            software.update_pricing(price_cents=500, currency="KES")
        case "change_visibility":
            software.change_visibility(SoftwareVisibility.PRIVATE)
        case "publish":
            software.publish()
        case "mark_deleted":
            software.mark_deleted(actor_id=software.owner_id)
        case "archive":
            software.archive()
        case "restore":
            software.mark_deleted(actor_id=software.owner_id)
            software.pull_events()
            software.restore()
        case "change_access_policy":
            software.change_access_policy(AccessType.PURCHASE_REQUIRED)
        case "add_version":
            software.add_version(_version(software, semver="2.0.0"))
        case "publish_version":
            has_artifact()
            software.publish_version(version.id)
        case "deprecate_version":
            prereq()
            software.deprecate_version(version.id)
        case "revoke_version":
            prereq()
            software.revoke_version(version.id)
        case "remove_version":
            software.remove_version(version.id)
        case "increment_download_count":
            software.increment_download_count()
        case _:
            raise AssertionError(f"unknown command: {command}")

    return software, software.pull_events()


@pytest.mark.parametrize(
    "command",
    [
        "update_pricing",
        "change_visibility",
        "publish",
        "mark_deleted",
        "archive",
        "restore",
        "change_access_policy",
        "add_version",
        "publish_version",
        "deprecate_version",
        "revoke_version",
        "remove_version",
        "increment_download_count",
    ],
)
def test_every_recorded_event_names_the_aggregate(command: str) -> None:
    """A missing ``aggregate_id`` is a TypeError at construction, not a silent gap.

    ``DomainEvent.aggregate_id`` is a required keyword-only field, so an event
    built without it raises where the command runs. These commands all run on
    the live upload, publish and download paths, so the exception would surface
    as a 500 after the caller had already mutated the aggregate.
    """
    software, events = _exercise(command)

    assert events, f"{command} recorded no event"
    for event in events:
        assert event.aggregate_id == software.id
        assert event.actor_id == software.owner_id
