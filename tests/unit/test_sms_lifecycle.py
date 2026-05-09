from datetime import datetime, timezone
from uuid import uuid4

from app.domain.software import Artifact, ArtifactStatus, SemVer, Software, SoftwareVisibility, Version, VersionStatus
from app.domain.software.events import malware_scan_success


def test_sms_version_becomes_downloadable_only_after_scan_and_publish() -> None:
    software = Software.create(
        name="Package",
        description="Useful package",
        owner_id=uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
    )
    version = Version(
        id=uuid4(),
        software_id=software.id,
        number=SemVer.parse("1.0.0"),
        release_notes="Initial release",
        status=VersionStatus.DRAFT,
        lock_version=0,
    )
    artifact = Artifact(
        id=uuid4(),
        version_id=version.id,
        storage_key="software/package/1.0.0/package.zip",
        sha256="a" * 64,
        size_bytes=3,
        mime_type="application/zip",
        filename="package.zip",
        status=ArtifactStatus.UPLOADING,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    software.add_version(version)
    version.attach_artifact(artifact)
    assert not version.is_downloadable()

    artifact.process_malware_scan_success(
        malware_scan_success(
            software_id=software.id,
            version_id=version.id,
            artifact_id=artifact.id,
        )
    )
    software.publish_version(version.id)

    assert version.status == VersionStatus.PUBLISHED
    assert version.is_downloadable()
    assert software.latest_downloadable() == version


def test_sms_owner_controlled_pricing_is_normalized() -> None:
    software = Software.create(
        name="Paid Package",
        description="Useful package",
        owner_id=uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
        price_cents=1999,
        currency="kes",
    )

    assert software.price_cents == 1999
    assert software.currency == "KES"

    software.update_pricing(price_cents=-50, currency="usd")

    assert software.price_cents == 0
    assert software.currency == "USD"
