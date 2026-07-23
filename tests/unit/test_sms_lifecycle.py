import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.modules.software_management.domain.entities import Artifact, ArtifactStatus, SemVer, Software, SoftwareVisibility, Version, VersionStatus
from app.modules.software_management.domain.events.events import malware_scan_success
from app.modules.software_management.domain.exceptions import DownloadDeniedError
from app.modules.software_management.application.services.software_service import SoftwareService


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

    assert software.price.amount_cents == 1999
    assert software.price.currency.code == "KES"

    software.update_pricing(price_cents=-50, currency="usd")

    assert software.price.amount_cents == 0
    assert software.price.currency.code == "USD"


def test_paid_download_requires_purchase() -> None:
    owner_id = UUID(int=1)
    buyer_user_id = UUID(int=2)
    software = Software.create(
        name="Paid Package",
        description="Useful package",
        owner_id=owner_id,
        visibility=SoftwareVisibility.PUBLIC,
        price_cents=1999,
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
        storage_key="software/paid/1.0.0/package.zip",
        sha256="b" * 64,
        size_bytes=3,
        mime_type="application/zip",
        filename="package.zip",
        status=ArtifactStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    version.attach_artifact(artifact)
    software.add_version(version)
    software.publish_version(version.id)

    class Repository:
        async def get(self, software_id):
            return software

        async def increment_download_count(self, version_id):
            raise AssertionError("download count must not increment for denied downloads")

    class Session:
        async def scalar(self, statement):
            return None

        async def commit(self):
            raise AssertionError("session must not commit for denied downloads")

    class Storage:
        def create_download_url(self, storage_key):
            return f"https://example.com/download/{storage_key}"

    class _ReadOnlyCM:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass

    class SoftwareRepo:
        async def get(self, software_id):
            return software

        async def has_purchase(self, software_id, user_id):
            return False

        async def increment_download_count(self, version_id):
            raise AssertionError("download count must not increment for denied downloads")

    class UnitOfWork:
        def __init__(self):
            self.software_repo = SoftwareRepo()
        def read_only(self):
            return _ReadOnlyCM()

    service = SoftwareService.__new__(SoftwareService)
    service._uow = UnitOfWork()
    service.repository = Repository()
    service.session = Session()
    service.storage = Storage()

    async def run() -> None:
        try:
            await service.download_url(
                software_id=software.id,
                version_number="1.0.0",
                user_id=buyer_user_id,
            )
        except DownloadDeniedError:
            return
        raise AssertionError("paid download should require a purchase")

    asyncio.run(run())
