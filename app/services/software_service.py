from __future__ import annotations

import hashlib
import hmac
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO
from urllib.parse import quote
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.domain.software import Artifact, ArtifactStatus, SemVer, Software, SoftwareVisibility, Version, VersionStatus
from app.domain.software.events import malware_scan_failed, malware_scan_requested, malware_scan_success
from app.domain.software.exceptions import SoftwareAccessDeniedError, SoftwareDomainError, SoftwareNotFoundError
from app.models.payment import SoftwarePaymentModel, SoftwarePurchaseModel
from app.repositories.software import SoftwareRepository
from app.services.malware_scanner import MalwareScanner, get_malware_scanner
from app.services.payment_provider import PaymentProvider, get_payment_provider


@dataclass(frozen=True, slots=True)
class UploadedFile:
    """ Upload file data shape"""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    temp_path: Path


class LocalSoftwareStorage:
    """
     Storage management for local disk storage
    """
    def __init__(self, storage_root: str | Path, signing_secret: str, backend_url: str) -> None:
        self.root = Path(storage_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.encode("utf-8")
        self._backend_url = backend_url.rstrip("/")

    def resolve_path(self, storage_key: str) -> Path:
        """ Resolve path if it exists using a storage key"""
        key = self._validate_storage_key(storage_key)
        target = (self.root / key).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError("Invalid storage key path traversal")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def save_path(self, storage_key: str, source_path: Path) -> None:
        target = self.resolve_path(storage_key)
        with source_path.open("rb") as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)

    def read(self, storage_key: str) -> tuple[bytes, str]:
        target = self.resolve_path(storage_key)
        if not target.exists():
            raise FileNotFoundError(storage_key)
        return target.read_bytes(), "application/octet-stream"

    def delete(self, storage_key: str) -> None:
        target = self.resolve_path(storage_key)
        target.unlink(missing_ok=True)

    def create_download_url(self, storage_key: str, expires_in_seconds: int = 900) -> str:
        key = self._validate_storage_key(storage_key)
        expires_at = int(time.time()) + expires_in_seconds
        token = self._sign(storage_key=key, expires_at=expires_at, method="GET")
        return (
            f"{self._backend_url}/api/v1/software-management/storage/download/"
            f"{quote(key, safe='')}?expires={expires_at}&token={token}"
        )

    def verify_signed_request(self, *, storage_key: str, expires: int, token: str, method: str) -> bool:
        key = self._validate_storage_key(storage_key)
        if expires < int(time.time()):
            return False
        expected = self._sign(storage_key=key, expires_at=expires, method=method.upper())
        return hmac.compare_digest(expected, token)

    def _validate_storage_key(self, storage_key: str) -> str:
        key = storage_key.strip()
        if not key or key.startswith("/") or any(ord(char) < 32 for char in key):
            raise ValueError("Invalid storage key")
        return key

    def _sign(self, *, storage_key: str, expires_at: int, method: str) -> str:
        payload = f"{method}:{storage_key}:{expires_at}".encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


class SoftwareService:
    def __init__(
        self,
        session: Session,
        storage: LocalSoftwareStorage | None = None,
        payment_provider: PaymentProvider | None = None,
        malware_scanner: MalwareScanner | None = None,
    ):
        self.session = session
        self.repository = SoftwareRepository(session)
        self.payment_provider = payment_provider or get_payment_provider()
        self.malware_scanner = malware_scanner or get_malware_scanner()
        self.storage = storage or LocalSoftwareStorage(
            Path(settings.UPLOAD_ROOT) / "software_management",
            settings.SECRET_KEY,
            settings.BACKEND_URL,
        )

    @staticmethod
    def actor_uuid(user_id: int) -> UUID:
        return UUID(int=max(0, int(user_id)))

    @staticmethod
    def actor_int(user_id: UUID) -> int:
        return int(user_id.int)

    @staticmethod
    def spool_file(file: BinaryIO, filename: str, chunk_size: int = 1024 * 1024) -> UploadedFile:
        digest = hashlib.sha256()
        total = 0
        suffix = Path(filename or "package.bin").suffix
        temp = NamedTemporaryFile(delete=False, suffix=suffix)
        temp_path = Path(temp.name)
        try:
            with temp:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    temp.write(chunk)
            return UploadedFile(
                filename=filename or "package.bin",
                content_type="application/octet-stream",
                size_bytes=total,
                sha256=digest.hexdigest(),
                temp_path=temp_path,
            )
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    def list_visible(self, *, user_id: int, limit: int = 100) -> list[Software]:
        """ List packages that are visible for users."""
        return self.repository.list_visible_for_user(self.actor_uuid(user_id), limit=limit)

    def get(self, software_id: UUID) -> Software:
        """ Get software """
        software = self.repository.get(software_id)
        if software is None:
            raise SoftwareNotFoundError("Software not found")
        return software

    def create(
        self,
        *,
        user_id: int,
        name: str,
        description: str,
        visibility: str,
        price_cents: int = 0,
        currency: str = "USD",
    ) -> Software:
        """ Create a software"""
        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=self.actor_uuid(user_id),
            visibility=SoftwareVisibility(visibility),
            price_cents=price_cents,
            currency=currency,
        )
        self.repository.save(software)
        self.session.commit()
        return software

    def upload_package(
        self,
        *,
        user_id: int,
        name: str,
        description: str,
        version_number: str,
        is_public: bool,
        price_cents: int = 0,
        currency: str = "USD",
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> tuple[Software, Version]:
        """ Upload a software package."""
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        
        # Create a software object
        software = Software.create(
            name=name.strip(),
            description=description.strip(),
            owner_id=self.actor_uuid(user_id),
            visibility=SoftwareVisibility.PUBLIC if is_public else SoftwareVisibility.PRIVATE,
            price_cents=price_cents,
            currency=currency,
        )

        version = self._build_scanned_version(
            software=software,
            version_number=version_number,
            release_notes="Initial upload",
            uploaded=uploaded,
            content_type=content_type,
        )
        software.add_version(version)
        if version.artifact and version.artifact.status == ArtifactStatus.ACTIVE:
            software.publish_version(version.id)

        self.repository.save(software)
        self.session.commit()
        return software, version

    def upload_version(
        self,
        *,
        software_id: UUID,
        user_id: int,
        version_number: str,
        release_notes: str,
        uploaded: UploadedFile,
        content_type: str | None,
        is_admin: bool = False,
    ) -> Version:
        if uploaded.size_bytes <= 0:
            raise SoftwareDomainError("Uploaded file is empty.")
        software = self.require_owner(software_id=software_id, user_id=user_id, is_admin=is_admin)
        version = self._build_scanned_version(
            software=software,
            version_number=version_number,
            release_notes=release_notes.strip() or "Version upload",
            uploaded=uploaded,
            content_type=content_type,
        )
        software.add_version(version)
        if version.artifact and version.artifact.status == ArtifactStatus.ACTIVE:
            software.publish_version(version.id)
        self.repository.save(software)
        self.session.commit()
        return version

    def _build_scanned_version(
        self,
        *,
        software: Software,
        version_number: str,
        release_notes: str,
        uploaded: UploadedFile,
        content_type: str | None,
    ) -> Version:
        version = Version(
            id=uuid4(),
            software_id=software.id,
            number=SemVer.parse(version_number),
            release_notes=release_notes,
            status=VersionStatus.DRAFT,
            lock_version=0,
        )
        artifact = Artifact(
            id=uuid4(),
            version_id=version.id,
            storage_key=f"software/{software.id}/versions/{version.id}/{uuid4()}/{uploaded.filename}",
            sha256=uploaded.sha256,
            size_bytes=uploaded.size_bytes,
            mime_type=content_type or uploaded.content_type,
            filename=uploaded.filename,
            status=ArtifactStatus.UPLOADING,
            created_at=version.created_at,
            updated_at=version.updated_at,
        )
        version.attach_artifact(artifact)
        malware_scan_requested(software.id, version.id, artifact.id, artifact.storage_key)
        self.storage.save_path(artifact.storage_key, uploaded.temp_path)
        scan = self.malware_scanner.scan_file(
            file_path=uploaded.temp_path,
            filename=uploaded.filename,
            sha256=uploaded.sha256,
            content_type=content_type or uploaded.content_type,
        )
        if scan.is_clean:
            artifact.process_malware_scan_success(malware_scan_success(software.id, version.id, artifact.id))
        else:
            artifact.process_malware_scan_failed(
                malware_scan_failed(
                    software.id,
                    version.id,
                    artifact.id,
                    scan.reason or "Malware scanner rejected this artifact.",
                )
            )
        return version

    def update_pricing(
        self,
        *,
        software_id: UUID,
        user_id: int,
        price_cents: int,
        currency: str,
        is_admin: bool = False,
    ) -> Software:
        software = self.require_owner(software_id=software_id, user_id=user_id, is_admin=is_admin)
        software.update_pricing(price_cents=price_cents, currency=currency)
        self.repository.save(software)
        self.session.commit()
        return software

    def require_owner(self, *, software_id: UUID, user_id: int, is_admin: bool = False) -> Software:
        software = self.get(software_id)
        if not is_admin and software.owner_id != self.actor_uuid(user_id):
            raise SoftwareAccessDeniedError("Only the owner or an admin can modify this software.")
        return software

    def deprecate_version(self, *, software_id: UUID, version_number: str, user_id: int, is_admin: bool) -> Version:
        software = self.require_owner(software_id=software_id, user_id=user_id, is_admin=is_admin)
        version = software.get_version_by_semver(SemVer.parse(version_number))
        software.deprecate_version(version.id)
        self.repository.save(software)
        self.session.commit()
        return version

    def revoke_version(self, *, software_id: UUID, version_number: str, user_id: int, is_admin: bool) -> Version:
        software = self.require_owner(software_id=software_id, user_id=user_id, is_admin=is_admin)
        version = software.get_version_by_semver(SemVer.parse(version_number))
        software.revoke_version(version.id)
        self.repository.save(software)
        self.session.commit()
        return version

    def download_url(self, *, software_id: UUID, version_number: str, user_id: int) -> str:
        software = self.get(software_id)
        actor = self.actor_uuid(user_id)
        if software.visibility == SoftwareVisibility.PRIVATE and software.owner_id != actor:
            raise SoftwareAccessDeniedError("User is not entitled to this software.")
        if software.price_cents > 0 and software.owner_id != actor and not self.has_purchase(software_id=software_id, user_id=user_id):
            raise SoftwareAccessDeniedError("Purchase is required before downloading this software.")
        version = software.get_version_by_semver(SemVer.parse(version_number))
        if not version.is_downloadable() or version.artifact is None:
            raise SoftwareNotFoundError("Requested version is not downloadable.")
        self.repository.increment_download_count(version.id)
        self.session.commit()
        return self.storage.create_download_url(version.artifact.storage_key)

    def has_purchase(self, *, software_id: UUID, user_id: int) -> bool:
        buyer_id = str(self.actor_uuid(user_id))
        stmt = select(SoftwarePurchaseModel.id).where(
            SoftwarePurchaseModel.software_id == str(software_id),
            SoftwarePurchaseModel.buyer_id == buyer_id,
        )
        return self.session.scalar(stmt) is not None

    def create_checkout(self, *, software_id: UUID, user_id: int) -> SoftwarePaymentModel:
        software = self.get(software_id)
        buyer_id = self.actor_uuid(user_id)
        if software.owner_id == buyer_id:
            raise SoftwareDomainError("Owners already have access to their own software.")
        if software.visibility == SoftwareVisibility.PRIVATE:
            raise SoftwareAccessDeniedError("This software is private and cannot be purchased.")
        if software.price_cents <= 0:
            raise SoftwareDomainError("This software is free and does not require checkout.")
        if self.has_purchase(software_id=software_id, user_id=user_id):
            raise SoftwareDomainError("You already own this software.")

        existing = self.session.scalar(
            select(SoftwarePaymentModel).where(
                SoftwarePaymentModel.software_id == str(software.id),
                SoftwarePaymentModel.buyer_id == str(buyer_id),
                SoftwarePaymentModel.status == "pending",
            )
        )
        if existing:
            return existing

        now = datetime.now(timezone.utc)
        payment_id = str(uuid4())
        intent = self.payment_provider.create_intent(
            payment_id=payment_id,
            amount_cents=software.price_cents,
            currency=software.currency,
            description=f"Project purchase: {software.name}",
            buyer_id=str(buyer_id),
            owner_id=str(software.owner_id),
        )
        payment = SoftwarePaymentModel(
            id=payment_id,
            software_id=str(software.id),
            buyer_id=str(buyer_id),
            owner_id=str(software.owner_id),
            amount_cents=software.price_cents,
            currency=software.currency,
            status=intent.status,
            provider=intent.provider,
            provider_reference=intent.provider_reference,
            created_at=now,
            updated_at=now,
        )
        self.session.add(payment)
        self.session.commit()
        self.session.refresh(payment)
        return payment

    def confirm_checkout(self, *, payment_id: UUID, user_id: int) -> SoftwarePaymentModel:
        buyer_id = str(self.actor_uuid(user_id))
        payment = self.session.get(SoftwarePaymentModel, str(payment_id))
        if payment is None or payment.buyer_id != buyer_id:
            raise SoftwareNotFoundError("Payment not found.")
        if payment.status == "completed":
            return payment
        if payment.status != "pending":
            raise SoftwareDomainError("Only pending payments can be confirmed.")

        intent = self.payment_provider.confirm_intent(provider_reference=payment.provider_reference or payment.id)
        if intent.status != "completed":
            payment.status = intent.status
            payment.updated_at = datetime.now(timezone.utc)
            self.session.commit()
            self.session.refresh(payment)
            return payment

        now = datetime.now(timezone.utc)
        payment.status = "completed"
        payment.updated_at = now
        payment.completed_at = now
        purchase = SoftwarePurchaseModel(
            id=str(uuid4()),
            software_id=payment.software_id,
            buyer_id=payment.buyer_id,
            owner_id=payment.owner_id,
            payment_id=payment.id,
            amount_cents=payment.amount_cents,
            currency=payment.currency,
            purchased_at=now,
        )
        self.session.merge(purchase)
        self.session.commit()
        self.session.refresh(payment)
        return payment
