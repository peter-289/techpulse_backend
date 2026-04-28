from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from ..domain.entities.software import Software
from ..domain.events import DomainEvent, MalwareScanRequestedEvent


@dataclass(frozen=True, slots=True)
class PresignedUpload:
    url: str
    fields: dict[str, str]
    expires_in_seconds: int


class SoftwareRepositoryPort(ABC):
    @abstractmethod
    async def get(self, software_id: UUID) -> Software | None:
        raise NotImplementedError

    @abstractmethod
    async def save(self, software: Software) -> None:
        raise NotImplementedError

    @abstractmethod
    async def list_for_owner(self, owner_id: UUID) -> list[Software]:
        raise NotImplementedError


class StoragePort(ABC):
    @abstractmethod
    async def create_presigned_upload(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUpload:
        raise NotImplementedError

    @abstractmethod
    async def create_presigned_download(
        self,
        storage_key: str,
        expires_in_seconds: int = 900,
    ) -> str:
        raise NotImplementedError

    @abstractmethod
    async def delete_object(self, storage_key: str) -> None:
        raise NotImplementedError


class SubscriptionPort(ABC):
    @abstractmethod
    async def verify_access(self, user_id: UUID, software_id: UUID) -> bool:
        raise NotImplementedError


class SubscriptionChecker(SubscriptionPort):
    """Host application should implement this interface."""


class PaymentPort(ABC):
    @abstractmethod
    async def record_download_charge(
        self,
        user_id: UUID,
        software_id: UUID,
        version_id: UUID,
    ) -> None:
        raise NotImplementedError


class MalwareScanQueuePort(ABC):
    @abstractmethod
    async def enqueue_scan(self, event: MalwareScanRequestedEvent) -> None:
        raise NotImplementedError


class EventPublisherPort(ABC):
    @abstractmethod
    async def publish(self, events: list[DomainEvent]) -> None:
        raise NotImplementedError
