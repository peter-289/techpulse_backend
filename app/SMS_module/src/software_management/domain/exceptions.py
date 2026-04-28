from __future__ import annotations

from dataclasses import dataclass


class DomainError(Exception):
    pass


class NotFoundError(DomainError):
    pass


class ConcurrencyError(DomainError):
    pass


class InvalidStateTransitionError(DomainError):
    pass


class InvalidSemVerError(DomainError):
    pass


class ArtifactIntegrityError(DomainError):
    pass


class AccessDeniedError(DomainError):
    pass


class MalwareScanPendingError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class ValidationError(DomainError):
    message: str

    def __str__(self) -> str:
        return self.message
