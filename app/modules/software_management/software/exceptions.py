from dataclasses import dataclass


class SoftwareDomainError(Exception):
    pass


class SoftwareNotFoundError(SoftwareDomainError):
    pass


class SoftwareAccessDeniedError(SoftwareDomainError):
    pass


class InvalidStateTransitionError(SoftwareDomainError):
    pass


class InvalidSemVerError(SoftwareDomainError):
    pass


class ArtifactIntegrityError(SoftwareDomainError):
    pass


class MalwareScanPendingError(SoftwareDomainError):
    pass


@dataclass(frozen=True, slots=True)
class SoftwareValidationError(SoftwareDomainError):
    message: str

    def __str__(self) -> str:
        return self.message
