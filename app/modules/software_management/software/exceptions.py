from dataclasses import dataclass


class SoftwareDomainError(Exception):
    """Base class for software domain exceptions."""


class SoftwareNotFoundError(SoftwareDomainError):
    """Raised when the requested software or version cannot be found."""


class SoftwareAccessDeniedError(SoftwareDomainError):
    """Raised when an actor is not allowed to perform the requested action."""


class OwnerCannotPurchaseError(SoftwareDomainError):
    """Raised when the owner attempts to purchase their own software."""


class DuplicatePurchaseError(SoftwareDomainError):
    """Raised when an actor attempts to purchase software they already own."""


class SoftwareArchivedError(SoftwareDomainError):
    """Raised when an operation is attempted against archived software."""


class SoftwareDeletedError(SoftwareDomainError):
    """Raised when an operation is attempted against deleted software."""


class SoftwareNotPublishedError(SoftwareDomainError):
    """Raised when a software or version is not available for publication use-cases."""


class VersionUnavailableError(SoftwareDomainError):
    """Raised when a version is not currently downloadable or usable."""


class DownloadDeniedError(SoftwareDomainError):
    """Raised when an actor is not permitted to download a software artifact."""


class InvalidStateTransitionError(SoftwareDomainError):
    """Raised when a domain aggregate transitions through an invalid state."""


class InvalidSemVerError(SoftwareDomainError):
    """Raised when semantic version data is invalid."""


class ArtifactIntegrityError(SoftwareDomainError):
    """Raised when an uploaded artifact fails integrity checks."""


class MalwareScanPendingError(SoftwareDomainError):
    """Raised when malware scanning is still pending for an artifact."""


@dataclass(frozen=True, slots=True)
class SoftwareValidationError(SoftwareDomainError):
    message: str

    def __str__(self) -> str:
        return self.message


class RepositoryUnavailableError(SoftwareDomainError):
    """Raised when the repository layer cannot service a domain request."""
