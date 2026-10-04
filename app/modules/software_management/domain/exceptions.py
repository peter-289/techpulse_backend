from dataclasses import dataclass


class SoftwareDomainError(Exception):
    """Base class for software domain exceptions."""


class SoftwareNotFoundError(SoftwareDomainError):
    """Raised when the requested software or version cannot be found."""


class VersionNotFoundError(SoftwareNotFoundError):
    """Raised when a version cannot be found."""


class ArtifactNotFoundError(SoftwareNotFoundError):
    """Raised when an artifact cannot be found."""


class VersionNotDownloadableError(SoftwareDomainError):
    """Raised when a version is not in a downloadable state."""


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


class InvalidDownloadTokenError(SoftwareAccessDeniedError):
    """Raised when a signed download URL is missing, malformed or not authentic.

    Distinct from :class:`ExpiredDownloadTokenError` because the remedy differs:
    an expired link is fixed by requesting a new one, a forged one is not.
    """


class ExpiredDownloadTokenError(SoftwareAccessDeniedError):
    """Raised when a signed download URL carries a valid signature but has lapsed."""


class UnsafeStorageKeyError(SoftwareAccessDeniedError):
    """Raised when an authentic signed URL names a key that is not addressable.

    A sibling of :class:`InvalidDownloadTokenError`, not a subclass of it, and
    deliberately kept apart: the token was genuine, so the client did nothing
    wrong, and the difference is what tells an operator this is a probing request
    against the storage layout rather than a client with a broken link. The two
    are also reported differently -- a forged token is the client's problem, an
    unaddressable key is logged as a security event.
    """


class ArtifactStorageUnreadableError(SoftwareDomainError):
    """Raised when a stored artifact exists but cannot be read back.

    The adapter's message names the failure, which can include the container's
    filesystem layout. That detail is not returned to the client; this error
    carries only a generic message so no storage path escapes the boundary.
    """


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


class CategoryDomainError(SoftwareDomainError):
    """Base class for all category domain exceptions."""


class CategoryNotFoundError(CategoryDomainError):
    """Raised when a requested category does not exist."""


class DuplicateCategoryError(CategoryDomainError):
    """Raised when attempting to create or rename to a name that already exists."""


class CategoryInUseError(CategoryDomainError):
    """Raised when attempting to delete a category that still references software."""


class CategoryDeletedError(CategoryDomainError):
    """Raised when attempting to mutate a soft-deleted category."""


class CategoryRepositoryUnavailableError(CategoryDomainError):
    """Raised when the repository layer cannot service a category request."""
