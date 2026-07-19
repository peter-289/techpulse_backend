from __future__ import annotations

from app.modules.software_management.software.exceptions import SoftwareDomainError


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
