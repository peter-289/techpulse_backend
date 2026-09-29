"""Translation from software_management domain exceptions to HTTP responses.

The domain raises typed errors; the transport needs status codes. That mapping
is a boundary concern, so it lives here in the API layer rather than in the
application services (which must stay framework-free per ARCHITECTURE.md 3.3)
or in the global handler registry (which only knows the base types).
"""

from __future__ import annotations

from fastapi import HTTPException, status

from app.modules.software_management.domain.exceptions import (
    SoftwareAccessDeniedError,
    SoftwareDomainError,
    SoftwareNotFoundError,
)


def http_error(exc: SoftwareDomainError) -> HTTPException:
    """Map a software_management domain error to an ``HTTPException``.

    Subclass order matters: the more specific cases are tested first, so
    ``SoftwareNotFoundError`` does not fall through to the generic 400.
    """
    if isinstance(exc, SoftwareAccessDeniedError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, SoftwareNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
