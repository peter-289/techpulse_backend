"""The security context's domain exceptions.

The audit trail is written on every API request, so the repository failures
here are deliberately coarse: a caller that cannot record the fact gets one
exception type and no partially-applied state, because the alternative is a
request that appears to have been audited and was not.
"""

from __future__ import annotations


class SecurityDomainError(Exception):
    """Base class for security context domain exceptions."""


class AuditEventInvalidError(SecurityDomainError):
    """Raised when an audit event does not describe a well-formed request."""


class SecurityAlertError(SecurityDomainError):
    """Base class for security alert failures."""


class AlertAlreadyAcknowledgedError(SecurityAlertError):
    """Raised when acknowledging an alert that has already been acknowledged."""


class AuditRepositoryUnavailableError(SecurityDomainError):
    """Raised when the audit repository cannot service a request.

    Named for the repository rather than the database on purpose: the
    application layer must not know which store is behind it, and Phase 3's
    removal of a duplicate ``except SQLAlchemyError`` in two places is the
    precedent for translating in exactly one place.
    """
