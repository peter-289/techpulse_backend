
class DomainError(Exception):
    """Base exception for all domain errors.
    This is the root exception for all domain layer errors. Services should catch
    this exception and convert it to appropriate HTTP responses.
    """
    def __init__(self, message: str | None = None):
        """Initialize domain error with message.
        Args:
            message: Error message.
        """
        super().__init__(message or "Domain error")


class NotFoundError(DomainError):
    """Exception raised when a requested resource is not found in the domain."""
    pass

class UnauthorizedError(DomainError):
    """ Exception raised when server fail to validate client credentials."""
    pass

class ConflictError(DomainError):
    """Exception raised when a domain operation conflicts with existing state."""
    pass

class ValidationError(DomainError):
    """Exception raised when domain data fails validation rules."""
    pass

class PermissionError(DomainError):
    """Exception raised when a user lacks required permissions for an operation."""
    pass


class ExternalServiceError(DomainError):
    """Exception raised when an external dependency fails."""
    pass

class TooManyRequestsError(DomainError):
    """Exception raised when too many requests are made to an API."""
    pass

class InvalidCurrencyError(DomainError):
    """Exception raised when currency type is invalid."""
    pass

class InvalidMoneyError(DomainError):
    """Exception raised when money values are invalid."""
    pass

class PaymentDomainError(DomainError):
    """Exception raised when an error occors while processing a payment request."""
    pass