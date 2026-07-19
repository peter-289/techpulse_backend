
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
    """Exception raised when an error occurs while processing a payment request."""
    pass

class DuplicatePaymentError(DomainError):
    """Exception raised when payment is done twice."""
    pass

class PurchaseDomainError(DomainError):
    """Raised when an error involving the purchase domain occurs."""
    pass

class DuplicatePurchaseError(DomainError):
    """Exception raised when payment is done twice."""
    pass

class RepositoryUnavailableError(DomainError):
    """Raised when a required repository is not available."""
    pass

class PurchaseNotFoundError(DomainError):
    """Raised when a purchase could not be found."""
    pass

class OwnerCannotPurchaseError(DomainError):
    """Raised when an owner of a product tries to purchase it."""
    pass


class PaymentProviderGatewayError(Exception):
    """Base exception for provider gateway errors."""


class PaymentGatewayUnavailableError(PaymentProviderGatewayError):
    """Raised when the provider cannot be reached or is unavailable."""


class PaymentProviderTimeoutError(PaymentGatewayUnavailableError):
    """Raised when a provider request times out."""


class PaymentProviderAuthenticationError(PaymentGatewayUnavailableError):
    """Raised when authentication with a provider fails."""


class InvalidWebhookSignatureError(PaymentProviderGatewayError):
    """Raised when a webhook signature fails verification."""


class PaymentProviderRequestError(PaymentProviderGatewayError):
    """Raised when a provider request fails for a non-timeout reason."""


class RefundFailedError(PaymentProviderGatewayError):
    """Raised when issuing a refund fails."""

class PaymentGatewayRegistryError(Exception):
    """Base exception for payment gateway registry configuration and lookup errors."""


class InvalidGatewayConfigurationError(PaymentGatewayRegistryError):
    """Raised when the gateway registry is constructed with invalid configuration."""


class DuplicateGatewayRegistrationError(PaymentGatewayRegistryError):
    """Raised when the same payment provider is registered more than once."""


class UnsupportedPaymentProviderError(PaymentGatewayRegistryError):
    """Raised when attempting to resolve an unsupported payment provider."""
