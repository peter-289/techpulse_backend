from __future__ import annotations


class PaymentNotFoundError(Exception):
    """Raised when a payment cannot be found by id or provider reference."""


class DuplicatePendingPaymentError(Exception):
    """Raised when attempting to create a pending duplicate payment."""


class InvalidPaymentStateTransitionError(Exception):
    """Raised when a payment state transition is not allowed by the aggregate."""


class PaymentAccessDenied(Exception):
    """Raised when a buyer attempts to access a payment they do not own.

    A domain-layer authorization violation. The HTTP adapter is responsible
    for translating it into a ``403 Forbidden``.
    """


class InvalidProviderReference(Exception):
    """Raised when a webhook references a provider reference that cannot be resolved."""


class WebhookProcessingError(Exception):
    """Raised when a verified webhook event cannot be applied to local state."""


__all__ = [
    "PaymentNotFoundError",
    "DuplicatePendingPaymentError",
    "InvalidPaymentStateTransitionError",
    "PaymentAccessDenied",
    "InvalidProviderReference",
    "WebhookProcessingError",
]
