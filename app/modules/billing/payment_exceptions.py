from __future__ import annotations


class PaymentNotFoundError(Exception):
    """Raised when a payment cannot be found by id or provider reference."""


class DuplicatePendingPaymentError(Exception):
    """Raised when attempting to create a pending duplicate payment for the same buyer and subject."""


class InvalidPaymentStateTransitionError(Exception):
    """Raised when a payment state transition is not allowed by the domain aggregate."""

