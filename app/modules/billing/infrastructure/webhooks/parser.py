"""Provider-agnostic webhook event classification.

Adapters delegate outcome classification here so the keyword heuristics live in
one place. Each adapter is still responsible for extracting the event type and
reference from its provider-specific payload; this module only maps an event
type string onto a canonical :class:`WebhookOutcome`.
"""

from __future__ import annotations

from app.modules.billing.infrastructure.webhooks.models import WebhookOutcome

# Tokens that indicate a successful/completed payment.
_COMPLETED_TOKENS = ("succeed", "complete", "paid", "captured", "fulfill")
# Tokens that indicate a failed/cancelled/refunded payment.
_FAILED_TOKENS = ("fail", "cancel", "expire", "refund", "void")


def classify_event(event_type: str) -> WebhookOutcome:
    """Classify a provider event-type string into a canonical outcome."""
    et = (event_type or "").lower()
    if any(token in et for token in _COMPLETED_TOKENS):
        return WebhookOutcome.COMPLETED
    if any(token in et for token in _FAILED_TOKENS):
        return WebhookOutcome.FAILED
    return WebhookOutcome.IGNORED


__all__ = ["classify_event", "WebhookOutcome"]
