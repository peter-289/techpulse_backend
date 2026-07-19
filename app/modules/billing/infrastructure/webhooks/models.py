from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class WebhookOutcome(str, Enum):
    """Canonical outcome of a provider webhook event.

    Gateways map their provider-specific event strings onto these three values.
    The HTTP adapter branches only on this enum, never on raw provider strings.
    """

    COMPLETED = "completed"
    FAILED = "failed"
    IGNORED = "ignored"


@dataclass(frozen=True, slots=True)
class ProviderWebhookEvent:
    """Normalized, provider-independent webhook event DTO.

    ``outcome`` is mandatory: every gateway adapter must classify its
    provider-specific event into a :class:`WebhookOutcome` before returning
    this object. ``event_type`` is retained only for observability.
    """

    provider_reference: str
    outcome: WebhookOutcome
    event_type: Optional[str] = None


__all__ = ["WebhookOutcome", "ProviderWebhookEvent"]
