from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.modules.billing.domain.value_objects import Money
from app.modules.shared.enums import PaymentProvider, PaymentStatus


@dataclass(frozen=True, slots=True)
class PaymentSummary:
    """Lightweight projection used for payment history and billing pages.

    This is a query result (read model), not a domain entity. It lives in the
    application layer and carries no behavior.
    """

    payment_id: UUID
    software_id: UUID
    software_name: str
    amount: Money
    provider: PaymentProvider
    status: PaymentStatus
    created_at: datetime


__all__ = ["PaymentSummary"]
