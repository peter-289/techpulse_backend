from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.modules.shared.enums import PurchaseStatus


class PurchaseResponse(BaseModel):
    """API DTO describing an owned software purchase."""

    purchase_id: UUID
    software_id: UUID
    software_name: str
    amount_cents: int
    currency: str
    status: PurchaseStatus
    purchased_at: datetime
    refunded_at: datetime | None = None
    revoked_at: datetime | None = None
    last_activity_at: datetime | None = None


__all__ = ["PurchaseResponse"]
