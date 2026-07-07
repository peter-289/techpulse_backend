from __future__ import annotations

from pydantic import BaseModel
from uuid import UUID
from datetime import datetime


class OwnedSoftwareResponse(BaseModel):
    software_id: UUID
    name: str
    description: str

    latest_version: str | None

    visibility: str

    price_cents: int
    currency: str

    purchase_status: str

    purchased_at: datetime

    created_at: datetime


class PurchaseResponse(BaseModel):
    purchase_id: UUID
    software_id: UUID
    software_name: str

    amount_cents: int
    currency: str

    status: str

    purchased_at: datetime
    refunded_at: datetime | None
    revoked_at: datetime | None
    last_activity_at: datetime