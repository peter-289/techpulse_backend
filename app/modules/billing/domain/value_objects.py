from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping
from uuid import UUID

from pydantic import BaseModel, Field

from app.exceptions.exceptions import InvalidCurrencyError, InvalidMoneyError
from app.modules.shared.enums import (
    PaymentResourceType,
    PurchaseStatus,
)


@dataclass(frozen=True, slots=True)
class PaymentSubject:
    resource_type: PaymentResourceType
    resource_id: UUID
    description: str | None = None


@dataclass(slots=True)
class PaymentProviderDetails:
    reference: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Currency:
    """Immutable ISO 4217 currency code value object."""

    code: str
    _SUPPORTED: frozenset[str] = frozenset({"USD", "KES", "EUR"})

    def __post_init__(self) -> None:
        code = self.code.strip().upper()
        if len(code) != 3 or not code.isalpha():
            raise InvalidCurrencyError("Currency code must contain exactly three alphabetic characters.")
        if code not in self._SUPPORTED:
            raise InvalidCurrencyError(f"Unsupported currency '{code}'.")
        object.__setattr__(self, "code", code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return f"Currency('{self.code}')"


@dataclass(frozen=True, slots=True)
class Money:
    amount_cents: int
    currency: Currency

    def __post_init__(self) -> None:
        if self.amount_cents < 0:
            raise InvalidMoneyError("Amount cannot be negative.")

    def __composite_values__(self):
        return (self.amount_cents, self.currency)


@dataclass(frozen=True, slots=True)
class PurchaseHistoryCard:
    purchase_id: UUID
    software_id: UUID
    software_name: str
    amount: Money
    status: PurchaseStatus
    purchased_at: datetime
    last_activity_at: datetime
    refunded_at: datetime | None
    revoked_at: datetime | None


class PurchaseHistoryQuery(BaseModel):
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0)


class PurchaseHistoryPage(BaseModel):
    items: list[PurchaseHistoryCard]
    total: int
    limit: int
    offset: int


__all__ = [
    "PaymentSubject",
    "PaymentProviderDetails",
    "Currency",
    "Money",
    "PurchaseHistoryCard",
    "PurchaseHistoryQuery",
    "PurchaseHistoryPage",
]
