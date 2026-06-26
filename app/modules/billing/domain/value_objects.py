from __future__ import annotations


from dataclasses import dataclass, field
from typing import Mapping
from uuid import UUID


from app.modules.shared.enums import PaymentResourceType
from app.exceptions.exceptions import InvalidCurrencyError, InvalidMoneyError





@dataclass(frozen=True, slots=True)
class PaymentSubject:
    resource_type: PaymentResourceType
    resource_id: UUID

@dataclass(frozen=True, slots=True)
class PaymentProviderDetails:
    reference: str
    metadata: Mapping[str, str] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class Currency:
    """
    Immutable value object representing a supported ISO 4217 currency code.

    Guarantees:
        - Uppercase
        - Exactly 3 alphabetic characters
        - Supported by the business
    """

    code: str
    _SUPPORTED: frozenset[str] = frozenset({
        "USD",
        "KES",
        "EUR",
    })

    def __post_init__(self) -> None:
        code = self.code.strip().upper()

        if len(code) != 3 or not code.isalpha():
            raise InvalidCurrencyError(
                "Currency code must contain exactly three alphabetic characters."
            )

        if code not in self._SUPPORTED:
            raise InvalidCurrencyError(
                f"Unsupported currency '{code}'."
            )

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
            raise InvalidMoneyError(
                "Amount cannot be negative."
            )


