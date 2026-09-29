from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import re

from app.modules.shared.enums import SoftwareStatus, SoftwareVisibility
from app.modules.software_management.domain.exceptions import InvalidSemVerError
from app.exceptions.exceptions import InvalidCurrencyError, InvalidMoneyError


_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "SemVer":
        match = _SEMVER_RE.match((raw or "").strip())
        if not match:
            raise InvalidSemVerError(f"Invalid semantic version: {raw}")
        major, minor, patch = (int(part) for part in match.groups())
        return cls(major=major, minor=minor, patch=patch)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


# Minimal representation of a software card for listing purposes
@dataclass(frozen=True, slots=True)
class SoftwareCard:
    id: UUID
    name: str
    description: str

    price_cents: int | None
    currency: str | None

    latest_version: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class OwnedSoftwareCard:
    id: str
    name: str
    description: Optional[str]

    visibility: SoftwareVisibility
    status: SoftwareStatus | None = None

    latest_version: str | None = None

    price_cents: int | None = None
    currency: str | None = None

    updated_at: datetime | None = None
    created_at: datetime | None = None
   
   



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
