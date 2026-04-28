from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re

from .exceptions import InvalidSemVerError, ValidationError

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "SemVer":
        match = _SEMVER_RE.match(raw)
        if not match:
            raise InvalidSemVerError(f"Invalid semantic version: {raw}")
        major, minor, patch = (int(part) for part in match.groups())
        return cls(major=major, minor=minor, patch=patch)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class Money:
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        if self.amount < Decimal("0"):
            raise ValidationError("Money amount cannot be negative.")
        if len(self.currency) != 3:
            raise ValidationError("Currency must be ISO-4217 3-letter code.")
