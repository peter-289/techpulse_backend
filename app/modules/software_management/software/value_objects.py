from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import re
from .enums import SoftwareStatus, SoftwareVisibility


from .exceptions import InvalidSemVerError


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
    id: UUID
    name: str
    description: str
    
    visibility: SoftwareVisibility
    status: SoftwareStatus

    latest_version: str | None
    
    price_cents: int | None
    currency: str | None

    updated_at: datetime | None
    created_at: datetime | None
    latest_version: str | None