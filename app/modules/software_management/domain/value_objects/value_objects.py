from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
import re
from pathlib import Path

from app.modules.shared.enums import SoftwareStatus, SoftwareVisibility
from app.modules.software_management.domain.exceptions import InvalidSemVerError


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
class UploadedFile:
    """Upload file data shape."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    temp_path: Path