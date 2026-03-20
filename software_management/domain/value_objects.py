from __future__ import annotations

import re
from enum import Enum
from dataclasses import dataclass


_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class VersionStatus(str, Enum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    DEPRECATED = "DEPRECATED"
    REVOKED = "REVOKED"

    @property
    def is_public(self) -> bool:
        return self in {VersionStatus.PUBLISHED, VersionStatus.DEPRECATED}


@dataclass(frozen=True, slots=True)
class VersionNumber:
    value: str

    def __post_init__(self) -> None:
        if not _SEMVER_RE.match(self.value):
            raise ValueError("version must follow semantic versioning (e.g. 1.2.3)")


@dataclass(frozen=True, slots=True)
class FileHash:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().lower()
        if not _SHA256_RE.match(normalized):
            raise ValueError("file hash must be a valid sha256 hex digest")
        object.__setattr__(self, "value", normalized)
