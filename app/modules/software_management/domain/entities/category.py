from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4
from app.modules.software_management.domain.exceptions import CategoryDeletedError


def utc_now() -> datetime:
    """Return the current time in UTC with a timezone aware value."""
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    """Coerce a naive datetime to UTC and normalize aware ones to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_name(name: str) -> str:
    """Trim and collapse internal whitespace for stable, unique names."""
    return " ".join(name.strip().split())


@dataclass(slots=True)
class Category:
    """Software category aggregate root.

    Encapsulates the business invariants for a category. Persistence concerns
    are intentionally absent; the repository is responsible for mapping to and
    from this entity.
    """

    id: UUID
    name: str
    description: str | None = None

    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    deleted_at: datetime | None = None

    def __post_init__(self) -> None:
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)

    # ─── Factories ───
    @classmethod
    def create(
        cls,
        *,
        name: str,
        description: str | None = None,
    ) -> "Category":
        """Create a new category with normalized fields."""
        normalized_name = _normalize_name(name)
        normalized_description = description.strip() if description else None
        return cls(
            id=uuid4(),
            name=normalized_name,
            description=normalized_description,
        )

    # ─── Invariants ───
    def _ensure_modifiable(self) -> None:
        """Guard that blocks state-changing commands on deleted categories."""
        if self.is_deleted():
            raise CategoryDeletedError("Deleted categories cannot be modified.")

    # ─── Behavior ───
    def rename(self, name: str) -> None:
        """Rename the category, normalizing the incoming value."""
        self._ensure_modifiable()
        self.name = _normalize_name(name)
        self._touch()

    def update_description(self, description: str | None) -> None:
        """Update or clear the category description."""
        self._ensure_modifiable()
        self.description = description.strip() if description else None
        self._touch()

    def mark_deleted(self, *, marked_at: datetime | None = None) -> None:
        """Soft-delete the category."""
        if self.is_deleted():
            return
        self.deleted_at = _ensure_utc(marked_at) if marked_at else utc_now()
        self._touch()

    def restore(self) -> None:
        """Restore a previously soft-deleted category."""
        if not self.is_deleted():
            return
        self.deleted_at = None
        self._touch()

    def _touch(self) -> None:
        """Update the updated_at timestamp to the current UTC time."""
        self.updated_at = utc_now()

    # ─── Queries ───
    def is_deleted(self) -> bool:
        """Return whether the category is currently soft-deleted."""
        return self.deleted_at is not None
