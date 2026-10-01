from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.value_objects import SoftwareCard, OwnedSoftwareCard


@runtime_checkable
class ISoftwareRepository(Protocol):
    async def save(self, software: Software) -> None:
        """Persist or update software."""
        ...

    async def get(self, software_id: UUID) -> Software | None:
        """Get software by ID with all relationships loaded."""
        ...

    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        """Check if a buyer has a purchase.

        This one method deliberately does not have a ``...`` body. The
        implementation subclasses this protocol explicitly, so an unimplemented
        member is inherited rather than missing: with a ``...`` body
        ``has_purchase`` returned ``None`` for every user, which is falsy, which
        read as "this user has no purchase" and cost a 403 to anyone who had
        actually bought the software. An unimplemented query that decides
        authorization has to be loud. ``tests/architecture/
        test_ports_have_no_silent_defaults.py`` fails if this returns to ``...``.
        """
        raise NotImplementedError(
            "has_purchase has no data source: the purchase table was removed with the "
            "billing module. See docs/REVIEW.md, Phase 9a, 'Left alone deliberately'."
        )

    async def list_marketplace(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SoftwareCard]:
        """List software cards for marketplace. Returns (items, total)."""
        ...

    async def list_owned(
        self,
        owner_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[OwnedSoftwareCard], int]:
        """
        List software owned by owner. Returns (items, total).
         If owner_id is None, returns empty list.
         Used for "My Software" page.
        """
        ...

    async def soft_delete(self, software_id: UUID) -> None:
        """Mark as deleted."""
        ...

    async def search_candidates(
        self,
        query: str | None = None,
        *,
        category_id: UUID | None = None,
        tags: list[str] | None = None,
        limit: int = 500,
    ) -> list[Software]:
        """
        Fetch candidate software matching broad filters.
        Returns unranked results — service layer applies ranking.
        """
        ...
