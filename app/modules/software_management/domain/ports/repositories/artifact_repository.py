from typing import Protocol, runtime_checkable
from uuid import UUID

from app.modules.software_management.domain.entities.artifact import Artifact


@runtime_checkable
class ArtifactRepository(Protocol):
    async def get(self, artifact_id: UUID) -> Artifact | None:
        """Return an artifact by ID, or ``None`` if absent."""

    async def save(self, artifact: Artifact) -> None:
        """Persist (insert or update) an artifact."""
