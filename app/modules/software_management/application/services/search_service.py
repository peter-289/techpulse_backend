from __future__ import annotations

from typing import List, Tuple
from uuid import UUID

from .search_algorithm import SearchAlgorithm, ScoredSoftware
from app.modules.software_management.domain.exceptions import RepositoryUnavailableError


class SearchService:
    def __init__(self, repository, algorithm: SearchAlgorithm | None = None):
        self.repository = repository
        self.algorithm = algorithm or SearchAlgorithm()

    async def search(
        self,
        query: str | None = None,
        *,
        category_id: UUID | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[ScoredSoftware], int]:
        # sanitize query
        q = query.strip() if query else None
        try:
            candidates = await self.repository.search_candidates(query=q, category_id=category_id, tags=tags, limit=500)
        except Exception as exc:
            # translate DB errors
            raise RepositoryUnavailableError("Search repository unavailable") from exc

        scored = self.algorithm.rank(candidates=candidates, query=q)
        total = len(scored)
        page = scored[offset : offset + limit]
        return page, total
