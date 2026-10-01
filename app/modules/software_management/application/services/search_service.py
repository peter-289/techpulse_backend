from __future__ import annotations

from typing import List, Tuple
from uuid import UUID

from .search_algorithm import SearchAlgorithm, ScoredSoftware
from app.modules.software_management.domain.exceptions import RepositoryUnavailableError


class SearchService:
    """Ranks software against a query and paginates the result.

    Ranking happens in Python over a bounded candidate set rather than in SQL, so
    scoring rules can change without a migration. The trade-off is a hard ceiling:
    the repository returns at most ``CANDIDATE_LIMIT`` rows, so results past that
    boundary are unreachable and ``total`` reports the ranked count, not the number
    of matching rows in the table.
    """

    CANDIDATE_LIMIT = 500

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
        """Search and return ``(page, total_ranked)``.

        ``total`` is the number of ranked candidates, not a database count, so it
        saturates at :attr:`CANDIDATE_LIMIT`.

        Raises:
            RepositoryUnavailableError: If the candidate query fails.
        """
        q = query.strip() if query else None
        try:
            candidates = await self.repository.search_candidates(
                query=q,
                category_id=category_id,
                tags=tags,
                limit=self.CANDIDATE_LIMIT,
            )
        except Exception as exc:
            # Any adapter failure is reported as one domain error rather than
            # leaking a driver-specific exception to the API layer. The cause is
            # chained so the original is still visible in the traceback.
            raise RepositoryUnavailableError("Search repository unavailable") from exc

        scored = self.algorithm.rank(candidates=candidates, query=q)
        total = len(scored)
        page = scored[offset : offset + limit]
        return page, total
