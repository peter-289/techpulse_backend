from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import log1p, exp
from typing import List, Optional

from app.modules.software_management.domain.entities.software import Software


@dataclass(frozen=True)
class ScoredSoftware:
    """Container for a software candidate with its calculated relevance score.

    Attributes:
        software: The software entity being scored.
        score: Calculated relevance score (higher is more relevant).
        matched_fields: The signals that contributed to ``score`` — ``"name"``,
            ``"name_exact"``, ``"description"``, ``"popularity"``, ``"recency"``.
            A signal appears only if it added something, so a zero weight suppresses
            its name rather than claiming a contribution it did not make.

            The field name says "fields" and the first three entries are fields, but
            ``"popularity"`` and ``"recency"`` are properties of the software rather
            than fields of it, and they are recorded for the same reason: the score
            is a sum of named parts, and a reader asking why one result outranked
            another is asking which parts moved. The name is kept because the
            attribute is asserted by name in ``tests/unit/test_search_algorithm.py``.

            This is not part of any HTTP response. The search route returns
            ``items``, ``scores``, ``total``, ``limit`` and ``offset``
            (``api/routers/software_router.py``) and drops it, so it is a debugging
            and analytics surface only.
    """
    software: Software
    score: float
    matched_fields: list[str]


class SearchAlgorithm:
    """Implements a flexible, weighted search algorithm for software candidates.
    
    The algorithm ranks software candidates based on multiple relevance signals:
    1. **Name Matching** - Priority weighting for software name tokens
    2. **Description Matching** - Secondary weighting for description tokens  
    3. **Popularity** - Logarithmic scoring based on download count + version count
    4. **Recency** - Exponential decay scoring based on creation time
    5. **Exact Match Bonus** - Boost for whole-word exact matches
    
    Designed for marketplace search where users expect software to be discovered
    by name, with recency and popularity as tie-breakers for ranking.
    
    Args:
        name_weight: Weight applied to name token matches (default: 3.0).
        description_weight: Weight applied to description token matches (default: 1.0).
        popularity_weight: Weight applied to popularity metric (default: 0.5).
        recency_weight: Weight applied to recency metric (default: 0.3).
        exact_match_boost: Bonus score for whole-word exact matches (default: 2.5).
    
    Example:
        >>> algo = SearchAlgorithm()
        >>> candidates = [Software.create(name="Apache", description="Web server...")]
        >>> results = algo.rank(candidates, query="Apache")
        >>> top_match = results[0].software
    """

    def __init__(
        self,
        *,
        name_weight: float = 3.0,
        description_weight: float = 1.0,
        popularity_weight: float = 0.5,
        recency_weight: float = 0.3,
        exact_match_boost: float = 2.5,
    ):
        """Initialize the search algorithm with configurable signal weights.
        
        All weights are clamped to non-negative values. Consider tuning these based
        on typical user search behavior and business requirements.
        """
        self.name_weight = float(max(0.0, name_weight))
        self.description_weight = float(max(0.0, description_weight))
        self.popularity_weight = float(max(0.0, popularity_weight))
        self.recency_weight = float(max(0.0, recency_weight))
        self.exact_match_boost = float(max(0.0, exact_match_boost))

    @staticmethod
    def _tokens(text: str) -> list[str]:
        """Extract and normalize tokens from text for matching.
        
        Uses improved tokenization that handles:
        - Unicode word characters
        - Apostrophes (e.g., "don't" → ["don", "t"])
        - Hyphens (e.g., "machine-learning" → ["machine", "learning"])
        - Numbers and underscores
        
        Args:
            text: Input text to tokenize (case-insensitive).
        
        Returns:
            List of normalized lowercase tokens.
        """
        if not text:
            return []
        
        import re
        # Improved regex: matches word characters, apostrophes (as separate tokens), hyphens
        # This handles common software naming patterns and edge cases
        tokens = re.findall(r"[\w']+|[\w-]+", text.lower())
        return [token for token in tokens if token]  # Remove any empty tokens

    def rank(self, candidates: list[Software], query: Optional[str] = None) -> list[ScoredSoftware]:
        """Rank software candidates by relevance to the search query.
        
        Implements a weighted scoring algorithm that balances multiple relevance signals.
        The algorithm is deterministic and side-effect free, making it suitable for
        concurrent use and caching.
        
        Args:
            candidates: List of Software entities to rank.
            query: Search query string. Empty or None queries return all candidates
                ranked by popularity and recency only.
        
        Returns:
            List of ScoredSoftware instances sorted by relevance score (highest first).
            Empty list if candidates is empty.
        
        Raises:
            TypeError: If candidates is not a list or contains invalid types.
            
        Performance:
            O(N*M) where N=candidates and M=query_tokens. For large candidate sets,
            consider pre-filtering or implementing pagination at the service layer.
        """
        if not candidates:
            return []
        
        # Handle empty/invalid queries gracefully - rank by relevance signals only
        query_normalized = (query or "").strip()
        query_tokens = self._tokens(query_normalized) if query_normalized else []
        
        now = datetime.now(timezone.utc)
        scored: List[ScoredSoftware] = []

        for software in candidates:
            contributions = self._score_contributions(
                software=software,
                query_tokens=query_tokens,
                query_normalized=query_normalized,
                now=now,
            )

            scored.append(ScoredSoftware(
                software=software,
                score=float(sum(contributions.values())),
                matched_fields=[name for name, value in contributions.items() if value > 0.0],
            ))

        # Sort by relevance score (highest first) with tie-breaking by name match count
        scored.sort(key=lambda x: (-x.score, -sum(1 for f in x.matched_fields if f == "name")))
        return scored

    def _score_contributions(
        self,
        software: Software,
        query_tokens: list[str],
        query_normalized: str,
        now: datetime,
    ) -> dict[str, float]:
        """Score one candidate, naming each part of the score.

        The score is a sum of independent signals, and the list of what matched is
        the same sum read back by name. Returning both from one pass is the point:
        this used to be a `_calculate_relevance_score` that added four values and
        returned the total, plus a separate `_identify_matched_fields` that re-derived
        which of them applied. Two derivations of one fact is how the two could
        disagree, and they did — the query signals were recorded and the popularity
        and recency signals were not, so a result could be ranked by a signal it did
        not claim. `tests/unit/test_search_algorithm.py` failed on exactly that from
        the Phase 0 baseline until Phase 9a.

        A signal with a zero weight contributes zero and is therefore absent from
        `matched_fields`, which is the truthful reading: with `popularity_weight=0`
        no result should claim popularity moved it.

        Returns:
            Signal name to contribution, in the order they are summed. Every value is
            >= 0, so `value > 0.0` means "this signal moved the score".
        """
        contributions: dict[str, float] = {}
        contributions.update(
            self._calculate_name_contributions(software, query_tokens, query_normalized)
        )
        contributions["description"] = self._calculate_description_score(
            software, query_tokens
        )
        contributions["popularity"] = self._calculate_popularity_score(software)
        contributions["recency"] = self._calculate_recency_score(software, now)
        return contributions

    def _calculate_name_contributions(
        self,
        software: Software,
        query_tokens: list[str],
        query_normalized: str,
    ) -> dict[str, float]:
        """Split the name signal into token matches and the whole-word exact bonus.

        Two signals rather than one, because they are two different reasons a result
        ranks where it does: a query token appearing in the name is weak evidence,
        and the query *being* the name is strong. Recorded separately since the
        distinction was there before Phase 9a and folding them together would have
        thrown it away.

        The two sum to the value `_calculate_name_score` used to return, so the
        total score is unchanged.

        Args:
            software: Software entity to evaluate.
            query_tokens: Tokenized query.
            query_normalized: Normalized query string.

        Returns:
            ``{"name": ..., "name_exact": ...}``, with the absent part as 0.0.
        """
        name_tokens = self._tokens(software.name)
        lowered = software.name.lower()
        exact_word_matches = sum(1 for token in query_tokens if token == lowered)
        partial_matches = sum(
            1 for token in query_tokens if token in name_tokens and token != lowered
        )

        return {
            "name": self.name_weight * (exact_word_matches * 2 + partial_matches),
            "name_exact": (
                self.exact_match_boost
                if query_normalized and lowered == query_normalized
                else 0.0
            ),
        }

    def _calculate_description_score(self, software: Software, query_tokens: list[str]) -> float:
        """Calculate description relevance score.
        
        Args:
            software: Software entity to evaluate.
            query_tokens: Tokenized query.
        
        Returns:
            Description relevance score.
        """
        if not query_tokens or not software.description:
            return 0.0
        
        desc_tokens = self._tokens(software.description)
        matches = sum(1 for token in query_tokens if token in desc_tokens)
        
        return self.description_weight * matches

    def _calculate_popularity_score(self, software: Software) -> float:
        """Calculate popularity-based relevance score.
        
        Uses logarithmic scaling to prevent high-traffic software from dominating
        rankings disproportionately while still rewarding popularity.
        
        Args:
            software: Software entity to evaluate.
        
        Returns:
            Popularity relevance score.
        """
        # Get download count with safe default
        download_count = getattr(software, "download_count", 0) or 0
        
        # Get version count with safe default  
        version_count = len(getattr(software, "versions", []) or [])
        
        pop_metric = download_count + version_count
        
        if pop_metric <= 0:
            return 0.0
            
        # Apply logarithmic scaling: each order of magnitude has diminishing returns
        return self.popularity_weight * log1p(pop_metric)

    def _calculate_recency_score(self, software: Software, now: datetime) -> float:
        """Calculate recency-based relevance score using exponential decay.
        
        Newer software gets higher scores with exponential decay over time.
        The half-life is approximately 1 year (365 days) - balances freshness
        without being overly punitive toward older but established software.
        
        Args:
            software: Software entity to evaluate.
            now: Current timestamp for age calculation.
        
        Returns:
            Recency relevance score, or 0.0 if creation date is unavailable.
        """
        created_at = getattr(software, "created_at", None)
        if not created_at:
            return 0.0

        try:
            # Calculate age in days with timezone awareness
            age_seconds = max(0.0, (now - created_at).total_seconds())
            age_days = age_seconds / 86400.0

            # Exponential decay: score decays from 1.0 (new) to near 0 (old)
            # Half-life of approximately 1 year (365 days)
            recency_score = exp(-age_days / 365.0)

            return self.recency_weight * recency_score

        except Exception:
            # Fail gracefully if datetime calculations fail
            return 0.0
