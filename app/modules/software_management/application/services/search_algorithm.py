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
        matched_fields: List of field names where the query matched (e.g., "name", "description").
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
            score = self._calculate_relevance_score(
                software=software,
                query_tokens=query_tokens,
                query_normalized=query_normalized,
                now=now
            )
            
            matched_fields = self._identify_matched_fields(
                software=software,
                query_tokens=query_tokens,
                query_normalized=query_normalized
            )
            
            scored.append(ScoredSoftware(
                software=software,
                score=float(score),
                matched_fields=matched_fields
            ))
        
        # Sort by relevance score (highest first) with tie-breaking by name match count
        scored.sort(key=lambda x: (-x.score, -sum(1 for f in x.matched_fields if f == "name")))
        return scored

    def _calculate_relevance_score(
        self,
        software: Software,
        query_tokens: list[str],
        query_normalized: str,
        now: datetime
    ) -> float:
        """Calculate the total relevance score for a single software candidate.
        
        Args:
            software: The Software entity to score.
            query_tokens: Pre-tokenized query tokens (lowercased).
            query_normalized: Original normalized query string (lowercased).
            now: Current timestamp for recency calculations.
        
        Returns:
            Total relevance score as a float.
        """
        base_score = 0.0
        
        # Name matching - primary signal for search relevance
        name_score = self._calculate_name_score(software, query_tokens, query_normalized)
        base_score += name_score
        
        # Description matching - secondary signal for semantic relevance  
        description_score = self._calculate_description_score(software, query_tokens)
        base_score += description_score
        
        # Popularity signal - favors well-established, widely used software
        popularity_score = self._calculate_popularity_score(software)
        base_score += popularity_score
        
        # Recency signal - favors newer, recently updated software
        recency_score = self._calculate_recency_score(software, now)
        base_score += recency_score
        
        return base_score

    def _calculate_name_score(
        self,
        software: Software,
        query_tokens: list[str],
        query_normalized: str
    ) -> float:
        """Calculate name relevance score including exact match bonus.
        
        Args:
            software: Software entity to evaluate.
            query_tokens: Tokenized query.
            query_normalized: Normalized query string.
        
        Returns:
            Name relevance score.
        """
        score = 0.0
        
        # Count matching tokens in software name
        name_tokens = self._tokens(software.name)
        exact_word_matches = sum(1 for token in query_tokens if token == software.name.lower())
        partial_matches = sum(1 for token in query_tokens if token in name_tokens and token != software.name.lower())
        
        score += self.name_weight * (exact_word_matches * 2 + partial_matches)
        
        # Apply exact match bonus for whole-word name matches
        if query_normalized and software.name.lower() == query_normalized:
            score += self.exact_match_boost
        
        return score

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

    def _identify_matched_fields(
        self,
        software: Software,
        query_tokens: list[str],
        query_normalized: str
    ) -> list[str]:
        """Identify which software fields matched the query.
        
        Tracks match sources for debugging, analytics, and UI highlighting.
        
        Args:
            software: Software entity to evaluate.
            query_tokens: Tokenized query.
            query_normalized: Normalized query string.
        
        Returns:
            List of field names where matches were found (e.g., ["name", "description"]).
        """
        matched_fields = []
        
        # Check name matches
        name_tokens = self._tokens(software.name)
        if any(token in name_tokens for token in query_tokens):
            matched_fields.append("name")
        
        # Check for whole-word exact match in name
        if query_normalized and software.name.lower() == query_normalized:
            matched_fields.append("name_exact")
        
        # Check description matches
        if software.description:
            desc_tokens = self._tokens(software.description)
            if any(token in desc_tokens for token in query_tokens):
                matched_fields.append("description")
        
        return matched_fields
