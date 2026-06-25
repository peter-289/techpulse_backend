from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import log1p, exp
from typing import List

from .software.software import Software


@dataclass(frozen=True)
class ScoredSoftware:
    software: Software
    score: float
    matched_fields: list[str]


class SearchAlgorithm:
    def __init__(
        self,
        *,
        name_weight: float = 3.0,
        description_weight: float = 1.0,
        popularity_weight: float = 0.5,
        recency_weight: float = 0.3,
        exact_match_boost: float = 2.5,
    ):
        self.name_weight = float(name_weight)
        self.description_weight = float(description_weight)
        self.popularity_weight = float(popularity_weight)
        self.recency_weight = float(recency_weight)
        self.exact_match_boost = float(exact_match_boost)

    @staticmethod
    def _tokens(text: str) -> list[str]:
        if not text:
            return []
        # simple tokenization: split on non-word characters
        import re

        return [t.lower() for t in re.findall(r"\b\w+\b", text)]

    def rank(self, candidates: list[Software], query: str | None = None) -> list[ScoredSoftware]:
        query_tokens = self._tokens(query or "")
        query_lower = (query or "").strip().lower()
        now = datetime.now(timezone.utc)

        scored: List[ScoredSoftware] = []

        for s in candidates:
            score = 0.0
            matched: list[str] = []

            # Name matches
            name_tokens = self._tokens(s.name)
            name_matches = sum(1 for t in query_tokens if t in name_tokens)
            if name_matches:
                score += self.name_weight * name_matches
                matched.append("name")

            # word-boundary exact token match in name (bonus)
            if query_lower and query_lower in s.name.lower():
                # partial exact or substring
                score += self.exact_match_boost
                if "name_exact" not in matched:
                    matched.append("name_exact")

            # Description matches
            desc_tokens = self._tokens(s.description or "")
            desc_matches = sum(1 for t in query_tokens if t in desc_tokens)
            if desc_matches:
                score += self.description_weight * desc_matches
                matched.append("description")

            # Popularity: use download_count + version_count from the entity if present
            download_count = getattr(s, "download_count", 0) or 0
            version_count = len(getattr(s, "versions", []) or [])
            pop_metric = download_count + version_count
            if pop_metric > 0:
                score += self.popularity_weight * log1p(pop_metric)
                matched.append("popularity")

            # Recency: exponential decay based on created_at
            created_at = getattr(s, "created_at", None)
            if created_at:
                try:
                    # assume datetime
                    age_days = max(0.0, (now - created_at).total_seconds() / 86400.0)
                    recency_score = exp(-age_days / 365.0)  # year-scale decay
                    score += self.recency_weight * recency_score
                    matched.append("recency")
                except Exception:
                    pass

            scored.append(ScoredSoftware(software=s, score=float(score), matched_fields=matched))

        # sort descending by score
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored
