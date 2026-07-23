import asyncio
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from app.modules.software_management.application.services.search_algorithm import SearchAlgorithm
from app.modules.software_management.domain.entities.software import Software
from app.modules.shared.enums import SoftwareVisibility


def make_software(name: str, description: str = "", download_count: int = 0, versions: int = 0, created_at: datetime | None = None):
    owner = uuid4()
    s = Software.create(
        name=name,
        description=description,
        owner_id=owner,
        visibility=SoftwareVisibility.PUBLIC,
    )
    # attach lightweight metadata used by algorithm
    setattr(s, "download_count", download_count)
    s.versions = [object()] * versions
    if created_at:
        s.created_at = created_at
    return s


def test_name_matches_score_higher_than_description():
    algo = SearchAlgorithm(name_weight=3.0, description_weight=1.0, exact_match_boost=0.0)
    s_name = make_software("SearchMe", "not relevant")
    s_desc = make_software("Other", "SearchMe is excellent")

    scored = algo.rank([s_name, s_desc], query="SearchMe")
    assert scored[0].software is s_name
    assert scored[0].score > scored[1].score
    assert "name" in scored[0].matched_fields


def test_exact_match_boost_applies():
    algo = SearchAlgorithm(exact_match_boost=2.5)
    s_exact = make_software("MyPackage", "some desc")
    s_partial = make_software("My Pack", "MyPackage in description")

    scored = algo.rank([s_partial, s_exact], query="MyPackage")
    # exact by name should outrank partial
    assert scored[0].software is s_exact
    assert any(f.startswith("name") for f in scored[0].matched_fields)


def test_popularity_increases_score():
    algo = SearchAlgorithm(popularity_weight=1.0)
    s_pop = make_software("PopularPkg", "desc", download_count=1000, versions=5)
    s_plain = make_software("PopularPkg", "desc", download_count=0, versions=1)

    scored = algo.rank([s_plain, s_pop], query="PopularPkg")
    assert scored[0].software is s_pop
    assert scored[0].score > scored[1].score
    assert "popularity" in scored[0].matched_fields


def test_recency_prefers_newer():
    algo = SearchAlgorithm(recency_weight=1.0)
    now = datetime.now(timezone.utc)
    older = make_software("Pkg", "desc", created_at=now - timedelta(days=365 * 3))
    newer = make_software("Pkg", "desc", created_at=now - timedelta(days=30))

    scored = algo.rank([older, newer], query=None)
    # newer should have higher recency contribution and thus higher score
    assert scored[0].software is newer
    assert "recency" in scored[0].matched_fields


def test_algorithm_is_pure_and_non_mutating():
    algo = SearchAlgorithm()
    s = make_software("PurePkg", "desc")
    before = (s.name, s.description, getattr(s, "download_count", None))
    _ = algo.rank([s], query="PurePkg")
    after = (s.name, s.description, getattr(s, "download_count", None))
    assert before == after
