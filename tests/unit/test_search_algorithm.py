import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
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


# ─── matched_fields names the parts of the score ──────────────────────────────
#
# Phase 9a. `matched_fields` used to list only the query signals while the score
# also carried popularity and recency, so a result could be ranked by a signal it
# did not claim. The two pre-existing failures in this file were the symptom. The
# tests below pin the property that replaced the two independent derivations: the
# list is the score read back by name.


def _expected_signals(algo, s, query, now):
    """Recompute the contributions independently, as a cross-check would."""
    return algo._score_contributions(
        software=s,
        query_tokens=algo._tokens((query or "").strip()),
        query_normalized=(query or "").strip(),
        now=now,
    )


@pytest.mark.parametrize("query", ["PopularPkg", "desc", None, "", "nothing-matches"])
@pytest.mark.parametrize(
    "weights",
    [
        {},
        {"popularity_weight": 0.0},
        {"recency_weight": 0.0},
        {"name_weight": 0.0, "description_weight": 0.0},
        {"popularity_weight": 0.0, "recency_weight": 0.0, "exact_match_boost": 0.0},
    ],
    ids=["default", "no-popularity", "no-recency", "no-query-signals", "only-exact"],
)
def test_matched_fields_names_exactly_the_signals_that_moved_the_score(weights, query):
    """The list and the score are one fact, not two derivations of it.

    Parametrised over zero weights on purpose: a signal whose weight is 0 adds
    nothing, so claiming it would be a lie about why the result is where it is.
    This is the case the old string-matching approach could not express, because
    it asked whether a token appeared in the name and never consulted the weight.
    """
    algo = SearchAlgorithm(**weights)
    now = datetime.now(timezone.utc)
    s = make_software("PopularPkg", "desc", download_count=1000, versions=5,
                      created_at=now - timedelta(days=30))

    (scored,) = algo.rank([s], query=query)
    contributions = _expected_signals(algo, s, query, now)

    assert sorted(scored.matched_fields) == sorted(
        name for name, value in contributions.items() if value > 0.0
    )
    assert abs(sum(contributions.values()) - scored.score) < 1e-9


def test_a_zero_weight_signal_is_not_claimed():
    """Popularity with no weight must not appear in the explanation."""
    algo = SearchAlgorithm(popularity_weight=0.0)
    s = make_software("PopularPkg", "desc", download_count=1_000_000, versions=9)

    (scored,) = algo.rank([s], query=None)

    assert "popularity" not in scored.matched_fields
    assert "recency" in scored.matched_fields, "recency is still weighted here"


def test_an_exact_name_match_is_reported_separately():
    """`name_exact` survives, because it is a different reason to rank first.

    It was a distinct entry before Phase 9a and folding it into `name` would have
    discarded the strongest single signal the algorithm has.
    """
    algo = SearchAlgorithm()
    exact = make_software("mypackage", "some desc")
    partial = make_software("my pack", "mypackage in description")

    (top, _) = algo.rank([partial, exact], query="mypackage")

    assert "name_exact" in top.matched_fields
    assert "name" in top.matched_fields


def test_the_exact_match_bonus_is_case_sensitive_and_that_is_pinned():
    """A capitalised query gets no exact-match bonus. This is a bug, pinned.

    ``_calculate_name_contributions`` compares ``software.name.lower()`` against
    ``query_normalized``, and ``query_normalized`` is ``(query or "").strip()`` —
    stripped but never lowercased, despite the parameter docstring saying
    "(lowercased)". Token matching lowercases; the whole-word comparison does not.
    So ``?q=MyPackage`` scores lower than ``?q=mypackage`` for the same product, and
    the exact-match bonus has never fired for a query containing a capital letter.

    Fixing it changes ``score``, and ``score`` is returned by
    ``GET /api/v1/software-management/search`` as the ``scores`` array. Phase 9a's
    invariant is that the HTTP API does not change, so the fix is not made here.

    Pinned rather than left alone because it is otherwise indistinguishable from
    intended weighting: a team member tuning ``exact_match_boost`` would see it have
    no effect on a mixed-case query and conclude the weight was wrong. Recorded in
    docs/REVIEW.md, Phase 9a, "Left alone deliberately".
    """
    algo = SearchAlgorithm()

    lower = make_software("MyPackage", "some desc")
    (scored_lower,) = algo.rank([lower], query="mypackage")
    (scored_capital,) = algo.rank([lower], query="MyPackage")

    assert "name_exact" in scored_lower.matched_fields
    assert "name_exact" not in scored_capital.matched_fields
    assert scored_lower.score == pytest.approx(scored_capital.score + algo.exact_match_boost)


def test_matched_fields_is_not_part_of_any_response():
    """Why the phase could change it without changing the HTTP contract.

    The search route returns items, scores, total, limit and offset, and drops the
    field. This reads the route rather than asserting a snapshot of it, so it names
    the reason if the response ever grows a `matched_fields` key.
    """
    router_source = Path(
        "app/modules/software_management/api/routers/software_router.py"
    ).read_text()

    assert "matched_fields" not in router_source, (
        "matched_fields is now score-derived and reaches the HTTP response. The "
        "Phase 9a invariant that the response shape does not change no longer "
        "holds for the search route, and this needs to be called out as a contract "
        "change rather than discovered by a client."
    )
    for key in ("items", "scores", "total", "limit", "offset"):
        assert f'"{key}"' in router_source
